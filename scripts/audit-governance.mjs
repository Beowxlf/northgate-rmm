import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

import { validateV1dAuthority } from "./lib/validate-v1d-authority.mjs";
import { verifyCmsDetached } from "./lib/verify-cms.mjs";

const root = process.cwd();
const errors = [];
const warnings = [];

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

function exists(relativePath) {
  return fs.existsSync(path.join(root, relativePath));
}

function isRegularFile(relativePath) {
  if (typeof relativePath !== "string" || relativePath.trim() === "")
    return false;
  try {
    return fs.statSync(path.join(root, relativePath)).isFile();
  } catch {
    return false;
  }
}

function isCommit(commit) {
  return (
    spawnSync("git", ["cat-file", "-e", `${commit}^{commit}`], {
      cwd: root,
      stdio: "ignore",
    }).status === 0
  );
}

function isProtectedMainCommit(commit) {
  return (
    spawnSync("git", ["merge-base", "--is-ancestor", commit, "origin/main"], {
      cwd: root,
      stdio: "ignore",
    }).status === 0
  );
}

function readAtCommit(commit, relativePath) {
  const result = spawnSync("git", ["show", `${commit}:${relativePath}`], {
    cwd: root,
    encoding: "utf8",
  });
  return result.status === 0 ? result.stdout : null;
}

function readAtProtectedMain(relativePath) {
  const result = spawnSync("git", ["show", `origin/main:${relativePath}`], {
    cwd: root,
    encoding: "utf8",
  });
  return result.status === 0 ? result.stdout : null;
}

function isPathImmutableOnProtectedMain(commit, relativePath) {
  const history = spawnSync(
    "git",
    ["log", "--format=%H", "--full-history", "origin/main", "--", relativePath],
    { cwd: root, encoding: "utf8" },
  );
  if (history.status !== 0) return false;
  const commits = history.stdout.trim().split(/\r?\n/).filter(Boolean);
  if (commits.length !== 1) return false;
  return (
    spawnSync("git", ["merge-base", "--is-ancestor", commits[0], commit], {
      cwd: root,
      stdio: "ignore",
    }).status === 0
  );
}

function isPathIntroducedBefore(earlierPath, laterPath) {
  const historyFor = (relativePath) => {
    const history = spawnSync(
      "git",
      [
        "log",
        "--format=%H",
        "--full-history",
        "origin/main",
        "--",
        relativePath,
      ],
      { cwd: root, encoding: "utf8" },
    );
    if (history.status !== 0) return [];
    return history.stdout.trim().split(/\r?\n/).filter(Boolean);
  };
  const earlier = historyFor(earlierPath);
  const later = historyFor(laterPath);
  if (earlier.length !== 1 || later.length !== 1 || earlier[0] === later[0])
    return false;
  return (
    spawnSync("git", ["merge-base", "--is-ancestor", earlier[0], later[0]], {
      cwd: root,
      stdio: "ignore",
    }).status === 0
  );
}

function pathIntroductionTime(relativePath) {
  const history = spawnSync(
    "git",
    ["log", "--format=%H", "--full-history", "origin/main", "--", relativePath],
    { cwd: root, encoding: "utf8" },
  );
  if (history.status !== 0) return null;
  const commits = history.stdout.trim().split(/\r?\n/).filter(Boolean);
  if (commits.length !== 1) return null;
  const timestamp = spawnSync(
    "git",
    ["show", "-s", "--format=%cI", commits[0]],
    {
      cwd: root,
      encoding: "utf8",
    },
  );
  return timestamp.status === 0 ? timestamp.stdout.trim() : null;
}

function protectedMainPathVersionCount(relativePath) {
  const history = spawnSync(
    "git",
    ["log", "--format=%H", "--full-history", "origin/main", "--", relativePath],
    { cwd: root, encoding: "utf8" },
  );
  if (history.status !== 0) return null;
  return history.stdout.trim().split(/\r?\n/).filter(Boolean).length;
}

function walk(directory) {
  if (!exists(directory)) return [];
  return fs
    .readdirSync(path.join(root, directory), { withFileTypes: true })
    .flatMap((entry) => {
      const relative = path.posix.join(
        directory.replaceAll("\\", "/"),
        entry.name,
      );
      return entry.isDirectory() ? walk(relative) : [relative];
    });
}

function error(message) {
  errors.push(message);
}

function warning(message) {
  warnings.push(message);
}

const gates = JSON.parse(read("governance/gates.json"));
const controls = JSON.parse(read("governance/controls.json"));
const githubBaseline = JSON.parse(read("governance/github-baseline.json"));

if (gates.schemaVersion !== 1) error("Unsupported gates schema version.");
if (controls.schemaVersion !== 1) error("Unsupported controls schema version.");
if (githubBaseline.schemaVersion !== 1)
  error("Unsupported GitHub baseline schema version.");
if (
  githubBaseline.owner !== "Beowxlf" ||
  githubBaseline.repository !== "northgate-rmm"
) {
  error("GitHub baseline targets an unexpected repository.");
}
if (githubBaseline.visibility !== "public")
  error(
    "Licensed GitHub repository must be public for free branch protection.",
  );
if (githubBaseline.actions.defaultWorkflowPermissions !== "read")
  error("GitHub Actions default permissions must be read-only.");
if (githubBaseline.actions.canApprovePullRequestReviews !== false)
  error("GitHub Actions must not approve pull requests.");
if (githubBaseline.security.privateVulnerabilityReporting !== true)
  error(
    "Private vulnerability reporting must be required for the public repository.",
  );
if (
  !githubBaseline.security.dependabotAlerts ||
  !githubBaseline.security.dependabotSecurityUpdates
) {
  error("Dependabot alerts and security updates must be required.");
}
const expectedChecks = new Set([
  "Pre-code governance audit",
  "Free-software security checks",
  "Debian 12 systemd qualification",
  "Release-candidate trust qualification",
]);
for (const check of expectedChecks) {
  if (!githubBaseline.mainProtection.requiredStatusChecks.includes(check))
    error(`GitHub baseline lacks required status check: ${check}`);
}
if (
  githubBaseline.mainProtection.allowForcePushes ||
  githubBaseline.mainProtection.allowDeletions
) {
  error("GitHub baseline permits force pushes or deletions on main.");
}
if (githubBaseline.mainProtection.requireBranchesUpToDate !== true)
  error(
    "GitHub baseline must require pull-request branches to be current with main.",
  );
if (
  githubBaseline.mainProtection.reviewMode !== "single-maintainer" ||
  githubBaseline.mainProtection.requiredApprovingReviewCount !== 0 ||
  githubBaseline.mainProtection.requireCodeOwnerReview !== false
) {
  error("GitHub review settings do not match approved single-maintainer mode.");
}

const gateIds = gates.gates.map((gate) => gate.id);
if (new Set(gateIds).size !== gateIds.length) error("Duplicate gate ID.");
for (let number = 0; number <= 8; number += 1) {
  if (!gateIds.includes(`G${number}`)) error(`Missing gate G${number}.`);
}

for (const authorityError of validateV1dAuthority(gates, {
  isRegularFile,
  readText: read,
  readAtCommit,
  readAtProtectedMain,
  isPathImmutableOnProtectedMain,
  isPathIntroducedBefore,
  pathIntroductionTime,
  verifyFactoryReceiptSignature: verifyCmsDetached,
  isCommit,
  isProtectedMainCommit,
  protectedMainPathVersionCount,
}))
  error(authorityError);

for (const artifact of gates.requiredPhase0Artifacts) {
  if (!exists(artifact))
    error(`Missing required Phase 0 artifact: ${artifact}`);
  else if (!read(artifact).trim())
    error(`Empty required Phase 0 artifact: ${artifact}`);
}

for (const gate of gates.gates) {
  if (!["open", "closed"].includes(gate.status))
    error(`Invalid status for ${gate.id}.`);
  if (
    gate.status === "open" &&
    gate.authorization &&
    !exists(gate.authorization)
  ) {
    error(
      `Open gate ${gate.id} lacks authorization record ${gate.authorization}.`,
    );
  }
}

if (!gates.productCodeAuthorized) {
  for (const productPath of gates.productCodePaths) {
    if (exists(productPath))
      error(`Product code path exists while G1 is closed: ${productPath}`);
  }
}

const requirementText = read("docs/security/SECURITY_REQUIREMENTS.md");
const requirementIds = [
  ...requirementText.matchAll(/\*\*(SR-[A-Z]+-\d{3}):?\*\*/g),
].map((match) => match[1]);
if (requirementIds.length < 40)
  error(
    `Expected at least 40 security requirements; found ${requirementIds.length}.`,
  );
if (new Set(requirementIds).size !== requirementIds.length)
  error("Duplicate security requirement ID.");

const controlIds = controls.controls.map((control) => control.id);
if (new Set(controlIds).size !== controlIds.length)
  error("Duplicate control ID.");
const mappedRequirements = new Set(
  controls.controls.flatMap((control) => control.requirements),
);
for (const requirementId of requirementIds) {
  if (!mappedRequirements.has(requirementId))
    error(`Unmapped security requirement: ${requirementId}`);
}
for (const control of controls.controls) {
  for (const evidence of control.evidence) {
    if (!exists(evidence))
      error(`${control.id} references missing evidence: ${evidence}`);
  }
}

const mandatoryConcepts = {
  "docs/architecture/REMOTE_ACCESS.md": [
    "Windows",
    "Linux",
    "RDP",
    "SSH",
    "session gateway",
    "revocation",
  ],
  "docs/architecture/PROTOCOL.md": [
    "mutual TLS",
    "replay",
    "result_unknown",
    "revocation",
  ],
  "docs/security/THREAT_MODEL.md": [
    "remote-session",
    "update",
    "CI workflow",
    "backup",
  ],
  "docs/governance/PHASES.md": [
    "Phase 0",
    "Phase 1",
    "Phase 7",
    "Windows",
    "Linux",
  ],
};
for (const [document, concepts] of Object.entries(mandatoryConcepts)) {
  const text = read(document).toLowerCase();
  for (const concept of concepts) {
    if (!text.includes(concept.toLowerCase()))
      error(`${document} lacks mandatory concept: ${concept}`);
  }
}

const markdownFiles = walk("docs")
  .filter((file) => file.endsWith(".md"))
  .concat(
    [
      "README.md",
      "PROJECT_CHARTER.md",
      "GOVERNANCE.md",
      "SECURITY.md",
      "CONTRIBUTING.md",
      "CHANGELOG.md",
    ].filter(exists),
  );
const linkPattern = /\[[^\]]*\]\(([^)]+)\)/g;
for (const markdownFile of markdownFiles) {
  const base = path.dirname(path.join(root, markdownFile));
  for (const match of read(markdownFile).matchAll(linkPattern)) {
    const target = match[1].trim().replace(/^<|>$/g, "");
    if (/^(https?:|mailto:|#)/i.test(target)) continue;
    const withoutAnchor = decodeURIComponent(target.split("#", 1)[0]);
    if (!withoutAnchor) continue;
    if (!fs.existsSync(path.resolve(base, withoutAnchor)))
      error(`${markdownFile} has broken local link: ${target}`);
  }
}

if (!exists(".github/CODEOWNERS")) error("Missing CODEOWNERS.");
if (!exists(".github/pull_request_template.md"))
  error("Missing pull request template.");
if (!exists(".github/dependabot.yml"))
  error("Missing Dependabot configuration.");

if (!exists("LICENSE")) {
  error("Public repository lacks a LICENSE file.");
} else {
  const licenseText = read("LICENSE");
  if (
    !licenseText.includes("Apache License") ||
    !licenseText.includes("Version 2.0, January 2004") ||
    !licenseText.includes("END OF TERMS AND CONDITIONS")
  ) {
    error("LICENSE is not recognizable as Apache License 2.0.");
  }
}
if (!exists("NOTICE")) error("Apache-2.0 project lacks NOTICE attribution.");
if (!exists("docs/governance/LICENSING.md")) error("Missing licensing policy.");

for (const item of warnings) console.warn(`WARN: ${item}`);
for (const item of errors) console.error(`ERROR: ${item}`);
console.log(
  `Governance audit: ${errors.length} error(s), ${warnings.length} warning(s).`,
);
process.exitCode = errors.length === 0 ? 0 : 1;
