import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const errors = [];
const warnings = [];

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

function exists(relativePath) {
  return fs.existsSync(path.join(root, relativePath));
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

if (gates.schemaVersion !== 1) error("Unsupported gates schema version.");
if (controls.schemaVersion !== 1) error("Unsupported controls schema version.");

const gateIds = gates.gates.map((gate) => gate.id);
if (new Set(gateIds).size !== gateIds.length) error("Duplicate gate ID.");
for (let number = 0; number <= 8; number += 1) {
  if (!gateIds.includes(`G${number}`)) error(`Missing gate G${number}.`);
}

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

if (!exists("LICENSE"))
  warning("No public distribution license; repository must remain private.");

for (const item of warnings) console.warn(`WARN: ${item}`);
for (const item of errors) console.error(`ERROR: ${item}`);
console.log(
  `Governance audit: ${errors.length} error(s), ${warnings.length} warning(s).`,
);
process.exitCode = errors.length === 0 ? 0 : 1;
