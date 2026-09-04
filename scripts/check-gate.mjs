import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

import { validateProductGateAuthorization } from "./lib/validate-v1d-authority.mjs";

const root = process.cwd();

function read(relativePath) {
  try {
    return fs.readFileSync(path.join(root, relativePath), "utf8");
  } catch {
    return null;
  }
}

function isRegularFile(relativePath) {
  try {
    return fs.statSync(path.join(root, relativePath)).isFile();
  } catch {
    return false;
  }
}

function gitOutput(args) {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : null;
}

function readAtCommit(commit, relativePath) {
  const result = spawnSync("git", ["show", `${commit}:${relativePath}`], {
    cwd: root,
    encoding: "utf8",
  });
  return result.status === 0 ? result.stdout : null;
}

function readAtProtectedMain(relativePath) {
  return readAtCommit("origin/main", relativePath);
}

function protectedMainHistory(relativePath) {
  const output = gitOutput([
    "log",
    "--format=%H",
    "--full-history",
    "origin/main",
    "--",
    relativePath,
  ]);
  return output === null ? null : output.split(/\r?\n/).filter(Boolean);
}

function protectedMainPathVersionCount(relativePath) {
  return protectedMainHistory(relativePath)?.length ?? null;
}

function isPathImmutableOnProtectedMain(commit, relativePath) {
  const history = protectedMainHistory(relativePath);
  return (
    history?.length === 1 &&
    spawnSync("git", ["merge-base", "--is-ancestor", history[0], commit], {
      cwd: root,
      stdio: "ignore",
    }).status === 0
  );
}

function isPathIntroducedBefore(earlierPath, laterPath) {
  const earlier = protectedMainHistory(earlierPath);
  const later = protectedMainHistory(laterPath);
  return (
    earlier?.length === 1 &&
    later?.length === 1 &&
    earlier[0] !== later[0] &&
    spawnSync("git", ["merge-base", "--is-ancestor", earlier[0], later[0]], {
      cwd: root,
      stdio: "ignore",
    }).status === 0
  );
}

function pathIntroductionTime(relativePath) {
  const history = protectedMainHistory(relativePath);
  return history?.length === 1
    ? gitOutput(["show", "-s", "--format=%cI", history[0]])
    : null;
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

const requestedGate = process.argv[2];
if (!requestedGate)
  throw new Error("Usage: node scripts/check-gate.mjs GATE_ID");

const errors = [];
const productGateRequested = /^G[2-8]$/.test(requestedGate);
let verifiedProtectedMain = null;
let gatesText = read("governance/gates.json");
if (productGateRequested) {
  const fetch = spawnSync(
    "git",
    [
      "fetch",
      "--quiet",
      "--no-tags",
      "origin",
      "refs/heads/main:refs/remotes/origin/main",
    ],
    { cwd: root, stdio: "ignore" },
  );
  if (fetch.status !== 0)
    errors.push(
      `${requestedGate} cannot refresh the protected-main authority state.`,
    );
  const head = gitOutput(["rev-parse", "HEAD"]);
  verifiedProtectedMain = gitOutput(["rev-parse", "origin/main"]);
  if (!head || !verifiedProtectedMain || head !== verifiedProtectedMain)
    errors.push(
      `${requestedGate} may be consumed only from the current protected-main commit.`,
    );
  const worktreeState = gitOutput([
    "status",
    "--porcelain",
    "--untracked-files=normal",
  ]);
  if (worktreeState === null || worktreeState !== "")
    errors.push(`${requestedGate} cannot be consumed from a dirty worktree.`);
  const protectedGates = readAtProtectedMain("governance/gates.json");
  if (typeof protectedGates !== "string")
    errors.push(`${requestedGate} cannot read protected-main gate state.`);
  else gatesText = protectedGates;
}
let gates = null;
try {
  gates = JSON.parse(gatesText);
} catch {
  errors.push("Gate configuration is unreadable.");
}
const gate = gates?.gates?.find((candidate) => candidate.id === requestedGate);
if (!gate) errors.push(`Unknown gate: ${requestedGate}`);
else {
  if (gate.status !== "open")
    errors.push(`${requestedGate} is ${gate.status}.`);
  if (gate.status === "open" && !gate.authorization)
    errors.push(`${requestedGate} lacks an authorization record.`);
  else if (gate.status === "open" && !fs.existsSync(gate.authorization))
    errors.push(`Missing authorization: ${gate.authorization}`);
  if (requestedGate === "G1" && !gates.productCodeAuthorized)
    errors.push("productCodeAuthorized is false.");
  if (productGateRequested && gate.status === "open") {
    errors.push(
      ...validateProductGateAuthorization(gate, {
        isRegularFile,
        readText: (relativePath) =>
          readAtCommit(verifiedProtectedMain, relativePath),
        readAtCommit,
        readAtProtectedMain,
        isPathImmutableOnProtectedMain,
        isPathIntroducedBefore,
        pathIntroductionTime,
        protectedMainPathVersionCount,
        isCommit,
        isProtectedMainCommit,
        now: new Date(),
      }),
    );
  } else if (gate.authorization && fs.existsSync(gate.authorization)) {
    const record = read(gate.authorization);
    if (!/Status:\s*Authorized/i.test(record))
      errors.push("Authorization record is not Authorized.");
    if (
      requestedGate !== "G0" &&
      !/Audited commit:\s*[0-9a-f]{40}/i.test(record)
    )
      errors.push("Authorization lacks audited commit SHA.");
  }
}

for (const error of errors) console.error(`ERROR: ${error}`);
if (errors.length === 0)
  console.log(`${requestedGate} is open and authorized.`);
process.exitCode = errors.length === 0 ? 0 : 1;
