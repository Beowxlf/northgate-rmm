import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const ignoredDirectories = new Set([".git", ".tools", ".venv", "node_modules", "artifacts"]);
const ignoredFiles = new Set(["package-lock.json"]);
const findings = [];
const rules = [
  ["private-key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ["github-token", /gh[pousr]_[A-Za-z0-9]{30,}/],
  ["aws-access-key", /AKIA[0-9A-Z]{16}/],
  ["generic-secret-assignment", /(?:password|passwd|api[_-]?key|secret|token)\s*[:=]\s*["'][^"'\s]{12,}["']/i]
];

function walk(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (ignoredDirectories.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(absolute);
    else if (!ignoredFiles.has(entry.name) && fs.statSync(absolute).size <= 2_000_000) scan(absolute);
  }
}

function scan(file) {
  let text;
  try { text = fs.readFileSync(file, "utf8"); } catch { return; }
  for (const [rule, pattern] of rules) {
    const match = pattern.exec(text);
    if (match) {
      const line = text.slice(0, match.index).split(/\r?\n/).length;
      findings.push(`${path.relative(root, file)}:${line} (${rule})`);
    }
  }
}

walk(root);
for (const finding of findings) console.error(`ERROR: possible secret: ${finding}`);
console.log(`Lightweight secret audit: ${findings.length} finding(s). Gitleaks remains required.`);
process.exitCode = findings.length === 0 ? 0 : 1;
