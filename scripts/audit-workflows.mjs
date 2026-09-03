import fs from "node:fs";
import path from "node:path";

const workflowDirectory = path.join(process.cwd(), ".github", "workflows");
const errors = [];
const headBoundWorkflows = new Set([
  "g2a-systemd-qualification.yml",
  "governance.yml",
  "security.yml",
]);
const expectedHeadRef =
  "ref: ${{ github.event.pull_request.head.sha || github.sha }}";

function auditCheckoutBindings(relative, text) {
  const lines = text.split(/\r?\n/);
  let checkoutCount = 0;
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(
      /^(\s*)uses:\s*actions\/checkout@[0-9a-f]{40}(?:\s*#.*)?$/,
    );
    if (!match) continue;
    checkoutCount += 1;
    const usesIndent = match[1].length;
    let bound = false;
    let inWith = false;
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const next = lines[cursor];
      const trimmed = next.trimStart();
      const indent = next.length - trimmed.length;
      if (trimmed.startsWith("- ") && indent < usesIndent) break;
      if (trimmed === "with:" && indent === usesIndent) {
        inWith = true;
        continue;
      }
      if (inWith && trimmed.length > 0 && indent <= usesIndent) inWith = false;
      if (inWith && trimmed === expectedHeadRef && indent === usesIndent + 2)
        bound = true;
    }
    if (!bound)
      errors.push(`${relative}: checkout step is not bound to the PR head.`);
  }
  if (checkoutCount === 0)
    errors.push(`${relative}: required closure workflow has no checkout step.`);
}

if (!fs.existsSync(workflowDirectory)) {
  errors.push("Missing .github/workflows directory.");
} else {
  for (const name of fs.readdirSync(workflowDirectory)) {
    if (!/\.ya?ml$/i.test(name)) continue;
    const relative = `.github/workflows/${name}`;
    const text = fs.readFileSync(path.join(workflowDirectory, name), "utf8");
    if (!/(^|\n)permissions:\s*(\n|$)/.test(text))
      errors.push(`${relative}: missing top-level permissions.`);
    if (/pull_request_target\s*:/.test(text))
      errors.push(`${relative}: pull_request_target is prohibited.`);
    for (const match of text.matchAll(
      /^\s*-?\s*uses:\s*([^\s#]+)(?:\s*#.*)?$/gm,
    )) {
      const use = match[1];
      if (use.startsWith("./")) continue;
      const reference = use.split("@")[1] ?? "";
      if (!/^[0-9a-f]{40}$/.test(reference))
        errors.push(`${relative}: action is not pinned to a full SHA: ${use}`);
    }
    if (/permissions:\s*write-all/.test(text))
      errors.push(`${relative}: write-all permissions are prohibited.`);
    if (headBoundWorkflows.has(name)) auditCheckoutBindings(relative, text);
  }
}

for (const error of errors) console.error(`ERROR: ${error}`);
console.log(`Workflow audit: ${errors.length} error(s).`);
process.exitCode = errors.length === 0 ? 0 : 1;
