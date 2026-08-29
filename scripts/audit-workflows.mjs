import fs from "node:fs";
import path from "node:path";

const workflowDirectory = path.join(process.cwd(), ".github", "workflows");
const errors = [];

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
  }
}

for (const error of errors) console.error(`ERROR: ${error}`);
console.log(`Workflow audit: ${errors.length} error(s).`);
process.exitCode = errors.length === 0 ? 0 : 1;
