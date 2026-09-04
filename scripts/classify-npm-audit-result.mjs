import fs from "node:fs";
import { pathToFileURL } from "node:url";

const RETRYABLE_PREFIXES = [
  "network timeout at:",
  "502 Bad Gateway -",
  "503 Service Unavailable -",
  "504 Gateway Time-out -",
  "request to ",
];
const NPM_ADVISORY_ENDPOINT =
  "https://registry.npmjs.org/-/npm/v1/security/advisories/";

export function isRetryableAuditFailure(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  if (
    !("error" in value) ||
    value.error === null ||
    typeof value.error !== "object" ||
    Array.isArray(value.error) ||
    typeof value.message !== "string" ||
    !value.message.includes(NPM_ADVISORY_ENDPOINT)
  ) {
    return false;
  }
  return RETRYABLE_PREFIXES.some((prefix) => value.message.startsWith(prefix));
}

export function classifyAuditFile(path) {
  let value;
  try {
    value = JSON.parse(fs.readFileSync(path, "utf8"));
  } catch {
    return false;
  }
  return isRetryableAuditFailure(value);
}

function main() {
  if (process.argv.length !== 3) {
    process.exitCode = 2;
    return;
  }
  process.exitCode = classifyAuditFile(process.argv[2]) ? 0 : 1;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main();
}
