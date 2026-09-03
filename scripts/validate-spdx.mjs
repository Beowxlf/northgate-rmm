import fs from "node:fs";
import process from "node:process";
import Ajv from "ajv";
import addFormats from "ajv-formats";

if (process.argv.length !== 4) {
  console.error("usage: validate-spdx.mjs SCHEMA DOCUMENT");
  process.exit(64);
}

const [, , schemaPath, documentPath] = process.argv;
const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
const document = JSON.parse(fs.readFileSync(documentPath, "utf8"));
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validate = ajv.compile(schema);

if (!validate(document)) {
  for (const error of (validate.errors ?? []).slice(0, 20)) {
    console.error(`${error.instancePath || "/"}: ${error.message}`);
  }
  process.exit(1);
}

console.log("SPDX 2.3 schema validation passed.");
