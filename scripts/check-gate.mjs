import fs from "node:fs";

const requestedGate = process.argv[2];
if (!requestedGate)
  throw new Error("Usage: node scripts/check-gate.mjs GATE_ID");

const gates = JSON.parse(fs.readFileSync("governance/gates.json", "utf8"));
const gate = gates.gates.find((candidate) => candidate.id === requestedGate);
const errors = [];
if (!gate) errors.push(`Unknown gate: ${requestedGate}`);
else {
  if (gate.status !== "open")
    errors.push(`${requestedGate} is ${gate.status}.`);
  if (gate.authorization && !fs.existsSync(gate.authorization))
    errors.push(`Missing authorization: ${gate.authorization}`);
  if (requestedGate === "G1" && !gates.productCodeAuthorized)
    errors.push("productCodeAuthorized is false.");
  if (gate.authorization && fs.existsSync(gate.authorization)) {
    const record = fs.readFileSync(gate.authorization, "utf8");
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
