import assert from "node:assert/strict";
import fs from "node:fs";

import { validateV1dAuthority } from "./lib/validate-v1d-authority.mjs";

const baseline = JSON.parse(fs.readFileSync("governance/gates.json", "utf8"));

function clone() {
  return structuredClone(baseline);
}

function authority(config) {
  return config.boundedOperationalAuthorizations.find(
    (item) => item.id === "V1D-SV",
  );
}

function expectFailure(name, mutate, expected) {
  const config = clone();
  mutate(config);
  const errors = validateV1dAuthority(config, (path) => path === "exact.md");
  assert(
    errors.some((item) => item.includes(expected)),
    `${name} did not fail with ${expected}: ${errors.join(" | ")}`,
  );
}

assert.deepEqual(validateV1dAuthority(baseline), []);

expectFailure(
  "missing authority",
  (config) => {
    config.boundedOperationalAuthorizations = [];
  },
  "Missing bounded V1D-SV",
);
expectFailure(
  "duplicate authority",
  (config) => {
    config.boundedOperationalAuthorizations.push(
      structuredClone(authority(config)),
    );
  },
  "Duplicate bounded operational authority",
);
expectFailure(
  "wrong phase",
  (config) => {
    authority(config).phase = 3;
  },
  "within Phase 2",
);
expectFailure(
  "gate opening",
  (config) => {
    authority(config).opensGate = true;
  },
  "must not open",
);
expectFailure(
  "G2 prerequisite removed",
  (config) => {
    authority(config).requiresClosedGates = [];
  },
  "require G2 to remain closed",
);
expectFailure(
  "invalid status",
  (config) => {
    authority(config).status = "active";
  },
  "Invalid status",
);
expectFailure(
  "missing exact record",
  (config) => {
    authority(config).status = "open";
  },
  "lacks its exact authorization record",
);
expectFailure(
  "concurrent G2",
  (config) => {
    authority(config).status = "open";
    authority(config).authorization = "exact.md";
    config.gates.find((gate) => gate.id === "G2").status = "open";
  },
  "cannot be open at the same time",
);
expectFailure(
  "prerequisite stripped",
  (config) => {
    authority(config).requirements.pop();
  },
  "lacks required prerequisite",
);
expectFailure(
  "prohibition stripped",
  (config) => {
    authority(config).prohibitions.pop();
  },
  "lacks required prohibition",
);

const exactOpen = clone();
authority(exactOpen).status = "open";
authority(exactOpen).authorization = "exact.md";
assert.deepEqual(
  validateV1dAuthority(exactOpen, (path) => path === "exact.md"),
  [],
);

console.log("V1D-SV governance tests: 11 passed.");
