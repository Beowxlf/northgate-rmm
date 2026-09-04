import assert from "node:assert/strict";
import fs from "node:fs";

import { validateV1dAuthority } from "./lib/validate-v1d-authority.mjs";

const baseline = JSON.parse(fs.readFileSync("governance/gates.json", "utf8"));
const exactPath = "docs/governance/authorizations/V1D-SV-EXACT.md";
const fixedNow = new Date("2026-09-04T14:00:00Z");
const digest = `sha256:${"a".repeat(64)}`;
const validFields = {
  Authority: "V1D-SV",
  Status: "Authorized",
  Approver: "Beowxlf",
  "Audited commit": "b".repeat(40),
  "Issued at": "2099-01-01T00:02:00Z",
  "Expires at": "2100-01-01T00:00:00Z",
  "Server binding": digest,
  "Signed release digest": digest,
  "Factory plan ID": "plan-v1d-0001",
  "Authenticated state hash": digest,
  "Factory plan issued at": "2099-01-01T00:00:00Z",
  "Factory plan approved at": "2099-01-01T00:01:00Z",
  "Factory plan approver": "Beowxlf",
  "External dependency set binding": digest,
  "Service identity binding": digest,
  "Database identity binding": digest,
  "Synthetic identity profile binding": digest,
  "Private network policy binding": digest,
  "Endpoint routes": "blocked",
  "Rollback binding": digest,
  "Recovery binding": digest,
  "Evidence boundary binding": digest,
};

function clone() {
  return structuredClone(baseline);
}

function authority(config) {
  return config.boundedOperationalAuthorizations.find(
    (item) => item.id === "V1D-SV",
  );
}

function renderRecord(fields = validFields) {
  return Object.entries(fields)
    .map(([key, value]) => `${key}: ${value}`)
    .join("\n");
}

function open(config) {
  authority(config).status = "open";
  authority(config).authorization = exactPath;
}

let passed = 0;
function expectFailure(
  name,
  mutateConfig,
  expected,
  { mutateFields, regularFile = true, recordText } = {},
) {
  const config = clone();
  mutateConfig(config);
  const fields = structuredClone(validFields);
  mutateFields?.(fields);
  const errors = validateV1dAuthority(config, {
    isRegularFile: (path) => regularFile && path === exactPath,
    readText: () => recordText ?? renderRecord(fields),
    isCommit: (commit) => commit === validFields["Audited commit"],
    now: fixedNow,
  });
  assert(
    errors.some((item) => item.includes(expected)),
    `${name} did not fail with ${expected}: ${errors.join(" | ")}`,
  );
  passed += 1;
}

assert.deepEqual(validateV1dAuthority(baseline), []);
passed += 1;

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
  "lacks its exact regular authorization file",
);
expectFailure(
  "directory path",
  (config) => {
    authority(config).status = "open";
    authority(config).authorization = "docs/governance/authorizations/";
  },
  "lacks its exact regular authorization file",
);
expectFailure(
  "out-of-scope path",
  (config) => {
    authority(config).status = "open";
    authority(config).authorization = "README.md";
  },
  "lacks its exact regular authorization file",
);
expectFailure(
  "not a regular file",
  open,
  "lacks its exact regular authorization file",
  { regularFile: false },
);
expectFailure("empty record", open, "unreadable authorization record", {
  recordText: " ",
});
expectFailure(
  "concurrent G2",
  (config) => {
    open(config);
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

for (const field of Object.keys(validFields)) {
  expectFailure(`missing ${field}`, open, `lacks exact ${field}`, {
    mutateFields: (fields) => delete fields[field],
  });
}

expectFailure("duplicate binding", open, "duplicates Server binding", {
  recordText: `${renderRecord()}\nServer binding: ${digest}`,
});
expectFailure("wrong authority", open, "wrong authority ID", {
  mutateFields: (fields) => (fields.Authority = "G2"),
});
expectFailure("wrong approver", open, "project owner approver", {
  mutateFields: (fields) => (fields.Approver = "another-user"),
});
expectFailure("wrong plan approver", open, "post-issuance owner approval", {
  mutateFields: (fields) => (fields["Factory plan approver"] = "another-user"),
});
expectFailure("bad audited commit", open, "invalid audited commit", {
  mutateFields: (fields) => (fields["Audited commit"] = "deadbeef"),
});
expectFailure("unknown audited commit", open, "not in the repository", {
  mutateFields: (fields) => (fields["Audited commit"] = "c".repeat(40)),
});
expectFailure("bad plan ID", open, "invalid Factory plan ID", {
  mutateFields: (fields) => (fields["Factory plan ID"] = "short"),
});
expectFailure("bad release digest", open, "invalid Signed release digest", {
  mutateFields: (fields) => (fields["Signed release digest"] = "sha256:bad"),
});
expectFailure("endpoint routes open", open, "endpoint routes blocked", {
  mutateFields: (fields) => (fields["Endpoint routes"] = "open"),
});
expectFailure("expired authority", open, "record is expired", {
  mutateFields: (fields) => (fields["Expires at"] = "2026-09-04T13:59:00Z"),
});
expectFailure("plan approval before issuance", open, "approval must follow", {
  mutateFields: (fields) =>
    (fields["Factory plan approved at"] = "2098-12-31T23:59:00Z"),
});
expectFailure(
  "authority before plan approval",
  open,
  "issued after Factory plan",
  {
    mutateFields: (fields) => (fields["Issued at"] = "2099-01-01T00:00:30Z"),
  },
);

const exactOpen = clone();
open(exactOpen);
assert.deepEqual(
  validateV1dAuthority(exactOpen, {
    isRegularFile: (path) => path === exactPath,
    readText: () => renderRecord(),
    isCommit: (commit) => commit === validFields["Audited commit"],
    now: fixedNow,
  }),
  [],
);
passed += 1;

console.log(`V1D-SV governance tests: ${passed} passed.`);
