import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";

import { validateV1dAuthority } from "./lib/validate-v1d-authority.mjs";

const baseline = JSON.parse(fs.readFileSync("governance/gates.json", "utf8"));
const exactPath = "docs/governance/authorizations/V1D-SV-EXACT.md";
const bindingPath = "docs/governance/authorizations/bindings/V1D-SV-EXACT.json";
const fixedNow = new Date("2026-09-04T14:00:00Z");
const digest = `sha256:${"a".repeat(64)}`;
const v1cPath = "docs/governance/authorizations/prerequisites/V1C-PASS.json";
const dependencyRecords = [
  ["V1D-DEP-DNS-TIME", "V1D-DEP-DNS-TIME.json"],
  ["V1D-DEP-SERVER-PKI", "V1D-DEP-SERVER-PKI.json"],
  ["V1D-DEP-SYNTHETIC-ISSUER-STATUS", "V1D-DEP-SYNTHETIC-ISSUER-STATUS.json"],
  ["V1D-DEP-OPERATOR-VERIFIER", "V1D-DEP-OPERATOR-VERIFIER.json"],
  ["V1D-DEP-TELEMETRY-AUDIT", "V1D-DEP-TELEMETRY-AUDIT.json"],
  ["V1D-DEP-BACKUP-RECOVERY", "V1D-DEP-BACKUP-RECOVERY.json"],
  ["V1D-DEP-ENCRYPTION-KEY-CUSTODY", "V1D-DEP-ENCRYPTION-KEY-CUSTODY.json"],
].map(([id, file]) => [
  id,
  `docs/governance/authorizations/prerequisites/${file}`,
]);
const v1cControls = [
  "exact production artifacts",
  "independent trust root",
  "signing custody and recovery",
  "protected distribution and bootstrap",
  "signing-key loss test",
  "signing-key compromise test",
  "independent verification",
];
const validFields = {
  Authority: "V1D-SV",
  Status: "Authorized",
  Approver: "Beowxlf",
  "Audited commit": "b".repeat(40),
  "Approved bindings record": bindingPath,
  "Issued at": "2026-09-04T13:03:00Z",
  "Expires at": "2026-09-05T00:00:00Z",
  "Server binding": digest,
  "Signed release digest": digest,
  "Factory plan ID": "plan-v1d-0001",
  "Authenticated state hash": digest,
  "Factory plan issued at": "2026-09-04T13:00:00Z",
  "Factory plan approved at": "2026-09-04T13:01:00Z",
  "Factory plan expires at": "2026-09-05T00:00:00Z",
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

function canonical(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function hash(text) {
  return `sha256:${createHash("sha256").update(text.replaceAll("\r\n", "\n")).digest("hex")}`;
}

function evidencePath(id) {
  return `docs/governance/authorizations/prerequisites/evidence/${id}.json`;
}

function rollbackPath(id) {
  return `docs/governance/authorizations/prerequisites/rollback/${id}.json`;
}

function renderEvidence(id) {
  return canonical({
    schemaVersion: 1,
    prerequisiteId: id,
    status: "ProvisionedAndVerified",
    approver: "Beowxlf",
    verifiedAt: "2026-09-04T12:50:00Z",
    targetBinding: digest,
    identityBinding: digest,
    flowBinding: digest,
    provisionReceiptDigest: digest,
    verificationReceiptDigest: digest,
  });
}

function renderRollbackEvidence(id) {
  return canonical({
    schemaVersion: 1,
    prerequisiteId: id,
    status: "RollbackVerified",
    approver: "Beowxlf",
    verifiedAt: "2026-09-04T12:51:00Z",
    procedureBinding: digest,
    recoveryEvidenceBinding: digest,
  });
}

function renderPrerequisite(id, status, records, extra = {}) {
  return canonical({
    schemaVersion: 1,
    id,
    status,
    approver: "Beowxlf",
    approvedAt: "2026-09-04T12:55:00Z",
    expiresAt: "2026-09-05T00:00:00Z",
    evidenceRecord: evidencePath(id),
    evidenceBinding: hash(records[evidencePath(id)]),
    rollbackRecord: rollbackPath(id),
    rollbackBinding: hash(records[rollbackPath(id)]),
    ...extra,
  });
}

function buildPrerequisites() {
  const records = {};
  const ids = ["V1C", ...dependencyRecords.map(([id]) => id)];
  for (const id of ids) {
    records[evidencePath(id)] = renderEvidence(id);
    records[rollbackPath(id)] = renderRollbackEvidence(id);
  }
  records[v1cPath] = renderPrerequisite("V1C", "Passed", records, {
    controls: v1cControls,
  });
  for (const [id, path] of dependencyRecords)
    records[path] = renderPrerequisite(id, "Approved", records);
  return records;
}

function renderApprovedBindings(
  fields = validFields,
  overrides = {},
  prerequisiteRecords = buildPrerequisites(),
) {
  const bindingFields = [
    "Server binding",
    "Signed release digest",
    "Factory plan ID",
    "Authenticated state hash",
    "Factory plan issued at",
    "Factory plan approved at",
    "Factory plan expires at",
    "Factory plan approver",
    "External dependency set binding",
    "Service identity binding",
    "Database identity binding",
    "Synthetic identity profile binding",
    "Private network policy binding",
    "Endpoint routes",
    "Rollback binding",
    "Recovery binding",
    "Evidence boundary binding",
  ];
  const descriptor = (id, record) => ({
    id,
    record,
    digest: prerequisiteRecords[record]
      ? hash(prerequisiteRecords[record])
      : digest,
  });
  return canonical({
    schemaVersion: 1,
    authority: "V1D-SV",
    status: "Approved",
    approver: "Beowxlf",
    approvedAt: "2026-09-04T13:02:00Z",
    expiresAt: "2026-09-05T00:00:00Z",
    bindings: Object.fromEntries(
      bindingFields.map((field) => [field, fields[field]]),
    ),
    prerequisites: {
      v1c: {
        record: v1cPath,
        digest: prerequisiteRecords[v1cPath]
          ? hash(prerequisiteRecords[v1cPath])
          : digest,
      },
      dependencies: dependencyRecords.map(([id, record]) =>
        descriptor(id, record),
      ),
    },
    ...overrides,
  });
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
  {
    mutateFields,
    mutateApproval,
    mutatePrerequisites,
    regularFile = true,
    protectedMain = true,
    recordText,
    approvedText,
    currentApprovedText,
  } = {},
) {
  const config = clone();
  mutateConfig(config);
  const fields = structuredClone(validFields);
  mutateFields?.(fields);
  const prerequisites = buildPrerequisites();
  mutatePrerequisites?.(prerequisites);
  const approval = JSON.parse(
    renderApprovedBindings(fields, {}, prerequisites),
  );
  mutateApproval?.(approval);
  const priorApproval = approvedText ?? canonical(approval);
  const errors = validateV1dAuthority(config, {
    isRegularFile: (path) =>
      regularFile &&
      (path === exactPath || path === bindingPath || path in prerequisites),
    readText: (path) => {
      if (path === exactPath) return recordText ?? renderRecord(fields);
      if (path === bindingPath) return currentApprovedText ?? priorApproval;
      if (path in prerequisites) return prerequisites[path];
      return null;
    },
    readAtCommit: (commit, path) => {
      if (commit !== validFields["Audited commit"]) return null;
      if (path === bindingPath) return priorApproval;
      return prerequisites[path] ?? null;
    },
    isCommit: (commit) => commit === validFields["Audited commit"],
    isProtectedMainCommit: (commit) =>
      protectedMain && commit === validFields["Audited commit"],
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
  "unknown authority",
  (config) => {
    config.boundedOperationalAuthorizations.push({
      id: "V1D-UNKNOWN",
      status: "open",
      opensGate: true,
    });
  },
  "Unknown bounded operational authority",
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
  "closed-gate constraint is not an array",
  (config) => {
    authority(config).requiresClosedGates = "G2";
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
  "prerequisites are not an array",
  (config) => {
    authority(config).requirements = authority(config).requirements.join("; ");
  },
  "invalid prerequisite set",
);
expectFailure(
  "prohibition stripped",
  (config) => {
    authority(config).prohibitions.pop();
  },
  "lacks required prohibition",
);
expectFailure(
  "prohibitions are not an array",
  (config) => {
    authority(config).prohibitions = authority(config).prohibitions.join("; ");
  },
  "invalid prohibition set",
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
expectFailure("audited commit off main", open, "not on protected main", {
  protectedMain: false,
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
    (fields["Factory plan approved at"] = "2026-09-04T12:59:00Z"),
});
expectFailure(
  "authority before plan approval",
  open,
  "issued after Factory plan",
  {
    mutateFields: (fields) => (fields["Issued at"] = "2026-09-04T13:00:30Z"),
  },
);
expectFailure("future authorization", open, "issue time is in the future", {
  mutateFields: (fields) => (fields["Issued at"] = "2026-09-04T15:03:00Z"),
});
expectFailure("impossible calendar date", open, "invalid expiry", {
  mutateFields: (fields) => (fields["Expires at"] = "2026-09-31T00:00:00Z"),
});
expectFailure("excessive authority lifetime", open, "24-hour lifetime", {
  mutateFields: (fields) => (fields["Expires at"] = "2026-09-06T13:03:01Z"),
});
expectFailure("future plan approval", open, "approval time is in the future", {
  mutateFields: (fields) =>
    (fields["Factory plan approved at"] = "2026-09-04T15:01:00Z"),
});
expectFailure("expired Factory plan", open, "Factory plan is expired", {
  mutateFields: (fields) =>
    (fields["Factory plan expires at"] = "2026-09-04T13:59:59Z"),
});
expectFailure(
  "authority outlives Factory plan",
  open,
  "outlives its Factory plan",
  {
    mutateFields: (fields) =>
      (fields["Factory plan expires at"] = "2026-09-04T23:59:59Z"),
  },
);
expectFailure("changed approved bindings", open, "changed after the audited", {
  currentApprovedText: "{}",
});
expectFailure(
  "mismatched approved binding",
  open,
  "Server binding mismatches",
  {
    mutateApproval: (approval) =>
      (approval.bindings["Server binding"] = `sha256:${"c".repeat(64)}`),
  },
);
expectFailure("future bindings approval", open, "approval time is invalid", {
  mutateApproval: (approval) => (approval.approvedAt = "2026-09-04T15:02:00Z"),
});
expectFailure("excessive bindings lifetime", open, "seven-day lifetime", {
  mutateApproval: (approval) => (approval.expiresAt = "2026-09-12T13:02:01Z"),
});
expectFailure(
  "bindings approved before plan",
  open,
  "must follow Factory plan",
  {
    mutateApproval: (approval) =>
      (approval.approvedAt = "2026-09-04T12:59:00Z"),
  },
);
expectFailure(
  "duplicate approved binding key",
  open,
  "canonical duplicate-free JSON",
  {
    approvedText: renderApprovedBindings().replace(
      '  "approver": "Beowxlf",',
      '  "approver": "Beowxlf",\n  "approver": "Beowxlf",',
    ),
  },
);
expectFailure("missing V1C pass record", open, "lacks the V1C prerequisite", {
  mutatePrerequisites: (records) => delete records[v1cPath],
});
expectFailure("V1C is not passed", open, "invalid identity or status", {
  mutatePrerequisites: (records) => {
    const record = JSON.parse(records[v1cPath]);
    record.status = "Open";
    records[v1cPath] = canonical(record);
  },
});
expectFailure("V1C control missing", open, "V1C pass record lacks control", {
  mutatePrerequisites: (records) => {
    const record = JSON.parse(records[v1cPath]);
    record.controls.pop();
    records[v1cPath] = canonical(record);
  },
});
expectFailure("V1C controls are not an array", open, "invalid control set", {
  mutatePrerequisites: (records) => {
    const record = JSON.parse(records[v1cPath]);
    record.controls = v1cControls.join("; ");
    records[v1cPath] = canonical(record);
  },
});
expectFailure(
  "V1C approval after Factory planning",
  open,
  "V1C prerequisite approval must precede Factory plan issuance",
  {
    mutatePrerequisites: (records) => {
      const record = JSON.parse(records[v1cPath]);
      record.approvedAt = "2026-09-04T13:00:01Z";
      records[v1cPath] = canonical(record);
    },
  },
);
expectFailure(
  "authority outlives V1C approval",
  open,
  "outlives the V1C prerequisite",
  {
    mutatePrerequisites: (records) => {
      const record = JSON.parse(records[v1cPath]);
      record.expiresAt = "2026-09-04T23:59:59Z";
      records[v1cPath] = canonical(record);
    },
  },
);
expectFailure("dependency approval missing", open, "prerequisite record", {
  mutatePrerequisites: (records) => delete records[dependencyRecords[0][1]],
});
expectFailure(
  "dependency approval has only arbitrary evidence hashes",
  open,
  "lacks immutable evidence",
  {
    mutatePrerequisites: (records) => {
      const path = dependencyRecords[0][1];
      const record = JSON.parse(records[path]);
      delete record.evidenceRecord;
      record.evidenceBinding = digest;
      records[path] = canonical(record);
    },
  },
);
expectFailure(
  "dependency evidence lacks scoped verification",
  open,
  "lacks scoped verificationReceiptDigest",
  {
    mutatePrerequisites: (records) => {
      const id = dependencyRecords[0][0];
      const path = evidencePath(id);
      const receipt = JSON.parse(records[path]);
      receipt.verificationReceiptDigest = "invalid";
      records[path] = canonical(receipt);
    },
  },
);
expectFailure(
  "dependency evidence verified after approval",
  open,
  "verified after approval",
  {
    mutatePrerequisites: (records) => {
      const id = dependencyRecords[0][0];
      const path = evidencePath(id);
      const receipt = JSON.parse(records[path]);
      receipt.verifiedAt = "2026-09-04T12:56:00Z";
      records[path] = canonical(receipt);
    },
  },
);
expectFailure(
  "dependency evidence verified at approval time",
  open,
  "verified after approval",
  {
    mutatePrerequisites: (records) => {
      const id = dependencyRecords[0][0];
      const path = evidencePath(id);
      const receipt = JSON.parse(records[path]);
      receipt.verifiedAt = "2026-09-04T12:55:00Z";
      records[path] = canonical(receipt);
    },
  },
);
expectFailure(
  "dependency approval after Factory planning",
  open,
  "prerequisite approval must precede Factory plan issuance",
  {
    mutatePrerequisites: (records) => {
      const path = dependencyRecords[0][1];
      const record = JSON.parse(records[path]);
      record.approvedAt = "2026-09-04T13:59:00Z";
      records[path] = canonical(record);
    },
  },
);
expectFailure("dependency set incomplete", open, "incomplete or duplicated", {
  mutateApproval: (approval) => approval.prerequisites.dependencies.pop(),
});

const exactOpen = clone();
open(exactOpen);
const exactPrerequisites = buildPrerequisites();
const exactApproval = renderApprovedBindings(
  validFields,
  {},
  exactPrerequisites,
);
assert.deepEqual(
  validateV1dAuthority(exactOpen, {
    isRegularFile: (path) =>
      path === exactPath || path === bindingPath || path in exactPrerequisites,
    readText: (path) => {
      if (path === exactPath) return renderRecord();
      if (path === bindingPath) return exactApproval;
      return exactPrerequisites[path] ?? null;
    },
    readAtCommit: (_commit, path) =>
      path === bindingPath ? exactApproval : (exactPrerequisites[path] ?? null),
    isCommit: (commit) => commit === validFields["Audited commit"],
    isProtectedMainCommit: (commit) => commit === validFields["Audited commit"],
    now: fixedNow,
  }),
  [],
);
passed += 1;

console.log(`V1D-SV governance tests: ${passed} passed.`);
