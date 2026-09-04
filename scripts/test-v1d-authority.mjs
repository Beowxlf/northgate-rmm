import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";

import { validateV1dAuthority } from "./lib/validate-v1d-authority.mjs";

const baseline = JSON.parse(fs.readFileSync("governance/gates.json", "utf8"));
const exactPath = "docs/governance/authorizations/V1D-SV-EXACT.md";
const bindingPath = "docs/governance/authorizations/bindings/V1D-SV-EXACT.json";
const factoryReceiptPath =
  "docs/governance/authorizations/factory-receipts/V1D-SV-PLAN.json";
const factorySignaturePath =
  "docs/governance/authorizations/factory-receipts/V1D-SV-PLAN.cms.pem";
const factoryTrustPath =
  "docs/governance/trust/vm-factory/plan-approval-signer.json";
const closeoutPath =
  "docs/governance/authorizations/closeouts/V1D-SV-PLAN-CLOSEOUT.json";
const cleanupEvidencePath =
  "docs/governance/authorizations/closeouts/evidence/V1D-SV-PLAN-CLEANUP.json";
const fixedNow = new Date("2026-09-04T14:00:00Z");
const digest = `sha256:${"a".repeat(64)}`;
const v1cPath = "docs/governance/authorizations/prerequisites/V1C-PASS.json";
const dependencyRecords = [
  ["V1D-DEP-DNS-TIME", "V1D-DEP-DNS-TIME.json"],
  ["V1D-DEP-SERVER-PKI", "V1D-DEP-SERVER-PKI.json"],
  ["V1D-DEP-NETWORK-SEGMENTATION", "V1D-DEP-NETWORK-SEGMENTATION.json"],
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
  "Expires at": "2026-09-04T14:59:59Z",
  "Server binding": digest,
  "Signed release digest": digest,
  "Factory plan receipt": factoryReceiptPath,
  "Factory plan receipt digest": digest,
  "Factory plan receipt signature": factorySignaturePath,
  "Factory plan receipt signature digest": digest,
  "Factory approval trust record": factoryTrustPath,
  "Factory approval trust record digest": digest,
  "Factory plan ID": `ngp-${"1".repeat(64)}`,
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

function renderFactoryPlanReceipt(fields = validFields, overrides = {}) {
  return canonical({
    schemaVersion: 1,
    receiptType: "PlanApprovalReceipt",
    issuer: "NorthGate VM Factory",
    status: "Approved",
    planId: fields["Factory plan ID"],
    authenticatedStateHash: fields["Authenticated state hash"],
    issuedAt: fields["Factory plan issued at"],
    approvedAt: fields["Factory plan approved at"],
    expiresAt: fields["Factory plan expires at"],
    approver: fields["Factory plan approver"],
    targetBinding: fields["Server binding"],
    ...overrides,
  });
}

function renderFactoryApprovalTrust(overrides = {}) {
  return canonical({
    schemaVersion: 1,
    trustPurpose: "NorthGate VM Factory plan approval signer",
    status: "Pinned",
    approver: "Beowxlf",
    approvedAt: "2026-09-04T12:54:00Z",
    certificateSha256: `sha256:${"b".repeat(64)}`,
    ...overrides,
  });
}

function renderFactorySignature(content, certificateSha256) {
  return `TEST-CMS ${hash(content)} ${certificateSha256}\n`;
}

function renderCleanupEvidence(overrides = {}) {
  return canonical({
    schemaVersion: 1,
    event: "V1D-SV-CleanupVerified",
    status: "Verified",
    approver: "Beowxlf",
    factoryPlanId: validFields["Factory plan ID"],
    serverBinding: validFields["Server binding"],
    serviceIdentityBinding: validFields["Service identity binding"],
    databaseIdentityBinding: validFields["Database identity binding"],
    syntheticIdentityProfileBinding:
      validFields["Synthetic identity profile binding"],
    privateNetworkPolicyBinding: validFields["Private network policy binding"],
    serviceStopped: true,
    syntheticIdentitiesRevoked: true,
    endpointRoutesBlocked: true,
    temporaryNetworkAccessRemoved: true,
    temporarySecretsDestroyed: true,
    rollbackVerified: true,
    verifiedAt: "2026-09-04T13:20:00Z",
    ...overrides,
  });
}

function renderCloseout(
  authorizationText = renderRecord(),
  evidenceText = renderCleanupEvidence(),
  overrides = {},
) {
  return canonical({
    schemaVersion: 1,
    receiptType: "V1D-SV-Closeout",
    authority: "V1D-SV",
    status: "ClosedAndClean",
    approver: "Beowxlf",
    authorizationRecord: exactPath,
    authorizationRecordDigest: hash(authorizationText),
    factoryPlanId: validFields["Factory plan ID"],
    serverBinding: validFields["Server binding"],
    signedReleaseDigest: validFields["Signed release digest"],
    cleanupEvidenceRecord: cleanupEvidencePath,
    cleanupEvidenceDigest: hash(evidenceText),
    serviceStopped: true,
    syntheticIdentitiesRevoked: true,
    endpointRoutesBlocked: true,
    temporaryNetworkAccessRemoved: true,
    temporarySecretsDestroyed: true,
    rollbackVerified: true,
    closedAt: "2026-09-04T13:30:00Z",
    ...overrides,
  });
}

function closeoutOptions(
  protectedMainGates,
  {
    closeoutText = renderCloseout(),
    evidenceText = renderCleanupEvidence(),
    artifactsOnProtectedMain = false,
  } = {},
) {
  return {
    isRegularFile: (path) =>
      path === closeoutPath || path === cleanupEvidencePath,
    readText: (path) => {
      if (path === closeoutPath) return closeoutText;
      if (path === cleanupEvidencePath) return evidenceText;
      return null;
    },
    readAtProtectedMain: (path) => {
      if (path === "governance/gates.json")
        return canonical(protectedMainGates);
      if (path === exactPath) return renderRecord();
      if (artifactsOnProtectedMain && path === closeoutPath)
        return closeoutText;
      if (artifactsOnProtectedMain && path === cleanupEvidencePath)
        return evidenceText;
      return null;
    },
    protectedMainPathVersionCount: (path) =>
      artifactsOnProtectedMain &&
      (path === closeoutPath || path === cleanupEvidencePath)
        ? 1
        : 0,
    pathIntroductionTime: (path) =>
      artifactsOnProtectedMain &&
      (path === closeoutPath || path === cleanupEvidencePath)
        ? "2026-09-04T13:35:00Z"
        : null,
    now: fixedNow,
  };
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

function networkArtifactPath(name) {
  return `docs/governance/authorizations/prerequisites/network/${name}.json`;
}

function renderNetworkArtifact(event, recordedAt) {
  return canonical({
    schemaVersion: 1,
    prerequisiteId: "V1D-DEP-NETWORK-SEGMENTATION",
    event,
    status: "Verified",
    approver: "Beowxlf",
    recordedAt,
    targetBinding: digest,
    flowBinding: digest,
  });
}

function renderEvidence(id, records) {
  const networkArtifacts = {
    changeApprovalRecord: networkArtifactPath("change-approval"),
    applyReceiptRecord: networkArtifactPath("apply-receipt"),
    allowTestRecord: networkArtifactPath("allow-test"),
    denyTestRecord: networkArtifactPath("deny-test"),
  };
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
    ...(id === "V1D-DEP-NETWORK-SEGMENTATION"
      ? {
          ...networkArtifacts,
          changeApprovalBinding: hash(
            records[networkArtifacts.changeApprovalRecord],
          ),
          applyReceiptDigest: hash(
            records[networkArtifacts.applyReceiptRecord],
          ),
          allowTestReceiptDigest: hash(
            records[networkArtifacts.allowTestRecord],
          ),
          denyTestReceiptDigest: hash(records[networkArtifacts.denyTestRecord]),
        }
      : {}),
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
  records[networkArtifactPath("change-approval")] = renderNetworkArtifact(
    "ChangeApproved",
    "2026-09-04T12:40:00Z",
  );
  records[networkArtifactPath("apply-receipt")] = renderNetworkArtifact(
    "ChangeApplied",
    "2026-09-04T12:42:00Z",
  );
  records[networkArtifactPath("allow-test")] = renderNetworkArtifact(
    "AllowPathVerified",
    "2026-09-04T12:45:00Z",
  );
  records[networkArtifactPath("deny-test")] = renderNetworkArtifact(
    "DenyPathVerified",
    "2026-09-04T12:46:00Z",
  );
  const ids = ["V1C", ...dependencyRecords.map(([id]) => id)];
  for (const id of ids) {
    records[evidencePath(id)] = renderEvidence(id, records);
    records[rollbackPath(id)] = renderRollbackEvidence(id);
  }
  records[v1cPath] = renderPrerequisite("V1C", "Passed", records, {
    releaseDigest: digest,
    controls: v1cControls,
  });
  for (const [id, path] of dependencyRecords)
    records[path] = renderPrerequisite(id, "Approved", records);
  return records;
}

function buildDependencyDescriptors(fields, prerequisiteRecords) {
  const descriptor = (id, record) => ({
    id,
    record,
    digest: prerequisiteRecords[record]
      ? hash(prerequisiteRecords[record])
      : digest,
    evidenceScope: {
      targetBinding: fields["Server binding"],
      identityBinding: fields["Service identity binding"],
      flowBinding: fields["Private network policy binding"],
      provisionReceiptDigest: digest,
      verificationReceiptDigest: digest,
      ...(id === "V1D-DEP-NETWORK-SEGMENTATION"
        ? {
            changeApprovalBinding: hash(
              prerequisiteRecords[networkArtifactPath("change-approval")],
            ),
            applyReceiptDigest: hash(
              prerequisiteRecords[networkArtifactPath("apply-receipt")],
            ),
            allowTestReceiptDigest: hash(
              prerequisiteRecords[networkArtifactPath("allow-test")],
            ),
            denyTestReceiptDigest: hash(
              prerequisiteRecords[networkArtifactPath("deny-test")],
            ),
          }
        : {}),
    },
    rollbackScope: {
      procedureBinding: fields["Rollback binding"],
      recoveryEvidenceBinding: fields["Recovery binding"],
    },
  });
  return dependencyRecords.map(([id, record]) => descriptor(id, record));
}

function renderApprovedBindings(
  fields = validFields,
  overrides = {},
  prerequisiteRecords = buildPrerequisites(),
) {
  const bindingFields = [
    "Issued at",
    "Expires at",
    "Server binding",
    "Signed release digest",
    "Factory plan receipt",
    "Factory plan receipt digest",
    "Factory plan receipt signature",
    "Factory plan receipt signature digest",
    "Factory approval trust record",
    "Factory approval trust record digest",
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
  const dependencies = buildDependencyDescriptors(fields, prerequisiteRecords);
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
        evidenceScope: {
          targetBinding: fields["Server binding"],
          identityBinding: fields["Service identity binding"],
          flowBinding: fields["Private network policy binding"],
          provisionReceiptDigest: digest,
          verificationReceiptDigest: digest,
        },
        rollbackScope: {
          procedureBinding: fields["Rollback binding"],
          recoveryEvidenceBinding: fields["Recovery binding"],
        },
      },
      dependencies,
    },
    ...overrides,
  });
}

validFields["External dependency set binding"] = hash(
  canonical(buildDependencyDescriptors(validFields, buildPrerequisites())),
);
validFields["Factory plan receipt digest"] = hash(renderFactoryPlanReceipt());
validFields["Factory approval trust record digest"] = hash(
  renderFactoryApprovalTrust(),
);
validFields["Factory plan receipt signature digest"] = hash(
  renderFactorySignature(
    renderFactoryPlanReceipt(),
    `sha256:${"b".repeat(64)}`,
  ),
);

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
    mutateFactoryReceipt,
    mutateFactoryTrust,
    mutateFactorySignature,
    mutatePrerequisites,
    regularFile = true,
    protectedMain = true,
    recordText,
    approvedText,
    currentApprovedText,
    currentFactoryReceiptText,
    currentFactorySignatureText,
    currentFactoryTrustText,
    protectedMainTexts = {},
    nonImmutablePaths = [],
    trustPredatesReceipt = true,
    trustIntroductionTime = "2026-09-04T12:55:00Z",
    prerequisiteIntroductionTime = "2026-09-04T12:56:00Z",
    bindingsIntroductionTime = "2026-09-04T13:02:30Z",
    receiptIntroductionTime = "2026-09-04T13:01:30Z",
    signatureIntroductionTime = "2026-09-04T13:01:30Z",
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
  const factoryReceipt = JSON.parse(renderFactoryPlanReceipt(fields));
  mutateFactoryReceipt?.(factoryReceipt);
  const priorFactoryReceipt = canonical(factoryReceipt);
  const factoryTrust = JSON.parse(renderFactoryApprovalTrust());
  mutateFactoryTrust?.(factoryTrust);
  const priorFactoryTrust = canonical(factoryTrust);
  let priorFactorySignature = renderFactorySignature(
    priorFactoryReceipt,
    factoryTrust.certificateSha256,
  );
  priorFactorySignature =
    mutateFactorySignature?.(priorFactorySignature) ?? priorFactorySignature;
  const errors = validateV1dAuthority(config, {
    isRegularFile: (path) =>
      regularFile &&
      (path === exactPath ||
        path === bindingPath ||
        path === factoryReceiptPath ||
        path === factorySignaturePath ||
        path === factoryTrustPath ||
        path in prerequisites),
    readText: (path) => {
      if (path === exactPath) return recordText ?? renderRecord(fields);
      if (path === bindingPath) return currentApprovedText ?? priorApproval;
      if (path === factoryReceiptPath)
        return currentFactoryReceiptText ?? priorFactoryReceipt;
      if (path === factorySignaturePath)
        return currentFactorySignatureText ?? priorFactorySignature;
      if (path === factoryTrustPath)
        return currentFactoryTrustText ?? priorFactoryTrust;
      if (path in prerequisites) return prerequisites[path];
      return null;
    },
    readAtCommit: (commit, path) => {
      if (commit !== validFields["Audited commit"]) return null;
      if (path === bindingPath) return priorApproval;
      if (path === factoryReceiptPath) return priorFactoryReceipt;
      if (path === factorySignaturePath) return priorFactorySignature;
      if (path === factoryTrustPath) return priorFactoryTrust;
      return prerequisites[path] ?? null;
    },
    readAtProtectedMain: (path) => {
      if (Object.hasOwn(protectedMainTexts, path))
        return protectedMainTexts[path];
      if (path === bindingPath) return priorApproval;
      if (path === factoryReceiptPath) return priorFactoryReceipt;
      if (path === factorySignaturePath) return priorFactorySignature;
      if (path === factoryTrustPath) return priorFactoryTrust;
      return prerequisites[path] ?? null;
    },
    isPathImmutableOnProtectedMain: (commit, path) =>
      commit === validFields["Audited commit"] &&
      !nonImmutablePaths.includes(path),
    isPathIntroducedBefore: (earlierPath, laterPath) =>
      trustPredatesReceipt &&
      earlierPath === factoryTrustPath &&
      laterPath === factoryReceiptPath,
    pathIntroductionTime: (path) => {
      if (path === factoryTrustPath) return trustIntroductionTime;
      if (path === bindingPath) return bindingsIntroductionTime;
      if (path === factoryReceiptPath) return receiptIntroductionTime;
      if (path === factorySignaturePath) return signatureIntroductionTime;
      return path in prerequisites ? prerequisiteIntroductionTime : null;
    },
    verifyFactoryReceiptSignature: (content, signature, certificateSha256) =>
      signature === renderFactorySignature(content, certificateSha256),
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
  "require G2 through G8 to remain closed",
);
expectFailure(
  "closed-gate constraint is not an array",
  (config) => {
    authority(config).requiresClosedGates = "G2";
  },
  "require G2 through G8 to remain closed",
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
  "concurrent G3",
  (config) => {
    open(config);
    config.gates.find((gate) => gate.id === "G3").status = "open";
  },
  "V1D-SV and G3 cannot be open at the same time",
);
expectFailure(
  "closed V1D-SV cannot bypass cleanup before G2",
  (config) => {
    config.gates.find((gate) => gate.id === "G2").status = "open";
    config.gates.find((gate) => gate.id === "G2").authorization =
      "docs/governance/authorizations/G1-PRODUCT-CODING.md";
  },
  "requires an immutable cleanup closeout receipt",
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
expectFailure(
  "Factory receipt substituted for another plan",
  open,
  "planId mismatches the authorized Factory plan ID",
  {
    mutateFactoryReceipt: (receipt) => (receipt.planId = "plan-v1d-other"),
  },
);
expectFailure(
  "Factory receipt substituted state hash",
  open,
  "authenticatedStateHash mismatches",
  {
    mutateFactoryReceipt: (receipt) =>
      (receipt.authenticatedStateHash = `sha256:${"c".repeat(64)}`),
  },
);
expectFailure(
  "non-Factory plan receipt",
  open,
  "lacks Factory-issued approval",
  {
    mutateFactoryReceipt: (receipt) => (receipt.issuer = "self-reported"),
  },
);
expectFailure(
  "forged Factory receipt signature",
  open,
  "signature is invalid for the pinned signer",
  { mutateFactorySignature: () => "forged-signature\n" },
);
expectFailure(
  "unpinned Factory approval signer",
  open,
  "not independently pinned",
  {
    mutateFactoryTrust: (trust) => (trust.status = "Proposed"),
  },
);
expectFailure(
  "Factory trust approved at plan issuance",
  open,
  "trust must predate plan issuance",
  {
    mutateFactoryTrust: (trust) =>
      (trust.approvedAt = validFields["Factory plan issued at"]),
  },
);
expectFailure(
  "Factory trust introduced with receipt",
  open,
  "pinned in an earlier protected-main change",
  { trustPredatesReceipt: false },
);
expectFailure(
  "Factory trust merged at plan issuance",
  open,
  "introduction must predate authenticated plan issuance",
  { trustIntroductionTime: validFields["Factory plan issued at"] },
);
expectFailure(
  "Factory trust committed before claimed approval",
  open,
  "claimed approval postdates protected-main introduction",
  { trustIntroductionTime: "2026-09-04T12:53:00Z" },
);
expectFailure(
  "prerequisites merged at plan issuance",
  open,
  "protected-main introduction must predate Factory plan issuance",
  { prerequisiteIntroductionTime: validFields["Factory plan issued at"] },
);
expectFailure(
  "prerequisite evidence committed before claimed events",
  open,
  "claimed event postdates its protected-main introduction",
  { prerequisiteIntroductionTime: "2026-09-04T12:30:00Z" },
);
expectFailure(
  "Factory receipt changed after approval",
  open,
  "Factory plan receipt changed after approval",
  { currentFactoryReceiptText: "{}" },
);
expectFailure(
  "Factory receipt restored after revocation",
  open,
  "Factory plan receipt was revoked from protected main",
  { protectedMainTexts: { [factoryReceiptPath]: null } },
);
expectFailure(
  "Factory receipt path replayed",
  open,
  "Factory plan receipt lacks single-use immutable protected-main history",
  { nonImmutablePaths: [factoryReceiptPath] },
);
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
expectFailure(
  "authority issued at plan approval",
  open,
  "issued after Factory plan approval",
  {
    mutateFields: (fields) =>
      (fields["Issued at"] = fields["Factory plan approved at"]),
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
expectFailure("stale Factory plan", open, "Factory plan is stale", {
  mutateFields: (fields) =>
    (fields["Factory plan issued at"] = "2026-09-04T11:59:59Z"),
});
expectFailure(
  "authority outlives Factory plan freshness",
  open,
  "outlives the Factory plan freshness window",
  {
    mutateFields: (fields) => (fields["Expires at"] = "2026-09-04T15:00:01Z"),
  },
);
expectFailure("excessive Factory plan lifetime", open, "24-hour lifetime", {
  mutateFields: (fields) =>
    (fields["Factory plan expires at"] = "2026-09-05T13:00:01Z"),
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
      (fields["Factory plan expires at"] = "2026-09-04T14:30:00Z"),
  },
);
expectFailure("changed approved bindings", open, "changed after the audited", {
  currentApprovedText: "{}",
});
expectFailure(
  "revoked V1C approval restored from an old snapshot",
  open,
  "V1C prerequisite was revoked from protected main",
  { protectedMainTexts: { [v1cPath]: null } },
);
expectFailure(
  "restored V1C approval selected as the new audit anchor",
  open,
  "V1C prerequisite lacks single-use immutable protected-main history",
  { nonImmutablePaths: [v1cPath] },
);
expectFailure(
  "mismatched approved binding",
  open,
  "Server binding mismatches",
  {
    mutateApproval: (approval) =>
      (approval.bindings["Server binding"] = `sha256:${"c".repeat(64)}`),
  },
);
expectFailure(
  "authorization window extended after approval",
  open,
  "Expires at mismatches its approved binding",
  {
    mutateApproval: (approval) =>
      (approval.bindings["Expires at"] = "2026-09-04T23:00:00Z"),
  },
);
expectFailure("future bindings approval", open, "approval time is invalid", {
  mutateApproval: (approval) => (approval.approvedAt = "2026-09-04T15:02:00Z"),
});
expectFailure(
  "authorization issued at bindings approval time",
  open,
  "authorization predates its approved bindings",
  {
    mutateApproval: (approval) =>
      (approval.approvedAt = validFields["Issued at"]),
  },
);
expectFailure(
  "bindings merged at authorization issuance",
  open,
  "bindings introduction must predate authorization issuance",
  { bindingsIntroductionTime: validFields["Issued at"] },
);
expectFailure(
  "bindings committed before claimed approval",
  open,
  "bindings claimed approval postdates protected-main introduction",
  { bindingsIntroductionTime: "2026-09-04T13:01:30Z" },
);
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
  "V1C evidence substituted for another signed release",
  open,
  "release digest mismatches the authorized signed release",
  {
    mutateFields: (fields) =>
      (fields["Signed release digest"] = `sha256:${"c".repeat(64)}`),
  },
);
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
      record.expiresAt = "2026-09-04T14:30:00Z";
      records[v1cPath] = canonical(record);
    },
  },
);
expectFailure("dependency approval missing", open, "prerequisite record", {
  mutatePrerequisites: (records) => delete records[dependencyRecords[0][1]],
});
expectFailure(
  "network segmentation evidence omits negative-path test",
  open,
  "lacks scoped denyTestReceiptDigest",
  {
    mutatePrerequisites: (records) => {
      const id = "V1D-DEP-NETWORK-SEGMENTATION";
      const prerequisitePath = dependencyRecords.find(
        ([dependencyId]) => dependencyId === id,
      )[1];
      const receiptPath = evidencePath(id);
      const receipt = JSON.parse(records[receiptPath]);
      delete receipt.denyTestReceiptDigest;
      records[receiptPath] = canonical(receipt);
      const prerequisite = JSON.parse(records[prerequisitePath]);
      prerequisite.evidenceBinding = hash(records[receiptPath]);
      records[prerequisitePath] = canonical(prerequisite);
    },
  },
);
expectFailure(
  "network segmentation scope substituted for another server and policy",
  open,
  "network target scope mismatches the authorized server binding",
  {
    mutateApproval: (approval) => {
      const network = approval.prerequisites.dependencies.find(
        ({ id }) => id === "V1D-DEP-NETWORK-SEGMENTATION",
      );
      network.evidenceScope.targetBinding = `sha256:${"c".repeat(64)}`;
      network.evidenceScope.flowBinding = `sha256:${"d".repeat(64)}`;
    },
  },
);
expectFailure(
  "server PKI evidence scope substituted for another environment",
  open,
  "external dependency set mismatches its authorized aggregate binding",
  {
    mutateApproval: (approval) => {
      const serverPki = approval.prerequisites.dependencies.find(
        ({ id }) => id === "V1D-DEP-SERVER-PKI",
      );
      serverPki.evidenceScope.targetBinding = `sha256:${"c".repeat(64)}`;
      serverPki.evidenceScope.identityBinding = `sha256:${"d".repeat(64)}`;
      serverPki.evidenceScope.flowBinding = `sha256:${"e".repeat(64)}`;
    },
  },
);
expectFailure(
  "network segmentation tests precede apply",
  open,
  "AllowPathVerified record is out of sequence",
  {
    mutatePrerequisites: (records) => {
      const id = "V1D-DEP-NETWORK-SEGMENTATION";
      const prerequisitePath = dependencyRecords.find(
        ([dependencyId]) => dependencyId === id,
      )[1];
      const applyPath = networkArtifactPath("apply-receipt");
      const applyRecord = JSON.parse(records[applyPath]);
      applyRecord.recordedAt = "2026-09-04T12:47:00Z";
      records[applyPath] = canonical(applyRecord);
      const receiptPath = evidencePath(id);
      const receipt = JSON.parse(records[receiptPath]);
      receipt.applyReceiptDigest = hash(records[applyPath]);
      records[receiptPath] = canonical(receipt);
      const prerequisite = JSON.parse(records[prerequisitePath]);
      prerequisite.evidenceBinding = hash(records[receiptPath]);
      records[prerequisitePath] = canonical(prerequisite);
    },
  },
);
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
  "dependency evidence scope substitution",
  open,
  "targetBinding mismatches its approved scope",
  {
    mutatePrerequisites: (records) => {
      const [id, prerequisitePath] = dependencyRecords[0];
      const receiptPath = evidencePath(id);
      const receipt = JSON.parse(records[receiptPath]);
      receipt.targetBinding = `sha256:${"c".repeat(64)}`;
      records[receiptPath] = canonical(receipt);
      const prerequisite = JSON.parse(records[prerequisitePath]);
      prerequisite.evidenceBinding = hash(records[receiptPath]);
      records[prerequisitePath] = canonical(prerequisite);
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
expectFailure(
  "dependency set reordered",
  open,
  "approval set is out of order",
  {
    mutateApproval: (approval) => approval.prerequisites.dependencies.reverse(),
  },
);

const priorOpen = clone();
open(priorOpen);
const closedWithCloseout = clone();
authority(closedWithCloseout).closeout = closeoutPath;
assert.deepEqual(
  validateV1dAuthority(closedWithCloseout, closeoutOptions(priorOpen)),
  [],
);
passed += 1;

const sameChangeG2 = structuredClone(closedWithCloseout);
sameChangeG2.gates.find((gate) => gate.id === "G2").status = "open";
assert(
  validateV1dAuthority(sameChangeG2, closeoutOptions(priorOpen)).some((item) =>
    item.includes("must be accepted once on protected main"),
  ),
  "same-change G2 opening did not require a prior protected-main closeout",
);
passed += 1;

const g2AfterCloseout = structuredClone(closedWithCloseout);
g2AfterCloseout.gates.find((gate) => gate.id === "G2").status = "open";
assert.deepEqual(
  validateV1dAuthority(
    g2AfterCloseout,
    closeoutOptions(closedWithCloseout, {
      artifactsOnProtectedMain: true,
    }),
  ),
  [],
);
passed += 1;

const incompleteCleanupEvidence = renderCleanupEvidence({
  syntheticIdentitiesRevoked: false,
});
const incompleteCleanupCloseout = renderCloseout(
  renderRecord(),
  incompleteCleanupEvidence,
);
assert(
  validateV1dAuthority(
    closedWithCloseout,
    closeoutOptions(priorOpen, {
      closeoutText: incompleteCleanupCloseout,
      evidenceText: incompleteCleanupEvidence,
    }),
  ).some((item) => item.includes("syntheticIdentitiesRevoked")),
  "incomplete identity cleanup evidence was accepted",
);
passed += 1;

const exactOpen = clone();
open(exactOpen);
const exactPrerequisites = buildPrerequisites();
const exactApproval = renderApprovedBindings(
  validFields,
  {},
  exactPrerequisites,
);
const exactFactoryReceipt = renderFactoryPlanReceipt();
const exactFactoryTrust = renderFactoryApprovalTrust();
const exactFactorySignature = renderFactorySignature(
  exactFactoryReceipt,
  `sha256:${"b".repeat(64)}`,
);
assert.deepEqual(
  validateV1dAuthority(exactOpen, {
    isRegularFile: (path) =>
      path === exactPath ||
      path === bindingPath ||
      path === factoryReceiptPath ||
      path === factorySignaturePath ||
      path === factoryTrustPath ||
      path in exactPrerequisites,
    readText: (path) => {
      if (path === exactPath) return renderRecord();
      if (path === bindingPath) return exactApproval;
      if (path === factoryReceiptPath) return exactFactoryReceipt;
      if (path === factorySignaturePath) return exactFactorySignature;
      if (path === factoryTrustPath) return exactFactoryTrust;
      return exactPrerequisites[path] ?? null;
    },
    readAtCommit: (_commit, path) => {
      if (path === bindingPath) return exactApproval;
      if (path === factoryReceiptPath) return exactFactoryReceipt;
      if (path === factorySignaturePath) return exactFactorySignature;
      if (path === factoryTrustPath) return exactFactoryTrust;
      return exactPrerequisites[path] ?? null;
    },
    readAtProtectedMain: (path) => {
      if (path === bindingPath) return exactApproval;
      if (path === factoryReceiptPath) return exactFactoryReceipt;
      if (path === factorySignaturePath) return exactFactorySignature;
      if (path === factoryTrustPath) return exactFactoryTrust;
      return exactPrerequisites[path] ?? null;
    },
    isPathImmutableOnProtectedMain: (commit) =>
      commit === validFields["Audited commit"],
    isPathIntroducedBefore: (earlierPath, laterPath) =>
      earlierPath === factoryTrustPath && laterPath === factoryReceiptPath,
    pathIntroductionTime: (path) => {
      if (path === factoryTrustPath) return "2026-09-04T12:55:00Z";
      if (path === bindingPath) return "2026-09-04T13:02:30Z";
      if (path === factoryReceiptPath) return "2026-09-04T13:01:30Z";
      if (path === factorySignaturePath) return "2026-09-04T13:01:30Z";
      return path in exactPrerequisites ? "2026-09-04T12:56:00Z" : null;
    },
    verifyFactoryReceiptSignature: (content, signature, certificateSha256) =>
      signature === renderFactorySignature(content, certificateSha256),
    isCommit: (commit) => commit === validFields["Audited commit"],
    isProtectedMainCommit: (commit) => commit === validFields["Audited commit"],
    now: fixedNow,
  }),
  [],
);
passed += 1;

console.log(`V1D-SV governance tests: ${passed} passed.`);
