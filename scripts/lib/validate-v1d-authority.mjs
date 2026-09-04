import { createHash } from "node:crypto";

const REQUIRED_REQUIREMENTS = [
  "V1C production release trust pass",
  "separately approved and verified external V1D dependencies",
  "exact named private control-plane server and signed release",
  "fresh host-issued Factory plan and post-issuance owner approval",
  "synthetic-only identities and blocked endpoint routes",
  "expiry, rollback, recovery, and evidence boundaries",
  "immutable verified cleanup closeout before later gates",
];

const REQUIRED_PROHIBITIONS = [
  "endpoint package installation",
  "endpoint-usable enrollment grant or identity",
  "canary or other endpoint traffic",
  "artifact publication or update",
  "opening G2 through G8",
];

const REQUIRED_CLOSED_GATES = ["G2", "G3", "G4", "G5", "G6", "G7", "G8"];
const PRODUCT_GATE_AUTHORIZATION_FIELDS = [
  "Gate",
  "Status",
  "Approver",
  "Audited commit",
  "Issued at",
  "Expires at",
  "Operation record",
  "Operation binding",
  "Target set record",
  "Target set binding",
  "Artifact set record",
  "Artifact set binding",
  "Identity set record",
  "Identity set binding",
  "Network policy record",
  "Network policy binding",
  "Rollback record",
  "Rollback binding",
  "Evidence boundary record",
  "Evidence boundary binding",
];
const PRODUCT_GATE_SCOPE_BINDINGS = [
  ["Operation", "Operation record", "Operation binding"],
  ["TargetSet", "Target set record", "Target set binding"],
  ["ArtifactSet", "Artifact set record", "Artifact set binding"],
  ["IdentitySet", "Identity set record", "Identity set binding"],
  ["NetworkPolicy", "Network policy record", "Network policy binding"],
  ["Rollback", "Rollback record", "Rollback binding"],
  ["EvidenceBoundary", "Evidence boundary record", "Evidence boundary binding"],
];
const PRODUCT_GATE_SCOPE_FIELDS = [
  "schemaVersion",
  "gate",
  "bindingType",
  "status",
  "approver",
  "approvedAt",
  "expiresAt",
  "scope",
  "scopeDigest",
  "evidence",
];
const PRODUCT_GATE_EVIDENCE_FIELDS = [
  "schemaVersion",
  "gate",
  "evidenceId",
  "status",
  "approver",
  "verifiedAt",
  "targetBinding",
  "result",
  "resultBinding",
];
const PRODUCT_GATE_CLOSEOUT_FIELDS = [
  "schemaVersion",
  "gate",
  "status",
  "approver",
  "authorizationRecord",
  "authorizationDigest",
  "cleanupEvidenceRecord",
  "cleanupEvidenceDigest",
  "closedAt",
];
const PRODUCT_GATE_CLEANUP_FIELDS = [
  "schemaVersion",
  "gate",
  "status",
  "approver",
  "authorizationDigest",
  "targetsRevoked",
  "identitiesRevoked",
  "networkAccessRemoved",
  "artifactsWithdrawn",
  "rollbackVerified",
  "verifiedAt",
];
const PRODUCT_GATE_SCOPE_POLICY = {
  G2: {
    operation: /^install:linux-agent-read-only:[A-Za-z0-9._-]+$/,
    target: /^linux-canary:[A-Za-z0-9._-]+$/,
  },
  G3: {
    operation: /^install:windows-agent-read-only:[A-Za-z0-9._-]+$/,
    target: /^windows-canary:[A-Za-z0-9._-]+$/,
  },
  G4: {
    operation: /^execute:typed-read-only-job:[A-Za-z0-9._-]+$/,
    target: /^canary-endpoint:[A-Za-z0-9._-]+$/,
  },
  G5: {
    operation: /^execute:typed-state-change:[A-Za-z0-9._-]+$/,
    target: /^canary-endpoint:[A-Za-z0-9._-]+$/,
  },
  G6: {
    operation: /^release:signed-agent-update:[A-Za-z0-9._-]+$/,
    target: /^canary-ring:[A-Za-z0-9._-]+$/,
  },
  G7: {
    operation: /^access:brokered-interactive:[A-Za-z0-9._-]+$/,
    target: /^canary-endpoint:[A-Za-z0-9._-]+$/,
  },
  G8: {
    operation: /^(?:deploy:production|expose:public):[A-Za-z0-9._-]+$/,
    target: /^(?:production-environment|public-service):[A-Za-z0-9._-]+$/,
  },
};
const PRODUCT_GATE_REQUIRED_EVIDENCE = {
  G2: [
    "data-collection-inventory-approved",
    "endpoint-target-approved",
    "linux-package-qualified",
    "linux-service-reviewed",
    "resource-limits-verified",
    "uninstall-revoke-plan-verified",
    "v1d-closeout-accepted",
    "vm-factory-plan-approved",
  ],
  G3: [
    "data-collection-inventory-approved",
    "endpoint-target-approved",
    "resource-limits-verified",
    "uninstall-revoke-plan-verified",
    "v1d-closeout-accepted",
    "vm-factory-plan-approved",
    "windows-package-qualified",
    "windows-service-reviewed",
  ],
  G4: [
    "audit-evidence-verified",
    "cancellation-result-unknown-tested",
    "duplicate-replay-tested",
    "exact-target-approved",
    "lease-timeout-tested",
    "output-bounds-tested",
    "typed-action-reviewed",
  ],
  G5: [
    "audit-evidence-verified",
    "canary-tested",
    "exact-target-approved",
    "least-privilege-approved",
    "postcondition-verified",
    "rollback-verified",
    "state-change-reviewed",
  ],
  G6: [
    "canary-ring-approved",
    "distribution-protected",
    "exact-release-artifacts-verified",
    "key-custody-verified",
    "provenance-sbom-verified",
    "rollback-freeze-tested",
    "signing-profile-approved",
  ],
  G7: [
    "break-glass-tested",
    "consent-policy-approved",
    "exact-target-approved",
    "jit-expiry-tested",
    "operator-identity-approved",
    "protocol-reviewed",
    "recording-audit-verified",
  ],
  G8: [
    "backup-recovery-verified",
    "capacity-slo-verified",
    "data-retention-approved",
    "incident-response-ready",
    "multi-tenant-isolation-verified",
    "public-exposure-approved",
    "topology-approved",
  ],
};

const REQUIRED_RECORD_FIELDS = [
  "Authority",
  "Status",
  "Approver",
  "Audited commit",
  "Approved bindings record",
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

const DIGEST_FIELDS = [
  "Server binding",
  "Signed release digest",
  "Factory plan receipt digest",
  "Factory plan receipt signature digest",
  "Factory approval trust record digest",
  "Authenticated state hash",
  "External dependency set binding",
  "Service identity binding",
  "Database identity binding",
  "Synthetic identity profile binding",
  "Private network policy binding",
  "Rollback binding",
  "Recovery binding",
  "Evidence boundary binding",
];

const APPROVED_BINDING_FIELDS = [
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

function parseRecord(text) {
  const fields = new Map();
  const duplicates = new Set();
  for (const line of text.split(/\r?\n/)) {
    const match = /^([A-Za-z][A-Za-z0-9 -]*):\s*(.*?)\s*$/.exec(line);
    if (!match) continue;
    const [, key, value] = match;
    if (fields.has(key)) duplicates.add(key);
    else fields.set(key, value.replace(/^`|`$/g, "").trim());
  }
  return { fields, duplicates };
}

const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const MAX_AUTHORITY_LIFETIME_MS = 24 * 60 * 60 * 1000;
const MAX_BINDINGS_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_PLAN_AGE_MS = 2 * 60 * 60 * 1000;
const MAX_PLAN_LIFETIME_MS = 24 * 60 * 60 * 1000;
const FACTORY_PLAN_RECEIPT_FIELDS = [
  "schemaVersion",
  "receiptType",
  "issuer",
  "status",
  "planId",
  "authenticatedStateHash",
  "issuedAt",
  "approvedAt",
  "expiresAt",
  "approver",
  "targetBinding",
];
const FACTORY_APPROVAL_TRUST_FIELDS = [
  "schemaVersion",
  "trustPurpose",
  "status",
  "approver",
  "approvedAt",
  "certificateSha256",
];
const CLOSEOUT_RECEIPT_FIELDS = [
  "schemaVersion",
  "receiptType",
  "authority",
  "status",
  "approver",
  "authorizationRecord",
  "authorizationRecordDigest",
  "authorityOpenedAt",
  "factoryPlanId",
  "serverBinding",
  "signedReleaseDigest",
  "cleanupEvidenceRecord",
  "cleanupEvidenceDigest",
  "serviceStopped",
  "serviceIdentityRevoked",
  "databaseIdentityRevoked",
  "operatorValidationIdentitiesRevoked",
  "syntheticIdentitiesRevoked",
  "endpointRoutesBlocked",
  "temporaryNetworkAccessRemoved",
  "temporarySecretsDestroyed",
  "rollbackVerified",
  "closedAt",
];
const CLEANUP_EVIDENCE_FIELDS = [
  "schemaVersion",
  "event",
  "status",
  "approver",
  "factoryPlanId",
  "serverBinding",
  "externalDependencySetBinding",
  "serviceIdentityBinding",
  "databaseIdentityBinding",
  "syntheticIdentityProfileBinding",
  "privateNetworkPolicyBinding",
  "serviceStopped",
  "serviceIdentityRevoked",
  "databaseIdentityRevoked",
  "operatorValidationIdentitiesRevoked",
  "syntheticIdentitiesRevoked",
  "endpointRoutesBlocked",
  "temporaryNetworkAccessRemoved",
  "temporarySecretsDestroyed",
  "rollbackVerified",
  "verifiedAt",
];
const NETWORK_DEPENDENCY_ID = "V1D-DEP-NETWORK-SEGMENTATION";
const EXPECTED_DEPENDENCY_IDS = [
  "V1D-DEP-DNS-TIME",
  "V1D-DEP-SERVER-PKI",
  "V1D-DEP-NETWORK-SEGMENTATION",
  "V1D-DEP-SYNTHETIC-ISSUER-STATUS",
  "V1D-DEP-OPERATOR-VERIFIER",
  "V1D-DEP-TELEMETRY-AUDIT",
  "V1D-DEP-BACKUP-RECOVERY",
  "V1D-DEP-ENCRYPTION-KEY-CUSTODY",
];
const REQUIRED_V1C_CONTROLS = [
  "exact production artifacts",
  "independent trust root",
  "signing custody and recovery",
  "protected distribution and bootstrap",
  "signing-key loss test",
  "signing-key compromise test",
  "independent verification",
];

function hasExactUniqueEntries(value, expected) {
  return (
    Array.isArray(value) &&
    value.length === expected.length &&
    new Set(value).size === expected.length &&
    expected.every((item) => value.includes(item))
  );
}

function validDate(value) {
  if (!ISO_TIMESTAMP.test(value ?? "")) return null;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return null;
  const normalized = new Date(timestamp).toISOString().replace(".000Z", "Z");
  return normalized === value ? timestamp : null;
}

function normalizeText(text) {
  return text.replaceAll("\r\n", "\n");
}

function parseCanonicalJson(text) {
  try {
    const value = JSON.parse(text);
    return normalizeText(text) === `${JSON.stringify(value, null, 2)}\n`
      ? value
      : null;
  } catch {
    return null;
  }
}

function sha256(text) {
  return `sha256:${createHash("sha256").update(normalizeText(text)).digest("hex")}`;
}

function canonicalJsonDigest(value) {
  return sha256(`${JSON.stringify(value, null, 2)}\n`);
}

function validateTransitiveGovernanceRecords(
  authorizationText,
  {
    isRegularFile,
    readText,
    readAtProtectedMain,
    protectedMainPathVersionCount,
  },
  label,
) {
  const errors = [];
  const { fields } = parseRecord(authorizationText);
  const queue = [...fields.values()].filter(
    (value) =>
      typeof value === "string" &&
      /^docs\/governance\/[A-Za-z0-9_./-]+$/.test(value),
  );
  const visited = new Set();
  const enqueueGovernancePaths = (value) => {
    if (typeof value === "string") {
      if (/^docs\/governance\/[A-Za-z0-9_./-]+$/.test(value)) queue.push(value);
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) enqueueGovernancePaths(item);
      return;
    }
    if (value && typeof value === "object")
      for (const item of Object.values(value)) enqueueGovernancePaths(item);
  };
  while (queue.length > 0) {
    const recordPath = queue.shift();
    if (visited.has(recordPath)) continue;
    visited.add(recordPath);
    const protectedText = readAtProtectedMain(recordPath);
    const currentText = readText(recordPath);
    if (
      !isRegularFile(recordPath) ||
      typeof protectedText !== "string" ||
      typeof currentText !== "string" ||
      normalizeText(currentText) !== normalizeText(protectedText) ||
      protectedMainPathVersionCount(recordPath) !== 1
    ) {
      errors.push(`${label} must preserve transitive record: ${recordPath}.`);
      continue;
    }
    if (recordPath.endsWith(".json")) {
      const record = parseCanonicalJson(protectedText);
      if (record) enqueueGovernancePaths(record);
    }
  }
  return errors;
}

function protectedMainAuthority(readAtProtectedMain) {
  const text = readAtProtectedMain("governance/gates.json");
  if (typeof text !== "string") return null;
  try {
    const config = JSON.parse(text);
    return (
      config.boundedOperationalAuthorizations?.find(
        (item) => item.id === "V1D-SV",
      ) ?? null
    );
  } catch {
    return null;
  }
}

function protectedMainGate(readAtProtectedMain, gateId) {
  const text = readAtProtectedMain("governance/gates.json");
  if (typeof text !== "string") return null;
  try {
    const config = JSON.parse(text);
    return config.gates?.find((item) => item.id === gateId) ?? null;
  } catch {
    return null;
  }
}

function validateCloseout(
  authority,
  priorAuthority,
  laterGateOpen,
  {
    isRegularFile,
    readText,
    readAtProtectedMain,
    protectedMainPathVersionCount,
    pathIntroductionTime,
    authorityOpenIntroductionTime,
    now,
  },
) {
  const errors = [];
  const closeoutPath = authority.closeout;
  if (
    typeof closeoutPath !== "string" ||
    !/^docs\/governance\/authorizations\/closeouts\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/.test(
      closeoutPath,
    ) ||
    !isRegularFile(closeoutPath)
  ) {
    return ["Closed V1D-SV requires an immutable cleanup closeout receipt."];
  }

  if (
    !["open", "closing"].includes(priorAuthority?.status) &&
    priorAuthority?.closeout !== closeoutPath
  )
    errors.push(
      "V1D-SV closeout lacks a preceding open protected-main lifecycle.",
    );

  const closeoutText = readText(closeoutPath);
  const closeout =
    typeof closeoutText === "string" ? parseCanonicalJson(closeoutText) : null;
  if (!closeout) {
    errors.push(
      "V1D-SV cleanup closeout receipt is not canonical duplicate-free JSON.",
    );
    return errors;
  }
  if (!hasExactUniqueEntries(Object.keys(closeout), CLOSEOUT_RECEIPT_FIELDS))
    errors.push("V1D-SV cleanup closeout receipt has an invalid field set.");
  if (
    closeout.schemaVersion !== 1 ||
    closeout.receiptType !== "V1D-SV-Closeout" ||
    closeout.authority !== "V1D-SV" ||
    closeout.status !== "ClosedAndClean"
  )
    errors.push(
      "V1D-SV cleanup closeout receipt has invalid identity or status.",
    );
  if (closeout.approver !== "Beowxlf")
    errors.push("V1D-SV cleanup closeout receipt lacks owner approval.");

  const cleanupFlags = [
    "serviceStopped",
    "serviceIdentityRevoked",
    "databaseIdentityRevoked",
    "operatorValidationIdentitiesRevoked",
    "syntheticIdentitiesRevoked",
    "endpointRoutesBlocked",
    "temporaryNetworkAccessRemoved",
    "temporarySecretsDestroyed",
    "rollbackVerified",
  ];
  for (const field of cleanupFlags) {
    if (closeout[field] !== true)
      errors.push(`V1D-SV cleanup closeout does not prove ${field}.`);
  }

  const authorizationPath = closeout.authorizationRecord;
  const authorizationText =
    typeof authorizationPath === "string"
      ? readAtProtectedMain(authorizationPath)
      : null;
  const currentAuthorizationText =
    typeof authorizationPath === "string" ? readText(authorizationPath) : null;
  if (
    !/^docs\/governance\/authorizations\/[A-Za-z0-9][A-Za-z0-9._-]*\.md$/.test(
      authorizationPath ?? "",
    ) ||
    typeof authorizationText !== "string"
  ) {
    errors.push(
      "V1D-SV cleanup closeout lacks its protected-main authorization record.",
    );
    return errors;
  }
  if (
    !isRegularFile(authorizationPath) ||
    typeof currentAuthorizationText !== "string" ||
    normalizeText(currentAuthorizationText) !== normalizeText(authorizationText)
  )
    errors.push(
      "V1D-SV cleanup closeout must preserve the exact active authorization record.",
    );
  if (sha256(authorizationText) !== closeout.authorizationRecordDigest)
    errors.push("V1D-SV cleanup closeout authorization digest mismatches.");
  if (
    ["open", "closing"].includes(priorAuthority?.status) &&
    priorAuthority.authorization !== authorizationPath
  )
    errors.push(
      "V1D-SV cleanup closeout does not bind the preceding open authorization.",
    );
  errors.push(
    ...validateTransitiveGovernanceRecords(
      authorizationText,
      {
        isRegularFile,
        readText,
        readAtProtectedMain,
        protectedMainPathVersionCount,
      },
      "V1D-SV closing transition",
    ),
  );

  const { fields: authorizationFields, duplicates } =
    parseRecord(authorizationText);
  if (duplicates.size > 0)
    errors.push("V1D-SV cleanup closeout authorization is ambiguous.");
  const authorizationBindings = [
    ["factoryPlanId", "Factory plan ID"],
    ["serverBinding", "Server binding"],
    ["signedReleaseDigest", "Signed release digest"],
  ];
  for (const [closeoutField, authorizationField] of authorizationBindings) {
    if (closeout[closeoutField] !== authorizationFields.get(authorizationField))
      errors.push(
        `V1D-SV cleanup closeout ${closeoutField} mismatches its authorization.`,
      );
  }

  const evidencePath = closeout.cleanupEvidenceRecord;
  if (
    typeof evidencePath !== "string" ||
    !/^docs\/governance\/authorizations\/closeouts\/evidence\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/.test(
      evidencePath,
    ) ||
    !isRegularFile(evidencePath)
  ) {
    errors.push("V1D-SV cleanup closeout lacks immutable cleanup evidence.");
    return errors;
  }
  const evidenceText = readText(evidencePath);
  const evidence =
    typeof evidenceText === "string" ? parseCanonicalJson(evidenceText) : null;
  if (!evidence) {
    errors.push(
      "V1D-SV cleanup evidence is not canonical duplicate-free JSON.",
    );
    return errors;
  }
  if (!hasExactUniqueEntries(Object.keys(evidence), CLEANUP_EVIDENCE_FIELDS))
    errors.push("V1D-SV cleanup evidence has an invalid field set.");
  if (sha256(evidenceText) !== closeout.cleanupEvidenceDigest)
    errors.push("V1D-SV cleanup evidence digest mismatches.");
  if (
    evidence.schemaVersion !== 1 ||
    evidence.event !== "V1D-SV-CleanupVerified" ||
    evidence.status !== "Verified" ||
    evidence.approver !== "Beowxlf"
  )
    errors.push("V1D-SV cleanup evidence has invalid identity or status.");
  for (const field of cleanupFlags) {
    if (evidence[field] !== true || evidence[field] !== closeout[field])
      errors.push(`V1D-SV cleanup evidence does not prove ${field}.`);
  }
  const evidenceBindings = [
    ["factoryPlanId", "Factory plan ID"],
    ["serverBinding", "Server binding"],
    ["externalDependencySetBinding", "External dependency set binding"],
    ["serviceIdentityBinding", "Service identity binding"],
    ["databaseIdentityBinding", "Database identity binding"],
    ["syntheticIdentityProfileBinding", "Synthetic identity profile binding"],
    ["privateNetworkPolicyBinding", "Private network policy binding"],
  ];
  for (const [evidenceField, authorizationField] of evidenceBindings) {
    if (evidence[evidenceField] !== authorizationFields.get(authorizationField))
      errors.push(
        `V1D-SV cleanup evidence ${evidenceField} mismatches its authorization.`,
      );
  }

  const issuedAt = validDate(authorizationFields.get("Issued at"));
  const expiresAt = validDate(authorizationFields.get("Expires at"));
  const planExpiresAt = validDate(
    authorizationFields.get("Factory plan expires at"),
  );
  const verifiedAt = validDate(evidence.verifiedAt);
  const closedAt = validDate(closeout.closedAt);
  const authorityOpenedAt = validDate(closeout.authorityOpenedAt);
  const protectedOpenTime = Date.parse(authorityOpenIntroductionTime() ?? "");
  if (
    issuedAt === null ||
    expiresAt === null ||
    planExpiresAt === null ||
    verifiedAt === null ||
    closedAt === null ||
    authorityOpenedAt === null ||
    !Number.isFinite(protectedOpenTime) ||
    authorityOpenedAt !== protectedOpenTime ||
    verifiedAt <= authorityOpenedAt ||
    verifiedAt < issuedAt ||
    closedAt < verifiedAt ||
    closedAt > now.getTime()
  )
    errors.push(
      "V1D-SV cleanup closeout has an invalid evidence time sequence.",
    );

  if (["open", "closing"].includes(priorAuthority?.status)) {
    for (const [label, recordPath] of [
      ["closeout receipt", closeoutPath],
      ["cleanup evidence", evidencePath],
    ]) {
      if (
        readAtProtectedMain(recordPath) !== null ||
        protectedMainPathVersionCount(recordPath) !== 0
      )
        errors.push(
          `V1D-SV ${label} must be created after the protected-main authority opening.`,
        );
    }
  }

  if (priorAuthority?.status === "closed" || laterGateOpen) {
    for (const [label, recordPath, currentText, claimedAt] of [
      ["closeout receipt", closeoutPath, closeoutText, closedAt],
      ["cleanup evidence", evidencePath, evidenceText, verifiedAt],
    ]) {
      const protectedText = readAtProtectedMain(recordPath);
      const introducedAt = Date.parse(pathIntroductionTime(recordPath) ?? "");
      if (
        typeof protectedText !== "string" ||
        normalizeText(protectedText) !== normalizeText(currentText) ||
        protectedMainPathVersionCount(recordPath) !== 1 ||
        !Number.isFinite(introducedAt) ||
        claimedAt === null ||
        claimedAt > introducedAt
      )
        errors.push(
          `V1D-SV ${label} must remain accepted exactly once on protected main after its claimed event.`,
        );
    }
    if (priorAuthority?.closeout !== closeoutPath)
      errors.push(
        "Later gates require the protected-main V1D-SV closeout reference.",
      );
  }
  return errors;
}

function validateReopen(
  authorizationPath,
  authorizationText,
  priorAuthority,
  {
    isRegularFile,
    readText,
    readAtProtectedMain,
    protectedMainPathVersionCount,
  },
) {
  if (priorAuthority?.status !== "closed" || !priorAuthority.closeout)
    return [];
  const errors = [];
  const priorCloseoutPath = priorAuthority.closeout;
  const priorCloseoutText = readAtProtectedMain(priorCloseoutPath);
  const currentCloseoutText = readText(priorCloseoutPath);
  const priorCloseout =
    typeof priorCloseoutText === "string"
      ? parseCanonicalJson(priorCloseoutText)
      : null;
  if (
    !/^docs\/governance\/authorizations\/closeouts\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/.test(
      priorCloseoutPath,
    ) ||
    !isRegularFile(priorCloseoutPath) ||
    !priorCloseout ||
    typeof currentCloseoutText !== "string" ||
    normalizeText(currentCloseoutText) !== normalizeText(priorCloseoutText) ||
    protectedMainPathVersionCount(priorCloseoutPath) !== 1
  ) {
    return [
      "V1D-SV cannot reopen without its immutable prior lifecycle closeout.",
    ];
  }

  const priorLifecycleRecords = [
    [
      "authorization",
      priorCloseout.authorizationRecord,
      priorCloseout.authorizationRecordDigest,
      /^docs\/governance\/authorizations\/[A-Za-z0-9][A-Za-z0-9._-]*\.md$/,
    ],
    [
      "cleanup evidence",
      priorCloseout.cleanupEvidenceRecord,
      priorCloseout.cleanupEvidenceDigest,
      /^docs\/governance\/authorizations\/closeouts\/evidence\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/,
    ],
  ];
  for (const [
    label,
    recordPath,
    expectedDigest,
    pathPattern,
  ] of priorLifecycleRecords) {
    const protectedText =
      typeof recordPath === "string" ? readAtProtectedMain(recordPath) : null;
    const currentText =
      typeof recordPath === "string" ? readText(recordPath) : null;
    if (
      typeof recordPath !== "string" ||
      !pathPattern.test(recordPath) ||
      !isRegularFile(recordPath) ||
      typeof protectedText !== "string" ||
      typeof currentText !== "string" ||
      normalizeText(currentText) !== normalizeText(protectedText) ||
      protectedMainPathVersionCount(recordPath) !== 1 ||
      sha256(protectedText) !== expectedDigest
    )
      errors.push(
        `V1D-SV cannot reopen without preserving its immutable prior lifecycle ${label}.`,
      );
  }

  const { fields } = parseRecord(authorizationText);
  if (
    authorizationPath === priorCloseout.authorizationRecord ||
    sha256(authorizationText) === priorCloseout.authorizationRecordDigest
  )
    errors.push("V1D-SV cannot replay a consumed authorization record.");
  if (fields.get("Factory plan ID") === priorCloseout.factoryPlanId)
    errors.push("V1D-SV cannot replay a consumed Factory plan.");
  const priorClosedAt = validDate(priorCloseout.closedAt);
  const planIssuedAt = validDate(fields.get("Factory plan issued at"));
  const issuedAt = validDate(fields.get("Issued at"));
  if (
    priorClosedAt === null ||
    planIssuedAt === null ||
    issuedAt === null ||
    planIssuedAt <= priorClosedAt ||
    issuedAt <= priorClosedAt
  )
    errors.push(
      "Reopened V1D-SV requires a new authorization and Factory plan issued after prior closeout.",
    );
  return errors;
}

function validateV1dCloseoutHistory(
  authority,
  priorAuthority,
  {
    isRegularFile,
    readText,
    readAtProtectedMain,
    protectedMainPathVersionCount,
  },
) {
  const errors = [];
  const currentHistory = authority.closeouts;
  const priorHistory = priorAuthority?.closeouts ?? [];
  const validCurrentHistory =
    Array.isArray(currentHistory) &&
    new Set(currentHistory).size === currentHistory.length &&
    currentHistory.every(
      (path) =>
        typeof path === "string" &&
        /^docs\/governance\/authorizations\/closeouts\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/.test(
          path,
        ),
    );
  const validPriorHistory =
    Array.isArray(priorHistory) &&
    new Set(priorHistory).size === priorHistory.length;
  if (!validCurrentHistory)
    return ["V1D-SV has an invalid lifecycle closeout history."];
  if (!validPriorHistory)
    return ["Protected-main V1D-SV has an invalid closeout history."];
  if (priorHistory.some((path, index) => currentHistory[index] !== path))
    errors.push(
      "V1D-SV must preserve every prior lifecycle closeout in order.",
    );
  if (
    Object.hasOwn(authority, "closeout") &&
    authority.closeout !== currentHistory.at(-1)
  )
    errors.push("V1D-SV latest closeout must end its lifecycle history.");
  if (currentHistory.length === 0 && Object.hasOwn(authority, "closeout"))
    errors.push("V1D-SV cannot name a closeout outside its lifecycle history.");

  for (const closeoutPath of priorHistory) {
    const protectedCloseoutText = readAtProtectedMain(closeoutPath);
    const currentCloseoutText = readText(closeoutPath);
    const closeout =
      typeof protectedCloseoutText === "string"
        ? parseCanonicalJson(protectedCloseoutText)
        : null;
    if (
      !currentHistory.includes(closeoutPath) ||
      !isRegularFile(closeoutPath) ||
      !closeout ||
      typeof currentCloseoutText !== "string" ||
      normalizeText(currentCloseoutText) !==
        normalizeText(protectedCloseoutText) ||
      protectedMainPathVersionCount(closeoutPath) !== 1
    ) {
      errors.push(
        "V1D-SV must preserve every immutable prior lifecycle closeout.",
      );
      continue;
    }
    for (const [label, recordPath, digest] of [
      [
        "authorization",
        closeout.authorizationRecord,
        closeout.authorizationRecordDigest,
      ],
      [
        "cleanup evidence",
        closeout.cleanupEvidenceRecord,
        closeout.cleanupEvidenceDigest,
      ],
    ]) {
      const protectedText =
        typeof recordPath === "string" ? readAtProtectedMain(recordPath) : null;
      const currentText =
        typeof recordPath === "string" ? readText(recordPath) : null;
      if (
        typeof recordPath !== "string" ||
        !isRegularFile(recordPath) ||
        typeof protectedText !== "string" ||
        typeof currentText !== "string" ||
        normalizeText(currentText) !== normalizeText(protectedText) ||
        protectedMainPathVersionCount(recordPath) !== 1 ||
        sha256(protectedText) !== digest
      )
        errors.push(`V1D-SV must preserve every prior lifecycle ${label}.`);
    }

    const consumedAuthorizationText = readAtProtectedMain(
      closeout.authorizationRecord,
    );
    if (typeof consumedAuthorizationText !== "string") continue;
    errors.push(
      ...validateTransitiveGovernanceRecords(
        consumedAuthorizationText,
        {
          isRegularFile,
          readText,
          readAtProtectedMain,
          protectedMainPathVersionCount,
        },
        "V1D-SV consumed lifecycle",
      ),
    );
  }
  return errors;
}

function validateProductGateLifecycle(
  gate,
  priorGate,
  {
    isRegularFile,
    readText,
    readAtCommit,
    readAtProtectedMain,
    isPathImmutableOnProtectedMain,
    isPathIntroducedBefore,
    pathIntroductionTime,
    gateOpenIntroductionTime,
    protectedMainPathVersionCount,
    isCommit,
    isProtectedMainCommit,
    now,
  },
) {
  const errors = [];
  const pathPattern = new RegExp(
    `^docs/governance/authorizations/product-gates/closeouts/${gate.id}-[A-Za-z0-9][A-Za-z0-9._-]*\\.json$`,
  );
  const cleanupPathPattern = new RegExp(
    `^docs/governance/authorizations/product-gates/closeouts/evidence/${gate.id}-[A-Za-z0-9][A-Za-z0-9._-]*\\.json$`,
  );
  const currentHistory = gate.closeouts;
  const priorHistory = priorGate?.closeouts ?? [];
  const validCurrentHistory =
    Array.isArray(currentHistory) &&
    new Set(currentHistory).size === currentHistory.length &&
    currentHistory.every(
      (path) => typeof path === "string" && pathPattern.test(path),
    );
  const validPriorHistory =
    Array.isArray(priorHistory) &&
    new Set(priorHistory).size === priorHistory.length;
  if (!validCurrentHistory)
    return [`${gate.id} has an invalid lifecycle closeout history.`];
  if (!validPriorHistory)
    return [`Protected-main ${gate.id} has an invalid closeout history.`];
  if (priorHistory.some((path, index) => currentHistory[index] !== path))
    errors.push(`${gate.id} must preserve every prior lifecycle closeout.`);
  if (
    Object.hasOwn(gate, "closeout") &&
    gate.closeout !== currentHistory.at(-1)
  )
    errors.push(`${gate.id} latest closeout must end its lifecycle history.`);
  if (currentHistory.length === 0 && Object.hasOwn(gate, "closeout"))
    errors.push(`${gate.id} cannot name a closeout outside its history.`);

  const scopeChanged =
    priorGate?.status === "open" &&
    gate.status === "open" &&
    gate.authorization !== priorGate.authorization;
  const enteringClosing =
    priorGate?.status === "open" && gate.status === "closing";
  const stagingCleanup =
    priorGate?.status === "closing" &&
    gate.status === "closing" &&
    !Object.hasOwn(priorGate, "pendingCloseout") &&
    Object.hasOwn(gate, "pendingCloseout");
  const finalizingCloseout =
    priorGate?.status === "closing" && gate.status !== "closing";
  if (
    priorGate?.status === "open" &&
    (scopeChanged || (!enteringClosing && gate.status !== "open"))
  )
    errors.push(
      `${gate.id} must enter a non-consumable closing state before cleanup or rescope.`,
    );
  if (
    enteringClosing &&
    (gate.authorization !== priorGate.authorization ||
      Object.hasOwn(gate, "pendingCloseout"))
  )
    errors.push(
      `${gate.id} closing transition must freeze the active authorization before cleanup.`,
    );
  if (
    priorGate?.status === "closing" &&
    gate.status === "closing" &&
    gate.authorization !== priorGate.authorization
  )
    errors.push(`${gate.id} closing state cannot change authorization scope.`);
  if (
    priorGate?.status === "closing" &&
    Object.hasOwn(priorGate, "pendingCloseout") &&
    ((gate.status === "closing" &&
      gate.pendingCloseout !== priorGate.pendingCloseout) ||
      (gate.status !== "closing" &&
        gate.closeout !== priorGate.pendingCloseout))
  )
    errors.push(
      `${gate.id} must preserve and consume its exact pending closeout.`,
    );
  if (finalizingCloseout && !Object.hasOwn(priorGate, "pendingCloseout"))
    errors.push(
      `${gate.id} cannot finalize before cleanup evidence is frozen.`,
    );
  if (gate.status !== "closing" && Object.hasOwn(gate, "pendingCloseout"))
    errors.push(`${gate.id} pending closeout is valid only while closing.`);
  if (
    finalizingCloseout &&
    (currentHistory.length !== priorHistory.length + 1 ||
      gate.closeout !== currentHistory.at(-1))
  )
    errors.push(
      `${gate.id} cannot close or replace scope without appending one cleanup closeout.`,
    );
  if (!finalizingCloseout && currentHistory.length !== priorHistory.length)
    errors.push(
      `${gate.id} lifecycle history may change only during cleanup closeout.`,
    );

  const preserveLifecycle = (closeoutPath) => {
    const protectedCloseoutText = readAtProtectedMain(closeoutPath);
    const currentCloseoutText = readText(closeoutPath);
    const closeout =
      typeof protectedCloseoutText === "string"
        ? parseCanonicalJson(protectedCloseoutText)
        : null;
    if (
      !currentHistory.includes(closeoutPath) ||
      !isRegularFile(closeoutPath) ||
      !closeout ||
      typeof currentCloseoutText !== "string" ||
      normalizeText(currentCloseoutText) !==
        normalizeText(protectedCloseoutText) ||
      protectedMainPathVersionCount(closeoutPath) !== 1
    ) {
      errors.push(`${gate.id} must preserve every immutable prior closeout.`);
      return;
    }
    for (const [label, recordPath, digest] of [
      [
        "authorization",
        closeout.authorizationRecord,
        closeout.authorizationDigest,
      ],
      [
        "cleanup evidence",
        closeout.cleanupEvidenceRecord,
        closeout.cleanupEvidenceDigest,
      ],
    ]) {
      const protectedText =
        typeof recordPath === "string" ? readAtProtectedMain(recordPath) : null;
      const currentText =
        typeof recordPath === "string" ? readText(recordPath) : null;
      if (
        typeof recordPath !== "string" ||
        !isRegularFile(recordPath) ||
        typeof protectedText !== "string" ||
        typeof currentText !== "string" ||
        normalizeText(currentText) !== normalizeText(protectedText) ||
        protectedMainPathVersionCount(recordPath) !== 1 ||
        sha256(protectedText) !== digest
      )
        errors.push(`${gate.id} must preserve every prior ${label}.`);
    }

    const consumedAuthorizationText = readAtProtectedMain(
      closeout.authorizationRecord,
    );
    if (typeof consumedAuthorizationText !== "string") return;
    const { fields } = parseRecord(consumedAuthorizationText);
    for (const [
      bindingType,
      pathField,
      digestField,
    ] of PRODUCT_GATE_SCOPE_BINDINGS) {
      const scopePath = fields.get(pathField);
      const scopeDigest = fields.get(digestField);
      const protectedScopeText =
        typeof scopePath === "string" ? readAtProtectedMain(scopePath) : null;
      const currentScopeText =
        typeof scopePath === "string" ? readText(scopePath) : null;
      if (
        typeof scopePath !== "string" ||
        !isRegularFile(scopePath) ||
        typeof protectedScopeText !== "string" ||
        typeof currentScopeText !== "string" ||
        normalizeText(currentScopeText) !== normalizeText(protectedScopeText) ||
        protectedMainPathVersionCount(scopePath) !== 1 ||
        sha256(protectedScopeText) !== scopeDigest
      ) {
        errors.push(`${gate.id} must preserve prior ${bindingType} scope.`);
        continue;
      }
      const scope = parseCanonicalJson(protectedScopeText);
      if (!scope || !Array.isArray(scope.evidence)) continue;
      for (const descriptor of scope.evidence) {
        const evidencePath = descriptor?.record;
        const protectedEvidenceText =
          typeof evidencePath === "string"
            ? readAtProtectedMain(evidencePath)
            : null;
        const currentEvidenceText =
          typeof evidencePath === "string" ? readText(evidencePath) : null;
        if (
          typeof evidencePath !== "string" ||
          !isRegularFile(evidencePath) ||
          typeof protectedEvidenceText !== "string" ||
          typeof currentEvidenceText !== "string" ||
          normalizeText(currentEvidenceText) !==
            normalizeText(protectedEvidenceText) ||
          protectedMainPathVersionCount(evidencePath) !== 1 ||
          sha256(protectedEvidenceText) !== descriptor.digest
        )
          errors.push(`${gate.id} must preserve every prior evidence record.`);
      }
    }
  };
  for (const closeoutPath of priorHistory) preserveLifecycle(closeoutPath);

  const validatePendingCloseout =
    stagingCleanup ||
    (priorGate?.status === "closing" &&
      Object.hasOwn(priorGate, "pendingCloseout"));
  if (!validatePendingCloseout && !finalizingCloseout) return errors;
  const requireProtectedEvidence = !stagingCleanup;
  if (finalizingCloseout)
    errors.push(
      ...validateProductGateAuthorization(priorGate, {
        isRegularFile,
        readText,
        readAtCommit,
        readAtProtectedMain,
        isPathImmutableOnProtectedMain,
        isPathIntroducedBefore,
        pathIntroductionTime,
        protectedMainPathVersionCount,
        isCommit,
        isProtectedMainCommit,
        allowExpired: true,
        now,
      }),
    );
  const closeoutPath = stagingCleanup
    ? gate.pendingCloseout
    : (priorGate?.pendingCloseout ?? gate.closeout);
  const closeoutText =
    typeof closeoutPath === "string" ? readText(closeoutPath) : null;
  const protectedCloseoutText =
    typeof closeoutPath === "string" ? readAtProtectedMain(closeoutPath) : null;
  const closeout =
    typeof closeoutText === "string" ? parseCanonicalJson(closeoutText) : null;
  if (
    typeof closeoutPath !== "string" ||
    !pathPattern.test(closeoutPath) ||
    !isRegularFile(closeoutPath) ||
    !closeout
  ) {
    errors.push(`${gate.id} cleanup closeout is missing or non-canonical.`);
    return errors;
  }
  if (
    (requireProtectedEvidence && typeof protectedCloseoutText !== "string") ||
    (requireProtectedEvidence &&
      normalizeText(closeoutText) !== normalizeText(protectedCloseoutText)) ||
    (requireProtectedEvidence &&
      protectedMainPathVersionCount(closeoutPath) !== 1)
  )
    errors.push(
      `${gate.id} cleanup closeout is not exact owner-accepted protected-main evidence.`,
    );
  if (
    !hasExactUniqueEntries(Object.keys(closeout), PRODUCT_GATE_CLOSEOUT_FIELDS)
  )
    errors.push(`${gate.id} cleanup closeout has an invalid field set.`);
  const authorizationPath = priorGate.authorization;
  const authorizationText =
    typeof authorizationPath === "string"
      ? readAtProtectedMain(authorizationPath)
      : null;
  const currentAuthorizationText =
    typeof authorizationPath === "string" ? readText(authorizationPath) : null;
  if (
    closeout.schemaVersion !== 1 ||
    closeout.gate !== gate.id ||
    closeout.status !== "Closed" ||
    closeout.approver !== "Beowxlf" ||
    closeout.authorizationRecord !== authorizationPath ||
    typeof authorizationText !== "string" ||
    typeof currentAuthorizationText !== "string" ||
    normalizeText(currentAuthorizationText) !==
      normalizeText(authorizationText) ||
    protectedMainPathVersionCount(authorizationPath) !== 1 ||
    sha256(authorizationText) !== closeout.authorizationDigest
  )
    errors.push(
      `${gate.id} cleanup closeout does not bind its active authorization.`,
    );

  const cleanupPath = closeout.cleanupEvidenceRecord;
  const cleanupText =
    typeof cleanupPath === "string" ? readText(cleanupPath) : null;
  const protectedCleanupText =
    typeof cleanupPath === "string" ? readAtProtectedMain(cleanupPath) : null;
  const cleanup =
    typeof cleanupText === "string" ? parseCanonicalJson(cleanupText) : null;
  if (
    typeof cleanupPath !== "string" ||
    !cleanupPathPattern.test(cleanupPath) ||
    !isRegularFile(cleanupPath) ||
    !cleanup ||
    sha256(cleanupText) !== closeout.cleanupEvidenceDigest
  ) {
    errors.push(`${gate.id} cleanup closeout lacks exact cleanup evidence.`);
    return errors;
  }
  if (
    (requireProtectedEvidence && typeof protectedCleanupText !== "string") ||
    (requireProtectedEvidence &&
      normalizeText(cleanupText) !== normalizeText(protectedCleanupText)) ||
    (requireProtectedEvidence &&
      protectedMainPathVersionCount(cleanupPath) !== 1)
  )
    errors.push(
      `${gate.id} cleanup evidence is not exact owner-accepted protected-main evidence.`,
    );
  if (!hasExactUniqueEntries(Object.keys(cleanup), PRODUCT_GATE_CLEANUP_FIELDS))
    errors.push(`${gate.id} cleanup evidence has an invalid field set.`);
  if (
    cleanup.schemaVersion !== 1 ||
    cleanup.gate !== gate.id ||
    cleanup.status !== "Verified" ||
    cleanup.approver !== "Beowxlf" ||
    cleanup.authorizationDigest !== closeout.authorizationDigest ||
    cleanup.targetsRevoked !== true ||
    cleanup.identitiesRevoked !== true ||
    cleanup.networkAccessRemoved !== true ||
    cleanup.artifactsWithdrawn !== true ||
    cleanup.rollbackVerified !== true
  )
    errors.push(`${gate.id} cleanup evidence leaves active capability behind.`);
  const verifiedAt = validDate(cleanup.verifiedAt);
  const closedAt = validDate(closeout.closedAt);
  const frozenAt = Date.parse(
    gateOpenIntroductionTime(gate.id, authorizationPath, "closing") ?? "",
  );
  const cleanupIntroducedAt = Date.parse(
    pathIntroductionTime(cleanupPath) ?? "",
  );
  const closeoutIntroducedAt = Date.parse(
    pathIntroductionTime(closeoutPath) ?? "",
  );
  if (
    verifiedAt === null ||
    closedAt === null ||
    !Number.isFinite(frozenAt) ||
    verifiedAt <= frozenAt ||
    closedAt < verifiedAt ||
    closedAt > now.getTime() ||
    (requireProtectedEvidence &&
      (!Number.isFinite(cleanupIntroducedAt) ||
        verifiedAt > cleanupIntroducedAt)) ||
    (requireProtectedEvidence &&
      (!Number.isFinite(closeoutIntroducedAt) ||
        closedAt > closeoutIntroducedAt))
  )
    errors.push(`${gate.id} cleanup closeout has an invalid event sequence.`);
  return errors;
}

export function validateProductGateAuthorization(
  gate,
  {
    isRegularFile = () => false,
    readText = () => null,
    readAtCommit = () => null,
    readAtProtectedMain = () => null,
    isPathImmutableOnProtectedMain = () => false,
    isPathIntroducedBefore = () => false,
    pathIntroductionTime = () => null,
    protectedMainPathVersionCount = () => null,
    isCommit = () => false,
    isProtectedMainCommit = () => false,
    allowExpired = false,
    now = new Date(),
  } = {},
) {
  const errors = [];
  const authorizationPath = gate.authorization;
  if (
    typeof authorizationPath !== "string" ||
    !new RegExp(
      `^docs/governance/authorizations/${gate.id}-[A-Za-z0-9][A-Za-z0-9._-]*\\.md$`,
    ).test(authorizationPath) ||
    !isRegularFile(authorizationPath)
  ) {
    return [
      `Open ${gate.id} lacks its exact gate-specific authorization file.`,
    ];
  }
  const text = readText(authorizationPath);
  if (typeof text !== "string" || text.trim() === "")
    return [`Open ${gate.id} has an unreadable authorization record.`];
  const authorizationDigest = sha256(text);
  for (const closeoutPath of gate.closeouts ?? []) {
    const closeoutText = readAtProtectedMain(closeoutPath);
    const closeout =
      typeof closeoutText === "string"
        ? parseCanonicalJson(closeoutText)
        : null;
    if (
      closeout?.authorizationRecord === authorizationPath ||
      closeout?.authorizationDigest === authorizationDigest
    )
      errors.push(
        `${gate.id} cannot reuse an authorization consumed by a prior closeout.`,
      );
  }
  const protectedAuthorization = readAtProtectedMain(authorizationPath);
  if (
    typeof protectedAuthorization !== "string" ||
    normalizeText(protectedAuthorization) !== normalizeText(text) ||
    protectedMainPathVersionCount(authorizationPath) !== 1
  )
    errors.push(
      `${gate.id} authorization must be owner-accepted once on protected main before the gate opens.`,
    );
  const { fields, duplicates } = parseRecord(text);
  for (const field of duplicates) {
    if (PRODUCT_GATE_AUTHORIZATION_FIELDS.includes(field))
      errors.push(`${gate.id} authorization record duplicates ${field}.`);
  }
  for (const field of PRODUCT_GATE_AUTHORIZATION_FIELDS) {
    const value = fields.get(field);
    if (!value || /\b(?:TBD|TODO|CHANGEME|PLACEHOLDER)\b/i.test(value))
      errors.push(`${gate.id} authorization record lacks exact ${field}.`);
  }
  if (fields.get("Gate") !== gate.id)
    errors.push(`${gate.id} authorization record names the wrong gate.`);
  if (fields.get("Status") !== "Authorized")
    errors.push(`${gate.id} authorization record is not Authorized.`);
  if (fields.get("Approver") !== "Beowxlf")
    errors.push(`${gate.id} authorization record lacks owner approval.`);
  const auditedCommit = fields.get("Audited commit") ?? "";
  if (!/^[a-f0-9]{40}$/.test(auditedCommit) || !isCommit(auditedCommit))
    errors.push(
      `${gate.id} authorization record has an invalid audited commit.`,
    );
  else if (!isProtectedMainCommit(auditedCommit))
    errors.push(
      `${gate.id} authorization audited commit is not on protected main.`,
    );
  const issuedAt = validDate(fields.get("Issued at"));
  const expiresAt = validDate(fields.get("Expires at"));
  const authorizationIntroducedAt = Date.parse(
    pathIntroductionTime(authorizationPath) ?? "",
  );
  if (
    issuedAt === null ||
    expiresAt === null ||
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > MAX_AUTHORITY_LIFETIME_MS ||
    issuedAt > now.getTime() ||
    (!allowExpired && expiresAt <= now.getTime()) ||
    !Number.isFinite(authorizationIntroducedAt) ||
    issuedAt > authorizationIntroducedAt
  )
    errors.push(`${gate.id} authorization has an invalid active time window.`);

  const evidenceIds = [];
  let targetSetScopeDigest = null;
  for (const [
    bindingType,
    pathField,
    digestField,
  ] of PRODUCT_GATE_SCOPE_BINDINGS) {
    const recordPath = fields.get(pathField) ?? "";
    const expectedDigest = fields.get(digestField) ?? "";
    if (
      !new RegExp(
        `^docs/governance/authorizations/product-gates/scopes/${gate.id}-[A-Za-z0-9][A-Za-z0-9._-]*\\.json$`,
      ).test(recordPath) ||
      !/^sha256:[a-f0-9]{64}$/.test(expectedDigest) ||
      !isRegularFile(recordPath)
    ) {
      errors.push(`${gate.id} lacks its exact ${bindingType} scope record.`);
      continue;
    }
    const currentText = readText(recordPath);
    const auditedText = readAtCommit(auditedCommit, recordPath);
    const protectedText = readAtProtectedMain(recordPath);
    if (
      typeof currentText !== "string" ||
      typeof auditedText !== "string" ||
      typeof protectedText !== "string" ||
      normalizeText(currentText) !== normalizeText(auditedText) ||
      normalizeText(protectedText) !== normalizeText(auditedText) ||
      !isPathImmutableOnProtectedMain(auditedCommit, recordPath) ||
      !isPathIntroducedBefore(recordPath, authorizationPath)
    ) {
      errors.push(
        `${gate.id} ${bindingType} scope is not immutable approved protected-main evidence.`,
      );
      continue;
    }
    if (sha256(auditedText) !== expectedDigest)
      errors.push(`${gate.id} ${bindingType} scope digest mismatches.`);
    const scope = parseCanonicalJson(auditedText);
    if (!scope) {
      errors.push(`${gate.id} ${bindingType} scope is not canonical JSON.`);
      continue;
    }
    if (!hasExactUniqueEntries(Object.keys(scope), PRODUCT_GATE_SCOPE_FIELDS))
      errors.push(`${gate.id} ${bindingType} scope has an invalid field set.`);
    const exactScope = scope.scope;
    const exactScopeIsValid =
      Array.isArray(exactScope) &&
      exactScope.length > 0 &&
      new Set(exactScope).size === exactScope.length &&
      exactScope.every(
        (item) =>
          typeof item === "string" &&
          item.trim() === item &&
          item.length > 0 &&
          !/\b(?:TBD|TODO|CHANGEME|PLACEHOLDER)\b/i.test(item),
      );
    const resolvedScopeDigest = exactScopeIsValid
      ? canonicalJsonDigest(exactScope)
      : null;
    if (
      scope.schemaVersion !== 1 ||
      scope.gate !== gate.id ||
      scope.bindingType !== bindingType ||
      scope.status !== "Approved" ||
      scope.approver !== "Beowxlf" ||
      !/^sha256:[a-f0-9]{64}$/.test(scope.scopeDigest ?? "") ||
      resolvedScopeDigest !== scope.scopeDigest
    )
      errors.push(
        `${gate.id} ${bindingType} scope does not resolve its exact approved content.`,
      );
    if (
      bindingType === "TargetSet" &&
      resolvedScopeDigest === scope.scopeDigest
    )
      targetSetScopeDigest = resolvedScopeDigest;
    const scopePolicy = PRODUCT_GATE_SCOPE_POLICY[gate.id];
    if (
      (bindingType === "Operation" &&
        (exactScope?.length !== 1 ||
          !scopePolicy?.operation.test(exactScope[0]))) ||
      (bindingType === "TargetSet" &&
        (exactScope?.length !== 1 || !scopePolicy?.target.test(exactScope[0])))
    )
      errors.push(
        `${gate.id} ${bindingType} scope exceeds the gate semantic boundary.`,
      );
    const approvedAt = validDate(scope.approvedAt);
    const scopeExpiresAt = validDate(scope.expiresAt);
    const scopeIntroducedAt = Date.parse(
      pathIntroductionTime(recordPath) ?? "",
    );
    if (
      approvedAt === null ||
      scopeExpiresAt === null ||
      issuedAt === null ||
      expiresAt === null ||
      approvedAt >= issuedAt ||
      scopeExpiresAt < expiresAt ||
      !Number.isFinite(scopeIntroducedAt) ||
      approvedAt > scopeIntroducedAt
    )
      errors.push(
        `${gate.id} ${bindingType} scope has an invalid time window.`,
      );
    if (!Array.isArray(scope.evidence)) {
      errors.push(`${gate.id} ${bindingType} scope lacks evidence records.`);
      continue;
    }
    if (bindingType !== "EvidenceBoundary" && scope.evidence.length !== 0)
      errors.push(
        `${gate.id} gate evidence must be listed only by the EvidenceBoundary scope.`,
      );
    for (const descriptor of scope.evidence) {
      const evidenceId = descriptor?.id;
      const evidencePath = descriptor?.record;
      const evidenceDigest = descriptor?.digest;
      if (
        typeof evidenceId !== "string" ||
        !new RegExp(
          `^docs/governance/authorizations/product-gates/evidence/${gate.id}-[A-Za-z0-9][A-Za-z0-9._-]*\\.json$`,
        ).test(evidencePath ?? "") ||
        !/^sha256:[a-f0-9]{64}$/.test(evidenceDigest ?? "") ||
        !isRegularFile(evidencePath)
      ) {
        errors.push(`${gate.id} ${bindingType} scope has invalid evidence.`);
        continue;
      }
      const currentEvidence = readText(evidencePath);
      const auditedEvidence = readAtCommit(auditedCommit, evidencePath);
      const protectedEvidence = readAtProtectedMain(evidencePath);
      if (
        typeof currentEvidence !== "string" ||
        typeof auditedEvidence !== "string" ||
        typeof protectedEvidence !== "string" ||
        normalizeText(currentEvidence) !== normalizeText(auditedEvidence) ||
        normalizeText(protectedEvidence) !== normalizeText(auditedEvidence) ||
        !isPathImmutableOnProtectedMain(auditedCommit, evidencePath) ||
        !isPathIntroducedBefore(evidencePath, authorizationPath)
      ) {
        errors.push(
          `${gate.id} evidence ${evidenceId} is not immutable approved protected-main evidence.`,
        );
        continue;
      }
      if (sha256(auditedEvidence) !== evidenceDigest)
        errors.push(`${gate.id} evidence ${evidenceId} digest mismatches.`);
      const evidence = parseCanonicalJson(auditedEvidence);
      if (!evidence) {
        errors.push(`${gate.id} evidence ${evidenceId} is not canonical JSON.`);
        continue;
      }
      if (
        !hasExactUniqueEntries(
          Object.keys(evidence),
          PRODUCT_GATE_EVIDENCE_FIELDS,
        )
      )
        errors.push(
          `${gate.id} evidence ${evidenceId} has an invalid field set.`,
        );
      const exactResult = evidence.result;
      const exactResultIsValid =
        Array.isArray(exactResult) &&
        exactResult.length > 0 &&
        new Set(exactResult).size === exactResult.length &&
        exactResult.every(
          (item) =>
            typeof item === "string" &&
            item.trim() === item &&
            item.length > 0 &&
            !/\b(?:TBD|TODO|CHANGEME|PLACEHOLDER)\b/i.test(item),
        );
      const resolvedResultDigest = exactResultIsValid
        ? canonicalJsonDigest(exactResult)
        : null;
      if (
        evidence.schemaVersion !== 1 ||
        evidence.gate !== gate.id ||
        evidence.evidenceId !== evidenceId ||
        evidence.status !== "Verified" ||
        evidence.approver !== "Beowxlf" ||
        !/^sha256:[a-f0-9]{64}$/.test(evidence.targetBinding ?? "") ||
        !/^sha256:[a-f0-9]{64}$/.test(evidence.resultBinding ?? "") ||
        evidence.targetBinding !== targetSetScopeDigest ||
        evidence.resultBinding !== resolvedResultDigest
      )
        errors.push(
          `${gate.id} evidence ${evidenceId} has invalid proof data.`,
        );
      const verifiedAt = validDate(evidence.verifiedAt);
      const evidenceIntroducedAt = Date.parse(
        pathIntroductionTime(evidencePath) ?? "",
      );
      if (
        verifiedAt === null ||
        approvedAt === null ||
        verifiedAt > approvedAt ||
        !Number.isFinite(evidenceIntroducedAt) ||
        verifiedAt > evidenceIntroducedAt
      )
        errors.push(`${gate.id} evidence ${evidenceId} has an invalid time.`);
      evidenceIds.push(evidenceId);
    }
  }
  const requiredEvidence = PRODUCT_GATE_REQUIRED_EVIDENCE[gate.id] ?? [];
  if (!hasExactUniqueEntries(evidenceIds, requiredEvidence))
    errors.push(
      `${gate.id} gate-specific evidence set is incomplete or duplicated.`,
    );
  return errors;
}

function validateProtectedMainContinuity(
  label,
  recordPath,
  approvedText,
  readAtProtectedMain,
  isPathImmutableOnProtectedMain,
  auditedCommit,
) {
  const protectedMainText = readAtProtectedMain(recordPath);
  if (typeof protectedMainText !== "string")
    return [`${label} was revoked from protected main.`];
  if (normalizeText(protectedMainText) !== normalizeText(approvedText))
    return [`${label} was superseded on protected main.`];
  if (!isPathImmutableOnProtectedMain(auditedCommit, recordPath))
    return [`${label} lacks single-use immutable protected-main history.`];
  return [];
}

function validatePathPredatesPlan(
  label,
  recordPath,
  planIssuedAt,
  pathIntroductionTime,
) {
  const introducedAt = Date.parse(pathIntroductionTime(recordPath) ?? "");
  if (
    !Number.isFinite(introducedAt) ||
    planIssuedAt === null ||
    introducedAt >= planIssuedAt
  )
    return [
      `${label} protected-main introduction must predate Factory plan issuance.`,
    ];
  return [];
}

function validateClaimAtIntroduction(
  label,
  recordPath,
  claimedAt,
  pathIntroductionTime,
) {
  const introducedAt = Date.parse(pathIntroductionTime(recordPath) ?? "");
  if (
    claimedAt !== null &&
    (!Number.isFinite(introducedAt) || claimedAt > introducedAt)
  )
    return [
      `${label} claimed event postdates its protected-main introduction.`,
    ];
  return [];
}

const NETWORK_EVIDENCE_ARTIFACTS = [
  ["changeApprovalRecord", "changeApprovalBinding", "ChangeApproved"],
  ["applyReceiptRecord", "applyReceiptDigest", "ChangeApplied"],
  ["allowTestRecord", "allowTestReceiptDigest", "AllowPathVerified"],
  ["denyTestRecord", "denyTestReceiptDigest", "DenyPathVerified"],
];

function validateNetworkEvidenceArtifacts(
  receipt,
  auditedCommit,
  evidenceVerifiedAt,
  options,
) {
  const errors = [];
  const {
    isRegularFile,
    readText,
    readAtCommit,
    readAtProtectedMain,
    isPathImmutableOnProtectedMain,
    pathIntroductionTime,
    planIssuedAt,
    now,
  } = options;
  const recordedAtByEvent = new Map();
  for (const [pathField, digestField, event] of NETWORK_EVIDENCE_ARTIFACTS) {
    const recordPath = receipt[pathField] ?? "";
    if (
      !/^docs\/governance\/authorizations\/prerequisites\/network\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/.test(
        recordPath,
      ) ||
      !isRegularFile(recordPath)
    ) {
      errors.push(`V1D-SV network evidence lacks immutable ${event} record.`);
      continue;
    }
    const currentText = readText(recordPath);
    const approvedText = readAtCommit(auditedCommit, recordPath);
    if (typeof currentText !== "string" || typeof approvedText !== "string") {
      errors.push(
        `V1D-SV network ${event} record is absent from the audited commit.`,
      );
      continue;
    }
    if (normalizeText(currentText) !== normalizeText(approvedText))
      errors.push(`V1D-SV network ${event} record changed after approval.`);
    errors.push(
      ...validateProtectedMainContinuity(
        `V1D-SV network ${event} record`,
        recordPath,
        approvedText,
        readAtProtectedMain,
        isPathImmutableOnProtectedMain,
        auditedCommit,
      ),
      ...validatePathPredatesPlan(
        `V1D-SV network ${event} record`,
        recordPath,
        planIssuedAt,
        pathIntroductionTime,
      ),
    );
    if (sha256(approvedText) !== receipt[digestField])
      errors.push(`V1D-SV network ${event} record digest mismatches.`);

    const artifact = parseCanonicalJson(approvedText);
    if (!artifact) {
      errors.push(
        `V1D-SV network ${event} record is not canonical duplicate-free JSON.`,
      );
      continue;
    }
    if (
      artifact.schemaVersion !== 1 ||
      artifact.prerequisiteId !== NETWORK_DEPENDENCY_ID ||
      artifact.event !== event ||
      artifact.status !== "Verified"
    )
      errors.push(
        `V1D-SV network ${event} record has invalid scope or status.`,
      );
    if (artifact.approver !== "Beowxlf")
      errors.push(`V1D-SV network ${event} record lacks owner approval.`);
    if (
      artifact.targetBinding !== receipt.targetBinding ||
      artifact.flowBinding !== receipt.flowBinding
    )
      errors.push(`V1D-SV network ${event} record has mismatched bindings.`);
    const recordedAt = validDate(artifact.recordedAt);
    if (
      recordedAt === null ||
      recordedAt > now.getTime() ||
      (evidenceVerifiedAt !== null && recordedAt >= evidenceVerifiedAt)
    )
      errors.push(`V1D-SV network ${event} record time is invalid.`);
    else recordedAtByEvent.set(event, recordedAt);
    errors.push(
      ...validateClaimAtIntroduction(
        `V1D-SV network ${event} record`,
        recordPath,
        recordedAt,
        pathIntroductionTime,
      ),
    );
  }
  const approvedAt = recordedAtByEvent.get("ChangeApproved");
  const appliedAt = recordedAtByEvent.get("ChangeApplied");
  for (const event of ["AllowPathVerified", "DenyPathVerified"]) {
    const testedAt = recordedAtByEvent.get(event);
    if (
      approvedAt !== undefined &&
      appliedAt !== undefined &&
      testedAt !== undefined &&
      !(approvedAt < appliedAt && appliedAt < testedAt)
    )
      errors.push(`V1D-SV network ${event} record is out of sequence.`);
  }
  return errors;
}

function validatePrerequisiteEvidence(
  record,
  descriptor,
  expectedId,
  kind,
  auditedCommit,
  approvedAt,
  options,
) {
  const errors = [];
  const {
    isRegularFile,
    readText,
    readAtCommit,
    readAtProtectedMain,
    isPathImmutableOnProtectedMain,
    pathIntroductionTime,
    planIssuedAt,
    now,
  } = options;
  const isEvidence = kind === "evidence";
  const label = isEvidence ? "evidence" : "rollback evidence";
  const pathField = isEvidence ? "evidenceRecord" : "rollbackRecord";
  const digestField = isEvidence ? "evidenceBinding" : "rollbackBinding";
  const folder = isEvidence ? "evidence" : "rollback";
  const recordPath = record[pathField] ?? "";
  const pathPattern = new RegExp(
    `^docs/governance/authorizations/prerequisites/${folder}/[A-Za-z0-9][A-Za-z0-9._-]*\\.json$`,
  );
  if (!pathPattern.test(recordPath) || !isRegularFile(recordPath))
    return [`V1D-SV ${expectedId} prerequisite lacks immutable ${label}.`];
  if (!/^sha256:[a-f0-9]{64}$/.test(record[digestField] ?? ""))
    return [
      `V1D-SV ${expectedId} prerequisite has an invalid ${label} digest.`,
    ];

  const currentText = readText(recordPath);
  const approvedText = readAtCommit(auditedCommit, recordPath);
  if (typeof currentText !== "string" || typeof approvedText !== "string")
    return [
      `V1D-SV ${expectedId} prerequisite ${label} is absent from the audited commit.`,
    ];
  if (normalizeText(currentText) !== normalizeText(approvedText))
    errors.push(
      `V1D-SV ${expectedId} prerequisite ${label} changed after approval.`,
    );
  errors.push(
    ...validateProtectedMainContinuity(
      `V1D-SV ${expectedId} prerequisite ${label}`,
      recordPath,
      approvedText,
      readAtProtectedMain,
      isPathImmutableOnProtectedMain,
      auditedCommit,
    ),
    ...validatePathPredatesPlan(
      `V1D-SV ${expectedId} prerequisite ${label}`,
      recordPath,
      planIssuedAt,
      pathIntroductionTime,
    ),
  );
  if (sha256(approvedText) !== record[digestField])
    errors.push(
      `V1D-SV ${expectedId} prerequisite ${label} digest mismatches.`,
    );

  const receipt = parseCanonicalJson(approvedText);
  if (!receipt)
    return [
      ...errors,
      `V1D-SV ${expectedId} prerequisite ${label} is not canonical duplicate-free JSON.`,
    ];
  const expectedStatus = isEvidence
    ? "ProvisionedAndVerified"
    : "RollbackVerified";
  if (
    receipt.schemaVersion !== 1 ||
    receipt.prerequisiteId !== expectedId ||
    receipt.status !== expectedStatus
  )
    errors.push(
      `V1D-SV ${expectedId} prerequisite ${label} has invalid scope or status.`,
    );
  if (receipt.approver !== "Beowxlf")
    errors.push(
      `V1D-SV ${expectedId} prerequisite ${label} lacks owner approval.`,
    );
  const verifiedAt = validDate(receipt.verifiedAt);
  if (verifiedAt === null || verifiedAt > now.getTime())
    errors.push(
      `V1D-SV ${expectedId} prerequisite ${label} verification time is invalid.`,
    );
  if (verifiedAt !== null && approvedAt !== null && verifiedAt >= approvedAt)
    errors.push(
      `V1D-SV ${expectedId} prerequisite ${label} was verified after approval.`,
    );
  errors.push(
    ...validateClaimAtIntroduction(
      `V1D-SV ${expectedId} prerequisite ${label}`,
      recordPath,
      verifiedAt,
      pathIntroductionTime,
    ),
  );
  const requiredBindings = isEvidence
    ? [
        "targetBinding",
        "identityBinding",
        "flowBinding",
        "provisionReceiptDigest",
        "verificationReceiptDigest",
        ...(expectedId === NETWORK_DEPENDENCY_ID
          ? [
              "changeApprovalBinding",
              "applyReceiptDigest",
              "allowTestReceiptDigest",
              "denyTestReceiptDigest",
            ]
          : []),
      ]
    : ["procedureBinding", "recoveryEvidenceBinding"];
  const approvedScope = isEvidence
    ? descriptor?.evidenceScope
    : descriptor?.rollbackScope;
  for (const field of requiredBindings) {
    if (!/^sha256:[a-f0-9]{64}$/.test(receipt[field] ?? ""))
      errors.push(
        `V1D-SV ${expectedId} prerequisite ${label} lacks scoped ${field}.`,
      );
    if (receipt[field] !== approvedScope?.[field])
      errors.push(
        `V1D-SV ${expectedId} prerequisite ${label} ${field} mismatches its approved scope.`,
      );
  }
  if (isEvidence && expectedId === NETWORK_DEPENDENCY_ID)
    errors.push(
      ...validateNetworkEvidenceArtifacts(
        receipt,
        auditedCommit,
        verifiedAt,
        options,
      ),
    );
  return errors;
}

function validatePrerequisite(
  descriptor,
  expectedId,
  expectedStatus,
  auditedCommit,
  options,
) {
  const errors = [];
  const {
    isRegularFile,
    readText,
    readAtCommit,
    readAtProtectedMain,
    isPathImmutableOnProtectedMain,
    pathIntroductionTime,
    now,
    authorityExpiresAt,
    planIssuedAt,
    bindingsApprovedAt,
    allowExpired = false,
  } = options;
  const recordPath = descriptor?.record ?? "";
  if (
    !/^docs\/governance\/authorizations\/prerequisites\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/.test(
      recordPath,
    ) ||
    !isRegularFile(recordPath)
  )
    return [`V1D-SV lacks the ${expectedId} prerequisite record.`];
  if (!/^sha256:[a-f0-9]{64}$/.test(descriptor?.digest ?? ""))
    return [`V1D-SV ${expectedId} prerequisite has an invalid digest.`];

  const currentText = readText(recordPath);
  const approvedText = readAtCommit(auditedCommit, recordPath);
  if (typeof currentText !== "string" || typeof approvedText !== "string")
    return [
      `V1D-SV ${expectedId} prerequisite is absent from the audited commit.`,
    ];
  if (normalizeText(currentText) !== normalizeText(approvedText))
    errors.push(`V1D-SV ${expectedId} prerequisite changed after approval.`);
  errors.push(
    ...validateProtectedMainContinuity(
      `V1D-SV ${expectedId} prerequisite`,
      recordPath,
      approvedText,
      readAtProtectedMain,
      isPathImmutableOnProtectedMain,
      auditedCommit,
    ),
    ...validatePathPredatesPlan(
      `V1D-SV ${expectedId} prerequisite`,
      recordPath,
      planIssuedAt,
      pathIntroductionTime,
    ),
  );
  if (sha256(approvedText) !== descriptor.digest)
    errors.push(`V1D-SV ${expectedId} prerequisite digest mismatches.`);

  const record = parseCanonicalJson(approvedText);
  if (!record)
    return [
      ...errors,
      `V1D-SV ${expectedId} prerequisite is not canonical duplicate-free JSON.`,
    ];
  if (
    record.schemaVersion !== 1 ||
    record.id !== expectedId ||
    record.status !== expectedStatus
  )
    errors.push(
      `V1D-SV ${expectedId} prerequisite has invalid identity or status.`,
    );
  if (record.approver !== "Beowxlf")
    errors.push(`V1D-SV ${expectedId} prerequisite lacks owner approval.`);
  const approvedAt = validDate(record.approvedAt);
  const expiresAt = validDate(record.expiresAt);
  if (approvedAt === null || approvedAt > now.getTime())
    errors.push(`V1D-SV ${expectedId} prerequisite approval time is invalid.`);
  errors.push(
    ...validateClaimAtIntroduction(
      `V1D-SV ${expectedId} prerequisite`,
      recordPath,
      approvedAt,
      pathIntroductionTime,
    ),
  );
  if (
    approvedAt !== null &&
    planIssuedAt !== null &&
    approvedAt >= planIssuedAt
  )
    errors.push(
      `V1D-SV ${expectedId} prerequisite approval must precede Factory plan issuance.`,
    );
  if (
    approvedAt !== null &&
    bindingsApprovedAt !== null &&
    approvedAt >= bindingsApprovedAt
  )
    errors.push(
      `V1D-SV ${expectedId} prerequisite approval must precede bindings approval.`,
    );
  if (expiresAt === null || (!allowExpired && expiresAt <= now.getTime()))
    errors.push(`V1D-SV ${expectedId} prerequisite is invalid or expired.`);
  if (
    expiresAt !== null &&
    authorityExpiresAt !== null &&
    authorityExpiresAt > expiresAt
  )
    errors.push(
      `V1D-SV authorization outlives the ${expectedId} prerequisite.`,
    );
  errors.push(
    ...validatePrerequisiteEvidence(
      record,
      descriptor,
      expectedId,
      "evidence",
      auditedCommit,
      approvedAt,
      options,
    ),
    ...validatePrerequisiteEvidence(
      record,
      descriptor,
      expectedId,
      "rollback",
      auditedCommit,
      approvedAt,
      options,
    ),
  );
  if (expectedId === "V1C") {
    if (!/^sha256:[a-f0-9]{64}$/.test(record.releaseDigest ?? ""))
      errors.push("V1D-SV V1C pass record has an invalid release digest.");
    if (record.releaseDigest !== options.authorizedReleaseDigest)
      errors.push(
        "V1D-SV V1C pass record release digest mismatches the authorized signed release.",
      );
    const controls = record.controls;
    if (
      !Array.isArray(controls) ||
      controls.length !== REQUIRED_V1C_CONTROLS.length ||
      new Set(controls).size !== REQUIRED_V1C_CONTROLS.length
    )
      errors.push("V1D-SV V1C pass record has an invalid control set.");
    for (const control of REQUIRED_V1C_CONTROLS) {
      if (!Array.isArray(controls) || !controls.includes(control))
        errors.push(`V1D-SV V1C pass record lacks control: ${control}.`);
    }
  }
  if (expectedId === NETWORK_DEPENDENCY_ID) {
    if (
      descriptor?.evidenceScope?.targetBinding !==
      options.authorizedServerBinding
    )
      errors.push(
        "V1D-SV network target scope mismatches the authorized server binding.",
      );
    if (
      descriptor?.evidenceScope?.flowBinding !==
      options.authorizedNetworkPolicyBinding
    )
      errors.push(
        "V1D-SV network flow scope mismatches the authorized private network policy.",
      );
  }
  return errors;
}

function validatePrerequisites(approval, auditedCommit, options) {
  const errors = validatePrerequisite(
    approval.prerequisites?.v1c,
    "V1C",
    "Passed",
    auditedCommit,
    options,
  );
  const dependencies = approval.prerequisites?.dependencies;
  if (!Array.isArray(dependencies))
    return [...errors, "V1D-SV lacks separate external dependency approvals."];
  const ids = dependencies.map((item) => item?.id);
  if (
    ids.length !== EXPECTED_DEPENDENCY_IDS.length ||
    new Set(ids).size !== EXPECTED_DEPENDENCY_IDS.length
  )
    errors.push(
      "V1D-SV external dependency approval set is incomplete or duplicated.",
    );
  if (!EXPECTED_DEPENDENCY_IDS.every((id, index) => ids[index] === id))
    errors.push("V1D-SV external dependency approval set is out of order.");
  if (
    canonicalJsonDigest(dependencies) !==
    options.authorizedExternalDependencySetBinding
  )
    errors.push(
      "V1D-SV external dependency set mismatches its authorized aggregate binding.",
    );
  for (const expectedId of EXPECTED_DEPENDENCY_IDS) {
    errors.push(
      ...validatePrerequisite(
        dependencies.find((item) => item?.id === expectedId),
        expectedId,
        "Approved",
        auditedCommit,
        options,
      ),
    );
  }
  return errors;
}

function validateApprovedBindings(
  fields,
  auditedCommit,
  {
    isRegularFile,
    readText,
    readAtCommit,
    readAtProtectedMain,
    isPathImmutableOnProtectedMain,
    isPathIntroducedBefore,
    pathIntroductionTime,
    verifyFactoryReceiptSignature,
    now,
    allowExpired = false,
  },
) {
  const errors = [];
  const recordPath = fields.get("Approved bindings record") ?? "";
  if (
    !/^docs\/governance\/authorizations\/bindings\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/.test(
      recordPath,
    ) ||
    !isRegularFile(recordPath)
  ) {
    return ["V1D-SV lacks its exact approved bindings record."];
  }

  const currentText = readText(recordPath);
  const approvedText = readAtCommit(auditedCommit, recordPath);
  if (
    typeof currentText !== "string" ||
    typeof approvedText !== "string" ||
    approvedText.trim() === ""
  ) {
    return ["V1D-SV approved bindings are absent from the audited commit."];
  }
  if (normalizeText(currentText) !== normalizeText(approvedText))
    errors.push("V1D-SV approved bindings changed after the audited commit.");
  errors.push(
    ...validateProtectedMainContinuity(
      "V1D-SV approved bindings",
      recordPath,
      approvedText,
      readAtProtectedMain,
      isPathImmutableOnProtectedMain,
      auditedCommit,
    ),
  );

  const approval = parseCanonicalJson(approvedText);
  if (!approval)
    return [
      ...errors,
      "V1D-SV approved bindings are not canonical duplicate-free JSON.",
    ];
  if (approval.schemaVersion !== 1)
    errors.push("V1D-SV approved bindings have an invalid schema version.");
  if (approval.authority !== "V1D-SV" || approval.status !== "Approved")
    errors.push("V1D-SV approved bindings have the wrong authority or status.");
  if (approval.approver !== "Beowxlf")
    errors.push("V1D-SV approved bindings lack project owner approval.");

  const approvedAt = validDate(approval.approvedAt);
  const bindingsExpireAt = validDate(approval.expiresAt);
  const issuedAt = validDate(fields.get("Issued at"));
  const authorizationExpiresAt = validDate(fields.get("Expires at"));
  const bindingsIntroducedAt = Date.parse(
    pathIntroductionTime(recordPath) ?? "",
  );
  if (
    !Number.isFinite(bindingsIntroducedAt) ||
    issuedAt === null ||
    bindingsIntroducedAt >= issuedAt
  )
    errors.push(
      "V1D-SV approved bindings introduction must predate authorization issuance.",
    );
  if (approvedAt !== null && approvedAt > bindingsIntroducedAt)
    errors.push(
      "V1D-SV approved bindings claimed approval postdates protected-main introduction.",
    );
  if (approvedAt === null || approvedAt > now.getTime())
    errors.push("V1D-SV bindings approval time is invalid or in the future.");
  if (
    bindingsExpireAt === null ||
    (!allowExpired && bindingsExpireAt <= now.getTime())
  )
    errors.push("V1D-SV approved bindings are invalid or expired.");
  if (
    approvedAt !== null &&
    bindingsExpireAt !== null &&
    bindingsExpireAt - approvedAt > MAX_BINDINGS_LIFETIME_MS
  )
    errors.push(
      "V1D-SV approved bindings exceed the seven-day lifetime limit.",
    );
  if (approvedAt !== null && issuedAt !== null && approvedAt >= issuedAt)
    errors.push("V1D-SV authorization predates its approved bindings.");
  const planApprovedAt = validDate(fields.get("Factory plan approved at"));
  if (
    approvedAt !== null &&
    planApprovedAt !== null &&
    approvedAt <= planApprovedAt
  )
    errors.push("V1D-SV bindings approval must follow Factory plan approval.");
  if (
    bindingsExpireAt !== null &&
    authorizationExpiresAt !== null &&
    authorizationExpiresAt > bindingsExpireAt
  )
    errors.push("V1D-SV authorization outlives its approved bindings.");

  for (const field of APPROVED_BINDING_FIELDS) {
    if (approval.bindings?.[field] !== fields.get(field))
      errors.push(`V1D-SV ${field} mismatches its approved binding.`);
  }
  errors.push(
    ...validateFactoryPlanReceipt(fields, auditedCommit, {
      isRegularFile,
      readText,
      readAtCommit,
      readAtProtectedMain,
      isPathImmutableOnProtectedMain,
      isPathIntroducedBefore,
      pathIntroductionTime,
      verifyFactoryReceiptSignature,
    }),
  );
  errors.push(
    ...validatePrerequisites(approval, auditedCommit, {
      isRegularFile,
      readText,
      readAtCommit,
      readAtProtectedMain,
      isPathImmutableOnProtectedMain,
      pathIntroductionTime,
      now,
      authorityExpiresAt: authorizationExpiresAt,
      planIssuedAt: validDate(fields.get("Factory plan issued at")),
      bindingsApprovedAt: approvedAt,
      allowExpired,
      authorizedReleaseDigest: fields.get("Signed release digest"),
      authorizedServerBinding: fields.get("Server binding"),
      authorizedNetworkPolicyBinding: fields.get(
        "Private network policy binding",
      ),
      authorizedExternalDependencySetBinding: fields.get(
        "External dependency set binding",
      ),
    }),
  );
  return errors;
}

function validateFactoryPlanReceipt(fields, auditedCommit, options) {
  const errors = [];
  const {
    isRegularFile,
    readText,
    readAtCommit,
    readAtProtectedMain,
    isPathImmutableOnProtectedMain,
    isPathIntroducedBefore,
    pathIntroductionTime,
    verifyFactoryReceiptSignature,
  } = options;
  const receiptPath = fields.get("Factory plan receipt") ?? "";
  if (
    !/^docs\/governance\/authorizations\/factory-receipts\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/.test(
      receiptPath,
    ) ||
    !isRegularFile(receiptPath)
  ) {
    return ["V1D-SV lacks its immutable Factory plan approval receipt."];
  }

  const currentText = readText(receiptPath);
  const approvedText = readAtCommit(auditedCommit, receiptPath);
  if (typeof currentText !== "string" || typeof approvedText !== "string")
    return ["V1D-SV Factory plan receipt is absent from the audited commit."];
  if (normalizeText(currentText) !== normalizeText(approvedText))
    errors.push("V1D-SV Factory plan receipt changed after approval.");
  errors.push(
    ...validateProtectedMainContinuity(
      "V1D-SV Factory plan receipt",
      receiptPath,
      approvedText,
      readAtProtectedMain,
      isPathImmutableOnProtectedMain,
      auditedCommit,
    ),
  );
  if (sha256(approvedText) !== fields.get("Factory plan receipt digest"))
    errors.push("V1D-SV Factory plan receipt digest mismatches.");

  const signaturePath = fields.get("Factory plan receipt signature") ?? "";
  const trustPath = fields.get("Factory approval trust record") ?? "";
  if (
    !/^docs\/governance\/authorizations\/factory-receipts\/[A-Za-z0-9][A-Za-z0-9._-]*\.cms\.pem$/.test(
      signaturePath,
    ) ||
    !isRegularFile(signaturePath)
  )
    errors.push("V1D-SV lacks its Factory receipt CMS signature.");
  if (
    !/^docs\/governance\/trust\/vm-factory\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/.test(
      trustPath,
    ) ||
    !isRegularFile(trustPath)
  )
    errors.push("V1D-SV lacks its pinned Factory approval trust record.");
  if (
    isRegularFile(receiptPath) &&
    isRegularFile(trustPath) &&
    !isPathIntroducedBefore(trustPath, receiptPath)
  )
    errors.push(
      "V1D-SV Factory approval trust must be pinned in an earlier protected-main change.",
    );
  const trustIntroductionAt = Date.parse(pathIntroductionTime(trustPath) ?? "");
  const authenticatedPlanIssuedAt = validDate(
    fields.get("Factory plan issued at"),
  );
  if (
    !Number.isFinite(trustIntroductionAt) ||
    authenticatedPlanIssuedAt === null ||
    trustIntroductionAt >= authenticatedPlanIssuedAt
  )
    errors.push(
      "V1D-SV Factory approval trust introduction must predate authenticated plan issuance.",
    );

  const signatureText = isRegularFile(signaturePath)
    ? readAtCommit(auditedCommit, signaturePath)
    : null;
  const trustText = isRegularFile(trustPath)
    ? readAtCommit(auditedCommit, trustPath)
    : null;
  if (typeof signatureText !== "string")
    errors.push(
      "V1D-SV Factory receipt signature is absent from the audited commit.",
    );
  if (typeof trustText !== "string")
    errors.push(
      "V1D-SV Factory approval trust record is absent from the audited commit.",
    );
  for (const [label, path, approvedArtifact] of [
    ["V1D-SV Factory receipt signature", signaturePath, signatureText],
    ["V1D-SV Factory approval trust record", trustPath, trustText],
  ]) {
    if (typeof approvedArtifact !== "string" || !isRegularFile(path)) continue;
    const currentArtifact = readText(path);
    if (
      typeof currentArtifact !== "string" ||
      normalizeText(currentArtifact) !== normalizeText(approvedArtifact)
    )
      errors.push(`${label} changed after approval.`);
    errors.push(
      ...validateProtectedMainContinuity(
        label,
        path,
        approvedArtifact,
        readAtProtectedMain,
        isPathImmutableOnProtectedMain,
        auditedCommit,
      ),
    );
  }
  if (
    typeof signatureText === "string" &&
    sha256(signatureText) !==
      fields.get("Factory plan receipt signature digest")
  )
    errors.push("V1D-SV Factory receipt signature digest mismatches.");
  if (
    typeof trustText === "string" &&
    sha256(trustText) !== fields.get("Factory approval trust record digest")
  )
    errors.push("V1D-SV Factory approval trust record digest mismatches.");

  const trust =
    typeof trustText === "string" ? parseCanonicalJson(trustText) : null;
  if (!trust) {
    errors.push(
      "V1D-SV Factory approval trust record is not canonical duplicate-free JSON.",
    );
  } else {
    if (
      !hasExactUniqueEntries(Object.keys(trust), FACTORY_APPROVAL_TRUST_FIELDS)
    )
      errors.push(
        "V1D-SV Factory approval trust record has an invalid field set.",
      );
    if (
      trust.schemaVersion !== 1 ||
      trust.trustPurpose !== "NorthGate VM Factory plan approval signer" ||
      trust.status !== "Pinned" ||
      trust.approver !== "Beowxlf"
    )
      errors.push(
        "V1D-SV Factory approval signer is not independently pinned.",
      );
    const trustApprovedAt = validDate(trust.approvedAt);
    const planIssuedAt = validDate(fields.get("Factory plan issued at"));
    if (
      trustApprovedAt === null ||
      planIssuedAt === null ||
      trustApprovedAt >= planIssuedAt
    )
      errors.push("V1D-SV Factory approval trust must predate plan issuance.");
    if (trustApprovedAt !== null && trustApprovedAt > trustIntroductionAt)
      errors.push(
        "V1D-SV Factory approval trust claimed approval postdates protected-main introduction.",
      );
    if (!/^sha256:[a-f0-9]{64}$/.test(trust.certificateSha256 ?? ""))
      errors.push(
        "V1D-SV Factory approval trust has an invalid certificate digest.",
      );
    if (
      typeof signatureText === "string" &&
      !verifyFactoryReceiptSignature(
        approvedText,
        signatureText,
        trust.certificateSha256,
        pathIntroductionTime(receiptPath),
        pathIntroductionTime(signaturePath),
      )
    )
      errors.push(
        "V1D-SV Factory plan receipt signature is invalid for the pinned signer.",
      );
  }

  const receipt = parseCanonicalJson(approvedText);
  if (!receipt) {
    errors.push(
      "V1D-SV Factory plan receipt is not canonical duplicate-free JSON.",
    );
    return errors;
  }
  if (!hasExactUniqueEntries(Object.keys(receipt), FACTORY_PLAN_RECEIPT_FIELDS))
    errors.push("V1D-SV Factory plan receipt has an invalid field set.");
  if (receipt.schemaVersion !== 1)
    errors.push("V1D-SV Factory plan receipt has an invalid schema version.");
  if (
    receipt.receiptType !== "PlanApprovalReceipt" ||
    receipt.issuer !== "NorthGate VM Factory" ||
    receipt.status !== "Approved"
  )
    errors.push("V1D-SV Factory plan receipt lacks Factory-issued approval.");

  const bindings = [
    ["planId", "Factory plan ID"],
    ["authenticatedStateHash", "Authenticated state hash"],
    ["issuedAt", "Factory plan issued at"],
    ["approvedAt", "Factory plan approved at"],
    ["expiresAt", "Factory plan expires at"],
    ["approver", "Factory plan approver"],
    ["targetBinding", "Server binding"],
  ];
  for (const [receiptField, authorityField] of bindings) {
    if (receipt[receiptField] !== fields.get(authorityField))
      errors.push(
        `V1D-SV Factory plan receipt ${receiptField} mismatches the authorized ${authorityField}.`,
      );
  }
  return errors;
}

function validateRecord(text, options) {
  const errors = [];
  const {
    now,
    isCommit,
    isProtectedMainCommit,
    allowExpired = false,
  } = options;
  const { fields, duplicates } = parseRecord(text);
  for (const field of duplicates)
    errors.push(`V1D-SV authorization record duplicates ${field}.`);
  for (const field of REQUIRED_RECORD_FIELDS) {
    const value = fields.get(field);
    if (!value || /\b(?:TBD|TODO|CHANGEME|PLACEHOLDER)\b/i.test(value))
      errors.push(`V1D-SV authorization record lacks exact ${field}.`);
  }

  if (fields.get("Authority") !== "V1D-SV")
    errors.push("V1D-SV authorization record has the wrong authority ID.");
  if (fields.get("Status") !== "Authorized")
    errors.push("V1D-SV authorization record is not Authorized.");
  if (fields.get("Approver") !== "Beowxlf")
    errors.push(
      "V1D-SV authorization record lacks the project owner approver.",
    );
  if (fields.get("Factory plan approver") !== "Beowxlf")
    errors.push("V1D-SV Factory plan lacks post-issuance owner approval.");
  const auditedCommit = fields.get("Audited commit") ?? "";
  if (!/^[a-f0-9]{40}$/.test(auditedCommit))
    errors.push("V1D-SV authorization record has an invalid audited commit.");
  else if (!isCommit(auditedCommit))
    errors.push(
      "V1D-SV authorization record audited commit is not in the repository.",
    );
  else if (!isProtectedMainCommit(auditedCommit))
    errors.push(
      "V1D-SV authorization record audited commit is not on protected main.",
    );
  if (!/^ngp-[a-f0-9]{64}$/.test(fields.get("Factory plan ID") ?? ""))
    errors.push("V1D-SV authorization record has an invalid Factory plan ID.");
  for (const field of DIGEST_FIELDS) {
    if (!/^sha256:[a-f0-9]{64}$/.test(fields.get(field) ?? ""))
      errors.push(`V1D-SV authorization record has an invalid ${field}.`);
  }
  if (fields.get("Endpoint routes") !== "blocked")
    errors.push(
      "V1D-SV authorization record must keep endpoint routes blocked.",
    );

  const issuedAt = validDate(fields.get("Issued at"));
  const expiresAt = validDate(fields.get("Expires at"));
  const planIssuedAt = validDate(fields.get("Factory plan issued at"));
  const planApprovedAt = validDate(fields.get("Factory plan approved at"));
  const planExpiresAt = validDate(fields.get("Factory plan expires at"));
  if (issuedAt === null)
    errors.push("V1D-SV authorization record has an invalid issue time.");
  if (expiresAt === null)
    errors.push("V1D-SV authorization record has an invalid expiry.");
  if (planIssuedAt === null)
    errors.push("V1D-SV Factory plan has an invalid issue time.");
  if (planApprovedAt === null)
    errors.push("V1D-SV Factory plan has an invalid approval time.");
  if (planExpiresAt === null)
    errors.push("V1D-SV Factory plan has an invalid expiry.");
  if (issuedAt !== null && expiresAt !== null && expiresAt <= issuedAt)
    errors.push("V1D-SV authorization expiry must follow issuance.");
  if (
    issuedAt !== null &&
    expiresAt !== null &&
    expiresAt - issuedAt > MAX_AUTHORITY_LIFETIME_MS
  )
    errors.push("V1D-SV authorization exceeds the 24-hour lifetime limit.");
  if (!allowExpired && expiresAt !== null && expiresAt <= now.getTime())
    errors.push("V1D-SV authorization record is expired.");
  if (issuedAt !== null && issuedAt > now.getTime())
    errors.push("V1D-SV authorization issue time is in the future.");
  if (planIssuedAt !== null && planIssuedAt > now.getTime())
    errors.push("V1D-SV Factory plan issue time is in the future.");
  if (
    !allowExpired &&
    planIssuedAt !== null &&
    now.getTime() - planIssuedAt > MAX_PLAN_AGE_MS
  )
    errors.push("V1D-SV Factory plan is stale.");
  if (planApprovedAt !== null && planApprovedAt > now.getTime())
    errors.push("V1D-SV Factory plan approval time is in the future.");
  if (!allowExpired && planExpiresAt !== null && planExpiresAt <= now.getTime())
    errors.push("V1D-SV Factory plan is expired.");
  if (
    planIssuedAt !== null &&
    planApprovedAt !== null &&
    planApprovedAt <= planIssuedAt
  )
    errors.push("V1D-SV Factory plan approval must follow plan issuance.");
  if (
    planApprovedAt !== null &&
    planExpiresAt !== null &&
    planExpiresAt <= planApprovedAt
  )
    errors.push("V1D-SV Factory plan expiry must follow plan approval.");
  if (
    planIssuedAt !== null &&
    planExpiresAt !== null &&
    planExpiresAt - planIssuedAt > MAX_PLAN_LIFETIME_MS
  )
    errors.push("V1D-SV Factory plan exceeds the 24-hour lifetime limit.");
  if (
    issuedAt !== null &&
    planApprovedAt !== null &&
    issuedAt <= planApprovedAt
  )
    errors.push(
      "V1D-SV authorization must be issued after Factory plan approval.",
    );
  if (
    expiresAt !== null &&
    planApprovedAt !== null &&
    planApprovedAt >= expiresAt
  )
    errors.push("V1D-SV Factory plan approval must precede authority expiry.");
  if (expiresAt !== null && planExpiresAt !== null && expiresAt > planExpiresAt)
    errors.push("V1D-SV authorization outlives its Factory plan.");
  if (
    expiresAt !== null &&
    planIssuedAt !== null &&
    expiresAt > planIssuedAt + MAX_PLAN_AGE_MS
  )
    errors.push(
      "V1D-SV authorization outlives the Factory plan freshness window.",
    );

  if (
    /^[a-f0-9]{40}$/.test(auditedCommit) &&
    isCommit(auditedCommit) &&
    isProtectedMainCommit(auditedCommit)
  )
    errors.push(...validateApprovedBindings(fields, auditedCommit, options));

  return errors;
}

export function validateV1dAuthority(
  gates,
  {
    isRegularFile = () => false,
    readText = () => null,
    readAtCommit = () => null,
    readAtProtectedMain = () => null,
    isPathImmutableOnProtectedMain = () => false,
    isPathIntroducedBefore = () => false,
    pathIntroductionTime = () => null,
    verifyFactoryReceiptSignature = () => false,
    isCommit = () => false,
    isProtectedMainCommit = () => false,
    protectedMainPathVersionCount = () => null,
    authorityOpenIntroductionTime = () => null,
    gateOpenIntroductionTime = () => null,
    now = new Date(),
  } = {},
) {
  const errors = [];
  const authorities = gates.boundedOperationalAuthorizations ?? [];
  const authorityIds = authorities.map((authority) => authority.id);
  if (new Set(authorityIds).size !== authorityIds.length)
    errors.push("Duplicate bounded operational authority ID.");
  for (const authorityId of authorityIds) {
    if (authorityId !== "V1D-SV")
      errors.push(`Unknown bounded operational authority ID: ${authorityId}.`);
  }

  const authority = authorities.find((item) => item.id === "V1D-SV");
  if (!authority) {
    errors.push("Missing bounded V1D-SV control-plane validation authority.");
    return errors;
  }

  if (authority.phase !== 2) errors.push("V1D-SV must remain within Phase 2.");
  if (authority.opensGate !== false)
    errors.push("V1D-SV must not open a product gate.");
  if (
    !hasExactUniqueEntries(authority.requiresClosedGates, REQUIRED_CLOSED_GATES)
  )
    errors.push("V1D-SV must require G2 through G8 to remain closed.");
  if (!["open", "closing", "closed"].includes(authority.status))
    errors.push("Invalid status for V1D-SV.");

  if (!hasExactUniqueEntries(authority.requirements, REQUIRED_REQUIREMENTS))
    errors.push("V1D-SV has an invalid prerequisite set.");
  for (const requirement of REQUIRED_REQUIREMENTS) {
    if (
      !Array.isArray(authority.requirements) ||
      !authority.requirements.includes(requirement)
    )
      errors.push(`V1D-SV lacks required prerequisite: ${requirement}.`);
  }
  if (!hasExactUniqueEntries(authority.prohibitions, REQUIRED_PROHIBITIONS))
    errors.push("V1D-SV has an invalid prohibition set.");
  for (const prohibition of REQUIRED_PROHIBITIONS) {
    if (
      !Array.isArray(authority.prohibitions) ||
      !authority.prohibitions.includes(prohibition)
    )
      errors.push(`V1D-SV lacks required prohibition: ${prohibition}.`);
  }

  const priorAuthority = protectedMainAuthority(readAtProtectedMain);
  errors.push(
    ...validateV1dCloseoutHistory(authority, priorAuthority, {
      isRegularFile,
      readText,
      readAtProtectedMain,
      protectedMainPathVersionCount,
    }),
  );
  const currentCloseoutHistory = Array.isArray(authority.closeouts)
    ? authority.closeouts
    : [];
  const priorCloseoutHistory = Array.isArray(priorAuthority?.closeouts)
    ? priorAuthority.closeouts
    : [];
  const laterGateOpen = REQUIRED_CLOSED_GATES.some(
    (gateId) =>
      gates.gates?.find((item) => item.id === gateId)?.status === "open",
  );
  if (["open", "closing"].includes(authority.status)) {
    const authorization = authority.authorization;
    const validPath =
      typeof authorization === "string" &&
      /^docs\/governance\/authorizations\/[A-Za-z0-9][A-Za-z0-9._-]*\.md$/.test(
        authorization,
      );
    if (!validPath || !isRegularFile(authorization)) {
      errors.push(
        "Open V1D-SV authority lacks its exact regular authorization file.",
      );
    } else {
      const record = readText(authorization);
      if (typeof record !== "string" || record.trim() === "")
        errors.push(
          "Open V1D-SV authority has an unreadable authorization record.",
        );
      else {
        if (["open", "closing"].includes(priorAuthority?.status)) {
          const protectedRecord = readAtProtectedMain(
            priorAuthority.authorization,
          );
          if (authorization !== priorAuthority.authorization)
            errors.push(
              "Open V1D-SV must preserve its protected-main authorization path until closeout.",
            );
          if (
            typeof protectedRecord !== "string" ||
            normalizeText(record) !== normalizeText(protectedRecord)
          )
            errors.push(
              "Open V1D-SV must preserve its exact protected-main authorization bytes until closeout.",
            );
        }
        errors.push(
          ...validateRecord(record, {
            isRegularFile,
            readText,
            readAtCommit,
            readAtProtectedMain,
            isPathImmutableOnProtectedMain,
            isPathIntroducedBefore,
            pathIntroductionTime,
            verifyFactoryReceiptSignature,
            isCommit,
            isProtectedMainCommit,
            allowExpired: authority.status === "closing",
            now,
          }),
          ...validateReopen(authorization, record, priorAuthority, {
            isRegularFile,
            readText,
            readAtProtectedMain,
            protectedMainPathVersionCount,
          }),
        );
      }
    }
  }
  const enteringClosing =
    priorAuthority?.status === "open" && authority.status === "closing";
  if (
    authority.status === "closing" &&
    !["open", "closing"].includes(priorAuthority?.status)
  )
    errors.push("V1D-SV closing state requires a preceding open lifecycle.");
  if (
    enteringClosing &&
    (authority.authorization !== priorAuthority.authorization ||
      currentCloseoutHistory.length !== priorCloseoutHistory.length ||
      Object.hasOwn(authority, "closeout"))
  )
    errors.push(
      "V1D-SV closing transition must freeze the active authorization before cleanup.",
    );
  if (priorAuthority?.status === "closing" && authority.status === "open")
    errors.push("V1D-SV closing state cannot restore operational authority.");
  if (priorAuthority?.status === "open" && authority.status === "closed")
    errors.push(
      "V1D-SV must enter a non-consumable closing state before cleanup.",
    );
  const requiresCloseout =
    authority.status === "closed" &&
    (priorAuthority?.status === "closing" ||
      priorAuthority?.closeout ||
      laterGateOpen);
  if (
    authority.status === "closed" &&
    priorAuthority?.status === "closing" &&
    (currentCloseoutHistory.length !== priorCloseoutHistory.length + 1 ||
      authority.closeout !== currentCloseoutHistory.at(-1))
  )
    errors.push("V1D-SV closeout must append exactly one lifecycle tombstone.");
  if (
    !(authority.status === "closed" && priorAuthority?.status === "closing") &&
    currentCloseoutHistory.length !== priorCloseoutHistory.length
  )
    errors.push(
      "V1D-SV lifecycle history may change only during verified closeout.",
    );
  if (
    authority.status === "closed" &&
    priorAuthority?.status === "closed" &&
    priorAuthority.closeout &&
    authority.closeout !== priorAuthority.closeout
  )
    errors.push(
      "Closed V1D-SV must preserve its consumed-lifecycle closeout tombstone.",
    );
  if (authority.status === "closed" && (requiresCloseout || authority.closeout))
    errors.push(
      ...validateCloseout(authority, priorAuthority, laterGateOpen, {
        isRegularFile,
        readText,
        readAtProtectedMain,
        protectedMainPathVersionCount,
        pathIntroductionTime,
        authorityOpenIntroductionTime,
        now,
      }),
    );
  for (const gateId of REQUIRED_CLOSED_GATES) {
    const gate = gates.gates?.find((item) => item.id === gateId);
    const priorGate = protectedMainGate(readAtProtectedMain, gateId);
    if (gate)
      errors.push(
        ...validateProductGateLifecycle(gate, priorGate, {
          isRegularFile,
          readText,
          readAtCommit,
          readAtProtectedMain,
          isPathImmutableOnProtectedMain,
          isPathIntroducedBefore,
          pathIntroductionTime,
          gateOpenIntroductionTime,
          protectedMainPathVersionCount,
          isCommit,
          isProtectedMainCommit,
          now,
        }),
      );
    if (
      ["open", "closing"].includes(authority.status) &&
      gate?.status !== "closed"
    )
      errors.push(`V1D-SV and ${gateId} cannot be open at the same time.`);
    if (gate?.status === "open" || gate?.status === "closing")
      errors.push(
        ...validateProductGateAuthorization(gate, {
          isRegularFile,
          readText,
          readAtCommit,
          readAtProtectedMain,
          isPathImmutableOnProtectedMain,
          isPathIntroducedBefore,
          pathIntroductionTime,
          protectedMainPathVersionCount,
          isCommit,
          isProtectedMainCommit,
          allowExpired: gate.status === "closing",
          now,
        }),
      );
  }

  return errors;
}
