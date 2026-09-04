import { createHash } from "node:crypto";

const REQUIRED_REQUIREMENTS = [
  "V1C production release trust pass",
  "separately approved and verified external V1D dependencies",
  "exact named private control-plane server and signed release",
  "fresh host-issued Factory plan and post-issuance owner approval",
  "synthetic-only identities and blocked endpoint routes",
  "expiry, rollback, recovery, and evidence boundaries",
];

const REQUIRED_PROHIBITIONS = [
  "endpoint package installation",
  "endpoint-usable enrollment grant or identity",
  "canary or other endpoint traffic",
  "artifact publication or update",
  "opening G2",
];

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
const EXPECTED_DEPENDENCY_IDS = [
  "V1D-DEP-DNS-TIME",
  "V1D-DEP-SERVER-PKI",
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
    now,
    authorityExpiresAt,
    planIssuedAt,
    bindingsApprovedAt,
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
  if (expiresAt === null || expiresAt <= now.getTime())
    errors.push(`V1D-SV ${expectedId} prerequisite is invalid or expired.`);
  if (
    expiresAt !== null &&
    authorityExpiresAt !== null &&
    authorityExpiresAt > expiresAt
  )
    errors.push(
      `V1D-SV authorization outlives the ${expectedId} prerequisite.`,
    );
  if (!/^sha256:[a-f0-9]{64}$/.test(record.evidenceBinding ?? ""))
    errors.push(
      `V1D-SV ${expectedId} prerequisite lacks its evidence binding.`,
    );
  if (!/^sha256:[a-f0-9]{64}$/.test(record.rollbackBinding ?? ""))
    errors.push(
      `V1D-SV ${expectedId} prerequisite lacks its rollback binding.`,
    );
  if (expectedId === "V1C") {
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
  { isRegularFile, readText, readAtCommit, now },
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
  if (approvedAt === null || approvedAt > now.getTime())
    errors.push("V1D-SV bindings approval time is invalid or in the future.");
  if (bindingsExpireAt === null || bindingsExpireAt <= now.getTime())
    errors.push("V1D-SV approved bindings are invalid or expired.");
  if (
    approvedAt !== null &&
    bindingsExpireAt !== null &&
    bindingsExpireAt - approvedAt > MAX_BINDINGS_LIFETIME_MS
  )
    errors.push(
      "V1D-SV approved bindings exceed the seven-day lifetime limit.",
    );
  if (approvedAt !== null && issuedAt !== null && approvedAt > issuedAt)
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
    ...validatePrerequisites(approval, auditedCommit, {
      isRegularFile,
      readText,
      readAtCommit,
      now,
      authorityExpiresAt: authorizationExpiresAt,
      planIssuedAt: validDate(fields.get("Factory plan issued at")),
      bindingsApprovedAt: approvedAt,
    }),
  );
  return errors;
}

function validateRecord(text, options) {
  const errors = [];
  const { now, isCommit, isProtectedMainCommit } = options;
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
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(
      fields.get("Factory plan ID") ?? "",
    )
  )
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
  if (expiresAt !== null && expiresAt <= now.getTime())
    errors.push("V1D-SV authorization record is expired.");
  if (issuedAt !== null && issuedAt > now.getTime())
    errors.push("V1D-SV authorization issue time is in the future.");
  if (planIssuedAt !== null && planIssuedAt > now.getTime())
    errors.push("V1D-SV Factory plan issue time is in the future.");
  if (planApprovedAt !== null && planApprovedAt > now.getTime())
    errors.push("V1D-SV Factory plan approval time is in the future.");
  if (planExpiresAt !== null && planExpiresAt <= now.getTime())
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
  if (issuedAt !== null && planApprovedAt !== null && issuedAt < planApprovedAt)
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
    isCommit = () => false,
    isProtectedMainCommit = () => false,
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
  if (!hasExactUniqueEntries(authority.requiresClosedGates, ["G2"]))
    errors.push("V1D-SV must require G2 to remain closed.");
  if (!["open", "closed"].includes(authority.status))
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

  if (authority.status === "open") {
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
      else
        errors.push(
          ...validateRecord(record, {
            isRegularFile,
            readText,
            readAtCommit,
            isCommit,
            isProtectedMainCommit,
            now,
          }),
        );
    }
  }
  const g2 = gates.gates?.find((gate) => gate.id === "G2");
  if (authority.status === "open" && g2?.status !== "closed")
    errors.push("V1D-SV and G2 cannot be open at the same time.");

  return errors;
}
