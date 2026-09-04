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
  "Issued at",
  "Expires at",
  "Server binding",
  "Signed release digest",
  "Factory plan ID",
  "Authenticated state hash",
  "Factory plan issued at",
  "Factory plan approved at",
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

function validDate(value) {
  if (!ISO_TIMESTAMP.test(value ?? "")) return null;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
}

function validateRecord(text, now, isCommit) {
  const errors = [];
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
  if (issuedAt === null)
    errors.push("V1D-SV authorization record has an invalid issue time.");
  if (expiresAt === null)
    errors.push("V1D-SV authorization record has an invalid expiry.");
  if (planIssuedAt === null)
    errors.push("V1D-SV Factory plan has an invalid issue time.");
  if (planApprovedAt === null)
    errors.push("V1D-SV Factory plan has an invalid approval time.");
  if (issuedAt !== null && expiresAt !== null && expiresAt <= issuedAt)
    errors.push("V1D-SV authorization expiry must follow issuance.");
  if (expiresAt !== null && expiresAt <= now.getTime())
    errors.push("V1D-SV authorization record is expired.");
  if (
    planIssuedAt !== null &&
    planApprovedAt !== null &&
    planApprovedAt <= planIssuedAt
  )
    errors.push("V1D-SV Factory plan approval must follow plan issuance.");
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

  return errors;
}

export function validateV1dAuthority(
  gates,
  {
    isRegularFile = () => false,
    readText = () => null,
    isCommit = () => false,
    now = new Date(),
  } = {},
) {
  const errors = [];
  const authorities = gates.boundedOperationalAuthorizations ?? [];
  const authorityIds = authorities.map((authority) => authority.id);
  if (new Set(authorityIds).size !== authorityIds.length)
    errors.push("Duplicate bounded operational authority ID.");

  const authority = authorities.find((item) => item.id === "V1D-SV");
  if (!authority) {
    errors.push("Missing bounded V1D-SV control-plane validation authority.");
    return errors;
  }

  if (authority.phase !== 2) errors.push("V1D-SV must remain within Phase 2.");
  if (authority.opensGate !== false)
    errors.push("V1D-SV must not open a product gate.");
  if (!authority.requiresClosedGates?.includes("G2"))
    errors.push("V1D-SV must require G2 to remain closed.");
  if (!["open", "closed"].includes(authority.status))
    errors.push("Invalid status for V1D-SV.");

  for (const requirement of REQUIRED_REQUIREMENTS) {
    if (!authority.requirements?.includes(requirement))
      errors.push(`V1D-SV lacks required prerequisite: ${requirement}.`);
  }
  for (const prohibition of REQUIRED_PROHIBITIONS) {
    if (!authority.prohibitions?.includes(prohibition))
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
      else errors.push(...validateRecord(record, now, isCommit));
    }
  }
  const g2 = gates.gates?.find((gate) => gate.id === "G2");
  if (authority.status === "open" && g2?.status !== "closed")
    errors.push("V1D-SV and G2 cannot be open at the same time.");

  return errors;
}
