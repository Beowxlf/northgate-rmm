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

export function validateV1dAuthority(gates, exists = () => false) {
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

  if (authority.status === "open" && !exists(authority.authorization ?? ""))
    errors.push("Open V1D-SV authority lacks its exact authorization record.");
  const g2 = gates.gates?.find((gate) => gate.id === "G2");
  if (authority.status === "open" && g2?.status !== "closed")
    errors.push("V1D-SV and G2 cannot be open at the same time.");

  return errors;
}
