# V1D-SV Authorization Record Template

Copy this template into `docs/governance/authorizations/` only after the Factory
has issued a fresh non-deployment plan and the owner has approved its exact plan
ID and authenticated state hash. Replace every placeholder. The governance
audit rejects an open `V1D-SV` authority if any required field is missing,
duplicated, malformed, expired, or still contains a placeholder.
The audited commit must resolve to an existing protected `main` commit. All
timestamps use real UTC calendar values in `YYYY-MM-DDTHH:MM:SSZ` form. The
authorization lifetime cannot exceed 24 hours, and the prior binding approval
lifetime cannot exceed seven days.

Exact private infrastructure facts remain in the protected evidence system.
Public fields ending in `binding` contain SHA-256 digests of the canonical
private records, not the sensitive facts themselves.

Authority: V1D-SV  
Status: Authorized  
Approver: Beowxlf  
Audited commit: PLACEHOLDER  
Approved bindings record: docs/governance/authorizations/bindings/PLACEHOLDER.json  
Issued at: PLACEHOLDER  
Expires at: PLACEHOLDER  
Server binding: sha256:PLACEHOLDER  
Signed release digest: sha256:PLACEHOLDER  
Factory plan ID: PLACEHOLDER  
Authenticated state hash: sha256:PLACEHOLDER  
Factory plan issued at: PLACEHOLDER  
Factory plan approved at: PLACEHOLDER  
Factory plan expires at: PLACEHOLDER  
Factory plan approver: Beowxlf  
External dependency set binding: sha256:PLACEHOLDER  
Service identity binding: sha256:PLACEHOLDER  
Database identity binding: sha256:PLACEHOLDER  
Synthetic identity profile binding: sha256:PLACEHOLDER  
Private network policy binding: sha256:PLACEHOLDER  
Endpoint routes: blocked  
Rollback binding: sha256:PLACEHOLDER  
Recovery binding: sha256:PLACEHOLDER  
Evidence boundary binding: sha256:PLACEHOLDER

The record authorizes only execution of the already approved Factory plan. It
does not authorize plan expansion, endpoint package installation,
endpoint-usable enrollment or identity material, canary or endpoint traffic,
artifact publication or update, or opening G2.

The approved-bindings JSON must be committed first. `Audited commit` identifies
the repository commit that already contains it. The governance audit loads that
exact historical file, requires the current content to remain identical, and
compares every operational field in this authorization with the approved value.
Use
[`V1D-SV-APPROVED-BINDINGS-TEMPLATE.json`](V1D-SV-APPROVED-BINDINGS-TEMPLATE.json)
for its schema. The manifest and every prerequisite record must be canonical
two-space-indented JSON with one trailing newline; noncanonical or duplicate-key
JSON is rejected. The manifest must hash and reference the protected-main
[`V1C-PASS-TEMPLATE.json`](V1C-PASS-TEMPLATE.json) record and all eight separate
external-dependency records built from
[`V1D-DEPENDENCY-APPROVAL-TEMPLATE.json`](V1D-DEPENDENCY-APPROVAL-TEMPLATE.json).
The V1C pass record's `releaseDigest` must be the exact `Signed release digest`
authorized here, preventing trust evidence for one release from qualifying a
different release.
The network-segmentation prerequisite must use
[`V1D-NETWORK-CHANGE-EVIDENCE-TEMPLATE.json`](V1D-NETWORK-CHANGE-EVIDENCE-TEMPLATE.json)
to bind its separate change approval, apply receipt, positive-path test, and
negative-path test in addition to the common evidence fields. Each referenced
network artifact must use
[`V1D-NETWORK-CHANGE-ARTIFACT-TEMPLATE.json`](V1D-NETWORK-CHANGE-ARTIFACT-TEMPLATE.json),
remain byte-identical to the audited protected-main version, match the approved
target and flow, and prove approval-before-apply-before-test ordering. The
network evidence target must equal `Server binding`, and its flow must equal
`Private network policy binding`.
Each prerequisite must reference immutable scoped provision/verification and
rollback receipts built from
[`V1D-PREREQUISITE-EVIDENCE-TEMPLATE.json`](V1D-PREREQUISITE-EVIDENCE-TEMPLATE.json)
and
[`V1D-PREREQUISITE-ROLLBACK-TEMPLATE.json`](V1D-PREREQUISITE-ROLLBACK-TEMPLATE.json).
Each receipt scope must exactly match its independently approved
`evidenceScope` or `rollbackScope` in the approved-bindings manifest.
Binding-manifest approval must occur after Factory plan approval.
The authorization expiry must not exceed the expiry of the binding manifest,
the Factory plan, the V1C pass record, or any external-dependency approval
record.
Every prerequisite record must be approved before Factory plan issuance and
before binding-manifest approval.
The plan must be no more than two hours old at governance validation, the
authority must expire no later than two hours after plan issuance, and the
plan's issue-to-expiry lifetime must not exceed 24 hours. G2 through G8 must all
remain closed for the full authority window.
