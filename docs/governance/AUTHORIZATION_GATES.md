# Authorization Gates

## Gate mechanics

The machine-readable source is `governance/gates.json`. A gate is open only when:

1. every required evidence artifact exists;
2. automated checks pass against the exact commit;
3. blocking findings are resolved or covered by a valid exception;
4. the owner signs the authorization record by committing it;
5. the record contains the audited commit hash and expiry or supersession rule.

A passing CI run is evidence, not authorization by itself.

Phase-specific source development may be authorized by a separate committed
development record that states an exact non-deployment boundary. Such a record
does not open the corresponding installation or capability gate. In particular,
reviewable Phase 2 agent source may be developed while G2 remains closed, but it
may not be installed, connected to live infrastructure, or supplied with live
identity material until G2 has its own complete authorization record.

## G0 — Repository establishment

Allows governance and audit tooling only. Requires charter, governance, security
policy, CODEOWNERS, change templates, and a protected remote repository plan.

## G1 — Product coding

Allows Phase 1 product code. Requires the full Phase 0 document set and a passing
pre-code audit. Evidence record:
`docs/governance/authorizations/G1-PRODUCT-CODING.md`.

## Pre-G2 V1D control-plane validation authority

`V1D-SV` is the only recognized bounded operational authority. Unknown
authority IDs fail governance validation. Its closed-gate requirements,
prerequisites, and prohibitions must be exact unique arrays; alternate types,
duplicates, omissions, and additions fail closed. Every endpoint-capable gate
from G2 through G8 must remain closed while V1D-SV is open.

This is an exact, bounded change authorization, not an opened product gate. It
may be issued only after V1C passes and the required external V1D dependencies
have been separately approved, provisioned, and verified. It must name the
control-plane server, signed release, private network policy, service and
database identities, synthetic validation identities, expiry, rollback, and
evidence boundary. Its fresh host-issued VM Factory plan ID and authenticated
state hash require exact owner approval after issuance. The plan is generated
and approved through the Factory's non-deployment planning path while `V1D-SV`
remains closed; `V1D-SV` governs only execution of the approved plan. Before the
authority can open, its record must use the parsed, fail-closed field contract in
the [V1D-SV authorization template](templates/V1D-SV-AUTHORIZATION-TEMPLATE.md).
The audited commit must contain the canonical Factory-exported plan approval
receipt. Its digest and plan, state, time, approver, and target fields must match
the authorization, and its detached CMS signature must verify against a
separately owner-pinned Factory approval certificate. The trust record must
be introduced in an earlier protected-main change and predate plan issuance.
Its protected-main introduction commit time must also predate the authenticated
plan issue time. The trust record, receipt, and signature each use an immutable,
single-use protected-main path.
Its sanitized approved-bindings manifest must already exist at the audited
commit; changing it in the authority-opening change or substituting any bound
value fails validation.
The manifest must also bind the exact authorization issuance and expiry; the
authority window cannot be extended by editing the later authorization record.
That manifest must hash and reference a protected-main V1C pass record and the
eight separate external-dependency approval records, including the separately
approved and tested network-segmentation change. Each prerequisite record
must be owner-approved, unexpired, evidence- and rollback-bound, unchanged from
the audited commit, valid for its exact required identity and status, and valid
through the authorization expiry. Every prerequisite approval must precede
Factory plan issuance and approval of the binding manifest. Protected-main
introduction commit times for every prerequisite, evidence, rollback, and
network artifact must also precede Factory plan issuance.
Each evidence and rollback binding must identify a separate canonical receipt
that is present and unchanged at the audited commit, matches the prerequisite,
records owner-approved verification before prerequisite approval, and binds the
approved target, identities, flows, provision/verification receipts, rollback
procedure, and recovery evidence without publishing live values.
Those receipt scopes must match the independently owner-approved per-prerequisite
scope values in the immutable approved-bindings manifest; recomputing inner
receipt and prerequisite digests cannot substitute evidence from another
environment.
The network prerequisite's target and flow scopes must also equal the
authorization's exact server and private-network-policy bindings; a
manifest-local alternate network scope is rejected.
The full dependency array has one fixed ID order and its canonical
two-space-indented JSON plus trailing newline is SHA-256 hashed. That derived
digest must equal `External dependency set binding`, binding every dependency
record, evidence scope, receipt digest, and rollback scope to the exact
authorization.
Every approved binding, prerequisite, evidence receipt, rollback receipt, and
network-change artifact must also remain byte-identical at the current
protected-main tip. Removing or replacing one revokes it; restoring an older
still-unexpired approval snapshot does not restore authority. Validation also
checks each path's entire protected-main history. Every approval path is
single-use: it must be introduced once and never changed, deleted, or recreated.
A later byte-identical restoration remains revoked even when its restoration
commit is selected as the audit anchor; renewal requires a new record path.
The protected branch requires strict up-to-date status checks, so any `main`
advance between validation and merge makes the authority-opening pull request
stale and forces these checks to rerun against the new protected-main tip.
The Factory plan expiry must cover the full authorization lifetime.
At every governance validation, the plan must be no more than two hours old and
its issue-to-expiry lifetime must not exceed 24 hours; older or longer-lived
plans fail closed and require a fresh host state validation and plan.
The V1D-SV authorization itself must expire no later than two hours after plan
issuance, preventing later execution after the freshness window has elapsed.

The authorization permits installation and operation of the named private
control-plane server only to complete V1D backup/restore, telemetry-outage,
capacity, certificate-revocation, containment, and rollback proofs. It cannot
install an endpoint package, create an enrollment grant usable by an endpoint,
issue a live endpoint identity, admit canary or other endpoint traffic, publish
or update artifacts, or open G2. G2 remains the separate gate for the one
disposable Linux endpoint canary.

## G2 — Linux endpoint installation

Allows one disposable Linux canary. Requires Phase 1 evidence, Linux package and
service review, data-collection inventory, uninstall/revoke plan, resource limits,
and explicit target authorization.

## G3 — Windows endpoint installation

Allows one disposable Windows canary. Requires the Windows-specific equivalent of
G2 plus installer signing and ACL review.

## G4 — Remote job delivery

Allows one typed, read-only diagnostic action. Requires job-state and duplicate
delivery tests, exact target binding, separate approval, output controls, and
result-unknown handling.

## G5 — State-changing or privileged action

Allows only the named action and targets in the authorization. Requires rollback,
postcondition verification, maintenance window, canary, privilege boundary,
incident plan, and second-person approval.

## G6 — Agent update release

Allows a staged signed update. Requires separated signing custody, provenance,
SBOM, downgrade/freeze protection, failed-update recovery, and a canary ring.

## G7 — Interactive remote access

Allows only the named session types and canary targets. Requires the remote-access
architecture, isolated gateway, just-in-time credential design, session approval,
idle/absolute timeout, forced termination, recording/privacy decision, disabled
redirection defaults, threat-model delta, penetration test, and recovery evidence.

## G8 — Production/public deployment

Allows only the topology and exposure named in the authorization. Requires an
independent assessment, restore exercise, operational monitoring, incident drill,
privacy review, capacity evidence, and explicit risk acceptance.

## Automatic closure

A gate closes when its authorization expires, required evidence is invalidated,
a signing or identity key is suspected compromised, a critical vulnerability is
unresolved, the architecture materially changes, or the target scope changes.
