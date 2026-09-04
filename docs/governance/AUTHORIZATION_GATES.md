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

This is an exact, bounded change authorization, not an opened product gate. It
may be issued only after V1C passes and must name the control-plane server,
signed release, private network policy, service and database identities,
synthetic validation identities, expiry, rollback, and evidence boundary. Its
fresh host-issued VM Factory plan ID and authenticated state hash require exact
owner approval after issuance.

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
