# ADR 0011 — Pre-G2 Control-Plane Validation Authority

Status: Accepted  
Date: 2026-09-04  
Change class: Class 2 authorization and identity boundary

## Context

V1D requires database-consistent restore, telemetry-outage, capacity,
certificate-revocation, containment, and rollback evidence before the disposable
Linux canary can be authorized. Those proofs need the production-shaped private
control plane and its separately approved dependencies, but G2 governs endpoint
installation rather than server infrastructure. Treating every server action as
G2 either creates a circular prerequisite or prematurely grants endpoint
authority.

## Decision

Define `V1D-SV` as one machine-readable, closed-by-default, bounded operational
authorization within Phase 2. It is not a product gate and cannot open G2. It may
be opened only after V1C passes, every external V1D dependency has its own exact
approved and verified implementation record, and a fresh host-issued Factory
plan ID and authenticated state hash receive owner approval after issuance.
Plan generation and approval use the Factory's existing non-deployment planning
path while `V1D-SV` remains closed. Only the later execution of that exact plan
is placed under `V1D-SV`.

An exact V1D-SV record must bind the named private control-plane server, signed
release, service and database identities, synthetic validation identity profile,
private flows, expiry, evidence, rollback, and recovery. It may install and
operate only that server for the required V1D proofs. Every endpoint and canary
route remains blocked. Synthetic grants and identities must be cryptographically
and operationally unusable by endpoints and removed or revoked at cleanup.

The machine-readable record format is defined by the
[V1D-SV authorization template](../../governance/templates/V1D-SV-AUTHORIZATION-TEMPLATE.md).
The separately approved binding manifest must already exist at the audited
protected-`main` commit. The governance audit loads that historical version,
requires the current content to remain identical, compares every operational binding,
and rejects missing, duplicate, placeholder, malformed, expired, future-dated,
or mismatched authority, owner, commit, time, server, release, plan, state-hash,
dependency, identity, network, rollback, recovery, and evidence values. Plan
approval must follow plan issuance, and the V1D-SV record must be issued after
that approval. Strict UTC calendar validation rejects normalized impossible
dates and future-effective records; the authority is limited to 24 hours and
its prior approved-bindings manifest to seven days.

V1D-SV cannot install an endpoint package, issue an endpoint-usable grant or
identity, admit endpoint traffic, publish or update artifacts, expand the plan,
or change any gate. G2 remains the separate exact authorization for the single
disposable Linux canary and cannot be open concurrently with V1D-SV.

## Consequences

- The phase model can obtain live server recovery evidence without granting
  endpoint authority.
- PKI, verifier, telemetry/audit, backup/recovery, DNS, authenticated-time,
  network, Factory, and key-custody changes retain separate approval records.
- Operators must prove cleanup and absence of residual endpoint authority before
  accepting the V1D evidence and before opening G2.
- The machine-readable governance audit rejects a missing authority definition,
  a gate-opening authority, the wrong phase, a missing exact record for an open
  authority, or concurrent V1D-SV and G2 state.

## Threat-model delta

This decision adds the V1D-SV record, synthetic validation identities, and the
temporary server-validation environment to the protected asset and trust-boundary
set. TM-49 covers abuse of the validation path as an unauthorized endpoint path.

## Negative validation and recovery

The security test plan requires denial for missing, expired, or mismatched
authority, plan, state hash, server, release, dependency, identity profile, and
route scope. It also requires proof that the authority cannot change G2, publish
artifacts, or create endpoint authority.

Recovery stops the services, revokes synthetic and workload identities, restores
the prior network policy, preserves database and protected audit evidence, and
proves there is no endpoint grant, identity, traffic, reachable endpoint path, or
residual V1D-SV authority. Failure to prove cleanup keeps V1D open and G2 closed.

## Alternatives rejected

- **Open G2 before V1D:** grants canary authority before recovery and containment
  evidence exists.
- **Call server deployment source development:** hides a real operational change
  behind a non-deployment authorization.
- **Reuse production endpoint identities for validation:** creates residual
  endpoint authority and makes cleanup unverifiable.
- **Combine every dependency into V1D-SV:** bypasses the separate ownership,
  rollback, and evidence boundaries required for external services and network
  policy.
