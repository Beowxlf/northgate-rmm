# Version 1.0 Release Criteria

## Release promise

NorthGate RMM 1.0 is a single-operator, single-site, lab-supported monitoring
release for one qualified Debian 12 amd64 endpoint. It proves the complete
charter slice with production-intent identities and release artifacts while
keeping endpoint authority read-only.

Version 1.0 is complete only when an enrolled endpoint can authenticate,
deliver bounded health and inventory observations, become healthy, stale, or
offline by explicit server receipt-time rules, be revoked, and leave a
correlated durable audit trail. Backup, restore, removal, containment, and
release verification must preserve those guarantees.

## Included scope

- one private NorthGate control-plane deployment;
- one disposable Debian 12 amd64 canary;
- single-use, expiring enrollment grants;
- endpoint-bound mutual-TLS identity, renewal, status, and revocation;
- outbound-only heartbeat and read-only inventory delivery;
- PostgreSQL-backed endpoint, identity, observation, and audit state;
- authenticated endpoint list and detail views;
- explicit healthy, stale, offline, pending, and revoked states;
- bounded local spooling, retries, resources, logs, and data retention;
- reproducible, signed Debian package with SBOM and provenance;
- documented backup, isolated restore, incident containment, uninstall, and
  rebuild procedures; and
- one evidence-backed lab soak followed by a G6-authorized signed `1.0.0`
  release.

## Explicit exclusions

Version 1.0 does not include Windows support, remote jobs, command text, shell
execution, remediation, privileged helpers, file transfer, agent-driven update
installation, remote desktop, public-internet exposure, multi-tenancy, or broad
fleet rollout. Those capabilities remain governed by G3 through G8 and later
release criteria. The architecture must preserve Windows and Linux as mature
product requirements without claiming either unqualified platform as supported.

## Qualification ladder

### V1A — Release contract and source authority

- this release contract is merged through protected `main`;
- status documentation agrees with executable behavior;
- source development for the control-plane listener and enrollment path has a
  bounded owner authorization that does not open G2; and
- required checks pass on the exact merge commit.

### V1B — Real control-plane service

- a production-shaped service exposes only the bounded operator and agent
  endpoints required by the included scope;
- enrollment grants are hashed, single-use, expiring, target-bound, and consumed
  atomically;
- post-enrollment messages bind the authenticated certificate identity to the
  payload endpoint and acknowledge an exact message ID idempotently;
- PostgreSQL migrations implement endpoint identities, grants, observations,
  revocation, and append-oriented audit records;
- the operator view escapes untrusted values and derives freshness from server
  receipt time; and
- malformed, oversized, replayed, expired, duplicate, unauthorized, revoked,
  and cross-endpoint inputs fail closed in isolated tests.

### V1C — Production release trust

- G6 authorization names the exact release, artifacts, signing profile,
  distribution location, canary ring, expiry, and rollback boundary;
- production signing custody and recovery are approved and separated from the
  ordinary control plane;
- the exact package, manifest, SBOM, provenance, signature, source commit, and
  compatibility policy verify from an independently pinned trust root;
- a protected distribution location and bootstrap trust procedure exist;
- signing-key loss and compromise procedures are tested; and
- no automatic update authority is introduced under G6.

### V1D — Operational readiness

- exact DNS, time, PKI, monitoring, audit, backup, recovery, storage, and
  microsegmentation dependencies replace every in-scope `TBD`;
- VM Factory supports the complete server and canary manifests;
- database-consistent backup and isolated restore preserve identity, revocation,
  observations, audit evidence, and phase-gate state;
- telemetry outage, capacity, certificate-revocation, and containment tests have
  observable outcomes and rollback; and
- secrets, keys, retention, incident response, and service objectives have
  named owners and runbooks.

### V1E — G2 canary

- G2 authorization names the exact server, canary, release, network policy,
  identities, expiry, rollback, and reviewed evidence;
- fresh host-issued VM Factory plans and authenticated state hashes receive
  exact owner approval after issuance;
- one disposable canary enrolls, reports, transitions through freshness states,
  is revoked, and is removed without residual authority; and
- before/after infrastructure, security, and recovery evidence is retained.

### V1F — Release acceptance

- the canary completes the approved soak without unresolved high or critical
  findings;
- restore and incident drills meet the approved RPO, RTO, and containment bound;
- all required checks and an independent security review pass the exact release
  commit and artifacts;
- documentation, support matrix, changelog, runbooks, and known risks agree;
- release evidence is published without secrets or live private configuration;
  and
- the owner approves and signs the immutable `1.0.0` release record under G6.

## Release stop conditions

Do not tag or publish 1.0 when G2 or G6 is closed, an in-scope value remains
`TBD`, a required check is not green on the exact commit, a high or critical
finding is unresolved, restore or revocation is unproven, the artifact cannot
be independently verified, or documentation overstates deployed or supported
behavior.

Passing qualification does not authorize VM Factory execution. A plan can be
executed only through its own unexpired, exact-plan approval and guarded apply
path.
