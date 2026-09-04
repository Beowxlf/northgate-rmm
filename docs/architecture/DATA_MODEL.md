# Data Model

## Modeling rules

- immutable IDs use opaque random identifiers;
- mutable names, addresses, and labels are attributes, not identities;
- observations are append-only facts with independent receipt and source times;
- derived status can be recomputed from observations and policy;
- approved job intent is immutable;
- audit events are append-oriented and never updated to rewrite history;
- tenant scope is reserved but multi-tenancy is not enabled.

## Core entities

### Endpoint

`endpoint_id`, display name, platform, architecture, enrollment state, current
identity reference, first/last receipt times, agent version, labels, and lifecycle
state.

### Endpoint identity

Public-key fingerprint, certificate serial, issuer, validity, status, rotation
chain, revocation reason/time, and endpoint binding. Private keys are never stored.

### Enrollment grant

The executable V1B subset stores a hashed secret reference, intended Linux/amd64
target facts, creator, creation/expiry, and the single consumed identity/time.
Plaintext is returned only at creation and is never persisted or audited. Future
phases may add richer scope and explicit invalidation state.

### Observation

Endpoint ID, observation type/schema version, source time, server receipt time,
boot/session identity, sequence number, bounded payload or artifact reference,
and payload digest.

### Desired state and finding

Versioned policy reference, evaluation time, input observation references,
outcome, severity, confidence, suppression/maintenance context, and lifecycle.

### Job

Job ID, action type/version/digest, exact target IDs, creator, approval policy,
created/approved/expiry times, retry/idempotency policy, current state, and
correlation ID.

### Job lease

Job ID, worker ID, monotonic fence, acquisition and expiry times, attempt number,
and release reason. Only the current fencing value may advance dispatch state.

### Result

Job ID, endpoint ID, attempt, authenticated agent identity, start/end times,
outcome, exit/domain status, truncation flags, sanitized output/artifact digests,
and postcondition references.

### Approval

Job/action digest, target digest, approver identity, policy evaluated, decision,
reason, authentication strength, decision time, and expiry.

### Audit event

Event ID, server time, actor type/ID, subject, action, target, decision, reason,
request/correlation IDs, source service, prior/current state references, and
sanitized metadata.

## Database invariants

- Phase 1 endpoint and identity creation is one deferred-constraint transaction;
- endpoint key fingerprint is unique;
- message ID is globally unique and each identity/boot sequence increases
  atomically under a database constraint;
- service-ingested messages retain an exact encoded digest so a byte-identical
  retry can receive the original acknowledgement without creating another
  observation; legacy synthetic observations intentionally retain `NULL`;
- observations and audit events are append-oriented; the Phase 1 application API
  exposes no update, delete, or truncate operation for either record type;
- an enrollment grant is short-lived, stores only a token digest, and is consumed
  atomically at most once with endpoint and identity creation;
- revoked identities cannot authenticate or receive work;
- job transitions satisfy the defined state graph;
- a result target must belong to the job and authenticated endpoint;
- one active lease exists per job;
- fencing tokens increase monotonically;
- approval digest must equal immutable job intent digest;
- audit event IDs and correlation IDs are indexed;
- destructive cascades do not delete audit, approval, or revocation evidence.

The executable schema is migrations
`src/northgate_rmm/migrations/0001_phase1.sql` and
`src/northgate_rmm/migrations/0002_enrollment_grants.sql`, with exact retry
digests added by
`src/northgate_rmm/migrations/0003_message_idempotency.sql` and current-identity,
certificate-lifecycle, and rotation lineage constraints added by
`src/northgate_rmm/migrations/0004_identity_rotation.sql`, followed by the
issued-before-active transition in
`src/northgate_rmm/migrations/0005_issued_identity_status.sql` and immutable,
same-endpoint, older-predecessor rotation lineage in
`src/northgate_rmm/migrations/0006_rotation_lineage.sql`. Jobs, leases, results,
and approvals remain future schema and are not executable capabilities.

## Retention

See [Data Classification and Retention](../security/DATA_CLASSIFICATION_RETENTION.md).
