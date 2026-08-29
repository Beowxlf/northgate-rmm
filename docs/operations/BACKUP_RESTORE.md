# Backup and Restore Plan

## Recovery objectives

Phase 0 does not claim operational RPO/RTO. Each operational gate must set and
test objectives appropriate to its deployment. Safety takes priority over rapid
reconnection.

## Backup scope

- PostgreSQL logical/physical data and schema history;
- endpoint identities, rotation lineage, and revocation state;
- authorization policy and phase-gate state;
- audit events and integrity checkpoints;
- configuration excluding plaintext secrets;
- artifact/update metadata, SBOMs, provenance, and public verification keys;
- encrypted gateway/session metadata if enabled;
- source commit and deployment manifests;
- secret-store backup through its own approved mechanism.

## Separation

Backups use a separate identity and destination, encryption, integrity
verification, access audit, retention, and deletion policy. The online application
cannot delete every recovery copy.

## Restore procedure

1. Open a recovery authorization and identify exact source artifacts.
2. Build an isolated network with no endpoint or operator ingress.
3. Restore configuration, schema, database, audit, and verification metadata.
4. Keep dispatch, enrollment, updates, and remote sessions disabled.
5. Verify backup digest/signature and schema migration state.
6. Run governance and data invariants, especially identity revocation and job
   cancellation/expiry.
7. Reconcile secrets/keys rather than blindly restoring compromised authority.
8. Authenticate test identities and one disposable canary only.
9. Document achieved RPO/RTO, gaps, and residual risk.
10. Authorize reconnection separately.

## Required restore tests

- revoked endpoint remains revoked;
- consumed enrollment grant cannot be reused;
- expired/cancelled job cannot dispatch;
- active leases and remote sessions restore as expired/closed;
- audit chain/checkpoints reconcile;
- update trust does not regress to an unauthorized root/version;
- no restored environment contacts real endpoints during validation.
