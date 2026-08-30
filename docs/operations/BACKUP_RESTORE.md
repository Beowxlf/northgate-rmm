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
- separately verified signed recovery packages, artifact/update metadata, SBOMs,
  provenance, and public verification keys;
- protected release-status sequence ledger, signed status digests, allocator
  checkpoints, pending-anchor receipts, reconciliation acknowledgements, and
  authority-epoch linkage; the non-rollbackable allocator itself remains outside
  the authority VM and ordinary restore set;
- encrypted gateway/session metadata if enabled;
- source commit and deployment manifests;
- secret-store backup through its own approved mechanism.

The authoritative source, bounded identity, destination, activation gate, and
network path for each item are defined in
[`INFRASTRUCTURE_AND_MICROSEGMENTATION.md`](../architecture/INFRASTRUCTURE_AND_MICROSEGMENTATION.md#backup-coverage).

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
8. Reconcile any restored status authority against its external allocator and the
   highest valid Z5/Z6 sequence anchor; keep signing disabled until the next
   sequence is proven greater than the pre-restore maximum.
9. Authenticate test identities and one disposable canary only.
10. Document achieved RPO/RTO, gaps, and residual risk.
11. Authorize reconnection separately.

## Required restore tests

- revoked endpoint remains revoked;
- consumed enrollment grant cannot be reused;
- expired/cancelled job cannot dispatch;
- active leases and remote sessions restore as expired/closed;
- audit chain/checkpoints reconcile;
- update trust does not regress to an unauthorized root/version;
- restored or rolled-back agent state cannot lower the accepted release-status
  sequence and must obtain a current signed authority checkpoint when uncertain;
- restoring or rolling back the status authority cannot lower its highest-issued
  sequence or undo a prior freeze/revocation; missing, lower, inconsistent, or
  unavailable allocator/anchor state keeps signing disabled;
- no restored environment contacts real endpoints during validation.
