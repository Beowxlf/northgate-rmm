# Security Test Plan

## Always-on tests

- input schema, size, Unicode, decompression, and timeout boundaries;
- authentication and authorization denials at every enforcement point;
- secret redaction in logs, traces, audit, errors, and artifacts;
- dependency, secret, SAST, workflow, and IaC scans;
- database constraints and cross-scope isolation;
- error handling that does not reveal resource existence or sensitive details.

## Identity/protocol tests

- expired, reused, brute-forced, or scope-mismatched enrollment grant;
- invalid server trust, invalid client certificate, revoked/expired identity;
- cloned key and simultaneous sessions;
- message replay, reorder, duplicate, gap, clock skew, unsupported version;
- malformed, oversized, truncated, compressed-bomb, and slow request;
- certificate rotation overlap and post-overlap rejection.

## Job tests

- illegal state transition;
- two workers claim one job;
- stale fencing token;
- delivery before approval or after expiry/revocation;
- duplicate delivery by idempotency class;
- cancellation during queued, leased, and running states;
- execution completes but result upload fails;
- truncated output and failed postcondition.

## Agent tests

- service runs unprivileged;
- structured agent logs reject arbitrary fields, raw errors, secret-shaped
  values, malformed identifiers, and control-character injection;
- package and service drafts reject root execution, shell wrappers, added
  environment fields, unbounded resources, and weakened sandbox directives;
- package removal and upgrade fail before artifact replacement when service
  stop or inactive state cannot be verified;
- key/config/spool permission enforcement;
- resource exhaustion and crash-loop limits;
- expired and explicitly rejected queue heads are quarantined without losing
  later delivery order; rejected evidence has independent byte/entry bounds,
  audited oldest-first rollover, and cannot exhaust the active queue;
- collector timeout/failure isolation;
- no shell metacharacter or path traversal construction;
- uninstall requires a fresh protected revocation receipt even when local
  identity material is already absent;
- source-only lifecycle simulation preserves evidence-bearing state on ordinary
  uninstall and requires approval, prior revocation, and evidence export for
  purge;
- purge authorization is root-owned outside service-writable state, and an
  approved purge removes non-empty retained state before deleting the service
  identity;
- account or group deletion failure keeps purge failed and preserves protected
  gate receipts for a retry after service-owned state has been removed;
- installation rejects a pre-existing service account with a non-system UID,
  mismatched primary group, or any supplementary group access;
- supported OS/architecture matrix and upgrade compatibility.

## Remote-access tests

- grant theft/reuse and cross-operator redemption;
- target/protocol/port manipulation;
- gateway attempt to connect outside tunnel allowlist;
- clipboard/file/device redirection denial;
- credential exposure to browser, logs, recordings, or database;
- idle/absolute timeout and forced revocation;
- suspected-gateway isolation through an independent endpoint-facing policy
  enforcement point with externally verified tunnel teardown;
- disconnect/reconnect and orphan-tunnel cleanup;
- concurrent session and cross-target isolation;
- Linux/Windows host-key/certificate identity validation;
- penetration test of gateway, tunnel broker, and browser session boundary.

## Recovery tests

- compromised key rotation;
- database restore with revocations and expired work;
- update freeze/rollback/signing compromise;
- signing-envelope tests that recompute the acknowledgement-free payload digest
  and reject acknowledgement/envelope self-reference or digest substitution;
- allocator-receipt tests that reject a status activation or checkpoint with a
  missing, forged, mismatched, replayed, or rolled-back external receipt;
- automatic-pause tests proving a failed threshold can invoke the dedicated
  pause-only health authority but cannot freeze/revoke/start/advance/resume;
- lost-floor recovery tests that reject stale or disagreeing authority,
  allocator, anchored-ledger, and repository-activation proofs;
- update-status authority restore with external sequence and Z5/Z6 anchor
  reconciliation;
- audit integrity gap;
- emergency disable independent of suspected component.

Every test records requirement IDs and exact artifact/commit under test.
