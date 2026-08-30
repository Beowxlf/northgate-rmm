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
- key/config/spool permission enforcement;
- resource exhaustion and crash-loop limits;
- collector timeout/failure isolation;
- no shell metacharacter or path traversal construction;
- uninstall removes executable/secrets and revokes identity;
- supported OS/architecture matrix and upgrade compatibility.

## Remote-access tests

- grant theft/reuse and cross-operator redemption;
- target/protocol/port manipulation;
- gateway attempt to connect outside tunnel allowlist;
- clipboard/file/device redirection denial;
- credential exposure to browser, logs, recordings, or database;
- idle/absolute timeout and forced revocation;
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
- update-status authority restore with external sequence and Z5/Z6 anchor
  reconciliation;
- audit integrity gap;
- emergency disable independent of suspected component.

Every test records requirement IDs and exact artifact/commit under test.
