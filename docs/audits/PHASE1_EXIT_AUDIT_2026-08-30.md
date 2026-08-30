# Phase 1 Exit Audit — 2026-08-30

Status: Candidate pending protected-branch review and remote PostgreSQL evidence  
Gate: G1 — Product coding  
Scope: Phase 1 simulated control-plane exit

## Executive conclusion

The candidate implementation covers the Phase 1 exit criteria without adding an
endpoint agent, operating-system collector, command/job model, network listener,
remote session, or live infrastructure dependency. G2 remains closed. This audit
becomes a pass only after the protected pull request records successful required
checks, PostgreSQL concurrency tests, and isolated dump/restore evidence.

## Exit-criteria mapping

| Exit criterion                                       | Candidate evidence                                                            | State   |
| ---------------------------------------------------- | ----------------------------------------------------------------------------- | ------- |
| Enrollment, heartbeat, freshness, revocation E2E     | in-memory and PostgreSQL control-plane tests                                  | Ready   |
| Malformed and oversized messages fail safely         | strict decoder and bounded domain tests                                       | Ready   |
| Replay, duplicate, expired, unauthorized fail safely | negative and competing-writer tests                                           | Ready   |
| Backup and isolated restore preserve revocation      | PostgreSQL custom-format dump, new database restore, post-restore denial test | CI gate |
| Audit correlation explains every transition          | accepted, rejected, and idempotent transition assertions                      | Ready   |
| Server-rendered endpoint list/detail                 | escaped read-only HTML tests                                                  | Ready   |
| Test-only endpoint identity credentials              | short-lived endpoint-bound Ed25519 client certificate test                    | Ready   |
| No endpoint command-execution capability             | source/API review plus security scans                                         | Ready   |

Dependency license and provenance evidence is recorded in
[the Phase 1 dependency review](PHASE1_DEPENDENCY_REVIEW_2026-08-30.md) and the
repository-root third-party notice inventory.

## Transaction and recovery controls

- deferred foreign keys make endpoint/identity enrollment atomic;
- unique database constraints protect fingerprints and message IDs;
- an atomic sequence upsert rejects duplicate or decreasing boot sequences under
  concurrency;
- identity rows are locked across authorization and observation commit so a
  concurrent revocation cannot be bypassed;
- observations and audit events are append-oriented and have no mutation method
  in the Phase 1 application boundary;
- migration names and SHA-256 checksums are recorded under an advisory lock;
- the recovery test restores into a separately named database and proves both the
  revoked lifecycle and rejection audit survive.

## Evidence to finalize

- protected pull request number and merge commit;
- governance/documentation workflow run and result;
- repository-security workflow run and result;
- Python 3.12 Ruff, strict mypy, pytest branch coverage, and Bandit results;
- PostgreSQL migration, concurrency, dump, isolated restore, and revoked-ingest
  results;
- Gitleaks, Semgrep, pip-audit, actionlint, Zizmor, Markdownlint, Prettier, and
  Lychee results;
- automated review disposition and unresolved-thread count.

## Authorization boundary

A Phase 1 pass establishes only a synthetic software and recovery proof. It does
not open G2, authorize a VM or network change, install an agent, collect real
endpoint data, deploy the server, expose a listener, or permit a command. Those
actions require their separate gates and change evidence.
