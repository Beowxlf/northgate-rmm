# Phase 1 Exit Audit — 2026-08-30

Status: Pass at reviewed implementation commit `0e6c4d020583220357a6cc91966a379c5b77046f`  
Gate: G1 — Product coding  
Scope: Phase 1 simulated control-plane exit

## Executive conclusion

The reviewed implementation covers the Phase 1 exit criteria without adding an
endpoint agent, operating-system collector, command/job model, network listener,
remote session, or live infrastructure dependency. G2 remains closed. Pull
request [#7](https://github.com/Beowxlf/northgate-rmm/pull/7) records successful
required checks, PostgreSQL concurrency tests, isolated dump/restore evidence,
and a completed automated review with no unresolved threads.

## Exit-criteria mapping

| Exit criterion                                       | Verified evidence                                                             | State |
| ---------------------------------------------------- | ----------------------------------------------------------------------------- | ----- |
| Enrollment, heartbeat, freshness, revocation E2E     | in-memory and PostgreSQL control-plane tests                                  | Pass  |
| Malformed and oversized messages fail safely         | strict decoder and bounded domain tests                                       | Pass  |
| Replay, duplicate, expired, unauthorized fail safely | negative and competing-writer tests                                           | Pass  |
| Backup and isolated restore preserve revocation      | PostgreSQL custom-format dump, new database restore, post-restore denial test | Pass  |
| Audit correlation explains every transition          | accepted, rejected, and idempotent transition assertions                      | Pass  |
| Server-rendered endpoint list/detail                 | escaped read-only HTML tests                                                  | Pass  |
| Test-only endpoint identity credentials              | short-lived endpoint-bound Ed25519 client certificate test                    | Pass  |
| No endpoint command-execution capability             | source/API review plus security scans                                         | Pass  |

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

## Protected-pull-request evidence

- protected pull request: [#7](https://github.com/Beowxlf/northgate-rmm/pull/7);
- reviewed implementation commit: `0e6c4d020583220357a6cc91966a379c5b77046f`;
- [governance/documentation run 33321194200](https://github.com/Beowxlf/northgate-rmm/actions/runs/33321194200):
  pass;
- [repository-security run 33321194150](https://github.com/Beowxlf/northgate-rmm/actions/runs/33321194150):
  pass;
- Python 3.12 result: 53 tests passed, including 11 PostgreSQL tests, with
  95.68% total branch coverage;
- Ruff, strict mypy, Bandit, pip-audit, Gitleaks, Semgrep, actionlint, Zizmor,
  Markdownlint, Prettier, and Lychee completed successfully;
- PostgreSQL migration, competing-writer concurrency, dump, isolated restore,
  and revoked-ingest checks passed;
- automated review completed for `0e6c4d0`; unresolved review threads: 0.

The audit-record-only commit that contains this pass does not alter the reviewed
runtime implementation. It must also complete the protected checks and automated
review before merge. The final squash merge commit and post-merge workflow runs
are release-history evidence, not prerequisites for the reviewed Phase 1 exit
decision recorded here.

## Authorization boundary

A Phase 1 pass establishes only a synthetic software and recovery proof. It does
not open G2, authorize a VM or network change, install an agent, collect real
endpoint data, deploy the server, expose a listener, or permit a command. Those
actions require their separate gates and change evidence.
