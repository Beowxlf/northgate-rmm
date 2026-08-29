# Phase 1 Initial Implementation Audit — 2026-08-29

Status: Pass for initial Phase 1 scope  
Audited implementation commit: `2d627aa3a130bfcccfba02ddcacd3c231ecde2d0`  
Gate: G1 — Product coding

## Scope

This audit covers the first synthetic-only Python domain slice. It verifies
Windows and Linux fixtures, endpoint and identity binding, heartbeat and inventory
contracts, deterministic freshness, replay and expiry checks, revocation, audit
events, tests, static analysis, dependency review, and repository controls.

It is not the Phase 1 exit audit. Persistence, backup/restore, concurrent
enrollment, a server-rendered view, test certificates, and broader malformed or
oversized payload coverage remain future Phase 1 work.

## Architecture conformance

| Control                                              | Evidence                          | Result |
| ---------------------------------------------------- | --------------------------------- | ------ |
| Python is simulation/control-plane code only         | ADR 0006 and `src/northgate_rmm/` | Pass   |
| Windows and Linux use one protocol model             | parameterized platform test       | Pass   |
| Transport identity binds the endpoint                | mismatch rejection test           | Pass   |
| Heartbeat and inventory are independent              | inventory freshness test          | Pass   |
| Server receipt time drives health                    | online/stale/offline test         | Pass   |
| Message IDs and boot sequences resist replay         | replay and restart tests          | Pass   |
| Expired messages fail closed                         | expiry-boundary test              | Pass   |
| Future-dated messages cannot extend acceptance       | clock-skew regression test        | Pass   |
| Inventory keys have unambiguous digests              | duplicate-key regression test     | Pass   |
| Revocation is immediate and idempotent               | revocation tests and audit events | Pass   |
| Accepted observations and audits are append-oriented | immutable snapshot test           | Pass   |
| No command or remote-session primitive exists        | source and path review            | Pass   |

## Executed checks

| Check                              | Result                              |
| ---------------------------------- | ----------------------------------- |
| Ruff format and lint               | Pass                                |
| mypy strict mode                   | Pass: seven source/test files       |
| pytest                             | Pass: 18 tests                      |
| branch coverage                    | Pass: 99%, threshold 90%            |
| Bandit                             | Pass: no medium or high findings    |
| Semgrep Community Edition          | Pass: 151 Python rules, no findings |
| pip-audit                          | Pass: no known vulnerabilities      |
| Gitleaks                           | Pass: no findings                   |
| actionlint and Zizmor              | Pass                                |
| Markdownlint, Prettier, and Lychee | Pass                                |
| Governance and gate checks         | Pass                                |

## Remote evidence

- protected pull request: `#5`;
- pre-code governance workflow: run `33263005622`, pass;
- free-software security workflow: run `33263005544`, pass;
- required branch checks prevented merge before completion.

## Security observations

### P1-001 — In-memory state is intentionally non-durable

Severity: Medium  
Status: Accepted for the initial slice

Restarting the process loses endpoint, replay, revocation, observation, and audit
state. This is acceptable only for local simulation. Phase 1 cannot exit and no
endpoint can be installed until a persistence model and isolated restore test
prove that revocation survives recovery.

### P1-002 — Synthetic fingerprints are identifiers, not credentials

Severity: Medium  
Status: Accepted for the initial slice

The simulator creates correctly formatted random SHA-256 fingerprint values but
does not generate a key pair, certificate, or mutually authenticated transport.
The values must never be represented as proof of real cryptographic enrollment.

### P1-003 — Single-process checks do not establish concurrency safety

Severity: Medium  
Status: Open, non-blocking for the initial slice

Replay, sequence, enrollment uniqueness, and revocation behavior are deterministic
in one process. Database transactions, competing writers, and recovery races are
not yet implemented or tested. They remain required before Phase 1 exit.

## Gate conclusion

The initial Phase 1 implementation is acceptable for protected merge. G1 remains
open for bounded synthetic development. G2 through G8 remain closed, and this
audit provides no authorization to install software, collect real endpoint data,
deliver jobs, execute commands, start remote sessions, or deploy a service.
