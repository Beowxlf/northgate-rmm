# Governance

## Decision ownership

The project owner approves phase transitions, changes to security invariants,
new endpoint authorities, public exposure, production deployment, and releases.

## Change classes

### Class 0 — Documentation clarification

No behavior or control changes. One reviewer and passing documentation checks.

### Class 1 — Internal implementation

No new authority, protocol trust, data class, or exposure. Tests, security scans,
and CODEOWNERS review are required.

### Class 2 — Security-significant change

Changes identity, authorization, cryptography, protocol, agent privilege, job
semantics, audit, updates, secrets, or retention. Requires an ADR, threat-model
delta, explicit owner approval, negative tests, and rollback/recovery evidence.

### Class 3 — Operational expansion

Adds public exposure, a new tenant, broad fleet execution, privileged helper,
remote shell, file transfer, remote desktop, network isolation, or production
deployment. Requires a new phase gate and separate operational authorization.

## Pull request requirements

- identify change class;
- link the requirement, issue, ADR, or risk being addressed;
- describe tests and security impact;
- include rollback or recovery behavior when state can change;
- pass all checks required for the active phase;
- obtain CODEOWNERS approval;
- contain no unresolved high or critical security finding.

Direct pushes to `main` are prohibited after GitHub branch protection is enabled.
Emergency changes must still produce a retrospective review and evidence record.

## Exceptions

An exception must be written, scoped, owned, risk-accepted, time-limited, and
linked to a remediation issue. CI bypasses without an exception record are not
valid authorization.

## Records

- ADRs: `docs/architecture/adr/`
- risks: `docs/security/RISK_REGISTER.md`
- phase authorizations: `docs/governance/authorizations/`
- audit reports: `docs/audits/`
- release evidence: `docs/releases/`
