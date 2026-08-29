# Security Requirements

`MUST` requirements are gate-blocking. IDs are stable and must be referenced by
tests, audits, risks, and exceptions.

## Governance and secure development

- **SR-GOV-001:** The active phase and open authorization gate MUST be
  machine-verifiable.
- **SR-GOV-002:** Class 2/3 changes MUST update the ADR and threat model or explain
  why no change is required.
- **SR-GOV-003:** Required checks MUST use version-locked free software and fail
  closed when a scanner is unavailable.
- **SR-GOV-004:** External CI actions MUST be pinned to a full commit SHA and run
  with least-privilege permissions.
- **SR-GOV-005:** No high/critical finding may be suppressed without a scoped,
  owned, expiring exception and compensating control.

## Identity and enrollment

- **SR-ID-001:** Human and endpoint identities MUST use separate trust domains.
- **SR-ID-002:** Endpoint private keys MUST be generated on and remain on the
  endpoint, except within an explicitly approved secure backup mechanism.
- **SR-ID-003:** Enrollment grants MUST be random, hashed at rest, short-lived,
  single-use by default, and bound to intended scope.
- **SR-ID-004:** Hostname, IP, label, serial number, or agent-provided endpoint ID
  MUST NOT authorize access or jobs.
- **SR-ID-005:** Revocation MUST be enforced at connection, authorization, job
  dispatch, session establishment, and update eligibility.
- **SR-ID-006:** Identity rotation MUST preserve lineage without accepting the old
  identity after the overlap window.

## Authentication and authorization

- **SR-AUTH-001:** Operator authentication MUST use an external identity provider
  with MFA before production-intent use.
- **SR-AUTH-002:** Authorization MUST bind actor, exact endpoint, operation,
  parameters/digest, time, and policy version.
- **SR-AUTH-003:** UI visibility MUST NOT substitute for server authorization.
- **SR-AUTH-004:** High-risk operations MUST require independent approval and
  step-up authentication.
- **SR-AUTH-005:** Default access MUST be deny; wildcard fleet scope MUST require a
  separately authorized policy.
- **SR-AUTH-006:** Authorization MUST be re-evaluated at every privileged hop.

## Agent and protocol

- **SR-AGENT-001:** The agent core MUST run without administrative/root privilege
  through the read-only phases.
- **SR-AGENT-002:** The agent MUST expose no inbound RMM listener in approved
  initial architectures.
- **SR-AGENT-003:** Every message MUST be authenticated, versioned, schema
  validated, size bounded, and replay aware.
- **SR-AGENT-004:** Every collector and handler MUST have time, memory, CPU, disk,
  network, concurrency, and output bounds appropriate to its function.
- **SR-AGENT-005:** The product MUST NOT construct a general shell from typed
  actions or privileged-helper verbs.
- **SR-AGENT-006:** Offline spool data MUST be encrypted where required, integrity
  protected, quota bounded, and safely evicted by explicit policy.

## Jobs and actions

- **SR-JOB-001:** Approved job intent and target set MUST be immutable.
- **SR-JOB-002:** Duplicate delivery MUST be detectable and governed by explicit
  idempotency policy.
- **SR-JOB-003:** Non-idempotent actions MUST NOT retry automatically.
- **SR-JOB-004:** Lease ownership MUST use expiry and fencing to prevent stale
  workers from advancing state.
- **SR-JOB-005:** Missing acknowledgement/result MUST remain unknown.
- **SR-JOB-006:** Success MUST include action-specific postcondition evidence, not
  only transport delivery or process exit status.

## Cryptography and secrets

- **SR-CRYPTO-001:** Approved platform cryptographic libraries and CSPRNGs MUST be
  used; custom cryptography is prohibited.
- **SR-CRYPTO-002:** TLS server identity MUST be validated; post-enrollment agent
  traffic MUST use mutual authentication.
- **SR-CRYPTO-003:** Keys MUST have documented purpose, owner, storage, rotation,
  revocation, backup, and compromise procedures.
- **SR-CRYPTO-004:** Release/update signing authority MUST be separate from online
  application and ordinary operator credentials.
- **SR-CRYPTO-005:** Secrets MUST NOT appear in repository content, URLs, command
  lines, logs, traces, audit payloads, examples, or test fixtures.

## Data, privacy, audit

- **SR-DATA-001:** Collection MUST be allowlisted, purpose-limited, documented,
  and disabled unless required.
- **SR-DATA-002:** Sensitive fields MUST be redacted before logging, tracing,
  auditing, or export.
- **SR-DATA-003:** Retention and deletion MUST be defined by data class while
  preserving security/legal holds.
- **SR-AUDIT-001:** Authentication, authorization, enrollment, revocation, job,
  configuration, release, and remote-session transitions MUST emit structured
  audit events.
- **SR-AUDIT-002:** Audit events MUST use server time and correlation IDs and MUST
  be protected from ordinary application modification.
- **SR-AUDIT-003:** Audit access and export MUST themselves be audited.

## Updates and supply chain

- **SR-UPD-001:** Release artifacts MUST be reproducibly bound to source commit,
  SBOM, provenance, platform, and version.
- **SR-UPD-002:** Agents MUST verify signed update metadata and artifact digest
  before installation.
- **SR-UPD-003:** Update design MUST address rollback, freeze, mix-and-match,
  expiry, and signing-key compromise.
- **SR-UPD-004:** Rollout MUST use canary rings, health gates, pause, and recovery.
- **SR-UPD-005:** Dependencies and CI actions MUST be locked and continuously
  scanned.

## Remote access

- **SR-REMOTE-001:** Interactive access MUST use an isolated session gateway and
  expiring single-target authorization.
- **SR-REMOTE-002:** The gateway MUST NOT expose durable endpoint credentials to
  the browser or store them in the RMM database.
- **SR-REMOTE-003:** Tunnels MUST restrict destination endpoint, protocol, port,
  lifetime, concurrency, and reconnect behavior.
- **SR-REMOTE-004:** Clipboard, file transfer, drive/device redirection, session
  sharing, and recording MUST be separately governed and disabled by default.
- **SR-REMOTE-005:** Active sessions MUST terminate on session, operator, endpoint,
  or policy revocation and at idle/absolute timeout.
- **SR-REMOTE-006:** Windows RDP, Linux SSH, and each Linux desktop backend MUST be
  independently qualified and patched.
- **SR-REMOTE-007:** Session metadata MUST be audited; content recording MUST have
  an approved privacy, access, retention, and incident policy.

## Recovery

- **SR-REC-001:** Backups MUST include configuration, schema, endpoint identity,
  revocation, audit, and release trust needed for safe recovery.
- **SR-REC-002:** Restore tests MUST occur in isolation and verify security
  invariants before reconnecting endpoints.
- **SR-REC-003:** Emergency revocation and session termination MUST not rely solely
  on the component suspected compromised.
