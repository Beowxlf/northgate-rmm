# Development Phases

Each phase has a purpose, permitted work, entry evidence, exit evidence, and an
authorization record. Later-phase operational work is prohibited while an
earlier gate is closed. Bounded source development may proceed only under the
separate non-deployment authorization mechanism defined in
`AUTHORIZATION_GATES.md`. The sole pre-G2 operational exception is the bounded
Phase 2 V1D control-plane validation authority defined there and in
[ADR 0011](../architecture/adr/0011-pre-g2-control-plane-validation.md). It may
operate only the named private server with synthetic validation identities and
blocked endpoint routes after all prerequisites pass; it does not open G2 or
permit an endpoint installation.

## Phase 0 — Govern and design

Purpose: establish the problem, trust model, system boundaries, controls, checks,
and recovery expectations before product code.

Permitted:

- documentation;
- architecture models and ADRs;
- schemas and interface specifications that are not executable product code;
- audit and repository-governance tooling;
- CI configuration.

Exit evidence:

- complete architecture set;
- threat model and risk register;
- security and privacy requirements;
- authorization-gate definitions;
- free-software required-check matrix;
- pre-code audit with no unresolved gate-blocking finding;
- owner authorization record.

## Phase 1 — Simulated control-plane slice

Purpose: prove endpoint identity, protocol, state, revocation, and audit semantics
without executing commands on a managed operating system.

Permitted:

- Python control-plane modules;
- in-process or local simulated agent;
- PostgreSQL schema and migrations;
- server-rendered endpoint list/detail view;
- test-only CA and credentials;
- automated negative, concurrency, and recovery tests.

Exit evidence:

- enrollment, heartbeat, freshness, and revocation work end-to-end;
- malformed, oversized, replayed, duplicate, expired, and unauthorized messages
  fail safely;
- database backup and isolated restore preserve revocation;
- audit correlation explains every state transition;
- no endpoint command-execution capability exists.

## Phase 2 — Linux read-only service and canary

Purpose: productize the private control-plane boundary and run an unprivileged
agent on one disposable supported Linux VM.

Permitted:

- Go agent core;
- private control-plane HTTP service and enrollment boundary;
- authenticated, read-only operator endpoint list and detail views;
- PostgreSQL migrations for grants, identities, observations, and audit;
- `systemd` service and native package draft;
- bounded read-only collectors;
- outbound authenticated transport;
- bounded offline spool.

Pre-G2 V1D validation boundary:

- the machine-readable `V1D-SV` authority remains closed until V1C and every
  required external dependency implementation pass;
- the Factory's non-deployment planning path must first issue a fresh plan and
  authenticated state hash for exact owner approval;
- a sanitized approved-bindings manifest must then reach protected `main`;
- a separate later exact record may open `V1D-SV` and permit execution only for
  the named private control-plane server and synthetic validation identities;
- canary and endpoint routes remain blocked, and no endpoint-usable grant,
  identity, package, or traffic is permitted; and
- the negative tests, rollback, and recovery evidence in ADR 0011 and the
  security test plan must pass before the server evidence can satisfy V1D; and
- `V1D-SV` must close in a separate protected-main change with immutable
  cleanup evidence proving service stop, service/database/operator/synthetic
  identity revocation, route blocking, temporary-access removal, secret
  destruction, and rollback before G2 or any later product gate may open.

Exit evidence:

- one named Linux version qualified;
- single-use enrollment, authenticated message delivery, freshness, revocation,
  and audit work across the real service boundary;
- resource, retry, log, spool, install, upgrade, revoke, and uninstall behavior
  verified;
- no inbound listener, root service, or general execution primitive;
- recovery and clean-removal evidence.

## Phase 3 — Windows read-only canary

Purpose: qualify the shared protocol and read-only model as a Windows Service.

Exit evidence mirrors Phase 2 and adds installer signing, ACL, Service Control
Manager, Event Log, and Windows support-matrix validation.

## Phase 4 — One typed diagnostic action

Purpose: prove bounded job scheduling and result semantics with one read-only
action that accepts no command text.

Exit evidence:

- approval, exact target, expiry, lease, cancellation, replay, timeout, unknown
  result, output bounding, and postcondition semantics tested;
- one-machine canary only;
- action and result audit records independently reconstructable.

## Phase 5 — Limited remediation

Purpose: introduce the first state-changing action and, only if required, a
narrow privileged helper.

Required new gate:

- action-specific threat model;
- rollback and recovery plan;
- second-person approval;
- sandbox and local authorization tests;
- maintenance and canary policy;
- incident containment path.

## Phase 6 — Secure updates and packaging

Purpose: release signed agents with staged rollout, rollback, downgrade defense,
key rotation, provenance, and SBOMs.

## Phase 7 — Cross-platform remote assistance

Purpose: provide explicitly authorized interactive access to supported Windows
and Linux endpoints through an isolated session gateway.

Required capabilities:

- Windows remote desktop using RDP;
- Linux remote terminal using SSH;
- Linux remote desktop using a separately qualified RDP, VNC, or Wayland-native
  backend;
- Windows remote terminal through separately configured OpenSSH or constrained
  PowerShell remoting when explicitly supported;
- just-in-time session authorization and credentials;
- encrypted, expiring, single-target tunnels;
- session termination, concurrency, idle timeout, and revocation;
- recording or transcript policy with sensitive-data controls;
- clipboard, file transfer, drive mapping, audio, and device redirection disabled
  by default and independently authorized;
- prominent operator and endpoint-session evidence.

Exit evidence:

- isolated session-gateway threat model and penetration test;
- no reusable endpoint password reaches the browser or control-plane database;
- cross-tenant and cross-target isolation tests;
- clean tunnel teardown under disconnect and gateway failure;
- Windows and Linux canary sessions, including forced termination and incident
  containment tests;
- documented accessibility, privacy, and user-consent behavior.

## Phase 8 — Scale and integrations

Purpose: add measured capacity, dedicated broker if justified, Wazuh/OPNsense/VM
Factory integrations, and broader support matrices. Each integration receives a
separate identity, data-flow, failure, and revocation design.

## Phase 9 — Production or external access

Purpose: authorize a production-intent deployment or public exposure.

This phase requires a separate operational risk acceptance, independent security
assessment, disaster-recovery exercise, privacy review, availability objectives,
and production secrets/key custody. Completion of earlier coding phases is not
deployment authorization.
