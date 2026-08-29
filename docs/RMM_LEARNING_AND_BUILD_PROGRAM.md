# NorthGate RMM Learning and Build Program

Status: design and education only  
Deployment authorization: not granted  
Initial platforms: Linux and Windows test endpoints  
Initial operating boundary: isolated NorthGate lab canaries

## 1. The central idea

An RMM is a privileged distributed control system. It continuously answers two
questions:

1. **What is happening on the managed machines?**
2. **What approved action should happen next?**

The dashboard is only the visible surface. The difficult product is the trust
system beneath it: endpoint identity, secure communications, job scheduling,
failure handling, privilege control, software updates, audit evidence, and
recovery when part of the system is unavailable or compromised.

An RMM agent can legitimately do many things that malicious command-and-control
software also does. It runs persistently, calls home, collects system data,
receives instructions, and may execute privileged actions. The difference must
be enforced by architecture and policy, not merely asserted by the operator.

## 2. Problems RMM software answers

### 2.1 Asset visibility

Questions answered:

- Which endpoints exist?
- Who owns them and where are they?
- Which operating system, hardware, software, and agent version do they run?
- When was each fact last observed?

Without an RMM, administrators often rely on spreadsheets, memory, or several
tools whose asset identities do not agree.

### 2.2 Health and availability

Questions answered:

- Is the endpoint online?
- Is storage, memory, CPU, or a critical service approaching failure?
- Is a failed check a momentary event or a persistent incident?
- Is the machine unhealthy, or is only the monitoring path broken?

The hard part is not collecting a number. It is interpreting freshness,
thresholds, missing data, maintenance windows, and noisy transient failures.

### 2.3 Configuration and compliance

Questions answered:

- Does the endpoint match an approved baseline?
- Which services, packages, policies, users, and security controls have drifted?
- Is the observed difference authorized, expected, or suspicious?

This requires versioned desired state and evidence. A green check without an
identified baseline is not a meaningful compliance result.

### 2.4 Patch and software lifecycle

Questions answered:

- Which updates are applicable?
- Which devices can receive them safely?
- Did the installation actually succeed?
- Is a restart required?
- Can the change be rolled back or recovered?

Patch management is a dependency and risk problem, not a single install button.

### 2.5 Remote support and automation

Questions answered:

- Can a reviewed diagnostic or repair action run without visiting the machine?
- Can it target exactly one intended endpoint first?
- Did it time out, partially complete, or produce the expected postcondition?
- What happened, who approved it, and what output is safe to retain?

An exit code alone is not proof that a repair achieved its intended outcome.

### 2.6 Security response

Questions answered:

- Can an endpoint be isolated, inspected, or have access revoked?
- Can suspicious RMM activity itself be detected?
- Can responders distinguish an operator action from attacker abuse?

RMM complements, but does not replace, EDR, SIEM, identity, backup, or network
security. Its high privilege makes it one of the systems those controls must
monitor.

### 2.7 Operational evidence

Questions answered:

- Who requested, approved, issued, received, and executed an action?
- Which version of the action ran against which endpoint identity?
- What was observed before and after?
- Can the record be correlated across the UI, API, scheduler, gateway, and agent?

Logs are raw observations. An audit record is a deliberately structured account
of a security-relevant event.

## 3. What an RMM is not

- **RMM:** inventory, health, policy, jobs, remote administration, and evidence.
- **EDR:** security detection, behavioral analysis, containment, and response.
- **SIEM:** centralized security-event storage, correlation, and investigation.
- **MDM:** device policy and application management, especially for mobile and
  organization-managed client platforms.
- **Configuration management:** declarative desired state and convergence.
- **Backup:** recoverable copies of systems and data.

These systems overlap, but combining all of them into the first product would
create an untestable and dangerously privileged scope.

## 4. Reference architecture

### 4.1 Trust domains

#### Operator plane

- web interface;
- human authentication;
- role and approval policy;
- session security.

#### Control plane

- API;
- endpoint registry;
- policy service;
- scheduler and job state machine;
- audit service;
- notification logic.

#### Agent communication plane

- enrollment endpoint;
- mutually authenticated gateway;
- heartbeat and inventory ingestion;
- job delivery and result collection;
- rate limits and revocation enforcement.

#### Data plane

- relational state database;
- time-series or summarized health observations;
- artifact storage;
- append-oriented audit records;
- backup and recovery copies.

#### Managed endpoint

- unprivileged agent core;
- local identity and trust store;
- bounded collectors;
- local policy enforcement;
- optional, narrowly scoped privileged helper;
- operating-system service integration.

### 4.2 Core message flow

1. An administrator creates a short-lived, single-use enrollment grant.
2. The agent generates its key pair locally and submits an enrollment request.
3. The control plane validates the grant and binds an endpoint identity to the
   public key. The private key never leaves the endpoint.
4. The agent authenticates on every connection and sends a versioned heartbeat.
5. The control plane records the observation time and computes freshness.
6. A policy or operator creates a typed job with explicit targets and limits.
7. The scheduler moves the job through a durable state machine.
8. The agent verifies identity, signature, policy, expiry, and replay protection
   before accepting the job.
9. A bounded handler executes it and records stdout/stderr safely, an exit
   result, duration, and domain-specific postconditions.
10. The control plane stores the result and writes correlated audit events.

### 4.3 Job state model

Use explicit states instead of a single `success` flag:

`created -> awaiting_approval -> approved -> queued -> leased -> running ->`
`succeeded | failed | timed_out | cancelled | expired | result_unknown`

`result_unknown` matters. If the network disappears after execution but before
acknowledgement, the server must not pretend it knows whether the action ran.

Each job needs:

- immutable job ID and correlation ID;
- action type and schema version;
- exact endpoint IDs, not mutable display names;
- creator and approver identities;
- creation, approval, expiry, lease, start, and completion timestamps;
- timeout, retry, and idempotency policy;
- action content hash or signed action reference;
- result and postcondition evidence;
- cancellation and revocation behavior.

## 5. Recommended first technical shape

This is a learning-oriented starting architecture, not a permanent commitment.

### 5.1 Control plane

- **Python API:** a small typed web API is fast to learn, test, and inspect.
- **PostgreSQL:** endpoints, observations, jobs, leases, approvals, and audit
  metadata need transactions and explicit concurrency handling.
- **Server-rendered UI first:** use a simple endpoint list and detail page before
  introducing a large front-end framework.
- **PostgreSQL-backed job queue first:** keep deployment small while learning the
  state machine. Introduce a dedicated broker only when measured load or
  isolation requirements justify it.
- **OpenTelemetry instrumentation:** correlate traces, metrics, and logs across
  enrollment, heartbeat, scheduling, and result ingestion.

### 5.2 Endpoint agent

- **Prototype:** a Python simulator teaches the protocol without touching a real
  operating system.
- **Production-intent agent:** Go is recommended for a small cross-platform
  executable, concurrency, straightforward service packaging, and fewer runtime
  dependencies on endpoints.
- **Privilege model:** run the core agent without administrative privileges.
  Add a separate, tightly allowlisted privileged helper only when a proven use
  case requires it.
- **Transport:** outbound-only TLS from agent to gateway; add mutual TLS after
  enrollment. Do not require inbound endpoint ports for the initial system.

### 5.3 Artifact and update path

- package Linux agents as native `deb` and `rpm` artifacts when those platforms
  enter support;
- package the Windows agent as a signed installer and Windows service;
- sign releases and publish provenance;
- design for update rollback, freeze, rollback-attack, and signing-key compromise
  scenarios rather than trusting a single download hash;
- keep update signing keys separated from online application credentials.

## 6. Required infrastructure

### 6.1 Development environment

- source repository with protected main branch;
- issue and architecture-decision records;
- repeatable local environment;
- unit, integration, protocol, migration, and security tests;
- Linux and Windows test runners or disposable test VMs;
- dependency and secret scanning;
- signed build and release process;
- isolated artifact repository;
- test PKI separate from future production PKI.

### 6.2 Minimum lab deployment

For the first lab slice:

1. **Control-plane host:** reverse proxy, web/API service, scheduler, and agent
   gateway. These may share one test VM initially.
2. **Data service:** PostgreSQL with authenticated backups. It may initially run
   on the control-plane VM, but its data and recovery lifecycle must be distinct.
3. **Identity material:** internal test CA, server certificate, endpoint
   certificates, rotation process, and revocation store.
4. **Observability:** health endpoints plus central metrics, logs, and traces for
   the RMM itself.
5. **Canaries:** one disposable Linux VM and later one disposable Windows VM.
6. **Recovery storage:** a separate destination for database, configuration,
   audit, and signing-metadata backups.

Do not expose the first build to the public internet. Use the lab network and an
approved administrative access path while the authentication, authorization,
update, monitoring, and recovery controls are still being proven.

### 6.3 Later production separation

Split components only when the trust boundary, availability goal, or measured
load requires it:

- public/operator reverse proxy;
- human identity provider;
- operator API and UI;
- agent gateways;
- scheduler workers;
- primary and standby database;
- object storage;
- secrets/keys service;
- observability stack;
- backup and restore environment.

Microservices are not a starting requirement. Clear module boundaries and
well-defined messages matter before independent deployment does.

## 7. Linux support requirements

“Runs on Linux” is not one requirement. It is a compatibility matrix.

### 7.1 Service lifecycle

- run under `systemd` on supported distributions;
- start after required networking is available, but tolerate temporary network
  loss after startup;
- handle stop/reload signals and bounded shutdown;
- declare restart and rate-limit behavior so a crash loop does not overwhelm the
  endpoint or control plane;
- log through the operating-system facility without leaking secrets.

### 7.2 Filesystem and identity

- executable in the appropriate system location;
- configuration separate from mutable state;
- durable identity and private-key material with strict ownership and mode;
- spool directory for bounded offline results;
- no secrets on command lines;
- dedicated system user and group;
- explicit uninstall and identity-revocation behavior.

### 7.3 Distribution differences

- Debian/Ubuntu versus RHEL-family package formats and dependency conventions;
- package-manager differences for inventory and patch assessment;
- different service, network, firewall, and logging tools;
- SELinux and AppArmor behavior;
- systemd availability and version differences;
- CPU architectures;
- container or immutable-host environments;
- end-of-life distribution policy.

Support only named distributions and versions that are continuously tested. An
untested Linux distribution is an unknown platform, not implicitly supported.

### 7.4 Privilege

Read-only host facts usually do not justify permanent root execution. Start with
an unprivileged service. For future administrative actions, compare:

- a privileged helper with a narrow authenticated protocol;
- constrained `sudoers` entries for exact programs and arguments;
- Linux capabilities for a specific kernel privilege;
- transient, sandboxed service units.

Never turn the first agent into a general root shell.

## 8. Windows support requirements

- Windows Service lifecycle through the Service Control Manager;
- a dedicated service identity with the minimum required rights;
- non-interactive behavior and Event Log integration;
- ACL-protected configuration, state, identity, and update directories;
- Authenticode-signed binaries and installer;
- safe uninstall, repair, and upgrade behavior;
- supported Windows release matrix;
- PowerShell and native API version differences;
- service recovery settings that avoid uncontrolled crash loops;
- a later privileged helper boundary rather than defaulting to LocalSystem.

The protocol and job semantics should be shared across platforms. Collectors and
action handlers should be operating-system-specific plugins behind that common
contract.

## 9. Development problems that will appear

### 9.1 Distributed-state ambiguity

Networks partition, endpoints sleep, certificates expire, and acknowledgements
get lost. The UI must distinguish `offline`, `stale`, `gateway unavailable`, and
`status unknown` instead of labeling all of them failed.

### 9.2 Duplicate delivery

Reliable systems commonly deliver a job at least once, not magically exactly
once. Agents must detect replay, handlers need idempotency rules, and retries must
be unsafe by default for non-repeatable actions.

### 9.3 Concurrency and leasing

Two scheduler workers can attempt to claim the same job. An endpoint can reconnect
while an old session remains alive. Database transactions, row leases, fencing
tokens, and expiry rules must make ownership explicit.

### 9.4 Clock disagreement

Endpoint time may be wrong. Record server receipt time separately from endpoint
observation time. Avoid trusting client clocks for security decisions without a
defined tolerance and synchronization health.

### 9.5 Schema and protocol evolution

Old agents will communicate with new servers during staged upgrades. Messages
need versions, optional fields, capability negotiation, and compatibility tests.

### 9.6 Cardinality and retention

Frequent metrics multiplied by many endpoints can produce expensive storage and
queries. Define collection intervals, aggregation, retention, deletion, and audit
retention independently.

### 9.7 Secret and output leakage

Inventory, process arguments, environment variables, command output, and logs can
contain credentials or personal data. Collection must be allowlisted, redacted,
size-bounded, access-controlled, and retention-limited.

### 9.8 Privilege escalation

An input-validation bug in a root or LocalSystem agent can become total endpoint
compromise. Typed actions, fixed handlers, strict argument schemas, OS sandboxing,
and privilege separation reduce this risk.

### 9.9 Supply-chain and updater risk

The component trusted to update the RMM agent can replace a highly privileged
program across the fleet. Build provenance, separated signing roles, rotation,
revocation, downgrade protection, staged rollout, and recovery are product
requirements.

### 9.10 Multi-tenant isolation

If multiple customers or administrative zones are ever supported, every query,
cache, job, artifact, log, and authorization check must enforce tenant boundaries.
Add multi-tenancy only after the single-tenant authorization model is testable.

### 9.11 Testing explosion

Tests must cover server version x agent version x operating system x architecture
x network condition x privilege mode. Define the supported matrix before users
define it accidentally.

### 9.12 Product safety and abuse resistance

Remote shell, file transfer, credential use, remote desktop, and mass execution
are attractive features and attractive attacker tools. Each requires stronger
identity, approvals, monitoring, containment, and customer-visible evidence.

## 10. Contextual learning path

Every module answers a real build question and produces evidence for the next
gate. Estimated effort is deliberately approximate.

### Track A — Understand the system (18–25 hours)

#### Module 1: RMM problem map

Learn: assets, observations, desired state, alerts, jobs, actions, and evidence.  
Mission: classify ten familiar TacticalRMM workflows by the underlying problem.  
Deliverable: problem-to-capability map and explicit v0 exclusions.  
Gate: every requested feature names the problem and the new authority it creates.

Lesson: [Module 1 — The RMM Problem Map](modules/01_RMM_PROBLEM_MAP.md)

#### Module 2: Trust and threat model

Learn: assets, actors, trust boundaries, attack paths, and abuse cases.  
Mission: model stolen operator credentials, stolen agent keys, gateway compromise,
malicious updates, replay, tenant crossover, and result forgery.  
Deliverable: data-flow diagram and threat register.  
Gate: each high-risk path has a preventive, detective, and recovery control.

#### Module 3: HTTP, TLS, and PKI

Learn: requests, certificates, trust chains, mutual TLS, rotation, and revocation.  
Mission: enroll a simulated endpoint into a disposable test CA.  
Deliverable: enrollment sequence and certificate lifecycle.  
Gate: no reusable enrollment secret becomes the endpoint identity.

#### Module 4: Distributed systems and job semantics

Learn: partitions, retries, idempotency, leases, fencing, timeouts, and clocks.  
Mission: reason through five failure points in one diagnostic job.  
Deliverable: job state machine and retry matrix.  
Gate: the design never converts missing evidence into success.

#### Module 5: Relational data and concurrency

Learn: transactions, constraints, indexes, migrations, row locks, and retention.  
Mission: model endpoints, identities, observations, jobs, leases, results, and
audit events.  
Deliverable: initial schema and invariants.  
Gate: duplicate claims and cross-endpoint result writes fail safely.

### Track B — Build the read-only vertical slice (28–40 hours)

#### Module 6: Protocol simulator

Learn: typed messages, validation, versioning, and test fixtures.  
Mission: write an in-process simulated agent that enrolls and heartbeats.  
Deliverable: protocol definitions and contract tests.  
Gate: malformed, oversized, replayed, and expired messages are rejected.

#### Module 7: Endpoint registry and freshness

Learn: observation versus derived state.  
Mission: show one simulated endpoint as healthy, stale, then offline without
changing its identity record.  
Deliverable: API and simple UI.  
Gate: freshness calculation is deterministic and tested around boundaries.

#### Module 8: Linux agent service

Learn: Go basics, service lifecycle, filesystem layout, signals, and local state.  
Mission: run the agent as an unprivileged `systemd` service on one disposable VM.  
Deliverable: signed development build, unit file, package draft, and uninstall.  
Gate: no inbound listener, no root service, strict key permissions, clean removal.

#### Module 9: Read-only collectors

Learn: collector interfaces, timeouts, sanitization, and platform variance.  
Mission: collect hostname, OS release, boot ID, agent version, disk summary, and
selected service state.  
Deliverable: versioned inventory payload.  
Gate: collectors are bounded and never collect command lines or secrets by default.

#### Module 10: Observability and audit

Learn: metrics versus logs versus traces versus audit records.  
Mission: trace one heartbeat from agent through gateway, API, and database.  
Deliverable: correlation scheme, dashboards, and audit event catalog.  
Gate: an operator can explain a stale endpoint without reading application code.

#### Module 11: Revocation and recovery

Learn: certificate revocation, disabled identities, backup, restore, and fail-safe
behavior.  
Mission: revoke the canary, prove reconnection fails, restore the database into an
isolated environment, and preserve the revocation state.  
Deliverable: tested runbook and recovery evidence.  
Gate: restoring a backup does not silently reauthorize a revoked endpoint.

### Track C — Add bounded management (30–45 hours)

#### Module 12: Typed action model

Learn: action schemas, allowlists, hashes, signatures, target binding, and expiry.  
Mission: define a `collect_diagnostics` action with no user-supplied command text.  
Deliverable: action manifest and handler contract.  
Gate: arbitrary executable paths, shell syntax, and unbounded arguments are absent.

#### Module 13: Scheduler, lease, and cancellation

Learn: durable queues, worker claims, fencing tokens, cancellation, and unknown
results.  
Mission: survive duplicate delivery and a network loss after execution.  
Deliverable: tested job state transitions.  
Gate: a non-idempotent job is never automatically retried.

#### Module 14: Approval and authorization

Learn: RBAC, separation of duties, target scope, step-up authentication, and
break-glass design.  
Mission: require a second identity to approve a canary action.  
Deliverable: authorization matrix and denial tests.  
Gate: authorization is checked at creation, approval, dispatch, and agent receipt.

#### Module 15: Privileged helper design

Learn: local IPC authentication, exact verbs, OS permissions, sandboxing, and
postconditions.  
Mission: design—but do not yet deploy—a helper for one narrowly privileged query
or repair.  
Deliverable: threat model, protocol, and rollback plan.  
Gate: no generic shell or arbitrary file-write primitive can be constructed.

#### Module 16: Secure agent updates

Learn: artifact signing, provenance, staged rollout, downgrade/freeze attacks,
key rotation, and recovery.  
Mission: update one disposable canary, verify it, then exercise a failed update.  
Deliverable: release metadata and recovery evidence.  
Gate: update trust is separated from the online control-plane administrator.

### Track D — Operate the product (20–30 hours)

#### Module 17: Deployment and secrets

Learn: reverse proxy, service identities, configuration, secrets, database
migrations, and environment separation.  
Mission: reproduce a test deployment from documented inputs.  
Deliverable: deployment manifest and configuration inventory.  
Gate: no secret is committed, printed by diagnostics, or shared between test and
production-intent environments.

#### Module 18: Reliability and capacity

Learn: service objectives, load shape, backpressure, rate limiting, retention,
and graceful degradation.  
Mission: simulate offline endpoints reconnecting at once.  
Deliverable: load test and bottleneck report.  
Gate: the gateway protects the database and remains administratively observable.

#### Module 19: Incident response for the RMM

Learn: operator compromise, key compromise, malicious action, audit preservation,
containment, and fleet recovery.  
Mission: tabletop a stolen administrator session and a stolen release-signing key.  
Deliverable: incident playbooks and emergency revocation plan.  
Gate: containment does not require trusting the component presumed compromised.

#### Module 20: Cross-platform release qualification

Learn: support matrix, package tests, upgrade compatibility, and end-of-life
policy.  
Mission: qualify one named Linux distribution and one named Windows release.  
Deliverable: compatibility evidence and known-limitations statement.  
Gate: “supported” means continuously tested, packaged, observable, and recoverable.

## 11. First build milestone

### Milestone 0 — Paper system

Deliverables:

- problem statement and v0 exclusions;
- architecture and trust boundaries;
- threat model;
- endpoint/observation/job/audit vocabulary;
- job state machine;
- support matrix draft;
- test and recovery strategy.

Acceptance:

- no operational lab change;
- security invariants are testable statements;
- every future privileged feature requires a separate design decision.

### Milestone 1 — Simulated vertical slice

Deliverables:

- control-plane API;
- PostgreSQL schema;
- simulated agent;
- one-time enrollment;
- heartbeat and freshness;
- endpoint list/detail page;
- revocation;
- correlated logs, traces, and audit events.

Acceptance:

- completely local or isolated test operation;
- no code execution on managed endpoints;
- automated tests for replay, expiry, duplicate heartbeat, stale state, revocation,
  malformed input, and database concurrency;
- backup and isolated restore test.

### Milestone 2 — Linux read-only canary

Deliverables:

- unprivileged Go agent;
- `systemd` service integration;
- development package;
- OS, boot, disk, and selected-service collectors;
- offline spool with strict size limits;
- install, upgrade, revoke, and uninstall runbooks.

Acceptance:

- one disposable Linux VM only;
- outbound-only authenticated communication;
- no general command execution;
- bounded CPU, memory, disk, network, and retry behavior;
- successful revocation and clean removal;
- evidence captured without secrets.

Only after these milestones should the project consider one typed, read-only
diagnostic job.

## 12. Architecture invariants

These are rules the code and tests must enforce:

1. Endpoint display names are never authorization identities.
2. Enrollment grants are short-lived, single-use, and not durable agent secrets.
3. Endpoint private keys are generated and retained on the endpoint.
4. Every accepted message is authenticated, versioned, bounded, and replay-aware.
5. Revocation is checked at connection and before job dispatch.
6. Missing results remain unknown; they never become success.
7. Agent actions are typed capabilities, not strings passed to a shell.
8. Targets, action content, expiry, approval, and audit correlation are immutable
   once a job is approved.
9. The core agent is unprivileged by default.
10. Any privileged helper exposes only exact, independently authorized verbs.
11. Update authority is separated from ordinary operator authority.
12. Server and endpoint collection paths redact secrets and enforce size limits.
13. Backups include identity and revocation state and are restore-tested.
14. A feature is not complete until its failure, cancellation, rollback or
    recovery, observability, and audit behavior are defined.

## 13. Decisions deliberately deferred

- product name and public branding;
- internet-facing or hosted operation;
- multi-tenancy;
- remote desktop;
- arbitrary shell or terminal;
- general file transfer;
- unattended mass patching;
- network isolation actions;
- integration with Wazuh, OPNsense, or the VM Factory;
- mobile clients;
- high-availability topology;
- dedicated message broker;
- commercial licensing or billing.

Deferral is not rejection. It keeps the first learning and security problem small
enough to reason about and test.

## 14. Authoritative reading

- CISA, [JCDC Remote Monitoring and Management Cyber Defense Plan](https://www.cisa.gov/topics/partnerships-and-collaboration/joint-cyber-defense-collaborative/jcdc-remote-monitoring-and-management-cyber-defense-plan)
- NIST, [SP 800-218 Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final)
- The Update Framework, [overview](https://theupdateframework.io/docs/overview/)
- The Update Framework, [security model](https://theupdateframework.io/docs/security/)
- Microsoft, [About Services](https://learn.microsoft.com/en-us/windows/win32/services/about-services)
- OpenTelemetry, [observability primer](https://opentelemetry.io/docs/concepts/observability-primer/)
- PostgreSQL, [Concurrency Control](https://www.postgresql.org/docs/current/mvcc.html)

These references guide the design; they do not substitute for product-specific
threat modeling, testing, or operating evidence.
