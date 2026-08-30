# Observability and Service Objectives

## Signals

### Metrics

- authenticated/failed enrollments and connections;
- active, stale, offline, revoked, and incompatible endpoints;
- heartbeat and inventory latency/size/rejection;
- queue depth, job age, lease conflicts, retries, unknown results;
- authorization allow/deny and approval latency;
- database pool, query latency, locks, replication/backup state;
- gateway connections, reconnect rate, throttling, and rejected messages;
- session grants, tunnels, active sessions, forced terminations;
- update rings, failures, pauses, and rollback/recovery;
- audit-write success, lag, and integrity checkpoint status.

For G6, a constrained Z5 evaluator produces a signed rollout-health attestation
binding the exact artifact, observed ring, window, sample size, required
availability/security thresholds, result, evidence digest, and freshness. It
cannot approve a rollout or alter release state; the status authority uses the
attestation only alongside a separately signed rollout decision.

Metrics must avoid endpoint names, job IDs, user IDs, or other unbounded sensitive
labels.

### Logs

Structured diagnostic events with severity, service, environment, request and
correlation IDs, stable error code, and sanitized context. Logs do not include
secrets, payload bodies, command output, credentials, or recording content.

### Traces

Trace enrollment, observation ingestion, authorization, job scheduling/result,
and session creation/termination across components. Sensitive values are not span
attributes.

### Audit

Security-relevant records defined in the threat and authorization models. Audit
has independent access, retention, and integrity controls.
Before privileged operator use, protected evidence records the signed IdP
issuer/tenant/subject/session/client binding, RMM session correlation, and a
non-secret opaque IdP revocation handle for case-scoped recovery lookup.
Every protected-audit query or export appends immutable correlated intent and
result events; inability to record them fails the access/export closed.

## Initial service-level indicators

- valid heartbeat ingestion availability and latency;
- freshness-classification correctness;
- authorization decision availability and latency;
- audit-write durability and lag;
- revocation propagation time;
- job/session forced-termination time in later phases;
- backup success and restore-test success.

## Objective policy

Numerical objectives are set only after load/failure measurements. A target that
cannot be measured and tied to a user or security outcome is not an SLO.

## Alert principles

Alert on actionable user/security impact, sustained error budgets, revocation or
audit failures, unexpected privilege, integrity loss, and capacity exhaustion.
Avoid per-endpoint transient alerts that create noise; use persistence, grouping,
maintenance context, and escalation.
