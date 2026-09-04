# Component Responsibilities

## Operator UI

Displays endpoint identity, observation freshness, findings, jobs, approvals, and
audit evidence. It never decides authorization by hiding or showing a button.

## API

Validates input and delegates to domain services. It authenticates the human
session, evaluates authorization for every request, and emits an audit intent.

## Endpoint registry

Owns durable endpoint IDs, public-key bindings, certificate status, enrollment,
revocation, supported capabilities, and mutable display attributes.

## Observation service

Accepts bounded, versioned observations; records endpoint observation time and
server receipt time separately; derives freshness without rewriting history.

## Policy service

Owns roles, scopes, action authorization, approval requirements, maintenance
constraints, target restrictions, and denial reasoning.

## Job service

Owns immutable job intent and legal state transitions. It never executes endpoint
actions directly.

## Scheduler

Claims jobs through durable leases and fencing tokens, respects expiry and
cancellation, and makes duplicate delivery safe to detect.

## Agent gateway

Terminates endpoint mTLS, checks revocation, validates message size/schema/version,
applies rate limits, binds messages to the authenticated endpoint, and relays
typed work/results.

## Agent service runtime

Composes only the agent gateway and its least-privilege PostgreSQL adapter. It
loads secret references separately from non-secret configuration, refuses root,
verifies the exact packaged migration set before socket bind, and owns graceful
listener shutdown. Enrollment and operator routes use separate processes and
credentials.

## Enrollment issuer client

Carries only the endpoint ID, pending identity ID, public-key fingerprint, CSR,
and request time from the enrollment process to the separately operated issuer.
It connects to one allowlisted private IP, verifies the issuer's DNS identity
with TLS 1.3, presents a dedicated enrollment-workload client certificate,
accepts no redirects, and bounds the returned public certificate chain. The RMM
service never loads or receives the endpoint CA private key.

## Enrollment service runtime

Composes only grant/CSR enrollment, the PostgreSQL adapter, and the isolated
issuer client. It refuses root, verifies schema and public issuer trust before
binding, exposes one bounded server-authenticated TLS route, rate-limits
pre-identity clients, and owns graceful listener shutdown. Its database,
inbound-server, and issuer-workload credentials are separate.

## Operator session verifier client

Presents one dedicated operator-service workload certificate to one allowlisted
private verifier address while checking its independent DNS TLS identity. It
forwards the opaque bearer credential only to the fixed verification route,
accepts one exact bounded current-session response, and never caches positive
identity state or follows redirects.

## Operator service runtime

Composes only the read-only operator application, its least-privilege
PostgreSQL adapter, and the external session verifier. It refuses root, verifies
schema and distinct inbound/verifier TLS identities before binding, exposes only
the endpoint list and canonical detail routes, and owns bounded admission and
graceful shutdown. It shares no listener or credential with enrollment or agent
ingress.

## Audit writer

Writes append-oriented structured events with actor, subject, action, decision,
reason, target, request/correlation IDs, timestamps, and sanitized result
references. Application logs do not replace audit records.

## Endpoint agent core

Runs without administrative privilege, maintains identity and connection state,
dispatches only compiled typed handlers, enforces local policy, and limits spool,
CPU, memory, output, retries, and concurrency. It reserves each outbound message
sequence durably under a single-writer lock before constructing the message.

## Collectors

Operating-system-specific, read-only, individually timed, size-bounded modules.
Collector failure is isolated and reported as partial or unavailable data.

## Privileged helper

Does not exist before Phase 5. If approved, it is a separate process exposing
exact verbs over authenticated local IPC. It cannot execute general commands or
write arbitrary paths.

## Update client

Does not trust ordinary operator/API credentials. It verifies signed metadata,
artifact digest, target platform, version monotonicity, expiry, rollout ring, and
rollback policy before replacing the agent.
