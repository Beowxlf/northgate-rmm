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
