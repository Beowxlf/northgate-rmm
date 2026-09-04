# Agent Protocol

## Transport

- TLS 1.3 preferred; TLS 1.2 allowed only when required by an approved supported
  platform and configured with modern suites;
- server authentication during enrollment;
- mutual TLS after enrollment;
- agent-initiated outbound connection;
- no secrets in URL query strings;
- bounded request bodies, response bodies, headers, and decompression ratios;
- idle, request, job, and shutdown timeouts.

Post-enrollment inventory delivery uses `POST /v1/agent/messages`. A spool item
is acknowledged only by an HTTP 200 JSON object containing exactly the same
canonical `message_id` and `accepted: true`. Redirects, environment proxies,
connection reuse, response compression, acknowledgement mismatch, and unknown
acknowledgement fields fail closed. A transient network, rate-limit, or server
error may use bounded exponential backoff with cryptographic jitter; permanent
authentication, trust, protocol, or authorization failures do not retry.
The server must make an accepted message ID idempotent: if the response is lost,
an exact retry returns the same accepted acknowledgement without applying the
message again. Reuse of the ID with different authenticated identity or payload
fails permanently and is audited.

The V1B source implements this contract as an in-process application boundary
behind an agent-only listener adapter. The adapter requires TLS 1.3 mutual
authentication, disables session tickets, accepts a private exact bind address
and authority, validates the single canonical endpoint URI SAN and supported
public key, and removes framework version headers even from parser failures.
It bounds TLS-handshake, header-read, and whole-request time; body size; backlog;
global and per-identity active body readers; database statement/lock time; and
global and per-identity request rate. Timed-out synchronous store work retains
its admission slot until the worker actually exits. Real loopback tests prove
successful profiled mTLS delivery and rejection of stalled TLS, incomplete
headers, one-identity concurrency saturation, excess rate, a stalled store, a
missing client identity, TLS 1.2, duplicate headers, and wrong authority.
The application binds the extracted endpoint and public-key fingerprint to an
active database identity and retains an encoded-message digest for exact retry.
No listener is activated or configured for a NorthGate network by this source
qualification.

## Envelope

Every post-enrollment message includes:

- protocol version;
- message ID;
- authenticated endpoint binding;
- message type and schema version;
- boot/session ID and monotonic sequence when applicable;
- creation time and expiry where applicable;
- correlation ID;
- payload length and digest;
- replay context.

Transport identity, not a caller-provided endpoint field, determines the endpoint.
Revocation is checked during TLS authentication, before accepting a message, and
again before any future job or remote-session dispatch.

## Enrollment

1. Operator creates a single-use, short-lived grant bound to intended scope.
2. Agent generates a key pair locally using an operating-system CSPRNG.
3. Agent validates server trust and submits public key plus grant.
4. Server atomically consumes the grant, creates endpoint and identity records,
   and returns certificate/trust metadata.
5. Agent protects key material using supported OS permissions or secure storage.
6. First mTLS heartbeat confirms activation; failure leaves an inspectable pending
   state rather than silently repeating enrollment.

The endpoint certificate contains exactly one URI subject alternative name in
the form `urn:northgate-rmm:endpoint:<canonical-endpoint-uuid>`. The agent must
match that binding to the stored endpoint ID and validate the complete supplied
client-authentication chain before using the identity. Local identity publication
is create-once and must fail closed on a partial, permissive, malformed, expired,
or mismatched bundle.

Enrollment grants are bootstrap authorization, not agent identities.

## Heartbeat and inventory

Heartbeat contains minimal liveness/capability state. Inventory is independent,
versioned, less frequent, and collector-specific. Partial inventory does not make
the heartbeat invalid.

Server receipt time defines communication freshness. Agent time is retained as an
observation and evaluated for skew.

For the read-only Linux agent, one exclusively locked private local store reserves
the next sequence before a message is created. One in-process critical section
extends from reservation through spool publication, so durable delivery order
cannot invert sequence order. The counter continues across agent restart for the
same kernel boot ID and starts at one for a new kernel boot ID. Reservation gaps
are valid after a later operation fails; reuse is not. A corrupt, ambiguous,
wrong-owner, multiply linked, permissive, or concurrently opened store fails
closed. Linux validation also walks the parent chain and rejects symlinked,
untrusted-owner, or mutable non-sticky ancestors that could replace the store's
directory entry. This local crash-durability control does not claim to resist VM
or filesystem rollback. A restored lower counter is rejected by the control
plane's identity/boot floor; the separate G6 update-status sequence requires the
externally allocated and independently anchored rollback-resistant design.

## Job delivery

No endpoint job exists before Phase 4. When enabled, a job includes exact target,
typed action/version, immutable parameter digest, approval reference, not-before,
expiry, timeout, idempotency class, attempt, lease/fencing token, and result size
limits.

Agent checks, in order:

1. server and message authenticity;
2. endpoint target match;
3. protocol/action support;
4. approval/action digest match;
5. not-before and expiry with allowed skew;
6. replay and attempt policy;
7. local authorization and resource policy;
8. concurrency and maintenance constraints.

## Outcomes

`succeeded`, `failed`, `rejected`, `timed_out`, `cancelled`, `expired`,
`unsupported`, and `result_unknown` are distinct. Transport acknowledgement and
domain postcondition success are distinct.

## Compatibility

- additive optional fields are preferred;
- unknown critical fields or unsupported required capabilities reject safely;
- control plane supports at least the current and previous qualified agent
  protocol during staged rollout;
- compatibility fixtures are preserved across releases;
- downgrade behavior is explicit and tested.
