# Operator Service Runtime

## Scope

`northgate-rmm-operator-service` is the private, server-authenticated TLS entry
point for the version 1.0 endpoint list and detail views. It exposes only
`GET /endpoints` and `GET /endpoints/<canonical-endpoint-uuid>`. It has no
enrollment, agent-message, job, shell, file-transfer, update, remote-access, or
mutation route.

Every request carries an opaque bearer session to a separately authenticated
external verifier. The RMM process does not decode, cache, persist, or log that
credential. It independently matches the verifier's current identity
facts to one pinned issuer, tenant, subject, client, MFA requirement, role, and
maximum session age before reading endpoint state.

This source and disabled reference unit do not authorize installation, an IdP
connection, a database, a listener, or a lab change. Exact infrastructure and a
separate G2 approval remain required.

## Startup and shutdown contract

The executable takes one argument:

```text
northgate-rmm-operator-service --config /etc/northgate-rmm/operator-service.json
```

The bounded JSON configuration rejects duplicate, missing, and extra fields and
contains paths rather than secret values. It must remain root-owned and not
writable by the service identity. The process refuses root. Before
binding it proves that the public server identity and verifier-workload identity
use different public keys, constructs a TLS 1.3 mTLS client for one fixed private
verifier address and DNS authority, reads the database DSN from a protected
credential file, and verifies every packaged PostgreSQL migration and checksum.
Any failure leaves the operator socket closed.

The inbound listener permits only private or loopback IP literals and TLS 1.3.
Raw TCP connections enter a pre-TLS boundary limited to 16 handshakes globally
and two per source. Each slot remains held through the TLS session and bounded
teardown. Parsed HTTP/1.1 headers are limited to 6 KiB and 24 unique fields;
ambiguous framing, request bodies, wrong Host values, and plaintext fail closed.
Eight application requests may run globally and two per source, with additional
source and global rate ceilings. A timed-out database or verifier worker retains
its slot until it actually finishes. Responses are non-cacheable, carry a
restrictive content-security policy and HSTS, and are capped at 512 KiB.

The verifier call is a fixed `POST /v1/operator-sessions/verify` with no body,
no redirect path, the opaque Authorization header, and a dedicated workload
certificate. Its exact JSON response is capped at 16 KiB and must contain only
canonical UTC identity, session, role, expiry, and MFA fields. The transport
re-arms each blocking operation with the remaining whole-request deadline.
Unknown, unavailable, malformed, stale, revoked, or out-of-scope sessions all
fail closed without exposing the credential or dependency details.

`SIGINT` or `SIGTERM` stops admission, rejects new database work, cancels known
database connections, and closes connection handlers within the reference
unit's stop budget.

## Credentials and segmentation

The reference unit uses a distinct `northgate-rmm-operator` operating-system
identity and separate systemd credentials for the database DSN and verifier
client certificate and key. The inbound server key is a different identity.
TLS keys require root/service ownership with no group or world permissions;
certificate and key files are bounded, opened without following final symlinks,
and held by inode while OpenSSL loads them.

Approved policy must permit only:

- the administrative source zone to the operator listener's exact private IP
  and port;
- the operator workload identity to the verifier's exact private IP and port;
- the operator database role to the exact PostgreSQL address and port; and
- explicitly approved DNS, time, certificate-status, audit, and monitoring
  dependencies.

The operator database role may select version 1.0 endpoint/observation state and
append its own access decisions. It may not create grants, enroll or revoke an
identity, ingest observations, migrate schema, administer PostgreSQL, contact
agent/enrollment ingress, or use the verifier credential for another service.

## Fail-closed acceptance checks

Before a G2 canary, prove that root execution, public/wildcard routes, port zero,
relative or symlinked files, broad key permissions, shared TLS identities,
invalid TLS material, schema drift, duplicate or oversized headers, request
bodies, verifier rejection/outage, malformed verifier JSON, stale sessions,
wrong identity scope, database outage, oversized output, rate-limit exhaustion,
and timeout all fail without returning endpoint data or internal detail. Also
prove that plaintext and untrusted TLS clients cannot reach the application,
every accepted or rejected authorization is durably audited, shutdown meets the
approved objective, and diagnostics contain no bearer tokens, DSNs, private
keys, or endpoint inventory bodies.
