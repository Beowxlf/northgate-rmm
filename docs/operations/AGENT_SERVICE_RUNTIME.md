# Agent Service Runtime

## Scope

`northgate-rmm-agent-service` is the executable boundary for post-enrollment
heartbeat and read-only inventory delivery. It composes only the private mTLS
agent listener and the PostgreSQL control-plane adapter. It has no enrollment,
operator, job, shell, file-transfer, update, or remote-access route.

Enrollment and operator traffic must use different executables, service
identities, listener certificates, and firewall policy. Do not add those routes
to this process for deployment convenience.

This source and reference unit do not authorize installation or a lab change.
The Factory may generate a non-deployment plan while `V1D-SV` is closed, but an
exact control-plane authorization binding its approved plan, service identity,
addresses, certificate profile, firewall flows, secret references, expiry, and
rollback remains required before execution. Before G2, the V1D
server-validation authority may admit only synthetic validation identities on
the named private server with
all canary and endpoint routes blocked. G2 remains required before this service
admits traffic from a disposable canary or any other endpoint.

## Startup contract

The executable takes one argument:

```text
northgate-rmm-agent-service --config /etc/northgate-rmm/agent-service.json
```

The JSON file is bounded to 16 KiB, must be a regular non-symlink file, rejects
duplicate or additional fields, and contains references rather than secret
values. [`deploy/agent-service.example.json`](../../deploy/agent-service.example.json)
shows the exact schema. Its loopback address and `.invalid` authority are safe
examples, not deployable NorthGate values.

The database DSN is read separately from an absolute, bounded credential file.
On Debian it must be owned by root or the service account and have no group or
world permission. It is never placed in the JSON configuration or command line.
The reference systemd unit uses `LoadCredential=` so the service receives the
DSN beneath its private runtime credential directory.

The v1 DSN names one RFC1918 IPv4, IPv4 loopback, IPv6 ULA, or IPv6 loopback
literal. DNS names, public, reserved, documentation, link-local, multicast, and
unspecified addresses, libpq multi-host authorities, and `host`, `hostaddr`, or
`service` query overrides fail closed so the configured connection timeout is
an overall connection-attempt bound rather than a per-target multiplier.
The process also refuses every inherited `PG...` libpq environment variable;
all connection identity, routing, TLS, and timeout inputs must therefore come
from the validated credential and the service's explicit connection options.
Network database credentials must set `sslmode=verify-full`, name an absolute
Debian `sslrootcert` path, and set `gssencmode=disable`. Opportunistic TLS,
plaintext fallback, and ambient GSS negotiation are rejected before startup.

Before opening a socket, startup verifies that every migration packaged with the
service is present in PostgreSQL with the exact expected checksum. Migration is
a separate administrative action and identity; the runtime never applies or
repairs schema. Missing, additional, reordered, or changed migration state keeps
the listener closed.

The process refuses to run as root. It binds a fixed, private IP literal and
non-privileged port, loads a TLS 1.3 server identity, requires an endpoint client
certificate, and validates the endpoint CA and certificate profile at the
existing listener boundary. `SIGINT` and `SIGTERM` stop admission and close the
listener. Before listener cleanup, shutdown rejects new database connections,
cancels and closes every registered connection, and makes any connection race
fail after the configured maximum 30-second connect timeout. Cancellation runs
on the service thread, not behind the database worker queue, and is bounded to
one second for each of the listener's eight admitted operations. The reference
unit allows 45 seconds for those overlapping bounds, five-second listener
cleanup, and executor shutdown before systemd may force termination.

## Reference Debian service

[`deploy/systemd/northgate-rmm-agent-ingress.service`](../../deploy/systemd/northgate-rmm-agent-ingress.service)
is a disabled reference unit. Its ingress-specific name cannot collide with the
endpoint package's `northgate-rmm-agent.service`. It expects:

- a dedicated `northgate-rmm-agent` system user and group;
- an immutable application virtual environment under `/opt/northgate-rmm`;
- non-secret configuration under `/etc/northgate-rmm`;
- separately permissioned TLS key material;
- a root-protected DSN source consumed through systemd credentials; and
- guest and upstream firewall enforcement for the exact Z4 endpoint-to-Z2 agent
  ingress and Z2 application-to-Z3 database flows.

The unit grants no Linux capabilities and applies a system-service syscall and
filesystem hardening baseline. Qualification must prove the final Debian image,
Python runtime, cryptography provider, PostgreSQL path, DNS/time dependencies,
and chosen hardening directives together; the reference unit is not evidence
that an untested host supports them.

## Fail-closed acceptance checks

Before a G2 canary, isolated tests must demonstrate:

1. root execution, wildcard/public bind addresses, port zero, relative paths,
   duplicate/extra JSON fields, broad DSN permissions, and symlinks are rejected;
2. a missing, modified, or additional database migration prevents socket bind;
3. invalid server key, certificate, endpoint CA, or TLS profile prevents bind;
4. the service exposes only the agent message route and rejects enrollment and
   operator traffic;
5. database timeout and audit failure do not produce a successful receipt;
6. `SIGTERM` closes the socket within the approved stop objective; and
7. logs and diagnostics do not contain the DSN, private keys, enrollment grants,
   bearer credentials, or endpoint certificate material.
