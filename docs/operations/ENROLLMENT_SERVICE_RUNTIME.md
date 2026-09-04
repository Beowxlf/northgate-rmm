# Enrollment Service Runtime

## Scope

`northgate-rmm-enrollment-service` is the one-time, server-authenticated TLS
entry point that exchanges an approved enrollment grant and endpoint-generated
CSR for a short-lived endpoint certificate. It owns no certificate-authority
private key. It authenticates separately to the isolated issuer with a dedicated
workload certificate and accepts only public certificate material in return.

This process has no post-enrollment agent, operator, job, shell, file-transfer,
update, or remote-access route. This source and disabled reference unit do not
authorize installation or a lab change. An exact VM Factory plan and separate
G2 approval remain required.

## Startup and shutdown contract

The executable takes one argument:

```text
northgate-rmm-enrollment-service --config /etc/northgate-rmm/enrollment-service.json
```

The bounded JSON configuration rejects duplicate, missing, and extra fields and
contains paths rather than secrets. The process refuses root. Before binding it
loads exactly one public endpoint-issuer trust root, constructs a TLS 1.3 mTLS
client for one fixed private issuer address and DNS authority, connects to one
fixed private PostgreSQL address with verified TLS, and verifies every packaged
database migration and checksum. Any failure leaves the enrollment socket
closed.

The inbound listener is TLS 1.3 server-authenticated because an endpoint has no
client identity yet. Raw TCP connections enter a separate pre-TLS admission
boundary limited to 16 handshakes globally and two per source before the process
performs a bounded handshake. Each slot remains held through the TLS session and
one-second bounded teardown; a peer that ignores shutdown is aborted. The
service then accepts only one exact HTTP/1.1 enrollment route, bounds headers
and body, rejects ambiguous framing, permits four
concurrent operations globally and one per source, and applies source and global
rate limits. A timed-out issuer or database worker retains its admission slot
until it actually finishes, preventing abandoned work from bypassing the
concurrency bound. Issuer transport re-arms every blocking operation with the
remaining monotonic whole-request budget, so a trickled response cannot reset
the 30-second maximum. Expected issuer, certificate-validation, and PostgreSQL
dependency faults return the same generic service-unavailable response.

`SIGINT` or `SIGTERM` stops admission, rejects new database work, cancels known
database connections, and closes connection handlers. Issuer calls have an
absolute 30-second maximum; the reference unit provides a 45-second stop budget
for that bound and executor cleanup.

## Credentials and segmentation

The reference unit uses a distinct `northgate-rmm-enrollment` identity and
separate systemd credentials for the database DSN and issuer workload
certificate and key. The inbound listener key is a different server identity.
The endpoint-issuer root and issuer-service CA are public trust material.
Every inbound and issuer TLS certificate, trust anchor, and private key is
opened as a bounded no-follow regular file and held by inode while OpenSSL loads
it; private keys additionally require root/service ownership and no group or
world permissions.

Approved network policy must permit only:

- the enrollment source zone to the enrollment listener's exact private IP and
  port;
- the enrollment service identity to the issuer's exact private IP and port;
- the enrollment service identity to PostgreSQL's exact private IP and port;
- explicitly documented DNS, time, and revocation dependencies, if selected.

There is no enrollment-to-agent-service or issuer-to-database flow. The issuer
must deny every client identity except the enrollment workload and must expose
only the certificate issuance route. The database role may consume grants and
write pending/issued identity state but may not migrate schema or administer the
database.

## Fail-closed acceptance checks

Before a G2 canary, prove that root execution, public/wildcard routes, port zero,
relative or symlinked inputs, broad secret permissions, invalid TLS material,
schema drift, issuer identity failure, duplicate HTTP framing, oversized input,
grant replay, CSR proof failure, certificate-binding mismatch, and issuer outage
all fail without issuing a credential or exposing internal detail. Also prove
that plaintext and untrusted TLS clients cannot submit enrollment, rate limits
hold under timeout, shutdown meets the approved objective, and diagnostics do
not contain grants, DSNs, private keys, CSR bodies, or certificate bodies.
