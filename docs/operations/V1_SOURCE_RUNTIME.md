# Version 1.0 runtime source

This source implements private monitoring for Debian 12 amd64, Windows 11 amd64
and Windows Server 2022 amd64. Platform acceptance, independent review, service
installation, recovery drills, signing and deployment remain subsequent work.
No remote command, desktop, transfer, remediation or automatic installation
capability is added.

## Components and entry points

| Component                                             | Executable / source                             |
| ----------------------------------------------------- | ----------------------------------------------- |
| Inventory and heartbeat ingress                       | `northgate-rmm-agent-service`                   |
| One-time enrollment                                   | `northgate-rmm-enrollment-service`              |
| Same-key renewal                                      | `/v1/agent/renew` through authenticated ingress |
| Restricted endpoint intermediate                      | `northgate-rmm-issuer-service`                  |
| Owner session introspection                           | `northgate-rmm-oidc-service`                    |
| Read-only browser views                               | `northgate-rmm-operator-service`                |
| Independent audit intake                              | `northgate-rmm-audit-service`                   |
| Outbox delivery                                       | `northgate-rmm-audit-export`                    |
| Offline ledger rebuild                                | `northgate-rmm-audit-reconcile`                 |
| Server certificate assertions                         | `northgate-rmm-certificate-status`              |
| Offline trust material creation                       | `northgate-rmm-pki-admin`                       |
| Encrypted, signed database backups / isolated restore | `northgate-rmm-recovery`                        |
| Bounded historical observation cleanup                | `northgate-rmm-retention`                       |

All Python commands are declared in `pyproject.toml` and the isolated Debian
launcher. The server package carries disabled services and timer definitions.
Package operations require operational services and timers to be stopped.

## Configure before activation

For this lab deployment, use the existing shared private lab network described
in the [owner network decision](../governance/authorizations/V1-SHARED-LAB-NETWORK-2026-09-04.md).
Dedicated VLANs and separate subnets are optional. Use verified private addresses
in the listener and client configurations; retain their identity checks.

Copy the relevant `deploy/*.example.json` files to the exact paths in the service
units. Replace example authorities, network addresses, deployment UUIDs,
certificate pins and the owner subject from verified deployment inventory.
Templates deliberately do not contain private keys, client secrets or an enabled
identity-provider client. Supply service credentials through `LoadCredential`.
Keep the original credential files root-only. Public roots and service
configuration must be protected from modification by runtime accounts.

The issuer, IdP bridge and audit sink should run in separate private workloads;
the package contains their code, but does not require co-location. Each listener
requires TLS 1.3, a trusted client chain and an exact client certificate hash.
Use distinct issuer-calling credentials for enrollment and agent renewal. The
agent ingress loads its own `renewal-service.json`; it must not borrow the
enrollment service's credential directory.

Run migrations as the migration owner, then apply `deploy/database-roles.sql`.
Associate distinct database login identities with the matching NOLOGIN roles.
Do not run services as the database owner. Keep database administration and
backup identity grants separate from these runtime roles.

Start independent audit delivery before enabling `enforce_delivery` in
`audit_delivery_state`. Activation must verify it is true; the bootstrap SQL
only enables it when a recent signed acknowledgement already exists. Audit
writes then stop if acknowledgements are older than five minutes or the pending
queue reaches 10,000 events. Provision the checkpoint archive on independent
storage with external retention protection; the sink's file permissions alone
do not make storage immutable.

Certificate status uses an independently pinned Ed25519 key. The private
registry maps each server leaf's lowercase DER SHA-256 to `good` or `revoked`.
Publish every 30 seconds and serve only its public output directory using
`nginx-status.example.conf`. Assertions expire after 120 seconds. Agents verify
status before enrollment, renewal and message submission. An unavailable,
expired, revoked or incorrectly signed assertion rejects the connection.
Endpoint revocation remains enforced from the database on authenticated calls.
Keep trust-authority registry backups outside ordinary application restores.

## Private owner sign-in

Use the disabled Keycloak client template, the oauth2-proxy configuration and
the nginx operator configuration. Configure the private realm's browser flow to
require password and OTP, set the OTP execution's authentication-method reference
to `otp`, and configure the achieved ACR to match `required_acr`. Assign the
client's `viewer` role only to the intended owner and pin that user's immutable
subject in both the bridge and operator service. Enable the client only after
the flow is configured. Store its secret in the separate login and bridge
credential locations; provide oauth2-proxy a private cookie secret and IdP CA.

The bridge checks current introspection, subject, issuer, audience, role,
session age, ACR and AMR on every request. It does not infer MFA from successful
login. The proxy removes incoming identity headers and supplies the verified
access token. The backend must be reachable only through the private proxy.
IdP compatibility must be checked against the installed version during testing.

Configuration references: [Keycloak protocol mappers](https://www.keycloak.org/admin-api/protocol-mappers),
[Keycloak authentication flows](https://www.keycloak.org/docs/26.7.0/server_admin/),
[oauth2-proxy nginx integration](https://oauth2-proxy.github.io/oauth2-proxy/7.9.x/configuration/integration/).

## Recovery and retention

`northgate-rmm-recovery --config CONFIG backup NEW_ABSOLUTE_DIRECTORY` creates
a PostgreSQL custom-format dump, encrypts it to an independent age recipient,
and signs the manifest with a backup-specific Ed25519 key. `backup-auto` creates
a new dated directory beneath a configured backup mount. The online backup
identity has no decryption key. Install owner-protected `pg_dump`, `pg_restore`
and `age` at the absolute paths in the configuration. Storage-side retention
must preserve independent copies that the application cannot delete.

`restore DIRECTORY` requires an independently pinned manifest verification key,
the age recovery identity, `isolated_restore=true`, matching deployment UUID and
an empty database named `northgate_restore_*`. Keep its network isolated: a
database name is not a network isolation control. The command verifies the
signed ciphertext and decrypted dump, restores transactionally, and verifies
migrations. It never starts services or reconnects endpoints.

Rebuild an audit ledger using `northgate-rmm-audit-reconcile --config CONFIG
--new-ledger NEW_PATH --minimum-sequence N --minimum-hash HASH`. The minimum
checkpoint and key must come from independent custody. Divergence or a missing
prefix rejects recovery; the tool never swaps a live ledger. Reconcile restored
source state against the current independent sink before any reconnection.

Retention defaults to a hold. After storage policy is selected, the database
administrator can clear `retention_hold.active`. Batches remove at most 1,000
old observations (30-day heartbeat / 90-day inventory), retaining the newest
observation for each endpoint and type. Identity/replay counters and current
read models remain. Only independently acknowledged outbox rows older than a
year are eligible for local cleanup. Audit archive expiry requires separate
storage policy and incident-hold checks.

## Windows lifecycle

The Windows directory includes build, sign, verify, install, enroll, upgrade
and uninstall scripts. Builds are unsigned until the separately invoked signing
command receives authorized certificate custody. Verification pins both signer
and source commit. Installation also requires the signed executable's exact
hash. The service uses a virtual account, protected state, native collection,
native file locks and Windows ACL checks. It starts stopped for enrollment.

Upgrade preserves identity and queued data and retains the previous binary;
the script attempts rollback if service startup fails. Reconcile retained
`.previous` / `.pending` binaries before another upgrade. Uninstall removes the
service and retains protected evidence; revoke its endpoint identity separately.
The agent flag `--recover-renewal --config PATH` discards an unpublished temporary
identity file only when the installed identity is valid and the process lock is
available. An expired or missing identity requires revocation and re-enrollment.

Windows storage uses write-capable directory handles with `FlushFileBuffers`;
flush failures remain failures. Filesystem/power-loss qualification on the named
Windows targets remains part of product testing. See Microsoft's
[flush API contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
