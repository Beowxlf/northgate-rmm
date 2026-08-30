# Cryptography and Key Management

## Key classes

| Key                       | Purpose                       |            Online? | Custody                   |
| ------------------------- | ----------------------------- | -----------------: | ------------------------- |
| Operator IdP keys         | Human authentication          |                Yes | Identity provider         |
| TLS server key            | Gateway/API server identity   |                Yes | TLS service/secret store  |
| TLS PKI client identity   | Authenticate issuance/renewal |         Restricted | Separate secret reference |
| Endpoint CA               | Issue endpoint identities     |         Restricted | Dedicated PKI role        |
| Endpoint private key      | Authenticate one endpoint     | Yes, endpoint only | OS-protected agent state  |
| Audit integrity key       | Checkpoint/sign audit batches |         Restricted | Audit service             |
| Update root key           | Root release trust            |      No by default | Offline/separated custody |
| Update targets key        | Authorize release artifacts   |         Controlled | Release role              |
| CI provenance identity    | Bind build to workflow/source |          Ephemeral | CI OIDC                   |
| Remote-session credential | One OS session                |          Ephemeral | Credential broker/gateway |

## Requirements

- use platform and maintained library primitives, not custom cryptography;
- maintain an inventory of fingerprint, algorithm, purpose, owner, creation,
  activation, expiry, rotation, revocation, and recovery status;
- encrypt private keys at rest when supported and restrict OS permissions;
- never export endpoint private keys through telemetry or support bundles;
- separate test, lab-canary, and production roots;
- test rotation and compromise recovery before reliance;
- log key identifiers/fingerprints, never private or secret material.

## Endpoint identity lifecycle

Generate locally, enroll with public key, activate after first mTLS proof, rotate
with an authenticated overlap, revoke immediately on compromise/retirement, and
destroy during verified uninstall. VM clones must not silently share identity.

## TLS server revocation

Z2 server certificates use short lifetimes and a signed status mechanism with a
maximum five-minute freshness window. Approved Z1, Z4, and Z8 clients hard-fail
missing, invalid, stale, unknown, or revoked status and can reach the independent
server-PKI status service without trusting Z2. Emergency revocation and rollover
use the independent Z1 recovery identity and are tested before endpoint reliance.
The TLS service's PKI issuance-client identity is separate from its served
certificate. When Z2 is suspected, recovery first disables or rotates that client
identity and proves it cannot obtain a replacement certificate, then revokes or
rolls the served certificate. New issuance authority is provisioned only to a
rebuilt and verified Z2 through the approved secret path.
Protected evidence records the client-change intent, old/new public identifiers,
signed PKI result, and verified denial-test outcome without client secrets.
Long-lived Z1, Z4, and Z8 TLS channels close and fully re-handshake with fresh
status at least every five minutes; resumption and 0-RTT cannot bypass the check.

## Update trust

Adopt TUF-style separated roles and metadata as the update design matures. Root
trust changes require an independently reviewed ceremony. Online compromise must
not be sufficient to publish an accepted arbitrary agent update.

## Compromise response

Identify affected key class and scope, stop dependent operations, revoke/rotate,
preserve evidence, distribute new trust through an independent path, reissue
identities, verify restored invariants, and document residual risk.
