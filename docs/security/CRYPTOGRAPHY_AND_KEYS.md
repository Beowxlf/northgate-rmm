# Cryptography and Key Management

## Key classes

| Key | Purpose | Online? | Custody |
| --- | --- | ---: | --- |
| Operator IdP keys | Human authentication | Yes | Identity provider |
| TLS server key | Gateway/API server identity | Yes | TLS service/secret store |
| Endpoint CA | Issue endpoint identities | Restricted | Dedicated PKI role |
| Endpoint private key | Authenticate one endpoint | Yes, endpoint only | OS-protected agent state |
| Audit integrity key | Checkpoint/sign audit batches | Restricted | Audit service |
| Update root key | Root release trust | No by default | Offline/separated custody |
| Update targets key | Authorize release artifacts | Controlled | Release role |
| CI provenance identity | Bind build to workflow/source | Ephemeral | CI OIDC |
| Remote-session credential | One OS session | Ephemeral | Credential broker/gateway |

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

## Update trust

Adopt TUF-style separated roles and metadata as the update design matures. Root
trust changes require an independently reviewed ceremony. Online compromise must
not be sufficient to publish an accepted arbitrary agent update.

## Compromise response

Identify affected key class and scope, stop dependent operations, revoke/rotate,
preserve evidence, distribute new trust through an independent path, reissue
identities, verify restored invariants, and document residual risk.
