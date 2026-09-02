# Linux Agent Package Lifecycle

Status: Sandbox package candidate; not approved for endpoint installation  
Candidate: Debian 12 amd64  
Gate: G2 closed

## Boundary

The repository contains an executable runtime, deterministic package builder,
machine-validated lifecycle contract, and hardened `systemd` unit under
`agent/`. CI creates a real `.deb` and installs it only in a disposable Debian
container whose network mode is `none`. No endpoint, VM, control plane, live
identity, credential, or private infrastructure data is available to that test.
The unsigned package is an ephemeral test artifact and is not published.

## Filesystem and identity contract

| Purpose            | Path                                                  | Ownership and treatment                       |
| ------------------ | ----------------------------------------------------- | --------------------------------------------- |
| Executable         | `/usr/libexec/northgate-rmm/northgate-rmm-agent`      | `root:root` mode `0755`; sandbox-tested       |
| Unit               | `/usr/lib/systemd/system/northgate-rmm-agent.service` | `root:root` mode `0644`; sandbox-tested       |
| Config             | `/etc/northgate-rmm/agent.json`                       | `root:northgate-rmm` mode `0640`; non-secret  |
| State              | `/var/lib/northgate-rmm`                              | `northgate-rmm:northgate-rmm` mode `0700`     |
| Identity           | `/var/lib/northgate-rmm/identity`                     | service-owned directory `0700`; bundle `0600` |
| Revocation receipt | `/etc/northgate-rmm/.identity-revoked`                | `root:root` mode `0600`; non-empty and fresh  |

The service identity has no login shell, administrative or supplementary group
membership, ambient capability, or capability bounding set. Installation rejects
a pre-existing account unless its system UID, primary group, home, shell, and
complete group assignment match the package policy. Installation must leave the
service disabled. Enrollment and activation require a separate authorized
workflow.

Expired or explicitly rejected messages move atomically from the active spool
to its private `rejected` directory. Rejected evidence has a separate byte quota
equal to the active spool quota and a 128-record limit. The oldest exact-payload
records are durably rolled over before either rejected limit is crossed, and each
removed message ID is audited through the closed event schema. Rejected data can
therefore consume at most one additional active-spool quota without stopping new
inventory. The newest retained record preserves durable order so later records
cannot reuse an earlier spool position.

## Lifecycle invariants

1. Install creates the locked service identity and private directories, places
   only verified root-owned artifacts, reloads unit metadata, and leaves the
   service disabled.
2. Upgrade stops only a running instance, replaces only verified artifacts,
   preserves configuration/state/identity, and restarts only if it was running.
3. Revoke invalidates the exact control-plane identity first, then stops and
   disables the service, removes local identity material, and writes a fresh,
   non-empty root-owned `0600` receipt. Enrollment, configure, and upgrade must
   invalidate older receipts.
4. Uninstall requires both absent local identity material and that protected
   receipt; absence alone is not proof. It removes the executable and unit while
   preserving configuration and state for recovery or investigation.
5. Purge is a separate destructive operation requiring explicit approval,
   confirmed revocation receipt, and evidence export before it removes retained
   state and the service identity. All three markers are root-owned `0600` files
   under `/etc/northgate-rmm`, outside service-writable state.

## Service containment

The unit runs unprivileged, exposes no listener, writes structured JSON to
the journal, and limits memory, CPU, tasks, file descriptors, and restart rate.
It makes the host filesystem read-only except for systemd-managed private state
and runtime directories; denies privilege gain and Linux capabilities; hides
unrelated processes; and protects kernel, device, home, namespace, control-group,
and temporary-file boundaries.

## Required evidence before G2

- release signing, SBOM, provenance, and protected artifact publication policy
  beyond the current deterministic ephemeral build;
- full-system Debian 12 tests covering upgrade, failed upgrade, restart bounds,
  live revoke, recovery, and systemd resource enforcement beyond the current
  network-isolated install/uninstall/purge and unit-verification test;
- verified file ownership/modes and proof the service runs as `northgate-rmm`;
- observed memory, CPU, task, descriptor, spool, and retry behavior;
- operational revocation and clean-removal evidence using synthetic canary
  identity only; and
- exact disposable VM, microsegmentation, recovery, retention, and separate G2
  authorization.
