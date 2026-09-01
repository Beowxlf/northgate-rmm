# Linux Agent Package Lifecycle

Status: Source draft; not approved for installation  
Candidate: Debian 12 amd64  
Gate: G2 closed

## Boundary

The repository contains a machine-validated lifecycle contract and hardened
`systemd` unit under `agent/packaging/debian/`. They are review artifacts, not
an installable package. No package manager, service manager, endpoint, VM,
control plane, identity, or network is contacted by the validation tests.

## Filesystem and identity contract

| Purpose    | Path                                                  | Ownership and treatment                          |
| ---------- | ----------------------------------------------------- | ------------------------------------------------ |
| Executable | `/usr/libexec/northgate-rmm/northgate-rmm-agent`      | `root:root` mode `0755`; not yet built/installed |
| Unit       | `/usr/lib/systemd/system/northgate-rmm-agent.service` | `root:root` mode `0644`; source draft            |
| Config     | `/etc/northgate-rmm/agent.json`                       | `root:northgate-rmm` mode `0640`; non-secret     |
| State      | `/var/lib/northgate-rmm`                              | `northgate-rmm:northgate-rmm` mode `0700`        |
| Identity   | `/var/lib/northgate-rmm/identity`                     | service-owned directory `0700`; bundle `0600`    |

The service identity has no login shell, administrative membership, ambient
capability, or capability bounding set. Installation must leave the service
disabled. Enrollment and activation require a separate authorized workflow.

## Lifecycle invariants

1. Install creates the locked service identity and private directories, places
   only verified root-owned artifacts, reloads unit metadata, and leaves the
   service disabled.
2. Upgrade stops only a running instance, replaces only verified artifacts,
   preserves configuration/state/identity, and restarts only if it was running.
3. Revoke invalidates the control-plane identity first, then stops and disables
   the service and removes the local identity material.
4. Uninstall refuses to claim safe completion before revocation. It removes the
   executable and unit while preserving configuration and state for recovery or
   investigation.
5. Purge is a separate destructive operation requiring explicit approval,
   confirmed revocation, and evidence export before it removes retained state and
   the service identity.

## Service containment

The draft unit runs unprivileged, exposes no listener, writes structured JSON to
the journal, and limits memory, CPU, tasks, file descriptors, and restart rate.
It makes the host filesystem read-only except for systemd-managed private state
and runtime directories; denies privilege gain and Linux capabilities; hides
unrelated processes; and protects kernel, device, home, namespace, control-group,
and temporary-file boundaries.

## Required evidence before G2

- deterministic Debian package build bound to source, digest, SBOM, provenance,
  and signing policy;
- network-isolated Debian 12 package-manager and `systemd` tests covering install,
  upgrade, failed upgrade, restart bounds, revoke, uninstall, purge, and recovery;
- verified file ownership/modes and proof the service runs as `northgate-rmm`;
- observed memory, CPU, task, descriptor, spool, and retry behavior;
- operational revocation and clean-removal evidence using synthetic canary
  identity only; and
- exact disposable VM, microsegmentation, recovery, retention, and separate G2
  authorization.
