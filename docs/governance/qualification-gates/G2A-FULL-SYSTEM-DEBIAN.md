# G2A Full-System Debian Agent Qualification

Status: Implemented; exact CI evidence pending  
Parent gate: G2 remains closed  
Scope: Synthetic Debian 12 systemd sandbox only

## Purpose

G2A proves that the read-only Linux agent package behaves correctly under a real
Debian 12 `systemd` manager before any NorthGate endpoint installation. It is a
precondition for G2, not deployment authority.

## Required evidence

- Debian 12 with `systemd` as PID 1 and no network interface other than loopback.
- Deterministic base and upgrade packages built from the exact source commit.
- Fresh installation leaves the service disabled and inactive.
- Synthetic identity and configuration files have the required owner and mode.
- The service runs as `northgate-rmm` with no effective or bounding capabilities.
- `NoNewPrivileges`, filesystem/device/process protections, memory, CPU, task,
  descriptor, and restart limits are enforced by the real service manager.
- Memory, CPU, task, descriptor, spool, retry/restart, and structured-journal
  observations are recorded without credentials or private infrastructure data.
- A normal upgrade preserves identity, configuration, enablement, and activity.
- An injected payload collision fails during unpack after the active old package
  is stopped, then recovers that prior package and clears its restart marker.
- A bounded restart storm exhausts the configured retries, refuses another
  start, and recovers after repair.
- Synthetic revocation permits removal while retaining configuration and state.
- Separately marked evidence and approval permit purge, remove the service
  identity and retained state, and preserve the root-controlled purge transaction.

## Implementation

The `G2A full-system Debian qualification` workflow builds three ephemeral test
packages and a synthetic identity fixture. It starts the digest-pinned Debian 12
image with `systemd` as PID 1 on an ephemeral GitHub-hosted runner, disconnects
the container from every Docker network, copies in only the generated artifacts
and qualification harness, and records a bounded JSON result.

The privileged container setting exists only to run a nested service manager and
cgroup enforcement on the disposable runner. The workflow has read-only
repository permission, persists no checkout credential, consumes no secret, and
publishes no package or identity. NorthGate routing and infrastructure are absent.

## Closure rule

G2A is complete only when the exact reviewed pull-request head passes:

1. `Debian 12 systemd qualification`;
2. `Free-software security checks`; and
3. `Pre-code governance audit`.

The final evidence record must name the exact head, workflow run and job IDs,
package hashes, measured resource results, review disposition, and merge commit.

## Explicit exclusions

G2 remains closed. G2A does not authorize a NorthGate VM, endpoint installation,
live identity, enrollment, VLAN or firewall change, package publication, release
signature, control-plane connection, remote action, or update rollout.
