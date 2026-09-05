# RMM initial testing and deployment preflight — 2026-09-04

## Outcome

The owner approved isolated deployment of Version 1.0 monitoring with Linux and
Windows support, including the RMM server, Linux canary, private VLANs 170/180,
and a separate disposable Windows target. No RMM VM, firewall rule, network,
server service, or endpoint installation was changed in this run.

Deployment is blocked by the installed VM Factory capability. This is not a
request to repeat the owner's deployment approval. A compatible signed factory
release, asset-bound installation media, and fresh host-issued capabilities are
still required. The existing generic MCP planner does not represent the required
protected storage, second disk, encryption, bootstrap, and network profiles.

## Testing and fixes

- Python tests excluding PostgreSQL integration: 333 passed, 1 failed, 3 skipped,
  27 deselected. The failure was an outdated listener test double missing the
  renewal keyword argument. After correcting that fixture, the affected module
  passed: 38 passed, 2 skipped. The full suite was not repeated.
- The Windows Go suite initially encountered unsafe temporary-directory ACLs.
  The checks were retained. Tests were rerun in a dedicated protected local
  directory, `C:\ProgramData\NorthGateRMM-Test-20260904`.
- In that directory, all Go packages passed except two interrupted spool-move
  recovery tests. Windows rejected the two legitimate internal hard links left
  by an interrupted transition.
- The fix permits exactly the known two-name recovery pair after checking both
  files, parent permissions, link count, and file identity. External aliases and
  a third alias remain rejected. Spool and agent-command tests passed after the
  fix; the added negative-link test and targeted vet checks also passed.
- No PostgreSQL integration, deployed Linux-agent, deployed Windows-service,
  browser/MFA, recovery, or live end-to-end acceptance result is claimed.

## Live preflight evidence

Authenticated constrained factory status returned:

- installed release: `ngcor-1.0.46-fda336c`;
- apply enabled, Create only, no destructive operations;
- effective rollout: `windows-canary`, sequence 1;
- incomplete transactions: 0;
- backend policy SHA-256:
  `8d10bc3adb6677b05715d783590f1c84087b162c62a4897f5f9f7a9006181a54`;
- data bundle SHA-256:
  `46b671e3549c0127f1c4d7b39025efa6fb10a43a8325a03b47b7b49517a5d539`;
- release manifest SHA-256:
  `51393dd6915a56436b081c321f31172486e2c1b688cc9aea8eb2525f75c524cb`.

The installed backend policy contains neither NG-VM-022 nor NG-VM-023, and its
network mappings omit 170 and 180. A constrained `plan NG-VM-022` request was
rejected with `NGCOR-COMMAND-NOT-ALLOWED`; no apply was submitted.

Hyper-V inventory confirmed NG-RMM-CP01 and NG-RMM-CAN01 absent. The OPNsense
private trunk allows 110,120,130,140,150,160,240,250; guest inventory independently
confirmed no 170/180 interfaces. The existing domain controller is excluded
from RMM testing.

Storage readback: F had 713,990,520,832 bytes free; D had 180,316,676,096 bytes
free. These are observations, not reservations or approved plans. Capacity,
identities, and network state must be refreshed at apply time.

## Required deployment work

1. Extend and qualify the signed factory release for the two RMM assets and a
   uniquely registered disposable Windows target. Preserve existing assets and
   reserve checks. Reconcile proposed catalog names with the RMM design packet.
2. Bind protected F storage, the server's 80-GiB OS plus 100-GiB data disks,
   Secure Boot/vTPM, encrypted Debian bootstrap and recovery, and asset-bound
   media. Prepare and verify rollback before replacing the factory release.
3. Back up OPNsense configuration privately, then apply the approved VLANs and
   exact required flows, preserving management access and public isolation.
   Firewall rules with unresolved destinations remain disabled.
4. Generate fresh constrained plans after the compatible release is installed;
   do not reuse the expired August 30 plan or substitute the generic creator.
5. Deploy distinct private service identities, PostgreSQL, issuer, signed status,
   audit delivery, protected backups, and owner MFA. Resolve real service
   addresses and identity-provider configuration before activation.
6. Deploy the candidate, then perform a consolidated Linux/Windows acceptance
   pass: enrollment, inventory, heartbeat, renewal, revocation, isolation,
   restart/spool recovery, browser authorization, and backup/restore.

## Cleanup and residual risk

The local protected test directory remains available for the remaining Windows
qualification. It is not an installed RMM service. No lab rollback was needed
because lab discovery and the rejected planning request were non-mutating.
The source remains a candidate; passing unit tests does not establish deployed
product readiness.
