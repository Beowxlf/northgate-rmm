# NorthGate RMM VM and Network Change Packet — 2026-08-30

Status: Plan only — not approved for execution  
Candidate change: `NG-CHG-20260830-001`  
Discovery authority: read-only NorthGate MCP and pinned OPNsense guest access  
Product gate: G1 remains open; G2 remains closed

## Decision summary

The proposed RMM service VM is `NG-VM-022 / NG-RMM-CP01`. The proposed first
managed endpoint is the separate disposable Linux canary
`NG-VM-023 / NG-RMM-CAN01`.

Do not submit the current Factory plan. The live Factory proved that it can
register a catalog-backed Debian Create plan, but its current request does not
represent the complete RMM design. Before VM creation, the Factory must gain
reviewed RMM-specific network, bootstrap, recovery, protected-storage, and
service-data-disk policy. The network boundary must be approved and changed
separately from the VM manifest.

## Read-only discovery evidence

Collected on 2026-08-30 without changing the host, VMs, switch, VLAN, firewall,
DNS, DHCP, or Factory policy.

| Area                       | Observed state                                                                                                      | Planning consequence                                                         |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Factory service            | `northgate-lab` 1.12.0 online on `HC-HV01`                                                                          | Use the guarded Factory; do not call a generic VM creator                    |
| Host                       | Windows Server 2022; 32 logical processors; about 192 GiB RAM                                                       | The 4-vCPU/8-GiB server envelope is feasible, subject to fresh plan reserves |
| VM inventory               | 18 VMs: 12 running and 6 off                                                                                        | Neither proposed RMM VM name exists                                          |
| F: storage                 | About 666 GiB free                                                                                                  | Preferred for the proposed 80-GiB OS and 100-GiB data disks                  |
| D: storage                 | About 169 GiB free                                                                                                  | Too close to the Factory reserve for the proposed 180-GiB allocation         |
| Image                      | `debian-12.12-amd64-netinst`, SHA-256 `dfc30e04fd095ac2c07e998f145e94bb8f7d3a8eca3a631d2eb012398deae531`            | Approved immutable Linux source candidate                                    |
| RMM fabric                 | `NorthGate-App-Trunk` is a private Hyper-V switch                                                                   | Reuse the existing private fabric; do not create a new virtual switch        |
| OPNsense trunk             | Native VLAN 0; allowed VLANs `110,120,130,140,150,160,240,250`                                                      | VLANs 170 and 180 require a separately approved trunk change                 |
| Routed networks            | Existing /24 networks match their VLAN numbers through 160, plus 240 and 250                                        | VLAN 170 and 180 are unconfigured; no address is treated as reserved yet     |
| OPNsense services          | Packet filter, DHCPv4, Unbound DNS, NTP, SSH, web GUI, and WireGuard running                                        | Preserve management and console recovery throughout any network change       |
| OPNsense before-state hash | SHA-256 `af671f7259a2966255674371141eb17bd10b075a8ff1e04c53b124e2938407b3`                                          | Recollect immediately before change and bind the backup to the new hash      |
| Existing dependencies      | DNS/time at `10.10.100.150`; Wazuh at `10.10.100.14`; exact admin sources include `10.10.100.11` and `10.10.100.21` | Reuse only exact-source flows; do not add broad inter-zone access            |

The historical asset register contains conflicting assignments through
`NG-VM-021`. This packet deliberately begins at `NG-VM-022`; publication must
reserve both new IDs before any Factory release includes them.

## Factory dry-run result

The read-only planner accepted this structural request:

| Field                 | Value                                                              |
| --------------------- | ------------------------------------------------------------------ |
| Asset and VM          | `NG-VM-022 / NG-RMM-CP01`                                          |
| Image                 | `debian-12.12-amd64-netinst`                                       |
| Compute               | 4 processors; 8,192 MiB memory                                     |
| Requested disk        | 80 GiB                                                             |
| Planner storage class | `lab-ephemeral`                                                    |
| Plan ID               | `ngplan-ng-vm-022-2cf7d889c1f7`                                    |
| State hash            | `f8bec48f1e9e77e4e7b13e6aabb3db2be01366dd43c3df5f9363e71c77451c77` |
| Expiry                | 2026-08-30 16:32:13Z                                               |

This plan was not submitted and must never be reused. It is evidence that the
Factory Create path and collision preflight respond; it is not deployment
approval. It lacks the target network, protected persistent storage, dedicated
data disk, RMM bootstrap, recovery profile, and postcondition set below.

## Target server manifest

The Factory repository should eventually resolve this opaque desired state. Raw
paths, switch names, VLANs, addresses, commands, and credentials must remain in
host policy or the separately controlled network packet, not the VM manifest.

| Manifest field            | Target value                                                              |
| ------------------------- | ------------------------------------------------------------------------- |
| Asset ID / name           | `NG-VM-022 / NG-RMM-CP01`                                                 |
| Owner                     | `northgate-owner`                                                         |
| Purpose                   | Private Linux RMM control plane for one canary                            |
| Environment / criticality | infrastructure / high                                                     |
| Data classification       | confidential                                                              |
| Lifecycle                 | proposed until change approval                                            |
| Image / generation        | Debian 12.12 immutable image / Generation 2                               |
| Firmware                  | RMM Linux Gen2 Secure Boot profile; vTPM decision required                |
| Compute                   | 4 vCPU; dynamic 4-GiB minimum, 8-GiB startup and maximum                  |
| OS storage                | 80 GiB through proposed `persistent-rmm-protected-f`                      |
| Service data              | Separate 100-GiB dynamic VHDX through the same protected class            |
| Network                   | One vNIC through proposed `rmm-service` profile only                      |
| Bootstrap                 | Proposed `debian12-rmm-control-plane`                                     |
| Recovery                  | Proposed `rmm-control-plane-protected`                                    |
| Desired state             | Off after creation unless the approved plan includes bounded installation |
| Destruction control       | `destroyProtection: true`                                                 |

Required Factory additions before a deployable manifest exists:

1. schema, planner, host-plan, executor, receipt, and postcondition support for
   one explicitly declared service-data disk;
2. a negative-test-covered `rmm-service` network profile;
3. an asset-bound Debian bootstrap profile with no embedded secret;
4. protected F: storage and recovery profiles with reserve checks;
5. immutable identity-ledger entries and unique locally administered MAC
   `02AABBCC0016` for `NG-VM-022`;
6. exact release, policy, image, bootstrap-media, catalog, and manifest hashes;
7. a fresh post-merge host-issued plan and separate one-time approval.

## Target disposable canary manifest

G2, if later approved, permits only this one endpoint:

| Manifest field               | Target value                                                                               |
| ---------------------------- | ------------------------------------------------------------------------------------------ |
| Asset ID / name              | `NG-VM-023 / NG-RMM-CAN01`                                                                 |
| Purpose                      | Disposable Debian endpoint for enrollment, heartbeat, inventory, freshness, and revocation |
| Criticality / classification | low / internal                                                                             |
| Compute                      | 2 vCPU; dynamic 2-GiB minimum/startup and 4-GiB maximum                                    |
| Storage                      | 40-GiB OS disk through `lab-ephemeral-f`                                                   |
| Network                      | One vNIC through proposed `rmm-canary` profile only                                        |
| Bootstrap                    | Proposed `debian12-rmm-agent-canary`; no command/job capability                            |
| Recovery                     | `none-canary`; quarantine and delete/rebuild are the rollback                              |
| MAC                          | Proposed unique `02AABBCC0017`                                                             |
| Retirement                   | Seven days after G2 exercise unless an evidence-backed extension is approved               |

The server VM and endpoint canary require separate fresh plans, separate request
IDs, separate receipts, and separate acceptance decisions.

## Proposed microsegmentation

These exact values are candidates for review, not live reservations:

| Zone           | Factory profile | VLAN / subnet               | Address                            |
| -------------- | --------------- | --------------------------- | ---------------------------------- |
| Z2 RMM service | `rmm-service`   | VLAN 170 / `10.10.170.0/24` | gateway `.1`; `NG-RMM-CP01` `.10`  |
| Z4 RMM canary  | `rmm-canary`    | VLAN 180 / `10.10.180.0/24` | gateway `.1`; `NG-RMM-CAN01` `.10` |

The RMM database remains on the control-plane VM for the first lab slice. The
future Z2-to-Z3 boundary is enforced by a local PostgreSQL socket, distinct Unix
service/database identities, least SQL privilege, filesystem ownership, and a
host firewall. A networked Z3 database requires a later separation decision.

### Minimum candidate flows

All other new inter-zone paths are denied and logged. Stateful return traffic is
implicit and does not authorize a reverse initiating flow.

| Source                         | Destination              | Service                                           | Gate / control                                                     |
| ------------------------------ | ------------------------ | ------------------------------------------------- | ------------------------------------------------------------------ |
| `10.10.100.11`, `10.10.100.21` | `10.10.170.10`           | TCP 443                                           | Z1 operator access; OIDC MFA and RBAC required before privilege    |
| `10.10.100.11`, `10.10.100.21` | `10.10.170.10`           | TCP 22                                            | Key-only admin; exact sources; no root/password login              |
| `10.10.180.10`                 | `10.10.170.10`           | TCP 443                                           | G2 only; bootstrap TLS then endpoint-bound mTLS                    |
| `10.10.170.10`                 | `10.10.100.150`          | TCP/UDP 53; UDP 123                               | Exact internal DNS and time dependencies                           |
| `10.10.180.10`                 | approved DNS/time        | existing exact services                           | G2 only; no broad route created by RMM                             |
| `10.10.170.10`                 | `10.10.100.14`           | approved Wazuh ports                              | Write-only monitoring path; confirm current listener before change |
| `10.10.170.10`                 | approved package mirrors | TCP 443, and TCP 80 only when repository-required | Named aliases and signed packages; maintenance only                |

No server-initiated management route from Z2 to Z4 is permitted in this phase.
The endpoint initiates the only RMM connection.

### Network actions requiring separate approval

1. Export the current OPNsense configuration, verify its SHA-256, and confirm
   Hyper-V console recovery.
2. Extend only the exact `OPNsense-Tooling / APP-TRUNK` allowed list from
   `110,120,130,140,150,160,240,250` to
   `110,120,130,140,150,160,170,180,240,250`.
3. Create OPNsense VLAN 170 and 180 interfaces with the candidate gateway
   addresses; disable DHCP unless an explicit reservation design is approved.
4. Add only the rules in the minimum flow table, plus explicit default-deny
   logging on each new interface.
5. Add exact DNS records and address reservations only after collision checks.
6. Validate management access, existing VLANs, DNS, time, Wazuh, NAT, and
   expected blocked paths before considering the network change complete.

## G2 blockers

G2 remains closed until evidence identifies and validates:

- the human OIDC provider and phishing-resistant privileged MFA;
- server TLS PKI plus independent certificate-status service;
- offline endpoint root, restricted issuer, renewal, revocation, and status;
- protected append-only audit destination independent of the RMM service;
- encrypted backup target, retention, RPO/RTO, and isolated restore proof;
- the final signed Linux agent package and enrollment protocol;
- exact DNS names and approved addresses;
- Factory support for the complete server and canary manifests; and
- before/after network validation and rollback evidence.

Phase 1 code has no listener or real agent. Creating a connected server or
installing an endpoint agent before these controls exist would not satisfy the
approved phase model.

## Rollback and containment

Network rollback restores the hash-verified pre-change OPNsense configuration,
returns the trunk to its original allowed list, and confirms all existing VLAN
and management paths. VM rollback uses the Factory receipt and exact plan-bound
cleanup or quarantine path; it never infers deletion from a missing manifest.
Failed bootstrap leaves the VM off and isolated. No checkpoint is treated as a
backup.

## Approval boundaries

The following decisions remain separate:

1. approve the candidate asset IDs, names, network numbers, and addresses;
2. approve and merge the Factory capability/catalog/manifest changes;
3. approve the exact OPNsense backup-bound network change;
4. approve the fresh host-issued server VM plan ID and state hash;
5. accept the hardened server and recovery evidence;
6. open G2 for only `NG-VM-023 / NG-RMM-CAN01`;
7. approve the fresh canary plan and the single endpoint installation.

This packet authorizes none of those actions by itself.
