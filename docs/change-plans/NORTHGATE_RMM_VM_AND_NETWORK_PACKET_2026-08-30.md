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
| Firmware                  | Proposed `rmm-linux-gen2-vtpm`; Secure Boot and vTPM required             |
| Compute                   | 4 vCPU; dynamic 4-GiB minimum, 8-GiB startup and maximum                  |
| OS storage                | 80-GiB LUKS2 volume through proposed `persistent-rmm-protected-f`         |
| Service data              | Separate 100-GiB dynamic VHDX with an independent LUKS2 volume            |
| Network                   | One vNIC through proposed `rmm-service` profile only                      |
| Bootstrap                 | Proposed `debian12-rmm-control-plane`                                     |
| Recovery                  | Proposed `rmm-control-plane-protected`                                    |
| Desired state             | Off after creation unless the approved plan includes bounded installation |
| Destruction control       | `destroyProtection: true`                                                 |

Required Factory additions before a deployable manifest exists:

1. schema, planner, host-plan, executor, receipt, and postcondition support for
   one explicitly declared service-data disk;
2. a `rmm-linux-gen2-vtpm` firmware profile that requires Secure Boot and vTPM;
3. a negative-test-covered `rmm-service` network profile;
4. an asset-bound Debian bootstrap profile with no embedded secret;
5. protected F: storage and recovery profiles with reserve checks;
6. LUKS2 encryption for both disks, TPM-bound normal unlock, and distinct
   recovery material escrowed in an approved system outside the VM;
7. acceptance checks proving both volumes are encrypted and that a controlled
   recovery-key boot succeeds without exposing the key in Factory evidence;
8. immutable identity-ledger entries and unique locally administered MAC
   `02AABBCC0016` for `NG-VM-022`;
9. exact release, policy, image, bootstrap-media, catalog, and manifest hashes;
10. a fresh post-merge host-issued plan and separate one-time approval.

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

No rule containing `TBD` may be installed. Each conditional row must first be
replaced by an exact destination identity, address/alias, service, and validation
case. The owner reviews every rule by 2026-09-30; continued need requires a new
evidence-backed review date.

| ID          | Source                         | Destination                           | Service                        | Activation gate / control                                  | Owner                   | Evidence reference    |
| ----------- | ------------------------------ | ------------------------------------- | ------------------------------ | ---------------------------------------------------------- | ----------------------- | --------------------- |
| RMM-NET-001 | `10.10.100.11`, `10.10.100.21` | `10.10.170.10`                        | TCP 443                        | OIDC MFA, source/device policy, RBAC, and audit proven     | RMM service owner       | `NG-CHG-20260830-001` |
| RMM-NET-002 | `10.10.100.11`, `10.10.100.21` | `10.10.170.10`                        | TCP 22                         | Key-only admin; exact sources; no root/password login      | Linux platform owner    | `NG-CHG-20260830-001` |
| RMM-NET-003 | `10.10.180.10`                 | `10.10.170.10`                        | TCP 443                        | G2 only; bootstrap TLS then endpoint-bound mTLS            | RMM service owner       | `NG-CHG-20260830-001` |
| RMM-NET-004 | `10.10.170.10`                 | `10.10.100.150`                       | TCP/UDP 53; UDP 123            | Exact internal DNS and monitored time                      | Linux platform owner    | `NG-CHG-20260830-001` |
| RMM-NET-005 | `10.10.180.10`                 | approved exact DNS/time services      | Existing exact services        | G2; no broad route created by RMM                          | RMM endpoint owner      | `NG-CHG-20260830-001` |
| RMM-NET-006 | `10.10.170.10`                 | `10.10.100.14`                        | Exact approved Wazuh ports     | Listener revalidated; write-only monitoring path           | Security monitoring     | `NG-CHG-20260830-001` |
| RMM-NET-007 | `10.10.170.10`                 | approved exact package-mirror aliases | TCP 443; conditional TCP 80    | Maintenance window; signed packages; exact repositories    | Linux platform owner    | `NG-CHG-20260830-001` |
| RMM-NET-008 | `10.10.170.10`                 | `TBD approved human IdP`              | TCP 443                        | Required before operator privilege; signed tuple/status    | Identity service owner  | `NG-CHG-20260830-001` |
| RMM-NET-009 | `10.10.170.10`                 | `TBD endpoint issuer`                 | TCP 443                        | G2; workload mTLS; issuance/renewal/revocation/status only | Endpoint PKI owner      | `NG-CHG-20260830-001` |
| RMM-NET-010 | `10.10.170.10`                 | `TBD server PKI`                      | TCP 443                        | Required before TLS activation; exact lifecycle APIs       | Server PKI owner        | `NG-CHG-20260830-001` |
| RMM-NET-011 | Z1 managed TLS client          | `TBD server-PKI status service`       | TCP 443                        | Signed status only; stale/unknown/revoked fails closed     | Server PKI owner        | `NG-CHG-20260830-001` |
| RMM-NET-012 | `10.10.180.10`                 | `TBD server-PKI status service`       | TCP 443                        | G2; exact certificate status only; hard-fail policy        | Endpoint PKI owner      | `NG-CHG-20260830-001` |
| RMM-NET-013 | Z2 audit-writer identity       | `TBD protected Z5 audit sink`         | `TBD approved TLS port`        | Required before G2; mTLS, append only, no read/delete      | Security evidence owner | `NG-CHG-20260830-001` |
| RMM-NET-014 | Z2 backup-export identity      | `TBD protected Z6 backup target`      | `TBD approved backup protocol` | Required before service acceptance; write only, immutable  | Recovery owner          | `NG-CHG-20260830-001` |
| RMM-NET-015 | Z3 database-backup identity    | `TBD protected Z6 backup target`      | `TBD approved backup protocol` | Database-consistent encrypted backup; no delete authority  | Recovery owner          | `NG-CHG-20260830-001` |

No server-initiated management route from Z2 to Z4 is permitted in this phase.
The endpoint initiates the only RMM connection.

### Initial IPv6 policy

IPv6 is fail-closed for the first lab slice. VLAN 170 and 180 have no IPv6
gateway, router advertisement, DHCPv6, global address, ULA, or IPv6 NAT. OPNsense
must install and log an explicit inbound IPv6 deny on both interfaces. Both
Linux guests must disable non-loopback IPv6 before connection to the fabric and
must expose no IPv6 listener. Acceptance tests verify no global or link-local
guest address, no IPv6 default route, no IPv6 listener, and failed IPv6 traffic
between Z1, Z2, Z4, and the Internet. Enabling IPv6 later requires equivalent
source/destination policy, DNS, PKI, monitoring, and negative tests in a separate
reviewed change.

### Network actions requiring separate approval

1. Export the current OPNsense configuration, verify its SHA-256, and confirm
   Hyper-V console recovery.
2. Extend only the exact `OPNsense-Tooling / APP-TRUNK` allowed list from
   `110,120,130,140,150,160,240,250` to
   `110,120,130,140,150,160,170,180,240,250`.
3. Create OPNsense VLAN 170 and 180 interfaces with the candidate gateway
   addresses; disable DHCP unless an explicit reservation design is approved.
4. Disable RA and DHCPv6, add the explicit IPv6 deny policy, and validate the
   initial IPv6 postconditions before attaching either VM.
5. Install only non-`TBD`, gate-satisfied rules from the minimum flow table, with
   their ID, owner, evidence reference, and 2026-09-30 review date, plus explicit
   IPv4 default-deny logging on each new interface.
6. Add exact DNS records and address reservations only after collision checks.
7. Validate management access, existing VLANs, DNS, time, Wazuh, NAT, and
   expected blocked paths before considering the network change complete.

## G2 blockers

G2 remains closed until evidence identifies and validates:

- the human OIDC provider and phishing-resistant privileged MFA;
- server TLS PKI plus independent certificate-status service;
- offline endpoint root, restricted issuer, renewal, revocation, and status;
- protected append-only audit destination independent of the RMM service;
- encrypted backup target, retention, RPO/RTO, and isolated restore proof;
- approved external recovery-key escrow plus verified LUKS2 recovery for both
  control-plane disks;
- the final signed Linux agent package and enrollment protocol;
- exact DNS names and approved addresses;
- the initial fail-closed IPv6 tests or a later equivalent dual-stack policy;
- Factory support for the complete server and canary manifests; and
- before/after network validation and rollback evidence.

Phase 1 code has no listener or real agent. Creating a connected server or
installing an endpoint agent before these controls exist would not satisfy the
approved phase model.

## Rollback and containment

The network change requires an exclusive firewall-change lock and a fresh
configuration hash immediately before apply. Rollback normally applies the
reviewed scoped inverse: remove only the new RMM rules/interfaces and return the
exact trunk adapter to its original allowed list, then verify the resulting
hash and all existing management/VLAN paths. Full configuration restore is
permitted only when the current hash proves that no intervening change occurred.
If the hash differs, stop and reconcile the later change instead of overwriting
it. The recovery operator retains the verified export and Hyper-V console path.

VM rollback uses the Factory receipt and exact plan-bound cleanup or quarantine
path; it never infers deletion from a missing manifest. Failed bootstrap leaves
the VM off and isolated. No checkpoint is treated as a backup.

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
