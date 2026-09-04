# V1D Live Readiness Audit — 2026-09-04

Status: Open; read-only reconciliation complete  
Change: `NG-CHG-20260830-001`  
Host: `HC-HV01`  
Authorization boundary: discovery and plan maintenance only; G2 and G6 closed

## Executive outcome

The source-qualified NorthGate RMM control plane is not yet eligible for a
version 1.0 lab deployment. The intended VM identities remain available and the
preferred F: volume has enough current capacity for the proposed server and
canary envelopes. The live network, installed VM Factory release, operational
PKI, operator verifier, protected audit, and recovery services do not yet meet
V1D.

No VM, switch, VLAN, route, firewall rule, DNS record, service, package,
identity, certificate, Factory policy, or repository release was changed by
this audit.

## Current evidence

Collection completed on 2026-09-04 through the loopback NorthGate MCP path,
pinned host SSH, the confined VM Factory identity, and audited read-only
OPNsense access.

| Area                | Verified state                                                                                                                                                       | V1D consequence                                                                                                 |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| NorthGate MCP       | Approved management path responded and both tunnel endpoints remained loopback-only                                                                                  | Approved management path is healthy                                                                             |
| Host key            | Pinned host identity matched the approved private baseline                                                                                                           | Read-only SSH fallback retained its trust binding                                                               |
| VM inventory        | Exact collision checks passed for both proposed RMM names                                                                                                            | Proposed identities remain collision-free at collection time                                                    |
| Host capacity       | The proposed server and canary resource envelopes passed current read-only feasibility checks                                                                        | A fresh Factory plan must still reserve and prove capacity                                                      |
| Storage             | The approved candidate storage root retained the required pre-plan headroom                                                                                          | A fresh Factory plan must revalidate the reserve                                                                |
| Debian source media | The immutable approved Debian 12.12 installation source remained available and digest-matched                                                                        | Source media is available, subject to release revalidation                                                      |
| Factory service     | The installed signed Factory release is healthy but predates VM Factory PR #56                                                                                       | New source capability is not installed                                                                          |
| Factory status      | Production create-only status reported no destructive operations and zero incomplete transactions                                                                    | The installed data bundle has no RMM asset, so no RMM plan is eligible                                          |
| Factory source      | Protected main includes guarded multi-disk support and proposed RMM network, storage, bootstrap, and recovery profiles                                               | Source capability exists; profiles, manifests, host bindings, signed release, and rollout promotion remain open |
| Hyper-V fabric      | The private application trunk remains unchanged and does not carry the proposed RMM segments                                                                         | The RMM service and canary segments cannot currently carry traffic                                              |
| OPNsense            | The protected configuration hash matched the prior private baseline; proposed RMM interfaces remain absent; required services and management listeners were observed | A separate backup-bound network change is required                                                              |
| Audit health        | The NorthGate 60-minute snapshot contained 12 events, no errors, no retry loop, and no repeated-equivalent calls                                                     | Read-only collection did not indicate a control-loop fault                                                      |

The MCP broad VM-list operation failed in its PowerShell/JSON command. Exact
inventory was therefore collected once through the pinned read-only SSH
fallback. This is a management-tool defect to repair; it is not evidence of a
Hyper-V outage.

## V1D control matrix

| Dependency                        | Current decision or evidence                                                                                                         | State       | Exit evidence required                                                                                               |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ----------- | -------------------------------------------------------------------------------------------------------------------- |
| VM Factory data disks             | Guarded implementation merged in VM Factory PR #56                                                                                   | Source pass | Installed signed release, RMM asset policies, plan and receipt negative tests                                        |
| VM Factory profiles and manifests | RMM profiles are proposed and disabled; no `NG-VM-022` or `NG-VM-023` manifest is in the installed bundle                            | Open        | Reviewed approved profiles, both exact manifests, host policy mappings, signed bundle and promotion                  |
| Network                           | Candidate Z2 VLAN 170 and Z4 VLAN 180 remain absent                                                                                  | Open        | OPNsense backup/hash, exact trunk and interface change, default-deny rules, permitted/denied path tests and rollback |
| DNS                               | Existing internal DNS is available; final operator and agent names are unassigned                                                    | Open        | Approved names, collision checks, exact records, resolver policy and negative tests                                  |
| Time                              | Existing OPNsense NTP is observable; the required authenticated-time design is not approved                                          | Open        | Exact trusted time source and policy, offset/freshness alert, outage and no-fallback proof                           |
| Server TLS and endpoint PKI       | Source clients exist; no approved live issuer, status service, trust roots, or recovery identities exist                             | Open        | Issuer/status design, offline recovery material, lifecycle runbook, revocation and established-channel tests         |
| Operator identity                 | Source operator service requires a fixed external session verifier; no live verifier or exact identity tuple is approved             | Open        | Exact verifier, phishing-resistant operator authentication, pinned scope, outage/revocation tests                    |
| PostgreSQL                        | Schema and service code are source-qualified; no live database or role set exists                                                    | Open        | Exact version/configuration, least-privilege roles, local/network boundary, migration and failure tests              |
| Monitoring and protected audit    | Wazuh exists, but exact RMM intake, protected append-only audit, integrity checkpoints, and independent alert route are not approved | Open        | Exact endpoints/ports/roles, deletion/reordering detection, outage queue bounds and independent alerts               |
| Backup and recovery               | Runbook exists; no RMM backup set or isolated restore has been executed                                                              | Open        | Encrypted immutable target, retention, RPO/RTO, database-consistent backup and isolated invariant-preserving restore |
| Storage encryption                | Proposed server uses two LUKS2 volumes; unlock and external recovery-key custody are not approved or tested                          | Open        | Exact key custody, normal unlock, recovery boot, rotation and evidence-redaction proof                               |
| Release trust                     | G2A/G2B source qualification passed; G6 production signing and publication remain closed                                             | Open        | Exact production artifacts, independent trust root, custody/recovery approval and G6 record                          |

## Ordered closeout sequence

1. Merge this refreshed evidence and repair the MCP VM-list read-only defect.
2. Complete the VM Factory RMM profiles, exact manifests, host policy mappings,
   signed release candidate, and offline plan/receipt tests without installing it.
3. Resolve the exact DNS, authenticated time, PKI, operator verifier, PostgreSQL,
   protected audit, monitoring, backup, recovery, encryption, retention, RPO,
   RTO, and named-owner decisions in one reviewed V1D packet.
4. Open a bounded G6 ceremony for the exact production package, manifest, SBOM,
   provenance, signing profile, trust root, distribution location, canary ring,
   expiry, and rollback boundary. Sign and independently verify those artifacts
   without activating automatic updates or signing the final acceptance record.
5. Obtain separate approval for the backup-bound VLAN 170/180 network change;
   apply it in isolation and retain positive and negative path evidence.
6. Install and promote the new Factory release only through its own reviewed
   bootstrap and activation ceremony.
7. Open G2 with the exact RMM server, canary, signed release, network policy, identities,
   expiry, rollback, and evidence. Generate fresh host-issued plans only after
   the merge and current-state validation.
8. Deploy and harden the control plane, prove backup/restore and containment,
   then deploy one disposable Debian canary and complete the soak.
9. After every other V1F prerequisite passes, use an exact G6 acceptance
   authorization to sign the immutable `1.0.0` release record as the final V1F
   action.

## Gate decision

V1D remains open. G2 and G6 remain closed. The owner’s retained intent to
continue toward `NG-VM-023 / NG-RMM-CAN01` does not approve an unknown future
Factory plan, the control-plane VM, a network-boundary change, installation, or
production signing.
