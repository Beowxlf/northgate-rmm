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

| Zone           | Factory profile | VLAN / subnet               | Address                                                               |
| -------------- | --------------- | --------------------------- | --------------------------------------------------------------------- |
| Z2 RMM service | `rmm-service`   | VLAN 170 / `10.10.170.0/24` | gateway `.1`; `NG-RMM-CP01` operator/admin `.10`, agent ingress `.11` |
| Z4 RMM canary  | `rmm-canary`    | VLAN 180 / `10.10.180.0/24` | gateway `.1`; `NG-RMM-CAN01` `.10`                                    |

The RMM database remains on the control-plane VM for the first lab slice. The
future Z2-to-Z3 boundary is enforced by a local PostgreSQL socket, distinct Unix
service/database identities, least SQL privilege, filesystem ownership, and a
host firewall. A networked Z3 database requires a later separation decision.

### Minimum candidate flows

All other new inter-zone paths are denied and logged. Stateful return traffic is
implicit and does not authorize a reverse initiating flow.

No rule containing `TBD` may be installed. Every row must first name an exact
source identity and address or immutable firewall alias, an exact destination
identity and address or immutable firewall alias, an exact protocol and port,
and a completed validation case. Workload or zone labels express design intent;
they are not installable firewall objects. The owner reviews every rule by
2026-09-30; continued need requires a new evidence-backed review date.

| ID          | Source                                                       | Destination                                              | Service                          | Activation gate / control                                                                                                                                                                                                                                               | Owner                   | Evidence reference    |
| ----------- | ------------------------------------------------------------ | -------------------------------------------------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | --------------------- |
| RMM-NET-001 | `10.10.100.11`, `10.10.100.21`                               | `10.10.170.10`                                           | TCP 443                          | OIDC MFA, source/device policy, RBAC, and audit proven                                                                                                                                                                                                                  | RMM service owner       | `NG-CHG-20260830-001` |
| RMM-NET-002 | `10.10.100.11`, `10.10.100.21`                               | `10.10.170.10`                                           | TCP 22                           | Key-only admin; exact sources; no root/password login                                                                                                                                                                                                                   | Linux platform owner    | `NG-CHG-20260830-001` |
| RMM-NET-003 | `10.10.180.10`                                               | `10.10.170.11`                                           | TCP 443                          | G2 only; exact agent service name and dedicated agent listener/certificate/authentication/policy/rate-limit/logging path; bootstrap TLS then endpoint-bound mTLS; Z4 access to operator `.10` must fail                                                                 | RMM service owner       | `NG-CHG-20260830-001` |
| RMM-NET-004 | `10.10.170.10`                                               | `10.10.100.150`                                          | TCP/UDP 53                       | Exact internal DNS only                                                                                                                                                                                                                                                 | Linux platform owner    | `NG-CHG-20260830-001` |
| RMM-NET-005 | `10.10.180.10`                                               | `TBD exact DNS firewall aliases`                         | TCP/UDP 53                       | G2; exact approved DNS only; no broad route created by RMM                                                                                                                                                                                                              | RMM endpoint owner      | `NG-CHG-20260830-001` |
| RMM-NET-006 | `10.10.170.10`                                               | `10.10.100.14`                                           | `TBD exact approved Wazuh ports` | Required before service acceptance and G2; listener revalidated; bounded write-only logs, metrics, and traces; exact queue byte/record/age bounds, overflow policy, service-data warning/critical thresholds, and independent capacity alerts; no RMM control authority | Security monitoring     | `NG-CHG-20260830-001` |
| RMM-NET-007 | `10.10.170.10`                                               | `TBD exact package-mirror firewall aliases`              | TCP 443; conditional TCP 80      | Maintenance window; signed packages; exact repositories                                                                                                                                                                                                                 | Linux platform owner    | `NG-CHG-20260830-001` |
| RMM-NET-008 | `10.10.170.10`                                               | `TBD approved human IdP`                                 | TCP 443                          | Required before operator privilege and G2; revalidate the signed issuer/tenant/subject/session/client tuple on every privileged request; positive cache at most 60 seconds; unknown, unavailable, stale, or revoked fails closed                                        | Identity service owner  | `NG-CHG-20260830-001` |
| RMM-NET-009 | `10.10.170.10`                                               | `TBD endpoint issuer`                                    | TCP 443                          | G2; workload mTLS; issuance/renewal/revocation/status only                                                                                                                                                                                                              | Endpoint PKI owner      | `NG-CHG-20260830-001` |
| RMM-NET-010 | `10.10.170.10`                                               | `TBD server PKI`                                         | TCP 443                          | Required before TLS activation; exact lifecycle APIs                                                                                                                                                                                                                    | Server PKI owner        | `NG-CHG-20260830-001` |
| RMM-NET-011 | `TBD exact Z1 managed TLS-client firewall alias`             | `TBD server-PKI status service`                          | TCP 443                          | Required before TLS activation; signed status only; stale/unknown/revoked fails closed; channel lifetime at most five minutes; full re-handshake with fresh status; resumption and 0-RTT cannot bypass validation                                                       | Server PKI owner        | `NG-CHG-20260830-001` |
| RMM-NET-012 | `10.10.180.10`                                               | `TBD server-PKI status service`                          | TCP 443                          | Required before G2; exact certificate status only; hard fail; channel lifetime at most five minutes; full re-handshake with fresh status; resumption and 0-RTT cannot bypass validation                                                                                 | Endpoint PKI owner      | `NG-CHG-20260830-001` |
| RMM-NET-013 | `TBD exact Z2 audit-writer firewall alias`                   | `TBD protected Z5 audit sink`                            | `TBD approved TLS port`          | Required before G2; mTLS and append-only integrity-chained records plus signed checkpoints; deletion, reordering, and checkpoint discontinuity detectable; no read/delete/control authority                                                                             | Security evidence owner | `NG-CHG-20260830-001` |
| RMM-NET-014 | `TBD exact Z2 backup-export firewall alias`                  | `TBD protected Z6 backup target`                         | `TBD approved backup protocol`   | Required before service acceptance; write only, immutable                                                                                                                                                                                                               | Recovery owner          | `NG-CHG-20260830-001` |
| RMM-NET-015 | `TBD exact Z3 database-backup firewall alias`                | `TBD protected Z6 backup target`                         | `TBD approved backup protocol`   | Required before G2 backup acceptance; separate credential; database-consistent encrypted export of schema/data, endpoint identity and revocation state, authorization policy, and phase-gate state; immutable retention; no delete authority                            | Recovery owner          | `NG-CHG-20260830-001` |
| RMM-NET-016 | `TBD exact Z5 audit-export firewall alias`                   | `TBD protected Z6 backup target`                         | `TBD approved backup protocol`   | Required before G2; audit/checkpoint scope, write only                                                                                                                                                                                                                  | Security evidence owner | `NG-CHG-20260830-001` |
| RMM-NET-017 | `TBD exact Z6 recovery-monitor firewall alias`               | `TBD protected Z5 telemetry sink`                        | `TBD approved TLS port`          | Required before G2 backup acceptance; write-only capacity, backup, retention, integrity, and restore-test health; no backup or recovery content                                                                                                                         | Recovery owner          | `NG-CHG-20260830-001` |
| RMM-NET-018 | `TBD exact Z6 source-collector firewall alias`               | `TBD exact RMM source/deployment repository alias`       | TCP 443                          | Required before G2 backup acceptance; read-only exact commit, signed tag, and deployment-manifest scope                                                                                                                                                                 | Recovery owner          | `NG-CHG-20260830-001` |
| RMM-NET-019 | `TBD exact Z5 telemetry firewall alias`                      | `TBD independent alert destination`                      | `TBD approved TLS port`          | Required before G2; notification-only credential and redacted bounded payload                                                                                                                                                                                           | Security monitoring     | `NG-CHG-20260830-001` |
| RMM-NET-020 | `TBD exact Z1 endpoint-PKI recovery-operator firewall alias` | `TBD endpoint issuer emergency revocation endpoint`      | TCP 443                          | Required before G2; independent MFA; exact endpoint identity; revoke/status only; signed intent/result; terminate bound sessions or isolate                                                                                                                             | Endpoint PKI owner      | `NG-CHG-20260830-001` |
| RMM-NET-021 | `TBD exact Z1 server-PKI recovery-operator firewall alias`   | `TBD server-PKI emergency-containment endpoint`          | TCP 443                          | Required before TLS activation and G2; independent MFA; disable/rotate exact Z2 issuance client, then revoke/roll exact certificate; signed intent/result; no unrelated authority                                                                                       | Server PKI owner        | `NG-CHG-20260830-001` |
| RMM-NET-022 | `TBD exact Z1 operator-browser firewall alias`               | `TBD exact human IdP authorization endpoint`             | TCP 443                          | Required before operator privilege; authorization endpoint only; TLS and IdP policy                                                                                                                                                                                     | Identity service owner  | `NG-CHG-20260830-001` |
| RMM-NET-023 | `TBD exact Z1 identity-recovery firewall alias`              | `TBD exact human IdP emergency-revocation endpoint`      | TCP 443                          | Required before operator privilege and G2; independent MFA; exact issuer/tenant/session/client or opaque handle revocation only; no user/role/policy authority                                                                                                          | Identity service owner  | `NG-CHG-20260830-001` |
| RMM-NET-024 | `TBD exact Z2 operator-session registrar firewall alias`     | `TBD protected Z5 operator-session evidence intake`      | `TBD approved TLS port`          | Required before operator privilege; append signed issuer/tenant/subject/session/client binding and opaque revocation handle; acknowledgement required                                                                                                                   | Security evidence owner | `NG-CHG-20260830-001` |
| RMM-NET-025 | `TBD exact Z1 identity-recovery firewall alias`              | `TBD protected Z5 revocation-handle lookup`              | TCP 443                          | Required before operator privilege and G2; independent MFA and case scope; exact session/operator/time query; bounded result; no enumeration                                                                                                                            | Security evidence owner | `NG-CHG-20260830-001` |
| RMM-NET-026 | `TBD exact Z1 security-recovery firewall alias`              | `TBD protected Z5 recovery-audit intake`                 | TCP 443                          | Required before TLS activation and G2; append signed intent before action and signed exact-scope result before containment completion                                                                                                                                   | Security evidence owner | `NG-CHG-20260830-001` |
| RMM-NET-027 | `TBD exact Z1 security-recovery firewall alias`              | `TBD immutable Z6 emergency-evidence intake`             | `TBD approved evidence protocol` | Required before TLS activation and G2 as the Z5-unavailable or untrusted fallback; signed append-only bundle; no read/restore/delete authority                                                                                                                          | Security evidence owner | `NG-CHG-20260830-001` |
| RMM-NET-028 | `TBD exact Z1 recovery-operator firewall alias`              | `TBD exact Z6 recovery-service admin endpoint`           | `TBD approved admin protocol`    | Required before G2 backup acceptance; recovery role, independent MFA, exact recovery set, reason, alert, short expiry, and evidence                                                                                                                                     | Recovery owner          | `NG-CHG-20260830-001` |
| RMM-NET-029 | `TBD exact Z6 recovery-service firewall alias`               | `TBD exact isolated-restore-target firewall alias`       | `TBD approved restore protocol`  | Required before G2 backup acceptance; exact authorization and recovery set; no endpoint/operator ingress; reconcile before use                                                                                                                                          | Recovery owner          | `NG-CHG-20260830-001` |
| RMM-NET-030 | `TBD exact Z1 incident-auditor firewall alias`               | `TBD protected Z5 audit-export endpoint`                 | TCP 443                          | Required before G2; independent MFA; exact case/time scope; immutable access/export event; no alter/delete                                                                                                                                                              | Security evidence owner | `NG-CHG-20260830-001` |
| RMM-NET-031 | `TBD exact Z1 network-recovery firewall alias`               | `TBD exact policy-enforcement-point management endpoint` | `TBD approved admin protocol`    | Required before G2; independent MFA; isolate only the exact suspected Z2 target; reason, alert, short expiry, audit, independently observed outcome, and tested rollback                                                                                                | Network recovery owner  | `NG-CHG-20260830-001` |
| RMM-NET-032 | `TBD exact Z6 emergency-evidence reconciler firewall alias`  | `TBD protected Z5 recovery-audit intake`                 | `TBD approved TLS port`          | Required before G2; only after Z5 re-establishment and independent integrity/authority verification, write the exact accepted fallback bundle plus original Z6 acknowledgement; no unrelated read, alter, or delete authority                                           | Security evidence owner | `NG-CHG-20260830-001` |
| RMM-NET-033 | `10.10.170.10`                                               | `TBD exact authenticated-time firewall alias`            | TCP 4460 NTS-KE; UDP 123 NTS     | Required before service acceptance; authenticated NTS only, pinned trust policy, monitored offset/freshness, no unauthenticated NTP fallback; loss or invalid time fails closed for new privileged work and alerts                                                      | Linux platform owner    | `NG-CHG-20260830-001` |
| RMM-NET-034 | `10.10.180.10`                                               | `TBD exact authenticated-time firewall alias`            | TCP 4460 NTS-KE; UDP 123 NTS     | Required before G2; authenticated NTS only, pinned trust policy, monitored offset/freshness, no unauthenticated NTP fallback; loss or invalid time fails canary admission and alerts                                                                                    | RMM endpoint owner      | `NG-CHG-20260830-001` |
| RMM-NET-035 | `TBD exact Z2 host-capacity monitor firewall alias`          | `TBD independent alert destination`                      | `TBD approved TLS port`          | Required before service acceptance and G2; independent of Z5/Wazuh and RMM application health; notification-only credential; bounded redacted queue/storage state; rate limited; no RMM control authority                                                               | Linux platform owner    | `NG-CHG-20260830-001` |

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
5. Install only non-`TBD`, gate-satisfied rules from the minimum flow table whose
   source and destination are exact addresses or already validated immutable
   firewall aliases and whose service is an exact protocol and port. Include
   each rule's ID, owner, evidence reference, and 2026-09-30 review date, plus
   explicit IPv4 default-deny logging on each new interface.
6. Add exact DNS records and address reservations only after collision checks.
7. Validate management access, existing VLANs, DNS, time, Wazuh, NAT, and
   expected blocked paths before considering the network change complete.

## G2 blockers

G2 remains closed until evidence identifies and validates:

- the human OIDC provider, phishing-resistant privileged MFA, browser
  authorization, independently authenticated exact-scope IdP revocation,
  acknowledged operator-session registration, and bounded revocation-handle
  lookup;
- a healthy-Z2 revocation test proving every privileged request revalidates the
  exact IdP tuple, positive status is cached no longer than 60 seconds, and an
  unknown, unavailable, stale, or revoked response stops privilege within that
  bound;
- server TLS PKI plus independent certificate-status service;
- an established-channel server-certificate revocation test for every activated
  Z1 and Z4 TLS client class, proving teardown or a full rejected re-handshake
  within five minutes; session resumption and 0-RTT must not bypass fresh status;
- offline endpoint root, restricted issuer, renewal, revocation, and status;
- protected append-only audit destination independent of the RMM service, with
  integrity-chained records, signed checkpoints, and tests proving deletion,
  reordering, and checkpoint discontinuity are detected;
- an exact independent alert destination, notification-only credential, and a
  tested delivery path that does not depend on the RMM service;
- encrypted backup target, retention, RPO/RTO, and a database-consistent isolated
  restore proving schema/data, endpoint identity and revocation state,
  authorization policy, and phase-gate state preserve their invariants;
- approved external recovery-key escrow plus verified LUKS2 recovery for both
  control-plane disks;
- the final signed Linux agent package and enrollment protocol;
- an independent endpoint-PKI recovery-operator route and a tested exact-target
  emergency revocation that terminates bound sessions or isolates the endpoint;
- an independent server-PKI recovery-operator route and a tested sequence that
  disables or rotates the exact Z2 issuance client before revoking or rolling
  the exact serving certificate;
- protected Z5 recovery-audit intake and an immutable Z6 fallback that both
  accept signed intent before containment and signed result before completion;
- exact recovery-operator-to-Z6 and Z6-to-isolated-target routes used by the
  successful isolated restore proof;
- an independently authenticated Z1-to-policy-enforcement-point route and a
  Z2-suspected test that retrieves only the bounded opaque IdP handle, revokes
  the exact IdP session, isolates the exact Z2 target without trusting Z2, and
  records the independently observed result;
- exact Z6 recovery-health telemetry and read-only source/deployment-record
  collection, including alert-delivery and recovery-catalog validation;
- the exact Z2-to-Z5 telemetry service and successful bounded write-only
  logs/metrics/traces delivery; exact local queue byte/record/age bounds, overflow
  policy, service-data warning/critical thresholds, and independent capacity
  alerts; outage and near-full-disk tests proving telemetry cannot exhaust the
  service-data volume; delivery of warning, critical, and overflow alerts through
  the Z2 host-monitor path while Z5/Wazuh and the RMM application are unavailable;
  and negative proof that neither destination can exercise RMM control authority;
- independent integrity and authority verification of re-established Z5,
  followed by successful reconciliation of a disposable Z6 emergency-evidence
  bundle into the protected Z5 recovery-audit intake; the test must fail closed
  when Z5 verification is absent or fails;
- exact DNS names and approved addresses;
- separate operator and agent service names resolving to `.10` and `.11`,
  distinct listener and certificate identities, authentication/policy/rate-limit
  and logging paths, and negative proof that Z4 cannot reach the operator UI/API;
- exact authenticated NTS endpoints and trust policy for the server and canary,
  successful authenticated synchronization, monitored offset/freshness, and
  negative tests proving there is no unauthenticated NTP fallback;
- the initial fail-closed IPv6 tests or a later equivalent dual-stack policy;
- Factory support for the complete server and canary manifests; and
- before/after network validation and rollback evidence.

Phase 1 code has no listener or real agent. Creating a connected server or
installing an endpoint agent before these controls exist would not satisfy the
approved phase model.

## Rollback and containment

The network change requires an exclusive firewall-change lock and a fresh
configuration hash immediately before apply. Rollback uses this dependency order:

1. stop new enrollment, jobs, sessions, and new canary traffic;
2. through the preserved Z1 recovery and evidence paths, append signed intent,
   revoke affected grants or certificates, isolate an exact suspected target if
   required, and append the signed and independently observed result;
3. disable the new non-recovery allow rules while preserving only the bounded Z1
   recovery and Z5/Z6 evidence routes needed to finish containment;
4. stop affected application listeners and quarantine or clean up only through
   the exact Factory receipt-bound path;
5. apply only the non-recovery portion of the reviewed scoped network inverse,
   explicitly retaining the exact Z1 recovery, Z5/Z6 evidence, supporting
   interfaces, and trunk paths still needed for evidence reconciliation;
6. verify the resulting hash and every existing management/VLAN path and prove
   no unintended route or listener remains; and
7. reconcile and acknowledge recovery evidence, then apply the remaining reviewed
   inverse to remove the temporary Z1 recovery/evidence rules, their supporting
   interfaces, and the RMM VLANs from the trunk only after revocation and evidence
   custody are proven; perform the final path and configuration-hash verification.

Full configuration restore is permitted only when the current hash proves that
no intervening change occurred. If the hash differs, stop and reconcile the later
change instead of overwriting it. The recovery operator retains the verified
export and Hyper-V console path throughout rollback.

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
