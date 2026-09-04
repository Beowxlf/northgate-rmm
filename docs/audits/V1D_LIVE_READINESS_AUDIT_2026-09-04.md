# V1D Live Readiness Audit — 2026-09-04

Status: Open; read-only reconciliation complete  
Change: `NG-CHG-20260830-001`  
Authorization boundary: discovery and plan maintenance only; G2 and G6 closed

## Executive outcome

The source-qualified NorthGate RMM control plane is not yet eligible for a
version 1.0 lab deployment. Private read-only reconciliation completed, but the
VM Factory, network, operational PKI, operator verifier, protected audit, and
recovery gates do not yet meet V1D.

No VM, switch, VLAN, route, firewall rule, DNS record, service, package,
identity, certificate, Factory policy, or repository release was changed by
this audit.

## Current evidence

Collection completed on 2026-09-04. Exact host identity, inventory, capacity,
storage, release, service, network, configuration-hash, listener, and tool
results are retained only in the approved private Operation-SeeSaw assessment
and evidence records.

| Gate                           | Redacted result                                            | Consequence                                                                      |
| ------------------------------ | ---------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Management trust path          | Private verification complete                              | Retain the approved path and repair the privately recorded read-only tool defect |
| Target identity and capacity   | Private preflight complete                                 | Revalidate through a fresh host-issued plan before any apply                     |
| Immutable installation source  | Private verification complete                              | Revalidate in the exact release ceremony                                         |
| Installed VM Factory authority | Does not include an RMM asset                              | Complete, sign, install, and promote the RMM-specific Factory bundle             |
| RMM network boundary           | Required private segmentation is not established           | Obtain separate backup-bound network approval and prove allow/deny paths         |
| Audit integrity                | Private collection and publication integrity checks passed | Preserve exact evidence outside the public repository                            |

## V1D control matrix

| Dependency                        | Current decision or evidence                                                                                             | State       | Exit evidence required                                                                                               |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------- | -------------------------------------------------------------------------------------------------------------------- |
| VM Factory data disks             | Guarded implementation merged in VM Factory PR #56                                                                       | Source pass | Installed signed release, RMM asset policies, plan and receipt negative tests                                        |
| VM Factory profiles and manifests | RMM profiles are proposed and disabled; no RMM manifest is in the installed bundle                                       | Open        | Reviewed approved profiles, both exact manifests, host policy mappings, signed bundle and promotion                  |
| Network                           | Required RMM segmentation is not established                                                                             | Open        | Private backup/hash, exact boundary change, default-deny rules, permitted/denied path tests and rollback             |
| DNS                               | Exact operator and agent DNS dependencies are unresolved                                                                 | Open        | Approved names, collision checks, exact records, resolver policy and negative tests                                  |
| Time                              | The authenticated-time design is unresolved                                                                              | Open        | Exact trusted time source and policy, offset/freshness alert, outage and no-fallback proof                           |
| Server TLS and endpoint PKI       | Source clients exist; no approved live issuer, status service, trust roots, or recovery identities exist                 | Open        | Issuer/status design, offline recovery material, lifecycle runbook, revocation and established-channel tests         |
| Operator identity                 | Source operator service requires a fixed external session verifier; no live verifier or exact identity tuple is approved | Open        | Exact verifier, phishing-resistant operator authentication, pinned scope, outage/revocation tests                    |
| PostgreSQL                        | Schema and service code are source-qualified; no live database or role set exists                                        | Open        | Exact version/configuration, least-privilege roles, local/network boundary, migration and failure tests              |
| Monitoring and protected audit    | Exact RMM monitoring, protected audit, integrity checkpoints, and independent alert route are unresolved                 | Open        | Exact endpoints/ports/roles, deletion/reordering detection, outage queue bounds and independent alerts               |
| Backup and recovery               | Runbook exists; no RMM backup set or isolated restore has been executed                                                  | Open        | Encrypted immutable target, retention, RPO/RTO, database-consistent backup and isolated invariant-preserving restore |
| Storage encryption                | Proposed server uses two LUKS2 volumes; unlock and external recovery-key custody are not approved or tested              | Open        | Exact key custody, normal unlock, recovery boot, rotation and evidence-redaction proof                               |
| Release trust                     | G2A/G2B source qualification passed; G6 production signing and publication remain closed                                 | Open        | Exact production artifacts, independent trust root, custody/recovery approval and G6 record                          |

## Ordered closeout sequence

1. Merge this redacted gate result and repair the privately recorded read-only
   inventory defect.
2. Complete the VM Factory RMM profiles, exact manifests, host policy mappings,
   signed release candidate, and offline plan/receipt tests without installing it.
3. Resolve the exact DNS, authenticated time, PKI, operator verifier, PostgreSQL,
   protected audit, monitoring, backup, recovery, encryption, retention, RPO,
   RTO, and named-owner decisions in one reviewed V1D packet.
4. Through separate bounded implementation records, approve, provision, and
   verify the exact DNS and authenticated-time dependencies, server PKI,
   synthetic-only endpoint issuer and status path, operator verifier, protected
   Z5 telemetry and audit destinations, Z6 backup/recovery target, and external
   encryption-key custody. Each record must name its targets, identities,
   permitted flows, expiry, rollback, and evidence and grant no endpoint or
   canary authority.
5. Open a bounded G6 ceremony for the exact production package, manifest, SBOM,
   provenance, signing profile, trust root, distribution location, canary ring,
   expiry, and rollback boundary. Sign and independently verify those artifacts
   without activating automatic updates or signing the final acceptance record.
   Establish and verify the protected distribution and bootstrap procedure, and
   complete the signing-key loss and compromise tests. V1C remains open until
   every production-release-trust control in the release criteria passes.
6. Obtain separate approval for the backup-bound VLAN 170/180 network change;
   apply it in isolation and retain positive and negative path evidence.
7. Install and promote the new Factory release only through its own reviewed
   bootstrap and activation ceremony.
8. Only after V1C and every required external-dependency implementation pass,
   use the Factory's non-deployment planning path to generate the fresh
   control-plane plan after current-state validation. Obtain exact owner approval
   of that plan ID and authenticated state hash after issuance. Commit the
   sanitized approved-bindings manifest to protected `main`. In a later change,
   commit the exact bounded V1D server-validation record, open `V1D-SV`, and use
   it only to execute that approved plan and harden the control plane without
   installing an endpoint.
   Prove database-consistent backup and isolated restore, telemetry-outage and
   capacity behavior, certificate revocation, containment, and rollback; V1D
   remains open until every required proof passes. Stop the validation service,
   revoke synthetic identities, preserve blocked endpoint routes, remove
   temporary access and secrets, verify rollback, and merge the immutable
   cleanup evidence and closeout receipt while G2 through G8 remain closed.
9. Only after V1D passes and the owner accepts the hardened-server and recovery
   evidence, and only after the closeout artifacts exist unchanged on protected
   `main`, open G2 for only the disposable canary while binding the exact
   deployed server, signed release, network policy, identities, expiry,
   rollback, server plan and receipt, and reviewed V1D evidence as fixed
   dependencies. Generate the fresh canary Factory plan after current-state
   validation, obtain exact owner approval of its plan ID and authenticated
   state hash after issuance, and only then deploy the canary and complete the
   approved lifecycle test and soak.
10. After every other V1F prerequisite passes, use an exact G6 acceptance
    authorization to sign the immutable `1.0.0` release record as the final V1F
    action.

## Gate decision

V1D remains open. G2 and G6 remain closed. The owner’s retained intent to
continue toward `NG-VM-023 / NG-RMM-CAN01` does not approve an unknown future
Factory plan, the control-plane VM, a network-boundary change, installation, or
production signing.
