# ADR 0008 — Zoned Default-Deny RMM Infrastructure

Status: Accepted  
Date: 2026-08-29  
Change class: Class 2 design change with Class 3 subjects held behind phase gates

## Context

NorthGate RMM is a privileged management system. Treating the control plane,
managed endpoints, hypervisor, data, audit, recovery, build/update, and remote
assistance services as one trusted network would let one compromised component
inherit unrelated authority. The platform also needs a deployable private Linux
baseline without prematurely requiring Kubernetes or a service mesh.

## Decision

Adopt the logical Z0-Z9 trust-zone model, default-deny flow matrix, layered
enforcement, provisioning sequence, and acceptance evidence defined in
[`INFRASTRUCTURE_AND_MICROSEGMENTATION.md`](../INFRASTRUCTURE_AND_MICROSEGMENTATION.md).

The initial private deployment may co-locate approved application capabilities
on one Linux control-plane VM, but process identities, local sockets, database
roles, listener policy, and guest firewall rules must preserve the documented
logical boundaries. Managed agents initiate outbound connections and expose no
RMM listener. The protected audit archive belongs to Z5, outside ordinary RMM
write, read, and deletion authority. Recovery and emergency revocation paths use
identities held outside the suspected runtime component.

VM manifests reference reviewed opaque profile IDs. They do not embed raw VLAN,
switch, route, firewall, address, credential, command, or script values. A merged
manifest or architecture change does not authorize a network-boundary or live-lab
change.

## Consequences

- Infrastructure can begin as a small private deployment while retaining explicit
  seams for measured separation.
- Every permitted flow needs an owner, exact source/destination, service identity,
  activation gate, expiry where applicable, logging, negative test, and rollback.
- Z5 and Z6 require independent identities and retention controls; they cannot
  become alternate RMM control paths.
- G2-G8 remain closed. Endpoint enrollment, update distribution, remote access,
  public exposure, and production use each require their named gate and separate
  operational authorization.
- Live NorthGate VLANs, subnets, addresses, VM names, profiles, PKI, and products
  remain undecided until discovery and an approved implementation plan.

## Threat-model delta

This decision adds network policy/enforcement state, the protected Z5 audit
archive, and recovery credentials to the protected asset set. It adds trust
boundaries between every logical zone and external dependency. Abuse cases and
controls are recorded as TM-17 through TM-40 in
[`THREAT_MODEL.md`](../../security/THREAT_MODEL.md).

## Alternatives rejected

- **Flat trusted management network:** compromise would inherit excessive reach.
- **Inbound endpoint listeners:** increases attack surface and complicates NAT and
  host-firewall policy.
- **Kubernetes or service mesh at G1:** adds operational and security complexity
  without a measured availability or scale requirement.
- **Raw network details in VM manifests:** couples workloads to mutable lab
  topology and bypasses separate network-change review.

## Validation and rollback

Documentation validation, threat review, and negative-test specifications are
required at G1. A live rollout must start with one disposable canary, capture
before-state and policy hashes, and prove both permitted and denied flows. Rollback
stops new privileged work, revokes affected authority, removes the new allow rule,
restores known-good policy, verifies listeners/routes, and preserves evidence.
