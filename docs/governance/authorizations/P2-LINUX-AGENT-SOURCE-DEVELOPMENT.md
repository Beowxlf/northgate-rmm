# Phase 2 Authorization — Linux Agent Source Development

Status: Authorized on merge  
Date: 2026-08-30  
Approver: Project owner (`Beowxlf`)  
Authorization source: Owner instruction to proceed after the Phase 1 exit and
VM Factory prerequisite review  
Audited base commit: `90e3c57d8ab844883a93fa323c384f2dfb4d0436`

## Authorized scope

Begin bounded Phase 2 source development for a Linux read-only agent:

- a Go agent core under `agent/`;
- strict configuration and protocol contracts compatible with the Phase 1
  control-plane model;
- bounded read-only Linux identity, operating-system, boot, disk, and agent
  metadata collectors;
- an outbound-only transport interface with no listener;
- a bounded offline spool that fails closed on corruption or capacity limits;
- unprivileged `systemd`, Debian package, install, upgrade, revoke, uninstall,
  resource-limit, and clean-removal drafts; and
- unit, race, fuzz, static-analysis, dependency, license, and packaging tests
  that use synthetic or local test data only.

The first qualification candidate is Debian 12 amd64. This selection is a test
target, not a support claim.

## Explicit exclusions

This record does not open G2 and does not authorize:

- installation on any NorthGate endpoint or VM;
- creation, connection, or modification of a VM, VLAN, firewall rule, DNS
  record, certificate authority, listener, database, or service;
- collection from a real endpoint;
- use of live endpoint identities, production certificates, enrollment grants,
  credentials, or private infrastructure data;
- remote jobs, command text, shell execution, privileged helpers, remediation,
  file transfer, updates, or interactive access; or
- promotion of proposed RMM network, storage, bootstrap, recovery, asset, or
  host-policy records.

## Exit evidence required before G2 installation authorization

- exact reviewed implementation commit and passing required checks;
- Go toolchain provenance, checksum, version, license, and dependency evidence;
- Debian 12 amd64 package and unprivileged `systemd` review;
- collector data inventory and bounded resource/spool behavior;
- no-listener, no-root, malformed-input, corruption, exhaustion, race, install,
  upgrade, revoke, uninstall, and clean-removal test evidence;
- an explicit disposable target, network policy, recovery route, and retention
  decision; and
- a separate G2 authorization record bound to those artifacts.

## Automatic closure

This source-development authorization closes if required checks fail, a critical
vulnerability remains unresolved, secrets or real endpoint data enter the
repository, the agent gains a listener or execution primitive, the target scope
changes, or the project owner revokes it.
