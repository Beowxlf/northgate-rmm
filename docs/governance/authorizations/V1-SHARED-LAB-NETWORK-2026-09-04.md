# Version 1.0 shared lab network decision

Date: 2026-09-04
Authority: explicit owner instruction in the RMM implementation/deployment task.
Scope: the lab-only Linux and Windows Version 1.0 monitoring deployment.

The owner approved deployment and subsequently removed the requirement for
different VLANs because the product will only be used inside the lab.

## Effective requirements

- The RMM server, disposable Linux endpoint, and disposable Windows endpoint may
  share an existing private lab subnet. Dedicated VLANs 170/180 are not required.
- Do not create the previously proposed RMM VLANs, add them to the firewall
  trunk, or require inter-VLAN deny tests for this shared-subnet deployment.
- Prefer the existing `business-apps` Factory network profile on the private
  application switch. Verify its live binding, available addresses, and required
  access before assigning addresses. No address is reserved by this document.
- Same-subnet reachability between test endpoints and RMM ingress is permitted.
  Operator and agent routes retain their distinct application authentication.
- Private service binding, TLS, endpoint identity, owner authentication,
  authorization, protected credentials, and audit behavior remain implemented.
  A reachable listener must still reject an unauthorized request.
- This decision does not enable public listeners, router port forwarding,
  unrestricted remote execution, or installation on the domain controller.
- Existing guests and data remain protected during creation and rollback.

## Supersession and testing

This decision supersedes dedicated RMM VLAN/subnet and inter-zone isolation
requirements in the August 30 network packet and zoned architecture for this
Version 1.0 lab deployment. Those documents remain historical design records.
It also supersedes the VLAN-creation prerequisite in the initial deployment
preflight report. The earlier owner deployment approval remains effective.

Network acceptance now verifies private-network attachment, required endpoint
connectivity, no added public exposure, and application rejection of invalid
identities. It must not claim that a shared subnet provides VLAN isolation.

The Factory asset/storage/bootstrap capability gap is separate: removing VLAN
separation does not add NG-VM-022 or NG-VM-023 to the installed signed release.
This document records revised requirements; it is not evidence of deployment.
