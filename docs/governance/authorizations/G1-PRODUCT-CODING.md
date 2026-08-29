# G1 Authorization — Product Coding

Status: Authorized on merge  
Date: 2026-08-29  
Approver: Project owner (`Beowxlf`)  
Audited commit: f426a7a1fc9108145de1d1456e6cdc4cd175fa2a

## Authorized scope

Begin Phase 1 product development using synthetic data and local simulation:

- a minimal Python control-plane skeleton;
- an unprivileged cross-platform endpoint simulator;
- typed inventory and heartbeat messages;
- deterministic online, stale, and offline state calculation;
- revocation behavior and append-only audit events; and
- unit, integration, schema, and security tests.

## Explicit exclusions

This record does not authorize:

- installation on a Linux or Windows endpoint;
- collection from a real endpoint;
- remote job or command delivery;
- privileged or state-changing actions;
- update signing or release distribution;
- interactive RDP, SSH, VNC, or desktop sessions;
- use of production credentials or private infrastructure data; or
- public or production service deployment.

Those capabilities remain closed behind G2 through G8.

## Evidence

- `docs/audits/PRE_CODE_AUDIT_2026-08-29.md`;
- licensed public baseline commit `f426a7a1fc9108145de1d1456e6cdc4cd175fa2a`;
- successful governance workflow run `33262548272`;
- successful security workflow run `33262548264`; and
- live protected-branch and repository-security verification.

## Automatic closure

G1 closes if required checks fail, protected-branch enforcement is removed, a
critical vulnerability remains unresolved, secrets enter the repository, the
architecture materially changes, or the project owner revokes this record.
