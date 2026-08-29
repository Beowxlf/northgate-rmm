# Pre-Code Audit

Date: YYYY-MM-DD  
Audited commit: COMMIT_SHA  
Auditor: NAME  
Gate: G1 — Product coding

## Scope

Review all Phase 0 deliverables, machine-enforced gates, repository controls, and
required checks. This audit does not authorize deployment.

## Evidence inventory

| Requirement                | Evidence                                 | Result  | Notes |
| -------------------------- | ---------------------------------------- | ------- | ----- |
| Charter and scope          | `PROJECT_CHARTER.md`                     | Pending |       |
| Architecture               | `docs/architecture/`                     | Pending |       |
| Threat model               | `docs/security/THREAT_MODEL.md`          | Pending |       |
| Security requirements      | `docs/security/SECURITY_REQUIREMENTS.md` | Pending |       |
| Authorization gates        | `docs/governance/AUTHORIZATION_GATES.md` | Pending |       |
| Required checks            | `docs/governance/REQUIRED_CHECKS.md`     | Pending |       |
| Operations and recovery    | `docs/operations/`                       | Pending |       |
| Automated governance audit | audit artifact                           | Pending |       |
| Secret scan                | scan artifact                            | Pending |       |
| Workflow/security scan     | scan artifact                            | Pending |       |

## Findings

Record ID, severity, affected requirement, evidence, remediation, owner, and
status. Do not write “none” until the complete evidence inventory is inspected.

## Gate conclusion

`PASS` is allowed only when every required item is proven and no gate-blocking
finding remains. The audit report is evidence; the separate G1 authorization
record opens the coding gate.
