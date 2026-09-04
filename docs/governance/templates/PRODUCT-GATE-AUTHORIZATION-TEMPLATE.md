# Product Gate Authorization Template

Copy this template to `docs/governance/authorizations/GN-DESCRIPTION.md`, where
`GN` is the exact gate from G2 through G8. Replace every placeholder. Values
ending in `binding` are SHA-256 digests of canonical private scope records; use
the digest of a canonical empty set when a category is not applicable. The
authorization must remain active, may last no more than 24 hours, and must name
an existing protected-main audit commit.

Gate: GN  
Status: Authorized  
Approver: Beowxlf  
Audited commit: PLACEHOLDER  
Issued at: YYYY-MM-DDTHH:MM:SSZ  
Expires at: YYYY-MM-DDTHH:MM:SSZ  
Operation binding: sha256:PLACEHOLDER  
Target set binding: sha256:PLACEHOLDER  
Artifact set binding: sha256:PLACEHOLDER  
Identity set binding: sha256:PLACEHOLDER  
Network policy binding: sha256:PLACEHOLDER  
Rollback binding: sha256:PLACEHOLDER  
Evidence boundary binding: sha256:PLACEHOLDER

The private scope records must expand these bindings into the exact action,
targets, artifacts, identities, permitted flows, rollback steps, and evidence
locations required by the selected gate. This core record does not replace the
additional gate-specific evidence required by `AUTHORIZATION_GATES.md`.
