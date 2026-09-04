# Product Gate Authorization Template

Copy this template to `docs/governance/authorizations/GN-DESCRIPTION.md`, where
`GN` is the exact gate from G2 through G8. Replace every placeholder. Values
ending in `binding` are SHA-256 digests of canonical scope records. Every scope
record must embed a non-empty exact `scope` array and its recomputed digest; use
a stable sanitized identifier for a sensitive target, never a secret. The
authorization must remain active, may last no more than 24 hours, and must name
an existing protected-main audit commit. The seven scope records and all of
their evidence must already exist unchanged at that commit. Merge this
authorization alone while the gate remains closed; a later change may open the
gate only after this record has been accepted exactly once on protected `main`.

Gate: GN  
Status: Authorized  
Approver: Beowxlf  
Audited commit: PLACEHOLDER  
Issued at: YYYY-MM-DDTHH:MM:SSZ  
Expires at: YYYY-MM-DDTHH:MM:SSZ  
Operation record: docs/governance/authorizations/product-gates/scopes/GN-PLACEHOLDER.json  
Operation binding: sha256:PLACEHOLDER  
Target set record: docs/governance/authorizations/product-gates/scopes/GN-PLACEHOLDER.json  
Target set binding: sha256:PLACEHOLDER  
Artifact set record: docs/governance/authorizations/product-gates/scopes/GN-PLACEHOLDER.json  
Artifact set binding: sha256:PLACEHOLDER  
Identity set record: docs/governance/authorizations/product-gates/scopes/GN-PLACEHOLDER.json  
Identity set binding: sha256:PLACEHOLDER  
Network policy record: docs/governance/authorizations/product-gates/scopes/GN-PLACEHOLDER.json  
Network policy binding: sha256:PLACEHOLDER  
Rollback record: docs/governance/authorizations/product-gates/scopes/GN-PLACEHOLDER.json  
Rollback binding: sha256:PLACEHOLDER  
Evidence boundary record: docs/governance/authorizations/product-gates/scopes/GN-PLACEHOLDER.json  
Evidence boundary binding: sha256:PLACEHOLDER

The scope records must expand these bindings into the exact action, targets,
artifacts, identities, permitted flows, rollback steps, and evidence locations
required by the selected gate. Every evidence record must likewise embed its
exact non-empty `result` array and recomputed result digest. This core record does not replace the
additional gate-specific evidence required by `AUTHORIZATION_GATES.md`.
Build each referenced scope and evidence record from the adjacent templates.
