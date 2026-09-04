# V1D-SV Authorization Record Template

Copy this template into `docs/governance/authorizations/` only after the Factory
has issued a fresh non-deployment plan and the owner has approved its exact plan
ID and authenticated state hash. Replace every placeholder. The governance
audit rejects an open `V1D-SV` authority if any required field is missing,
duplicated, malformed, expired, or still contains a placeholder.
The audited commit must resolve to a commit in this repository. All timestamps
use UTC `YYYY-MM-DDTHH:MM:SSZ` form.

Exact private infrastructure facts remain in the protected evidence system.
Public fields ending in `binding` contain SHA-256 digests of the canonical
private records, not the sensitive facts themselves.

Authority: V1D-SV  
Status: Authorized  
Approver: Beowxlf  
Audited commit: PLACEHOLDER  
Issued at: PLACEHOLDER  
Expires at: PLACEHOLDER  
Server binding: sha256:PLACEHOLDER  
Signed release digest: sha256:PLACEHOLDER  
Factory plan ID: PLACEHOLDER  
Authenticated state hash: sha256:PLACEHOLDER  
Factory plan issued at: PLACEHOLDER  
Factory plan approved at: PLACEHOLDER  
Factory plan approver: Beowxlf  
External dependency set binding: sha256:PLACEHOLDER  
Service identity binding: sha256:PLACEHOLDER  
Database identity binding: sha256:PLACEHOLDER  
Synthetic identity profile binding: sha256:PLACEHOLDER  
Private network policy binding: sha256:PLACEHOLDER  
Endpoint routes: blocked  
Rollback binding: sha256:PLACEHOLDER  
Recovery binding: sha256:PLACEHOLDER  
Evidence boundary binding: sha256:PLACEHOLDER

The record authorizes only execution of the already approved Factory plan. It
does not authorize plan expansion, endpoint package installation,
endpoint-usable enrollment or identity material, canary or endpoint traffic,
artifact publication or update, or opening G2.
