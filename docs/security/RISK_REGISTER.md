# Risk Register

Scale: likelihood and impact are Low, Medium, High, or Critical. Residual risk is
reassessed at every phase gate.

| ID    | Risk                                                  | Likelihood | Impact   | Current treatment                                                    | Owner                | Gate status               |
| ----- | ----------------------------------------------------- | ---------- | -------- | -------------------------------------------------------------------- | -------------------- | ------------------------- |
| R-001 | Operator compromise produces broad endpoint control   | Medium     | Critical | MFA, scope, approvals, canaries, audit, revocation                   | Project owner        | Blocks G7/G8 until tested |
| R-002 | Agent flaw enables endpoint privilege escalation      | Medium     | Critical | unprivileged core, typed handlers, helper isolation, SAST/fuzzing    | Agent owner          | Blocks privileged phase   |
| R-003 | Update signing/build compromise distributes malware   | Medium     | Critical | separated TUF-style trust, provenance, SBOM, rings                   | Release manager      | Blocks G6                 |
| R-004 | Lost/duplicate messages create false success          | High       | High     | explicit state machine, idempotency, fencing, unknown outcome        | Control-plane owner  | Blocks G4                 |
| R-005 | Endpoint data or output leaks secrets                 | Medium     | High     | allowlist, redaction, quotas, retention, access audit                | Security owner       | Blocks operational gates  |
| R-006 | Database/backup restore reauthorizes revoked endpoint | Medium     | Critical | revocation-aware restore and isolated invariant audit                | Recovery owner       | Blocks G2+                |
| R-007 | Reconnect storm exhausts services                     | Medium     | High     | jitter/backoff/rate limit/backpressure/load test                     | Platform owner       | Blocks broad scale        |
| R-008 | Linux platform variance causes unsafe behavior        | High       | High     | named support matrix, package/service tests, no implied support      | Agent owner          | Blocks G2 per platform    |
| R-009 | Remote gateway or tunnel permits lateral movement     | Medium     | Critical | isolated gateway, one-target tunnel, egress allowlist, pentest       | Remote-access owner  | Blocks G7                 |
| R-010 | Remote session exposes credentials or private data    | Medium     | Critical | JIT credential broker, disabled redirection, privacy policy          | Security owner       | Blocks G7                 |
| R-011 | CI dependency/action compromise alters artifacts      | Medium     | Critical | SHA pins, least privilege, locked deps, provenance, review           | Release manager      | Blocks release            |
| R-012 | Project scope expands faster than controls            | High       | High     | phased gates, Class 3 changes, owner authorization                   | Project owner        | Continuously monitored    |
| R-013 | GitHub repository controls are absent/misconfigured   | Low        | High     | public protected main, required checks, CODEOWNERS, recurring audit  | Project owner        | Continuously monitored    |
| R-014 | Licensing is undefined before public distribution     | Low        | Medium   | Apache-2.0 approved; dependency and notice checks remain required    | Project owner        | Closed for public release |
| R-015 | Segmentation drift exposes RMM trust domains          | Medium     | Critical | layered default deny, identity policy, flow tests, config evidence   | Infrastructure owner | Blocks G2+                |
| R-016 | Same-host service paths bypass network isolation      | Medium     | High     | local IPC, service/DB identities, host firewall, separation triggers | Platform owner       | Blocks G2+                |
