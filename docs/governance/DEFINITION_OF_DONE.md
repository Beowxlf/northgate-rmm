# Definition of Done

A change is done only when all applicable statements are true:

- user outcome and scope are documented;
- change class and active phase are identified;
- architecture and threat-model deltas are recorded;
- security and privacy requirements have tests or explicit evidence;
- code, protocol, database, migration, and compatibility tests pass;
- failure, retry, timeout, cancellation, rollback, and recovery behavior are
  defined where applicable;
- logs, metrics, traces, and audit events are sufficient to diagnose the change;
- secrets and sensitive data are excluded or protected by policy;
- documentation and runbooks match behavior;
- required free-software checks pass;
- unresolved findings have no invalid or expired exception;
- CODEOWNERS review and required phase authorization are present;
- the exact commit or release artifacts can be identified and reproduced.

An implementation that works only on the happy path is not done.
