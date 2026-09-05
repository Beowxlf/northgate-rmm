# Version 1.0 source completion

Owner scope: private, single-operator Linux and Windows amd64 monitoring.
Implementation only in this task; review, deployment, and product qualification
are separate subsequent tasks. Configuration templates never count as evidence
that a service, key, network rule, or recovery target exists.

## Implementation checklist

- [x] Existing inventory, freshness, enrollment, revocation, PostgreSQL and views.
- [x] Windows collection and service entry point.
- [x] Restricted operational issuer and certificate-status service.
- [x] Authenticated renewal and agent identity replacement.
- [x] Private OIDC introspection bridge and browser sign-in configuration.
- [x] Independent audit delivery, signed checkpoints and reconciliation.
- [x] Backup, isolated restore and retention commands.
- [x] Windows native storage security, upgrade and removal.
- [x] Release packaging/signature verification and service configuration.
- [x] Source consistency and build checks; product tests remain a later task.

Remote execution, desktop control, remediation, file transfer, automatic update
installation, public exposure and multi-tenancy remain excluded.

Implementation inventory and operational prerequisites are in
[the runtime guide](operations/V1_SOURCE_RUNTIME.md). The completion marks refer
to source presence, not review approval or executed acceptance tests.

Source checks: Windows and Linux Go builds and vet; Windows test-package
compilation without test execution; Python formatting, lint and strict type
analysis. The final status report records the exact completed checks.

Deferred stages: independent code review, complete regression/security suite,
Debian package qualification, Windows service/ACL/power-loss acceptance, actual
IdP login and revocation, backup restore drill, signed publication and deployment.
