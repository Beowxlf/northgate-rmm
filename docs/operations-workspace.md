# Operations workspace API

The operations workspace organizes IT/SOC cases, infrastructure records and
supporting evidence. Its record-management capability does not itself authorize
endpoint commands or establish operational acceptance.

This public overview intentionally omits installation-specific architecture,
access configuration, private storage details and recovery procedures. Integrators
must review the implementation and their approved deployment requirements before
connecting operational data.

## Composition and deployment

Use a reviewed release and an isolated qualification environment. Treat schema
changes, data migration and recovery as explicit deployment work with their own
verification. A successful application start is not proof of a safe migration.

## Authentication and permissions

Verify that each requested operation is authorized for the actual caller and
records involved. Hiding an interface control is not an authorization boundary.
Use synthetic identities and records for public examples and tests.

## Read endpoints

The interface can retrieve case and infrastructure records, related history and
evidence metadata. Validate both allowed access and denial cases. Do not place
private endpoint addresses, identities or operational records in public examples.

## Mutation endpoints

Supported workflows include record updates, case transitions, linked evidence
and upload management. Retries, revision conflicts and uncertain outcomes need
explicit handling; they must not silently duplicate or lose work.

### Record values

Records represent cases, assets, services, networks, relationships, documents,
changes and exercises. Keep data minimization and the intended audience in view
when preparing content for export or publication.

### Retained evidence

Evidence acceptance, retention and recovery require independent qualification.
A client assertion or pattern check cannot prove that arbitrary uploaded content
contains no sensitive information. Review each disclosure before publication.

## Wazuh intake

The optional intake capability associates normalized alerts with operations
workflows. Integration setup, source mappings and operational connection details
belong in private configuration. Test duplicates, invalid input, unavailable
sources and authorization failures before operational use.

See the [PR verification record](audits/PR36_VERIFICATION_2026-10-01.md) for current
repository checks and remaining acceptance limits.
