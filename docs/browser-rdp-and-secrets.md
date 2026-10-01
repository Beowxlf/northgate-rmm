# Browser desktop and provider-backed secrets

This public overview describes remote-session and secret-management features at
a product level. Deployment-specific endpoints, access grants, custody mechanisms
and recovery procedures are intentionally omitted.

## Endpoint methods

Supported configurations can offer browser remote sessions and native desktop
clients. Availability depends on the endpoint and its approved configuration.
Validate the selected method in the actual supported environment; transport
connectivity alone does not establish successful login or desktop usability.

Authentication and peer verification remain required. Do not weaken either to
make a qualification test pass. Session start, interruption and termination need
explicit evidence, including what termination does and does not end.

## Secrets UI and API

Secret-management features are authorization-sensitive and require dedicated
review. Public examples must use synthetic values. Never include credentials,
private access configuration or operational secret records in a public document.

Verify denied access, expired authorization, unavailable dependencies and failed
operations as well as successful requests. A metadata listing does not prove
that a privileged secret operation is available or authorized.

## Provider adoption and retirement

Provider transitions and retirement need an approved change plan and failure
qualification. A failed provider operation must remain visible rather than being
reported as successful. Review compatibility against the selected implementation.

## Completed recovery results

Recovery must establish the requested postcondition in an authorized test
environment. A completed job or stored record alone does not prove end-to-end
recovery. Keep operational custody and recovery evidence in private records.

See the [PR verification record](audits/PR36_VERIFICATION_2026-10-01.md) for the
boundary between repository checks and interactive acceptance.
