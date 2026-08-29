# Security Policy

## Supported versions

No production version is supported yet. The project is pre-alpha and restricted
to isolated test environments.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability, exposed credential, or
private infrastructure detail. Use GitHub private vulnerability reporting after
it is enabled. Until then, contact the repository owner through a previously
established private channel.

Do not include secrets, private keys, tokens, production data, private hostnames,
or exploit details in public reports.

## Response objectives

- acknowledge receipt within three business days;
- triage severity and affected trust boundaries;
- preserve evidence and rotate or revoke exposed credentials immediately;
- create a remediation and disclosure plan;
- publish a security advisory when users need to act.

These are objectives, not a warranty or service-level agreement.

## Security design

The normative requirements are in
[Security Requirements](docs/security/SECURITY_REQUIREMENTS.md). Changes to
identity, authorization, cryptography, agent privilege, updates, audit, protocol,
or external exposure are security-significant changes under `GOVERNANCE.md`.

## Safe research

Testing is authorized only against systems the tester owns or has explicit
permission to test. Do not degrade service, access unrelated data, persist on
systems, or test NorthGate infrastructure without separate operational scope.
