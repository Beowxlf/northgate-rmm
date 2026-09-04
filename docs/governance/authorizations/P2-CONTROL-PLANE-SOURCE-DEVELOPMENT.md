# Phase 2 Authorization — Control-Plane Source Development

Status: Authorized on merge  
Date: 2026-09-03  
Approver: Project owner (`Beowxlf`)  
Authorization source: Owner instruction authorizing completion of the project
to the charter-scoped 1.0 release  
Audited base commit: `bbf2b82f65944f541aaf2f93c47171e8b809b08d`

## Authorized scope

Develop and qualify the source needed for the version 1.0 control-plane slice:

- a bounded HTTP application under `control-plane/` or `src/northgate_rmm/`;
- loopback-only and isolated-test listeners;
- single-use enrollment-grant creation and consumption;
- endpoint-bound test PKI and mutual-TLS agent-message authentication;
- PostgreSQL migrations for grants and the version 1.0 identity, observation,
  revocation, and audit invariants;
- authenticated single-operator endpoint list and detail views;
- health, freshness, revocation, audit, rate-limit, size-limit, timeout,
  idempotency, and failure tests; and
- free-software dependency, license, static-analysis, secret, and workflow
  checks.

All listeners, databases, credentials, identities, certificates, and endpoint
records used by development or CI must be synthetic, disposable, locally
isolated, and unable to reach NorthGate infrastructure.

## Explicit exclusions

This authorization does not open G2 through G8 and does not authorize:

- installation, activation, enrollment, or collection on a real endpoint;
- creation or modification of a NorthGate VM, switch, VLAN, firewall rule, DNS
  record, PKI service, database, identity, listener, or persistent service;
- production or reusable credentials, certificates, signing keys, enrollment
  grants, endpoint data, or infrastructure configuration;
- package or service publication, production signing, or transparency-log
  submission;
- remote jobs, command text, remediation, privileged helpers, file transfer,
  updates, interactive access, Windows support, or public exposure; or
- approval or execution of any VM Factory plan or infrastructure change.

## Required evidence

- exact reviewed commits and passing protected checks;
- architecture, protocol, data-model, threat-model, and migration deltas;
- negative tests for authentication, authorization, replay, expiry, duplicate,
  binding, revocation, size, rate, timeout, and persistence failures;
- database concurrency, backup, restore, and migration evidence;
- no-listener-outside-isolation and no-live-data evidence; and
- a separate G2 authorization bound to the final release, target, network,
  recovery, and exact deployment plans.

## Automatic closure

This source authorization closes if a critical vulnerability remains unresolved,
required checks fail, live secrets or endpoint data enter development, a
listener is exposed outside an approved isolated test, the source gains an
execution primitive, the version 1.0 scope changes, or the owner revokes it. It
is superseded by the final G2 authorization for the exact canary exercise.
