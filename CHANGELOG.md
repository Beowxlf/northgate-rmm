# Changelog

All notable changes will be documented here. The project follows Keep a
Changelog structure and will adopt semantic versioning before its first release.

## Unreleased

### Added

- project charter, learning program, architecture, security governance, and
  pre-code authorization framework;
- repository audit tooling and free-software check plan;
- Apache-2.0 licensing and protected public repository controls;
- G1 authorization for bounded synthetic development;
- typed Python domain models for endpoint identity, heartbeat, inventory,
  freshness, revocation, and audit evidence;
- Windows and Linux synthetic fixtures with replay, expiry, binding, and
  revocation tests;
- strict bounded JSON decoding and escaped server-rendered endpoint list/detail
  views;
- transactional PostgreSQL migrations, concurrency-safe enrollment/ingestion,
  and an isolated dump/restore test that preserves revocation;
- an ephemeral test-only CA and endpoint-bound client certificate fixture;
- Ruff, mypy, pytest coverage, Bandit, and Python Semgrep checks in CI; and
- infrastructure capacity, trust-zone, flow-policy, microsegmentation,
  provisioning, validation, and rollback specification;
- bounded Phase 2 Linux-agent source authorization without opening G2;
- a standard-library-only Go agent core with strict configuration, allowlisted
  collectors, compatible inventory encoding, and a checksum-validated quota
  spool; and
- a source-tested TLS 1.3 mutual-authentication sender with exact bounded
  acknowledgements and jittered exponential retry policy; and
- a create-once, permission-restricted endpoint identity bundle with strict
  certificate/key/root validation, endpoint URI binding, durable publication,
  and fail-closed corruption and uncertain-install handling; and
- Go format, vet, race, fuzz, static analysis, vulnerability, and Semgrep checks
  in CI.
