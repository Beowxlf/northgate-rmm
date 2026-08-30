# Phase 1 Dependency Review — 2026-08-30

Status: Approved for the synthetic Phase 1 candidate  
Gate: G1 — Product coding

## Decision

Add one focused PostgreSQL client dependency and one development/test-only
cryptography dependency. Keep the server-rendered views and strict message
decoder on the Python standard library. Pin the ephemeral PostgreSQL CI image to
an immutable Linux/amd64 manifest digest.

## Reviewed components

| Component           | Version/digest                                                                   | Scope           | License                    |
| ------------------- | -------------------------------------------------------------------------------- | --------------- | -------------------------- |
| psycopg             | 3.3.4                                                                            | product runtime | LGPL-3.0-only              |
| psycopg-binary      | 3.3.4                                                                            | product runtime | LGPL-3.0-only              |
| cryptography        | 50.0.1                                                                           | tests only      | Apache-2.0 OR BSD-3-Clause |
| PostgreSQL CI image | 16.10, `sha256:ab8380566c3ea09690a9ecaa85a59d82bfc6eb86744151a2a54335866c83a3e9` | CI service only | PostgreSQL                 |

Installed package metadata was used to verify the Python SPDX expressions. The
Docker Hub tag metadata supplied the image manifest digest. The components are
recorded in the repository-root third-party notice inventory.

## Security and licensing disposition

- `psycopg` is limited to parameterized database access and migration execution
  from repository-controlled SQL files;
- the binary extra avoids an unreviewed local compiler path in Phase 1 but must be
  reassessed for release packaging and platform support;
- LGPL terms remain the dependency's terms and do not change the Apache-2.0
  license on repository-authored work;
- `cryptography` exists only in test support and no generated private key or
  certificate is committed;
- the PostgreSQL container is ephemeral, runner-local, and configured only for
  synthetic CI data;
- `pip-audit`, Dependabot, SBOM generation before release, and the existing
  exception process remain mandatory.

This is a technical compatibility and provenance record, not legal advice.
