# Third-Party Notice Inventory

NorthGate RMM repository-authored work is Apache-2.0. Third-party components
retain their own licenses. This inventory is not a replacement for the complete
license text supplied by each upstream distribution.

| Component           | Version | Use                                  | SPDX expression            | Upstream                            |
| ------------------- | ------- | ------------------------------------ | -------------------------- | ----------------------------------- |
| psycopg             | 3.3.4   | PostgreSQL runtime adapter           | LGPL-3.0-only              | <https://www.psycopg.org/psycopg3/> |
| psycopg-binary      | 3.3.4   | Prebuilt psycopg runtime extension   | LGPL-3.0-only              | <https://www.psycopg.org/psycopg3/> |
| cryptography        | 50.0.1  | Test-only ephemeral certificate code | Apache-2.0 OR BSD-3-Clause | <https://cryptography.io/>          |
| PostgreSQL CI image | 16.10   | Ephemeral integration-test database  | PostgreSQL                 | <https://hub.docker.com/_/postgres> |

The repository does not modify these components or relicense them. Release
packaging must regenerate the software bill of materials and include any license
texts, notices, and source-access mechanism required by the exact artifacts it
distributes.
