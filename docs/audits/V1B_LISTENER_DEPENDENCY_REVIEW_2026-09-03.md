# V1B Listener Dependency Review — 2026-09-03

Status: Approved for bounded V1B source development  
Gate: non-deployment control-plane source authorization

## Decision

Use `aiohttp` 3.14.3 for the private HTTP/TLS listener and move the already
reviewed `cryptography` 50.0.1 package into runtime scope for X.509 profile and
subject-public-key parsing. The listener remains unconfigured and inactive until
G2 approves exact infrastructure, identities, network policy, and rollback.

The selected aiohttp release is upstream-signed and published by the aio-libs
project. Its package metadata reports `Apache-2.0 AND MIT`; cryptography reports
`Apache-2.0 OR BSD-3-Clause`. Both are free-software expressions compatible with
the repository's Apache-2.0 distribution model. This is a technical provenance
assessment, not legal advice.

## Reviewed runtime closure

| Component         | Version | Relationship         | SPDX expression            |
| ----------------- | ------- | -------------------- | -------------------------- |
| aiohttp           | 3.14.3  | direct listener      | Apache-2.0 AND MIT         |
| aiohappyeyeballs  | 2.7.1   | aiohttp transitive   | PSF-2.0                    |
| aiosignal         | 1.4.0   | aiohttp transitive   | Apache-2.0                 |
| attrs             | 26.1.0  | aiohttp transitive   | MIT                        |
| frozenlist        | 1.8.0   | aiohttp transitive   | Apache-2.0                 |
| multidict         | 6.7.1   | aiohttp transitive   | Apache-2.0                 |
| propcache         | 0.5.2   | aiohttp transitive   | Apache-2.0                 |
| typing-extensions | 4.16.0  | aiohttp transitive   | PSF-2.0                    |
| yarl              | 1.24.5  | aiohttp transitive   | Apache-2.0                 |
| idna              | 3.19    | yarl transitive      | BSD-3-Clause               |
| cryptography      | 50.0.1  | direct X.509 parsing | Apache-2.0 OR BSD-3-Clause |
| cffi              | 2.1.1   | crypto transitive    | MIT-0                      |
| pycparser         | 3.0     | cffi transitive      | BSD-3-Clause               |

The exact versions above are pinned in the developer/CI requirements. Product
packaging must later add a hash-locked Linux runtime closure and regenerate the
SBOM from the exact built service artifact before V1C acceptance.

## Security disposition

- server code uses aiohttp's maintained HTTP parser instead of a custom parser;
- the exact version is pinned because the hardened malformed-request adapter
  intentionally tests a small internal protocol integration seam;
- parser limits disable request decompression and bound header count, header
  bytes, body bytes, backlog, and concurrent application handoffs;
- `cryptography` parses the TLS-verified leaf, exact URI SAN, certificate purpose,
  supported key profile, and DER SubjectPublicKeyInfo fingerprint;
- TLS chain verification remains OpenSSL/Python `ssl` responsibility;
- `pip-audit`, Bandit, Semgrep, SBOM generation, upstream-signature review, and
  the repository exception process remain mandatory.

Sources: [aiohttp v3.14.3](https://github.com/aio-libs/aiohttp/releases/tag/v3.14.3),
[aiohttp repository and license](https://github.com/aio-libs/aiohttp), and
[cryptography documentation](https://cryptography.io/).
