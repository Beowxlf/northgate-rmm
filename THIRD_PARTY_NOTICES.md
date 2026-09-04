# Third-Party Notice Inventory

NorthGate RMM repository-authored work is Apache-2.0. Third-party components
retain their own licenses. This inventory is not a replacement for the complete
license text supplied by each upstream distribution.

| Component           | Version | Use                                     | SPDX expression            | Upstream                                       |
| ------------------- | ------- | --------------------------------------- | -------------------------- | ---------------------------------------------- |
| aiohttp             | 3.14.3  | Bounded private HTTP/TLS listener       | Apache-2.0 AND MIT         | <https://docs.aiohttp.org/>                    |
| aiohappyeyeballs    | 2.7.1   | aiohttp runtime dependency              | PSF-2.0                    | <https://github.com/aio-libs/aiohappyeyeballs> |
| aiosignal           | 1.4.0   | aiohttp runtime dependency              | Apache-2.0                 | <https://github.com/aio-libs/aiosignal>        |
| attrs               | 26.1.0  | aiohttp runtime dependency              | MIT                        | <https://www.attrs.org/>                       |
| frozenlist          | 1.8.0   | aiohttp runtime dependency              | Apache-2.0                 | <https://github.com/aio-libs/frozenlist>       |
| multidict           | 6.7.1   | aiohttp runtime dependency              | Apache-2.0                 | <https://multidict.aio-libs.org/>              |
| propcache           | 0.5.2   | aiohttp runtime dependency              | Apache-2.0                 | <https://github.com/aio-libs/propcache>        |
| typing-extensions   | 4.16.0  | aiohttp runtime dependency              | PSF-2.0                    | <https://github.com/python/typing_extensions>  |
| yarl                | 1.24.5  | aiohttp runtime dependency              | Apache-2.0                 | <https://yarl.aio-libs.org/>                   |
| idna                | 3.19    | yarl runtime dependency                 | BSD-3-Clause               | <https://github.com/kjd/idna>                  |
| cryptography        | 50.0.1  | Runtime X.509 parsing and test-only PKI | Apache-2.0 OR BSD-3-Clause | <https://cryptography.io/>                     |
| cffi                | 2.1.1   | cryptography runtime dependency         | MIT-0                      | <https://cffi.readthedocs.io/>                 |
| pycparser           | 3.0     | cffi runtime dependency                 | BSD-3-Clause               | <https://github.com/eliben/pycparser>          |
| psycopg             | 3.3.4   | PostgreSQL runtime adapter              | LGPL-3.0-only              | <https://www.psycopg.org/psycopg3/>            |
| psycopg-binary      | 3.3.4   | Prebuilt psycopg runtime extension      | LGPL-3.0-only              | <https://www.psycopg.org/psycopg3/>            |
| PostgreSQL CI image | 16.10   | Ephemeral integration-test database     | PostgreSQL                 | <https://hub.docker.com/_/postgres>            |
| Go toolchain/stdlib | 1.27.0  | Agent build, test, and standard library | BSD-3-Clause               | <https://go.dev/>                              |

The repository does not modify these components or relicense them. Release
packaging must regenerate the software bill of materials and include any license
texts, notices, and source-access mechanism required by the exact artifacts it
distributes.
