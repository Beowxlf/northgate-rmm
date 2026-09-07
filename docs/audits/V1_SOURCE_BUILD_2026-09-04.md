# Version 1.0 source build record - 2026-09-04

Scope: implementation of private Linux and Windows monitoring. This record is
not an independent code review, security qualification, deployment or acceptance
test result. Earlier release-candidate evidence does not cover these changes.

| Source check                                       | Observed result                                                         |
| -------------------------------------------------- | ----------------------------------------------------------------------- |
| Windows amd64 Go build                             | Passed                                                                  |
| Linux amd64 Go cross-build                         | Passed                                                                  |
| Go vet, Windows and Linux targets                  | Passed                                                                  |
| Windows Go test-package compilation, `-run '^$'`   | Passed; tests not executed                                              |
| Python Ruff lint and format                        | Passed                                                                  |
| Python strict mypy, Linux target                   | Passed, 60 source/test files                                            |
| Python wheel, configured setuptools 84.0.0 backend | Built, including all 11 migrations and new command entry points         |
| Windows lifecycle script parsing                   | Passed                                                                  |
| Debian build and maintainer shell syntax           | Passed                                                                  |
| Lightweight secret scan                            | Zero findings; not a substitute for Gitleaks                            |
| Focused native Windows directory flush probe       | Write-capable directory opened and flushed successfully on this machine |

The standalone Python `build` frontend was absent and the environment initially
had an older setuptools. The wheel was subsequently built through the repository's
declared setuptools 84.0.0 backend. Application dependencies were not changed for
that environment correction.

New regression source covers signed status rejection, strict workload JSON and
recovery connection boundaries. The full test suite, coverage requirements,
security review, Debian/Windows installed-service behavior, actual IdP claims,
renewal/revocation, audit failure/rollback, restore, filesystem crash recovery,
signing custody and product acceptance remain the next stages.

All deployment-specific credentials, private authorities, client certificate
pins, owner subject, storage retention and network isolation must be supplied
from verified deployment configuration. No service was installed or activated
and no source was published by this implementation task.
