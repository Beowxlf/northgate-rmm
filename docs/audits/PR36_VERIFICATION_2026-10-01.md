# PR 36 verification and unresolved scan findings — 2026-10-01

Status: remediation in review; required security gates and interactive acceptance
remain blocking. This record does not approve exceptions or authorize deployment.

## Repository repairs

- Strict typing now covers the current remote, capture, secrets, native integration,
  backup and runbook implementation and its tests without disabling strict mypy
  checks or excluding owned modules.
- Independent checks run after earlier failures, retaining their own failing
  outcomes. Formatting, lint and typing have separate steps. The npm audit outcome
  is still enforced. Semgrep languages also run independently. Link validation
  retains its repository-wide supported-file scope.
- Server package qualification derives its wheel/version from project metadata
  and checks installed metadata against that version. The previous hard-coded
  `0.1.0.dev0` filename could never qualify the current application wheel.
- The application and Semgrep have separate dependency environments. Application
  tests install the declared optional MCP version. Both environments remain
  audited; isolation does not waive scanner-tool vulnerabilities.
- Native Windows NetAPI buffers retain pointer types until release instead of
  round-tripping persistent `uintptr` values. Linux and Windows `go vet` pass;
  Windows cross-compilation is not a Windows runtime or login acceptance test.
- New negative tests identified and fixed generic error-boundary behavior for
  missing release files (404), an unavailable Wazuh intake registry (401), and
  non-string native operations (400).
- Synthetic credential fixtures are generated explicitly. No real credentials,
  access profiles or endpoint state were added.

## Verification evidence

The full local suite passes all **1,464 tests**, with no skips, at **90.96%**
aggregate branch-inclusive coverage (the unchanged gate requires 90%). This run
uses Python 3.12.14 and isolated PostgreSQL 17.11; hosted CI uses its pinned
PostgreSQL 16.10 image. Strict mypy passes all 159 source/test files.

The original suite accounted for 833 tests. Additional tests cover token claims,
current identity revalidation, failure and cleanup paths, signed audit delivery,
retention, backup/restore isolation, remote sessions, staged secret rotation,
runbook execution, and fleet/operations rules.

Local governance, Markdown, Prettier, Ruff, strict mypy, Linux Go race tests,
Linux/Windows Go vet and Linux Staticcheck pass. The application-only dependency
audit reports no known vulnerabilities. The first repair commit's hosted Debian
and release-trust qualifications, both Debian package tests, Bandit, Zizmor and
actionlint pass. Final-head hosted results must be checked after publication.

Coverage is still enforced at 90%; no threshold or exclusion was added. Local
success does not substitute for the final-head hosted checks or scanner review.

## Gitleaks: unmodified vendored xterm exports

Rule: `generic-api-key`. There are two matches at
`src/northgate_rmm/management_xterm.js:1`, also reproduced if a wheel build copies
that file into `build/lib/northgate_rmm/management_xterm.js`.

The matches are JavaScript export-assignment chains around `FourKeyMap` and
`SequencerByKey`, not string credential values. The vendored file was compared
byte-for-byte against `package/lib/xterm.js` in the official
[@xterm/xterm 6.0.0 npm tarball](https://registry.npmjs.org/@xterm/xterm/-/xterm-6.0.0.tgz).
The tarball's SHA-512 integrity matches the checked-in provenance manifest, and
the JavaScript SHA-256 is
`14903579ff54664cd72f8e8699e6961a6272c21863ec1c3b118cdc8af5d4a972`.

No allowlist or suppression was applied. A reviewed disposition should match only
these verified public export expressions; it must not exempt a directory or all
secrets in a vendored file. Preserve the provenance digest check if an exception
is approved.

## Semgrep: application-specific review required

The `p/python` scan reports 20 findings across these exact rule/location groups.
Line numbers below describe the reviewed working tree and may move in later edits.

### python.django.security.injection.raw-html-format.raw-html-format

- `src/northgate_rmm/capture_ui.py:603`
- `src/northgate_rmm/capture_ui.py:605`
- `src/northgate_rmm/capture_ui.py:644`
- `src/northgate_rmm/remote_gateway.py:363`
- `src/northgate_rmm/remote_gateway.py:364`
- `src/northgate_rmm/remote_gateway.py:371`
- `src/northgate_rmm/remote_workspace.py:254`
- `src/northgate_rmm/remote_workspace.py:261`
- `src/northgate_rmm/remote_workspace.py:268`
- `src/northgate_rmm/remote_workspace.py:270`
- `src/northgate_rmm/remote_workspace.py:271`
- `src/northgate_rmm/remote_workspace.py:352`
- `src/northgate_rmm/remote_workspace.py:353`
- `src/northgate_rmm/remote_workspace.py:354`
- `src/northgate_rmm/remote_workspace.py:359`
- `src/northgate_rmm/remote_workspace.py:361`
- `src/northgate_rmm/remote_workspace.py:364`
- `src/northgate_rmm/remote_workspace.py:366`

These sites use escaped display names, request paths, states and credential
text; canonical UUID objects for route identifiers; internally generated URL-safe
nonces; or a fixed local script whose variable payload uses `script_json` to encode
HTML end-tag characters. New adversarial rendering tests complement the existing
script-serialization tests. Review must remain site-specific: this does not approve
manual HTML generally or future interpolation changes. No suppression was added.

### python.cryptography.security.mode-without-authentication.crypto-mode-without-authentication

- `src/northgate_rmm/remote_gateway.py:63`

The function prepends HMAC-SHA256 over the complete plaintext before AES-CBC
with a zero IV. This is the exact interoperability format documented by
[Apache Guacamole 1.6 encrypted JSON authentication](https://guacamole.apache.org/doc/gug/json-auth.html#generating-encrypted-json).
The existing round-trip test validates the MAC before reading plaintext. Changing
the wire algorithm independently would break authentication with the configured
Guacamole extension; this is not evidence of an unauthenticated encryption path.
The scanner does not recognize that protocol composition. No suppression was added.

### python.flask.security.audit.directly-returned-format-string.directly-returned-format-string

- `src/northgate_rmm/remote_workspace.py:462`

This method returns a plain upload-status message to its own caller. The caller
HTML-escapes the whole message before constructing the response. It is not a Flask
view directly returning unescaped markup. No suppression was added.

## Actual scanner-tool dependency vulnerability

Semgrep 1.175.0 and the checked newer 1.175.1, 1.176.1, 1.177.0 and 1.178.0 all
require `pyjwt[crypto]~=2.13.0` and `mcp==1.29.0`. The PyPI metadata for
[Semgrep 1.178.0](https://pypi.org/pypi/semgrep/1.178.0/json) confirms those
constraints. The dependency audit reports 13 advisories for PyJWT 2.13.0, including
CVE-2026-101918 and CVE-2026-103001. PyJWT 2.15.1 audits clean in the independent
application environment, but does not satisfy Semgrep's current declared pin.

The Semgrep dependency audit must remain failed. Do not force an incompatible
transitive version, mark the vulnerability as a false positive, or exclude the
tool environment from auditing. An upstream compatible release or separately
reviewed tool packaging/remediation is required.

## Approval and acceptance boundary

`PROJECT_CHARTER.md` requires CODEOWNERS review for security/workflow changes and
says automation cannot approve its own exceptions. `REQUIRED_CHECKS.md` requires
rule, exact location, justification, reviewer, expiry and compensating control for
a suppression. `EXCEPTIONS.md` requires an owner and independent approver plus a
scoped, time-limited remediation record. No exception is created by this report.

The PR remains draft. Interactive browser/native acceptance and deployment
qualification remain open. Cross-builds, unit tests and package qualifications
do not prove those workflows. No merge or deployment was performed. Operational
acceptance details are omitted from this public report.
