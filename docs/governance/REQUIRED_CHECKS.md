# Required Checks Using Free Software

Checks are activated by phase. Versions are locked in repository configuration or
CI, and external GitHub Actions are pinned to full commit SHAs.

## Phase 0 checks

| Check             | Free software             | Purpose                                      | Blocking rule                            |
| ----------------- | ------------------------- | -------------------------------------------- | ---------------------------------------- |
| Governance audit  | repository Node script    | Required artifacts, gates, links, invariants | Any error blocks                         |
| Markdown lint     | markdownlint-cli2         | Consistent, parseable documentation          | Any error blocks                         |
| Link check        | Lychee                    | Broken local/external references             | Broken required link blocks              |
| Secret scan       | Gitleaks                  | Credentials and token patterns               | Any verified secret blocks               |
| Workflow audit    | Zizmor and actionlint     | GitHub Actions security and syntax           | High finding or syntax error blocks      |
| Dependency review | npm audit and OSV-Scanner | Known vulnerable tooling dependencies        | Critical/high exploitable finding blocks |

## Python control-plane checks

| Check                  | Free software             | Blocking rule                                                                    |
| ---------------------- | ------------------------- | -------------------------------------------------------------------------------- |
| Format/lint            | Ruff                      | Any error                                                                        |
| Types                  | mypy                      | Any error in owned code                                                          |
| Unit/integration tests | pytest                    | Any failure                                                                      |
| Coverage               | coverage.py               | Changed security-critical module below 90%; project below active-phase threshold |
| SAST                   | Bandit and Semgrep CE     | Unresolved high finding                                                          |
| Dependency audit       | pip-audit and OSV-Scanner | Unresolved high/critical reachable finding                                       |
| API contract           | Spectral                  | OpenAPI error                                                                    |

## Go agent checks

| Check           | Free software                           | Blocking rule                              |
| --------------- | --------------------------------------- | ------------------------------------------ |
| Format          | gofmt                                   | Difference                                 |
| Correctness     | go test, go vet                         | Any failure                                |
| Static analysis | Staticcheck                             | Any error                                  |
| Vulnerabilities | govulncheck and OSV-Scanner             | Unresolved reachable high/critical finding |
| Lint            | golangci-lint                           | Configured error                           |
| Race tests      | Go race detector on supported CI target | Any race                                   |

## Build and release checks

| Check                  | Free software                                | Purpose                                            |
| ---------------------- | -------------------------------------------- | -------------------------------------------------- |
| SBOM                   | Syft                                         | SPDX or CycloneDX component inventory              |
| Artifact/image scan    | Trivy and Grype                              | OS and dependency vulnerability evidence           |
| Containerfile lint     | Hadolint                                     | Safer image construction                           |
| IaC scan               | Checkov and Trivy config                     | Misconfiguration detection                         |
| Provenance             | GitHub artifact attestations or SLSA tooling | Build/source binding                               |
| Signature verification | Cosign                                       | Artifact identity and integrity                    |
| OpenSSF Scorecard      | Scorecard CLI                                | Repository security posture; advisory until public |

## G2A full-system Debian qualification

`Debian 12 systemd qualification` is a protected-main check. It builds the
package from the exact commit and runs the G2A lifecycle, containment, resource,
upgrade, recovery, restart-bound, revocation, removal, and purge contract under
Debian 12 with `systemd` as PID 1 and no non-loopback network interface.

Any failed assertion blocks merge. Passing G2A is package-runtime evidence only;
it does not open G2 or authorize endpoint installation.

## Rules for findings

- Scanner absence is a failed check, not a pass.
- A suppression must identify the rule, exact location, justification, reviewer,
  expiry, and compensating control.
- Severity does not replace exploitability analysis, but high and critical
  findings remain blocking until triaged in writing.
- Generated reports must not contain secrets or private endpoint data.
- CI uses least-privilege `GITHUB_TOKEN` permissions and no untrusted-code
  execution with write-capable tokens.
