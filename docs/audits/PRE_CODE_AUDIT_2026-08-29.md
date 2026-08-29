# Pre-Code Audit — 2026-08-29

Status: Pending remote repository control verification  
Audited local commit: `a54ebd1d89b5fe8b860ad8aaea582e021b51f41a`  
Auditor: Codex acting under project-owner authorization  
Gate: G1 — Product coding

## Scope

This audit reviews Phase 0 architecture, Windows/Linux and remote-access scope,
security requirements, threat model, authorization gates, repository controls,
free-software checks, dependency state, documentation integrity, and absence of
product code.

The audit does not authorize endpoint installation, remote job delivery,
privileged actions, agent updates, interactive sessions, public exposure, or
production deployment.

## Requirement evidence

| Requirement                           | Evidence                                       | Result                  |
| ------------------------------------- | ---------------------------------------------- | ----------------------- |
| Charter and cross-platform scope      | `PROJECT_CHARTER.md`                           | Pass                    |
| Phased development                    | `docs/governance/PHASES.md`                    | Pass                    |
| Machine-enforced authorization gates  | `governance/gates.json`, gate scripts          | Pass                    |
| Control mapping                       | `governance/controls.json`                     | Pass                    |
| Architecture and component boundaries | `docs/architecture/`                           | Pass                    |
| Windows and Linux remote access       | `docs/architecture/REMOTE_ACCESS.md`, ADR 0007 | Pass                    |
| Identity/protocol/job model           | protocol and data-model documents              | Pass                    |
| Threat model and risk register        | `docs/security/`                               | Pass                    |
| Security requirements                 | 55 uniquely identified requirements            | Pass                    |
| Secure update and supply chain        | update and dependency policies                 | Pass                    |
| Data classification and retention     | data policy                                    | Pass                    |
| Incident response and recovery        | `docs/operations/`                             | Pass                    |
| Required free-software checks         | required-check matrix and CI workflows         | Pass                    |
| GitHub desired-state baseline         | documentation and machine-readable JSON        | Pass                    |
| Product code absent while G1 closed   | governance audit and path inspection           | Pass                    |
| Private GitHub repository exists      | GitHub API/repository URL                      | Pending authentication  |
| Branch/ruleset and security settings  | GitHub API/settings verification               | Pending authentication  |
| Remote CI results                     | GitHub Actions runs                            | Pending repository push |

## Executed checks

All checks targeted the exact local commit shown above with a clean worktree.

| Check                         | Version or source            | Result                                          |
| ----------------------------- | ---------------------------- | ----------------------------------------------- |
| Governance/control/link audit | repository script            | Pass: 0 errors; license warning retained        |
| Workflow pin/permission audit | repository script            | Pass: 0 errors                                  |
| Markdownlint                  | 0.23.2                       | Pass: 46 files, 0 issues                        |
| Prettier                      | 3.9.6                        | Pass                                            |
| Gitleaks directory scan       | 8.28.0                       | Pass: no leaks                                  |
| Gitleaks Git-history scan     | 8.28.0                       | Pass: two commits, no leaks                     |
| actionlint                    | 1.7.12                       | Pass                                            |
| Zizmor                        | 1.29.0                       | Pass offline audits; no findings                |
| Semgrep Community Edition     | 1.175.0, 68 JavaScript rules | Pass: 4 audit scripts, 0 findings               |
| npm audit                     | npm advisory service         | Pass: 0 vulnerabilities                         |
| pip-audit                     | 2.10.1                       | Pass after remediation: 0 known vulnerabilities |
| Lychee                        | 0.24.2                       | Pass: 34 links, 0 errors                        |
| Git staged whitespace check   | Git                          | Pass after remediation                          |

Zizmor reported that online-only audits were unavailable without a remote/auth
context. Its offline workflow analysis passed. Remote CI and GitHub settings remain
explicitly pending rather than being inferred from local files.

## Findings and remediation

### PC-001 — Security requirement parser mismatch

Severity: Medium  
Status: Resolved

The governance audit initially parsed zero requirement IDs because the Markdown
bold marker included a colon. The parser was corrected and now validates all 55
unique requirements and their control mappings.

### PC-002 — Protocol revocation checkpoint not explicit

Severity: High  
Status: Resolved

The protocol used revocation concepts elsewhere but did not explicitly state the
connection/message/dispatch checkpoints. The protocol now requires revocation
checks during TLS authentication, message acceptance, and dispatch.

### PC-003 — Markdown conformance failures

Severity: Low  
Status: Resolved

The first lint run reported 175 formatting findings. Markdownlint autofixes,
targeted heading changes, and a documented table-style configuration reduced the
result to zero.

### PC-004 — Secret-scanner false positive

Severity: Medium  
Status: Resolved without suppression

Gitleaks interpreted data-model prose containing “fencing token” as a generic
secret assignment. The prose was clarified to “monotonic fence”; no baseline or
scanner suppression was introduced.

### PC-005 — Vulnerable audit environment package manager

Severity: High  
Status: Resolved

Pip-audit identified seven advisories affecting inherited `pip` 25.0.1. The
isolated audit environment was upgraded to 26.2.1 and pip-audit then reported no
known vulnerabilities.

### PC-006 — Git line-ending and whitespace enforcement gap

Severity: Medium  
Status: Resolved

The first staged check exposed Windows line-ending conversion, intentional
Markdown hard-break whitespace, and blank lines at EOF. `.gitattributes`,
Prettier, and a blocking format check were added. The clean audited baseline is
the later commit identified above, not the initial root commit.

### PC-007 — Public license intentionally absent

Severity: Medium  
Status: Accepted constraint, not a waiver

No distribution license has been chosen. The repository must remain private and
no public release may occur until the owner makes a licensing decision and
dependency-license compatibility is audited. This blocks public distribution but
does not block private Phase 1 simulation.

### PC-008 — GitHub authentication and remote controls pending

Severity: High  
Status: Open and gate-blocking

The saved GitHub CLI token is invalid, and the in-app browser was signed out. An
official GitHub device-login flow is awaiting project-owner authorization. The
private repository, branch protection/ruleset, security settings, push, and remote
CI evidence cannot be verified until authentication succeeds.

## Gate conclusion

**G1 remains closed.** The local architecture and security baseline passed, but a
full repository audit is not complete until PC-008 is resolved and the remote CI
checks pass on the exact pushed baseline. No product code may be created yet.
