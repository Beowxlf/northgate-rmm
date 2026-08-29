# Pre-Code Audit — 2026-08-29

Status: Pass  
Audited licensed public baseline: `f426a7a1fc9108145de1d1456e6cdc4cd175fa2a`  
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

| Requirement                            | Evidence                                       | Result |
| -------------------------------------- | ---------------------------------------------- | ------ |
| Charter and cross-platform scope       | `PROJECT_CHARTER.md`                           | Pass   |
| Phased development                     | `docs/governance/PHASES.md`                    | Pass   |
| Machine-enforced authorization gates   | `governance/gates.json`, gate scripts          | Pass   |
| Control mapping                        | `governance/controls.json`                     | Pass   |
| Architecture and component boundaries  | `docs/architecture/`                           | Pass   |
| Windows and Linux remote access        | `docs/architecture/REMOTE_ACCESS.md`, ADR 0007 | Pass   |
| Identity/protocol/job model            | protocol and data-model documents              | Pass   |
| Threat model and risk register         | `docs/security/`                               | Pass   |
| Security requirements                  | 55 uniquely identified requirements            | Pass   |
| Secure update and supply chain         | update and dependency policies                 | Pass   |
| Data classification and retention      | data policy                                    | Pass   |
| Incident response and recovery         | `docs/operations/`                             | Pass   |
| Required free-software checks          | required-check matrix and CI workflows         | Pass   |
| GitHub desired-state baseline          | documentation and machine-readable JSON        | Pass   |
| Product code absent while G1 closed    | governance audit and path inspection           | Pass   |
| Public Apache-2.0 repository exists    | `Beowxlf/northgate-rmm`                        | Pass   |
| Merge and Actions settings             | GitHub API verification                        | Pass   |
| Dependabot alerts and security updates | GitHub API verification                        | Pass   |
| Secret scanning and push protection    | GitHub API verification                        | Pass   |
| Private vulnerability reporting        | GitHub API verification                        | Pass   |
| Protected `main`                       | GitHub branch-protection API                   | Pass   |
| Remote commit matches candidate        | local and remote `main` SHA                    | Pass   |
| Remote governance CI                   | Actions run `33262548272`                      | Pass   |
| Remote security CI                     | Actions run `33262548264`                      | Pass   |

## Executed checks

All checks targeted the exact local commit shown above with a clean worktree.

| Check                         | Version or source            | Result                                          |
| ----------------------------- | ---------------------------- | ----------------------------------------------- |
| Governance/control/link audit | repository script            | Pass: 0 errors and 0 warnings                   |
| Workflow pin/permission audit | repository script            | Pass: 0 errors                                  |
| Markdownlint                  | 0.23.2                       | Pass: 48 files, 0 issues                        |
| Prettier                      | 3.9.6                        | Pass                                            |
| Gitleaks directory scan       | 8.28.0                       | Pass: no leaks                                  |
| Gitleaks Git-history scan     | 8.28.0                       | Pass: repository history, no leaks              |
| actionlint                    | 1.7.12                       | Pass                                            |
| Zizmor                        | 1.29.0                       | Pass offline audits; no findings                |
| Semgrep Community Edition     | 1.175.0, 68 JavaScript rules | Pass: 4 audit scripts, 0 findings               |
| npm audit                     | npm advisory service         | Pass: 0 vulnerabilities                         |
| pip-audit                     | 2.10.1                       | Pass after remediation: 0 known vulnerabilities |
| Lychee                        | 0.24.2                       | Pass: 34 links, 0 errors                        |
| Git staged whitespace check   | Git                          | Pass after remediation                          |

Local Zizmor offline analysis passed. The remote workflow also ran Zizmor with its
online audits, and every security-workflow step passed on the exact candidate
commit. The two passing run URLs are retained by GitHub under the run identifiers
listed above.

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

### PC-007 — Public license initially absent

Severity: Medium  
Status: Resolved

The owner approved licensing and public visibility. The exact Apache-2.0 text,
NOTICE attribution, licensing policy, dependency rules, and contribution terms
are committed. GitHub recognizes the repository license as Apache-2.0.

### PC-008 — GitHub authentication was unavailable

Severity: High  
Status: Resolved

The saved GitHub CLI token was initially invalid. Project-owner authorization was
completed, the private repository was created, the candidate was pushed, and live
settings and CI results were verified.

### PC-009 — Linux CI shell and archive assumptions

Severity: High  
Status: Resolved

The first remote security run found three unquoted executable paths that the
Windows-local actionlint environment did not detect. After quoting them, the next
run proved that the Lychee archive contains a top-level directory. The executable
paths were quoted, the checksum-matched archive layout was inspected, extraction
now strips one path component, and all remote security steps pass.

### PC-010 — Private `main` cannot be protected on the current plan

Severity: Critical  
Status: Resolved

GitHub rejected protection while the repository was private. After explicit
owner authorization, Apache-2.0 licensing, and public publication, the same rule
was accepted. Pull requests, strict status checks, administrator enforcement,
linear history, conversation resolution, and force-push/deletion prohibitions are
live.

### PC-011 — Private vulnerability reporting applicability

Severity: Low  
Status: Resolved

The initial desired state incorrectly required private vulnerability reporting on
a private repository. GitHub returned HTTP 404 because the feature is intended to
receive confidential reports for public repositories. After the approved public
transition, private vulnerability reporting was enabled and verified. Dependabot
alerts and automated security fixes remain enabled.

### PC-012 — Single-maintainer review constraint

Severity: Medium  
Status: Accepted with enforced mitigation

The only maintainer cannot provide an independent approval for their own pull
request. The protected branch therefore requires a pull request and both CI
checks but temporarily requires zero approvals and no CODEOWNERS review. The rule
still applies to administrators and blocks direct push, stale branches, failed
checks, unresolved conversations, force pushes, and deletion. Onboarding a second
trusted maintainer requires raising the baseline to one independent approval and
CODEOWNERS review.

## Gate conclusion

**G1 passes.** The licensed public baseline, local audit suite, remote workflows,
security features, and protected branch satisfy the pre-code criteria. The G1
authorization record in this protected change permits only bounded Phase 1 coding
with synthetic data; G2 through G8 remain closed.
