# System and UX audit — 2026-09-14

Status: **historical engineering audit; interactive acceptance remains open**.

This public summary records source, test and documentation findings. Operational
identifiers, deployment measurements, fleet state, credential-custody details and
private acceptance records have been removed from this version. This redaction
does not rewrite earlier repository history.

The findings and test counts below describe the historical review. For current
repository verification and remaining scanner findings, see the
[PR 36 verification record](PR36_VERIFICATION_2026-10-01.md).

## Findings and treatment

| Finding                                                                | Treatment / acceptance                                                                                                                                                                                                                                                                                                   |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Source and documentation had diverged                                  | Reconciled the SOC/IT workspace, intake, tool catalog and guides; retained dated phase records as historical evidence.                                                                                                                                                                                                   |
| A long-idle browser tab could show an inaccurate refresh time          | Show the actual refresh time and refresh after the tab becomes visible or is restored.                                                                                                                                                                                                                                   |
| Windows native terminal input interpreted LF as multiline editing      | Normalize native Windows terminal newlines to ConPTY Enter; preserve Linux input; regression tests added.                                                                                                                                                                                                                |
| Linux fixtures did not preserve the product's file-validation contract | Correct private permissions and the executable fixture without weakening product validation.                                                                                                                                                                                                                             |
| Linux RDP tests could not be collected by the full suite               | Fixed the package-qualified fixture import.                                                                                                                                                                                                                                                                              |
| Strict typing failed in newer implementation and test modules          | Recorded as unresolved development work at the time of this audit. Current verification is tracked in the linked PR 36 record; no blanket ignores or weaker gate were introduced.                                                                                                                                        |
| Bandit flagged runbook SQL construction                                | Reviewed fixed predicates with bound values; the existing narrow documented suppression does not permit concatenating user-supplied SQL.                                                                                                                                                                                 |
| Native overview queries repeated enrollment lookups                    | Added request-local enrollment validation with final scope/enrollment revalidation; revocation regressions cover the authorization boundary.                                                                                                                                                                             |
| Windows Go vet reported native-pointer warnings                        | Recorded as unresolved during the historical review. Current native-pointer verification is tracked separately; unit and cross-build checks do not establish runtime acceptance.                                                                                                                                         |
| A development dependency had a high-severity advisory                  | Pinned `smol-toml` to 1.7.1 through an npm override and regenerated the lockfile. Historical npm audit reported no known vulnerabilities; malformed TOML rejects without hanging. [Upstream advisory](https://github.com/advisories/GHSA-7w5x-hrqm-74c2). Default-branch remediation requires the normal reviewed merge. |

## Historical repository verification

- Windows Go agent tests passed across the available packages.
- The historical Windows Python run reported 777 passed and 52 skipped for
  database/platform limitations. This was not complete cross-platform acceptance.
- Isolated Linux/PostgreSQL tests reported 828 passed and one restore-fixture
  failure. Explicit UTF-8 database creation corrected that fixture; its targeted
  rerun passed. This historical evidence was a full run plus a targeted rerun,
  not a later clean full-suite result.
- Native API, remote-access policy, tool-catalog contracts and authorization
  revocation regressions passed in their reported test environments.
- Ruff, JavaScript syntax and medium/high Bandit checks passed for that review.
- Earlier hosted qualification passed the Debian systemd and release-candidate
  trust workflows. Other workflows stopped before all required steps completed;
  those unexecuted checks were not reported as passing.

These statements preserve the historical evidence boundary. Later full-suite
results and precise scanner dispositions belong in their dated verification
records, rather than being retroactively attributed to this audit.

## Open acceptance boundary

1. Complete interactive browser and native-client qualification using authorized
   test identities and record the evidence in the appropriate private record.
2. Complete platform startup, service recovery and remote-session qualification
   before claiming runtime readiness.
3. Resolve required typing, coverage, dependency, security, packaging and governance
   gates against the final PR commit. Historical or local checks do not replace
   final-head hosted results.
4. Qualify install/uninstall, patch, backup/restore, capture, account recovery and
   remote-desktop workflows in their intended environments. Code availability or
   transport reachability alone does not prove operational acceptance.
5. Retain owner and independent-review requirements for security-significant
   changes and any proposed exception. This report grants no approval or waiver.

## Intended limitations

Capture dependencies and optional installable tools require their own platform
and licensing qualification. Package-manager availability depends on the actual
execution environment. Recovery and restore evidence must establish the requested
postcondition, rather than merely the presence of an account or an archive.

The public source review does not certify every OS, timing condition, deployment
or future configuration as free of defects. No new operational acceptance is
claimed by this redacted summary.
