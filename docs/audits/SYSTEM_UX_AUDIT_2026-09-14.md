# System and UX audit — 2026-09-14

Status: **audit findings recorded; remediation deployed, acceptance remains open**.

Scope: deployed server, all 16 enrolled devices, remote access, current UX,
source/deployment drift, repository documentation, and native credential custody.

## Findings and treatment

| Finding | Treatment / acceptance |
| --- | --- |
| Nine deployed source files were newer than the working checkout | Preserved the deployed SOC-case, intake, and tool-catalog changes in source; regression tests pass. |
| Modern features existed as uncommitted source while the README described an undeployed candidate | Reconciled source, release packaging and current guides; preserve historical phase records as historical evidence. |
| NG-CYBER-01 monitoring was online but its management service had failed at boot | Service recovered; delayed automatic start configured; fresh worker report verified. Reboot qualification pending. |
| A long-idle browser tab could say “Updated just now” | Show actual refresh time and refresh when returning to a visible/restored tab. |
| Windows native MCP terminal input interpreted LF as multiline editing | Normalize native Windows terminal newlines to ConPTY Enter; preserve Linux input; regression tests added. |
| Three Windows machines lacked RDP targets; two existing native routes were missing | All 16 now advertise RDP and SSH. Exact owner/gateway rules applied; TCP RDP reachable on 14/16, with the two OOBE machines excluded from connection acceptance. |
| NG-WRK-01 and NG-WRK-02 are still in Windows OOBE | Both report `OOBEInProgress=1` and `IMAGE_STATE_UNDEPLOYABLE`; completing Windows setup is required before RDP acceptance. Do not mark them ready merely because monitoring works. |
| Only ten native credentials had been stored on Smooth Operator | All 16 now stored and read back. Owner-bound current-user DPAPI profiles are deployed and match the current vault values. All 16 local encrypted RDP files were created. Interactive automatic sign-in pending. |
| Three daily backup timers contradicted the owner's preference | Disabled schedules; retained manual backup services and existing recovery artifacts. |
| Linux test fixtures did not set private permissions; a fixture used a symlinked executable | Correct the fixtures without weakening product file validation. |
| Linux RDP tests could not be collected by the full suite | Fixed the package-qualified fixture import. |
| Repository strict typing gate fails | 1,358 diagnostics in 48 files after this review, dominated by missing annotations/untyped calls in newer modules; local optional MCP dependencies also affect this check. This is outstanding development work, not 1,358 demonstrated runtime bugs. No blanket ignores or weakened gate were added. |
| Bandit flagged runbook SQL construction | Reviewed as fixed predicates with bound values; added a narrow documented suppression. No user-supplied SQL is concatenated. |
| Native case/infrastructure overview timed out at about 190 seconds | Repeated per-record enrollment connections caused excessive work. Request-local enrollment validation with final scope/enrollment revalidation reduced the live request to 8.6 seconds. Revocation regression tests pass. |
| Infrastructure documentation in the RMM is largely unpopulated | Live scope contains 2 assets and no service, network or relationship records. These workflows exist, but their data population is incomplete. |
| Automated credential/recovery policy is not configured fleet-wide | All 16 workers report credential rotation unavailable and no managed recovery account. The 16 vault-backed lab logins are separate from managed recovery/rotation policy; they must not be presented as equivalent coverage. |
| Windows Go vet is not clean | Two unsafe-pointer diagnostics remain in the native account-query code in `credential_rotation_windows.go`. Rotation is unavailable in the observed fleet configuration; review and qualify this path before enabling it. The passing Go tests do not clear these diagnostics. |
| High-severity development dependency advisory | Pinned `smol-toml` to 1.7.1 through an npm override and regenerated the lockfile. npm audit reports zero known vulnerabilities; malformed TOML now rejects without hanging. [Upstream advisory](https://github.com/advisories/GHSA-7w5x-hrqm-74c2). The default-branch alert remains open until the fix is merged there. |

## Verification

- Windows Go agent suite passed across all packages.
- Initial Windows Python suite: 770 passed, 52 skipped.
- Reconciled deployed-source Python suite: 770 passed, 52 skipped.
- Final Windows Python suite: 777 passed, 52 skipped (database/platform tests).
- Native encrypted RDP and browser/RDP policy checks: 31 passed.
- Native API suite including Windows/Linux newline regression: 31 passed.
- Tool-catalog DOM contract checks: 8 passed.
- Ruff source/test checks passed after fixture repairs.
- Isolated Linux/PostgreSQL suite: 828 passed, one restore fixture failed because
  it inherited SQL_ASCII. Creating its restore database explicitly as UTF-8 fixed
  it; the targeted rerun passed. All 829 collected Linux cases therefore have
  passing results across the full run and targeted repair rerun.
- Final native/profile/runbook/workspace regression batch: 48 passed; final
  native credential checks also passed after annotation-only cleanup.
- Ruff lint and formatting, JavaScript syntax and medium/high Bandit checks pass.
- Live deployment: all 16 devices online, all 16 management workers ready; core
  control-plane services active, no failed systemd units at verification.
- Every installed package file matched the reviewed wheel. Sixteen encrypted
  native profiles matched current enrollment, owner grants and OpenBao values.
- Live Windows SYSTEM terminal accepted LF input, executed the marker command,
  and returned `nt authority\\system`; audit terminal was closed afterward.
- Native RDP TCP connections succeeded from Smooth Operator to 14/16 machines.
  TCP reachability is not an interactive authentication or desktop usability test.
- Isolated PostgreSQL test service was stopped. Daily backup timers remain disabled.
- Native overview after repair: 21 cases, 344 alerts, 72 exercise records, 2 assets
  and 1 document; Wazuh intake is configured. Capture readiness returned actual
  interfaces on the Linux canary, and the Windows installable-tool catalog loaded.
- Operations regression checks after the timeout fix: 43 passed on Windows;
  44 passed with the isolated Linux/PostgreSQL adapter. Request-local caching,
  enrollment replacement, scope revocation and action revocation are covered.

Deployed server package: `1.2.0+lab.20260914`, wheel SHA-256
`5a1be94f146b40c8092758d12b3626919336213520dbf9c4ba2ca623d0d15f26`.
No new agent binary was needed for these server-side fixes.

The lightweight secret scan found only generated cache copies and explicit
synthetic security fixtures (a header without a private key, repeated-number
recovery test value and named synthetic password). Credential values, DPAPI
profiles and transfer envelopes are outside the Git source tree. This does not
replace the repository's full Gitleaks/dependency/security CI workflow.

## Open acceptance and development work

1. Finish Windows first-run setup on NG-WRK-01 and NG-WRK-02, then qualify RDP.
2. Complete owner MFA sign-in for the live browser walkthrough and verify native
   automatic sign-in from Smooth Operator. No human MFA session was fabricated.
3. Resolve the strict typing backlog and run the complete CI coverage, dependency,
   security, packaging and governance gates before declaring a fully clean release.
4. Reboot-qualify NG-CYBER-01's recovered management service in a maintenance window.
5. This audit did not repeat every install/uninstall, patch, restore, capture,
   red-team exercise, or remote desktop session on every device. Existing historical
   acceptance is not relabeled as fresh proof.
6. Populate infrastructure records and qualify a managed recovery/credential
   rotation policy before claiming those functions have fleet-wide coverage.

Credential transfer cleanup succeeded on the control plane and Hyper-V host.
Automatic approval review blocked deletion of the four local temporary transfer
artifacts. They contain encrypted envelopes/profiles or public transfer metadata,
not plaintext passwords, and are restricted to the owner, SYSTEM and
Administrators. They remain outside Git. The requested local RDP files and
Credential Manager entries are retained intentionally.

The owner's in-app browser session expired before live UI inspection. Owner
sign-in and Windows OOBE completion remain requested. Synthetic and API checks
must not be reported as those live acceptance results.

## Intended limitations

Npcap and installable capture tools are optional, on-demand prerequisites.
Windows package-manager availability under SYSTEM depends on the installed
package manager. Recovery-account rotation and full restore qualification are
separate from merely having a lab login or an archive. The product is private-lab
software; this audit does not certify every OS, timing condition, or future
configuration as free of defects.
