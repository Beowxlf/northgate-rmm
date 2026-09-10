# Modern workspace review — 2026-09-09

Reviewed baseline: `9ad6ff01f48609b34532bf3656ea6d922e1220d4`.

Four review passes were completed: three batches of findings and corrections,
followed by a pass with no new actionable findings in the reviewed scope.
This is a local code and fixture-based functional review, not a certification
that no bugs remain. Deployment stayed paused following the owner's instruction
to review and fix first. No lab configuration, endpoint or service was changed.

## Scope and method

Reviewed the modern workspace backend, authorization integration, encrypted
records, scheduler and job custody, export paths, alert lifecycle, frontend
interactions and packaging. Used focused reproductions before fixes, the full
local Python regression suite, and isolated headless Edge with synthetic data.
The browser runner intercepts all application requests and never targets the lab.
Existing IdP, SSH, SYSTEM/root and capture engines were covered only to the extent
exercised by local regressions; their live behavior was not requalified.

## Findings and corrections

| ID | Finding | Correction and evidence |
| --- | --- | --- |
| R01 | Automation previews could ignore their saved group | Resolve the saved automation group server-side and reject a conflicting override; regression reproduced and passes |
| R02 | Rollouts could attach an inaccessible or nonexistent exercise | Validate the exercise ID and author/admin access before preview creation; scoped regression passes |
| R03 | Bulk script execution accepted inputs rejected by individual execution | Centralize string/type/length validation in the shared action contract; three invalid-input cases pass |
| R04 | Export output/checkpoint aliases could overwrite a log or database | Reject identical files, hardlink aliases, state-directory destinations and encryption-key destinations before writing; alias/database cases pass |
| R05 | A newly failed job could remain acknowledged under an older alert | Reopen when the condition fingerprint changes and restart incident timing; regression passes |
| R06 | Expired jobs could stall a rollout when the worker stopped polling | Reconcile job expiry independently before advancing rollout state; offline expiry regression passes |
| R07 | Reads stopped below the supported record capacity | Read to the 10,000-record ceiling so active runs, metadata and dependency checks are not silently omitted; reviewed all internal list callers |
| R08 | Export could silently skip evidence after output deletion/truncation | Bind the cursor to output path and committed size; reject missing/mismatched output; output-loss regression passes |
| R09 | Interrupted cancellation could lose the operator's intent | Persist a token-free cancelling state before queue mutations; restart finishes cancellation; injected-write-failure regression passes |
| R10 | Queued patch work could survive withdrawal of its management grant | Recheck management permission as well as the action permission during dispatch/lease authorization; hide disallowed tool actions; revocation regression passes |
| R11 | Partial bulk assignment could not be retried | Retain successful revisions and remove completed devices from the remaining selection; browser fault injection passes |
| R12 | Navigating away during search raised a JavaScript exception | Clear pending search callbacks on navigation and verify the search element before focusing; browser reproduction passes |
| R13 | Deleted default alert rules returned after process restart | Seed defaults once using an atomic persistent marker; restart regression passes |
| R14 | Fleet configuration writes bypassed the management storage guard | Enforce the guard for edited configuration, baselines and previews while preserving cancellation/status persistence; capacity regression passes |

Also updated an outdated management test fixture for the real access-policy
contract, preserved generic rollout failure reasons in the UI, and corrected
remote redirect handling to avoid aiohttp deprecation warnings.

## Review passes

1. Initial suite: **426 passed, 1 failed, 46 skipped**. The failure was an outdated
   fixture; new reproductions also confirmed the first defect batch. Fixes passed
   the focused suite.
2. Failure recovery and browser pass: reproduced partial-edit/search errors,
   lost cancellation intent, export-output loss and management-grant withdrawal.
   All corresponding fixes passed targeted regressions and browser replay.
3. Persistence and integration pass: broader tests passed; final restart/storage
   probes exposed R13/R14. Both were corrected and their regressions passed.
4. Final pass: **445 Python tests passed, 46 skipped, no warnings**. The isolated
   desktop/mobile browser runner completed with **zero JavaScript errors**.
   No new actionable findings emerged from the reviewed contracts and final diff.

The original eight fleet tests are supplemented by eighteen review cases
(including parameterized cases). Additional cases verify crash-after-dispatch
idempotency, canary promotion, direct tool authorization, CSRF and packaged assets.

## Final checks and artifact

- Ruff passed for changed implementation and regression files.
- Focused strict typing passed for five fleet modules and both fleet test files.
  This does not claim repository-wide typing or coverage is clean.
- Browser checks cover navigation, group creation, partial-save retry, searching
  during navigation, device tool tab reuse, mobile navigation and overflow.
- Desktop/mobile screenshots were inspected. Embedded tools use synthetic content
  in this check; actual terminal sessions remain a deployment acceptance item.
- Wheel build passed and changed packaged modules/assets matched working source.

Reviewed wheel SHA-256:
`d2f6b7a7f2e354138495c1f53cea9b81f15b8296d7eddac68779d0e429ba3977`

The wheel is in the task's `outputs/modern-workspace-reviewed` directory. It
supersedes the original source-only candidate for any later deployment.

## Reproducing the review

Run the Python suite with the repository's environment: `python -m pytest -q`.
The test database must be disposable: PostgreSQL integration fixtures truncate
their configured database. Never point `DATABASE_URL` at production or the lab's
operational RMM database.

`scripts/test-fleet-browser.cjs` requires Playwright and an installed Microsoft
Edge. Set `RMM_PLAYWRIGHT_MODULE` to a provisioned Playwright module path when it
is not on the normal Node module path. Set `RMM_REVIEW_OUTPUT` to an evidence
directory, then run `node scripts/test-fleet-browser.cjs`. The runner launches a
fresh temporary headless browser profile and closes it afterward.

## Remaining qualification boundary

The 46 skips include PostgreSQL integration and POSIX-specific checks. This
workstation has no configured disposable PostgreSQL instance and no installed
WSL runtime. Those checks, Linux execution, actual Windows worker behavior,
live MFA/IdP integration, real remote sessions, restore testing and large-fleet
load behavior remain unverified by this review. No new claim of enterprise or
production readiness is made. The owner retains deployment authority; this
review does not deploy the revised artifact automatically.
