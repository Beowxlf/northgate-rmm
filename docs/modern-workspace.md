# Modern workspace source candidate â€” 2026-09-08

Status: implemented source, awaiting product qualification and deployment.
The owner requested code completion first and testing afterward. This candidate
does not change the running lab, identity-provider settings or endpoint software.

## Implemented capability

| Area | Behavior in this candidate |
| --- | --- |
| Workspace | Responsive CRM-style navigation, light/dark themes, overview, loading and stale-data states, keyboard-accessible dialogs and device tabs |
| Inventory | Search, sort, pagination, filters, private saved views, multi-select, JSON export, site/owner/tags/criticality/notes |
| Device workspace | Integrated tabs for existing SYSTEM/root management, SSH and NorthGateRMM-Ops file transfer, capture and inspection; Windows RDP download |
| Organization | Nested device groups; group targeting includes descendants; dependency and cycle validation |
| Policies | Validated Windows/Linux actions and parameters, UTC maintenance windows, canary count, concurrency, failure threshold and promotion review |
| Rollouts | Explicit target preview, exclusions, enrollment identity pinning, idempotent start/dispatch, pause/resume/cancel, queue-pressure waiting, outcomes |
| Automation | Saved recurring policy definitions; explicitly armed runs use the approving session and fixed target snapshot |
| Updates | Scan/install OS updates, package install/remove, prerequisite installation and signed component update dispatch through existing workers |
| Monitoring | Offline, missing worker, missing capture/package prerequisites, missing managed recovery account, latest failed job and baseline-drift alerts |
| Alert workflow | Deduplication, delay, escalation, acknowledge, snooze, resolve, condition-clear reconciliation and event export |
| Baselines | Compare platform, architecture, reported component versions and feature readiness with saved snapshots |
| Recovery | Scoped receipt metadata and reported managed-account coverage; existing role-protected secret retrieval remains in system tools |
| Exercises | Exercise context and outcome records; rollout/job evidence export with SHA-256 integrity reference |
| Access | Owner plus explicitly configured technicians, endpoint/action grants, existing identity-provider MFA and role verification |
| Operations | Workspace/scheduler readiness, encrypted record persistence, revision conflicts, resumable local JSONL export for SIEM collectors |

These workflows call the existing worker action implementations. No new agent
wire protocol, desktop engine, packet-capture engine or database server is added.
The browser does not store credentials or bearer tokens in local storage; only
the color-theme preference is saved there. Existing remote credentials remain
under the existing encrypted custody mechanism.

## Access configuration

The protected operator service configuration accepts optional
`policy_operator_grants`. Existing owner-only configurations remain valid.
Example additional grant (use a real IdP subject and enrolled endpoint UUID):

```json
{
  "policy_operator_grants": [
    {
      "subject": "technician-subject-from-idp",
      "endpoints": ["11111111-1111-4111-8111-111111111111"],
      "permissions": ["view", "remote", "manage", "patch"]
    }
  ]
}
```

Add the same subject to the OIDC bridge configuration's `allowed_subjects` list.
The issuer, tenant, client, MFA strength and existing IdP roles remain enforced.
`viewer` permits portal authentication; `remote_operator` is additionally
required for remote/management execution; `recovery_operator` is additionally
required for recovery operations and secret retrieval. Grants do not replace
those identity-provider roles. Use `view` with any endpoint tool permission and
`manage` with `patch` or `recovery` to access the corresponding system workspace.

Permissions are `view`, `remote`, `manage`, `patch`, `recovery`, and `fleet_admin`.
`fleet_admin` with endpoint scope `*` enables global record administration.
The pinned owner retains full policy access but still needs applicable IdP roles.
The UI cannot create grants, change identities or elevate itself. Saved views are
private to their author. Policies and automation administration are fleet-admin
operations; this candidate does not include a separate policy-sharing editor.

Before a future deployment, validate the two configuration files locally:

```sh
northgate-rmm-fleet-admin validate-access \
  --operator /absolute/path/operator.json \
  --bridge /absolute/path/oidc.json
```

This compares the subject allowlists, owner, issuer and client. It does not log
secrets, contact the identity provider or validate live MFA behavior. Keep the
configuration files private. A successful comparison is not a deployment test.

## Execution and recovery semantics

1. Preview resolves selected devices or a group, excludes unsupported/offline/
   unauthorized targets and pins enrollment identities plus the policy revision.
2. Start uses the preview ID as the rollout ID. The same preview cannot create
   duplicate rollouts. Previews expire after ten minutes.
3. Every scheduler pass revalidates the approving human's authorization. Every
   worker lease still uses the existing endpoint-bound authorization checks.
4. Runs last at most one hour and cannot outlive the approving session. Definitions
   can express longer intervals, but a cycle will not start beyond that lifetime.
   Long-term unattended scheduling requires a separately designed service identity;
   this implementation never turns a user token into one.
5. Canary dispatch precedes promotion. Default promotion requires explicit review.
   Maintenance windows apply to new dispatches. Overnight windows belong to the
   day on which they start; equal start/end means a full day on selected days.
6. Pause stops new dispatches. Cancel requests cancellation of active jobs; it
   cannot reverse an already completed installation or guarantee rollback of an
   OS operation. Existing worker lease expiration remains authoritative.
7. Durable per-cycle/per-endpoint job IDs recover dispatch records after process
   restart. Uncertain worker results remain uncertain and are not automatically
   replayed as if they had never run. Changed enrollment stops affected dispatch.

Fleet records and a monotonic event sequence are additive tables in the existing
encrypted management SQLite database. Existing database backup includes them;
the encryption key must still be backed up separately. No PostgreSQL schema
migration is introduced. The new inventory query uses existing read-only tables.
Database indexes, retention and full restore still need qualification together.

## Routes and future deployment integration

The new entry point is `/remote/fleet/ui`. Static assets are at
`/remote/fleet/assets/fleet.js` and `fleet.css`; authenticated state/mutations use
`/remote/fleet/api/`. The supplied remote Nginx snippet redirects exact
`/endpoints` to the new workspace. Existing `/endpoints/{uuid}` records and
`/remote/{uuid}/...` tools remain available.

Package and install the same reviewed server wheel into the operator, remote
gateway and OIDC bridge environments so policy support agrees across components.
Merge the updated Nginx snippet into the existing private operator server block;
avoid duplicate exact `/endpoints` locations. Retain the existing proxy identity
headers and same-origin frame configuration. All new assets are included in the
wheel; no frontend build service or external CDN is required.

Existing management workers already implement the actions used here. This
candidate does not require an agent version bump. Agents lacking an action or
dependency must report that limitation during qualification. Windows Update uses
the existing Windows Update Agent path independently of WinGet; software package
actions still require WinGet under SYSTEM. Linux package actions require the
supported package manager. Npcap installation/licensing and absent OS tooling
remain actual endpoint prerequisites, not UI success states.

For rollback after a future canary: stop new runs, cancel/drain active work,
restore the previous server wheel and Nginx configuration, and retain a consistent
database/key backup. Additive tables can remain for prior code, but rollback does
not undo completed endpoint actions. Reconcile those from receipts explicitly.

## SIEM event export

The local administrative CLI emits credential-free JSONL suitable for a file
collector. It does not install or configure a Wazuh/Splunk collector.

```sh
northgate-rmm-fleet-admin export-events \
  --root /var/lib/northgate-rmm-remote/management \
  --key /absolute/path/existing-management-key \
  --output /absolute/private/path/fleet-events.jsonl \
  --checkpoint /absolute/private/path/fleet-export-cursor.json
```

Use one exporter process per output/checkpoint pair. Each invocation exports up
to 1,000 new fleet events; repeat until `exported` is zero. Stable event IDs allow
collector deduplication. The file is flushed before checkpoint advancement, so
a crash may duplicate events rather than silently skip them. Output must be a
private regular file. Checkpoints and state are bound operationally: after a
database restore use a fresh cursor/output pair, deduplicating by event ID.

The export contains allowlisted identity references, operation/alert state and
counts. It excludes passwords, recovery keys, bearer tokens, arbitrary script
parameters, command output and notes. Export before the existing 90-day evidence
retention expires. A SHA-256 export checksum detects byte changes relative to a
trusted reference; it is not a digital signature or proof of independent custody.

## Explicit qualification limits

Source limits are 10,000 inventory rows, 4,096 pinned remote targets, 64 additional
operators with 4,096 aggregate endpoint-scope entries, 500 devices per preview,
16 simultaneous dispatches per run and the existing 64-job global queue. These
are bounds, not demonstrated performance claims. The workspace displays the most
recent 500 records per category; older audit evidence has its separate export path.

This is a private single-organization workspace with technician scopes, not
tenant-isolated SaaS. High availability, capacity/SLA guarantees, off-site backups,
unattended service-identity automation, external notification delivery, full patch
compliance history, ticketing/PSA, billing and regulatory certification are not
claimed. Recovery receipt coverage is not evidence that a restored system boots.
The new UI and existing embedded tools must still be reviewed in a real browser.

## Next testing phase

The new `tests/test_fleet.py` definitions cover scope denial, overnight windows,
unsupported bulk actions, encrypted revision conflicts, dispatch idempotency,
changed-payload conflicts and event-export retention/resumption. They were written
for the next phase and were not executed during source delivery.

Qualification order:

1. Run focused unit tests, existing authorization/management regressions and
   PostgreSQL integration tests in isolated test state. Record the existing
   repository-wide typing/coverage baseline separately from new-code checks.
2. Exercise owner and scoped technician sessions: cross-endpoint requests,
   guessed private policy IDs, expired/revoked sessions, missing MFA/roles,
   CSRF, exports and direct access to every embedded tool.
3. Browser review of login, assets/CSP, responsive layout, light/dark appearance,
   keyboard dialogs, filters, saved views, stale connection recovery and repeated
   opening of tabs while terminals remain active.
4. Simulate scheduler restart between queue insert and rollout persistence,
   repeated approval, stale editors, queue saturation, canary failure, window
   boundaries, pause/cancel, changed enrollment and session expiry.
5. Verify alert activation/delay/deduplication, snooze expiry, recurrence,
   acknowledgement, escalation, condition clear and JSONL export without secrets.
6. Deploy one reviewed server candidate with a recoverable backup, then use one
   Windows and one Linux canary. Begin with inventory/posture and update scans.
   Compare current/expected results before installing packages or updates.
7. Qualify prerequisite reporting, signed component upgrades, existing SYSTEM/root
   terminals, SSH/file transfer, packet capture, recovery permissions and restore
   evidence. Do not label a missing dependency as successful execution.
