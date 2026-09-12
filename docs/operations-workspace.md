# Operations workspace API

This module adds durable IT/SOC cases, infrastructure records and retained evidence. It does not run worker commands or grant extra endpoint privileges.

## Composition and deployment

```python
store = OperationsStore.postgres(dsn, artifact_root, management.gateway.key)
# Run store.migrate() explicitly with a migration-capable identity during deployment.
ops = Operations(management, fleet, store, inspection=None, capture=None,
                 wazuh_registry=None)
ops.register(app)
```

The store verifies its independent `ops_schema` version at startup. The production adapter uses PostgreSQL, with transactions, serialized mutations, revision conflicts, append-only record versions and timeline events. Its DDL is in `operations_store.SCHEMA`; migrating does not change the monitoring schema migration counter. Give the runtime identity only SELECT/INSERT/UPDATE on the new tables, DELETE only on `ops_scopes` and `ops_chunks`, and no UPDATE/DELETE on `ops_events` or `ops_versions`. Use a separate migration identity. `OperationsStore.sqlite_for_tests(path, artifact_root, key)` is an explicit test adapter, not the production fallback.

The artifact root must be a service-owned private directory. Evidence chunks are independently AES-GCM encrypted with artifact/index authenticated context. Back up the PostgreSQL operations tables, artifact directory and protected source key consistently. The default budget is 2 GiB reserved evidence, 128 MiB per artifact, 1 MiB per chunk, and 24 hours to finish an upload. Complete case evidence is not pruned by management/inspection retention. The operations service removes expired or cancelled partial uploads at startup and every 15 minutes, outside its request loop. Operators may cancel an unfinished upload from its case. No completed-evidence purge API is exposed in this first release.

## Authentication and permissions

Browser authentication reuses `Fleet.principal`. Mutations require a valid human MFA session with remote_operator role, the exact RMM Origin, and `X-CSRF-Token` from state. JSON `csrf` is accepted for existing clients. Every mutation must include a UUID `request_id`; retry the identical request with the same identifier after an uncertain response. Changed content with the same identifier fails with 409.

Permissions are explicit: `ops.view`, `case.manage`, `infrastructure.manage`, `evidence.manage`. A user must be permitted on **every** endpoint linked directly or through related records. Unscoped records require fleet administration. Scopes are cumulative: removing a device from a form does not declassify its older timeline/evidence. Case tasks and transitions require case.manage. Upload and pin require both case.manage and evidence.manage. Evidence download additionally requires evidence.manage. Old record versions retain their original scopes. Integration access uses the real service identity through `await ops.native_call(entry, operation, args)` after NativeAPI authentication, rechecks the registry/enrollment bindings, and does not fabricate MFA. Integration permissions must explicitly include the corresponding operations permissions.

## Read endpoints

| Request | Response |
| --- | --- |
| GET `/remote/ops/api/state` | `{csrf, capabilities, cases, assets, services, networks, relationships, documents, changes, exercises, alerts, metrics, limits}` |
| GET `/remote/ops/api/record/{kind}/{id}` | `{record, timeline, versions, evidence, next_before}`; pass `?before=<event timestamp>` for older timeline pages |
| GET `/remote/ops/api/upload/{id}` | `{upload}` including state, expected size/hash, received byte count, indexed chunk hashes and provenance |
| GET `/remote/ops/api/evidence/{id}/chunks/{index}` | `{index,size,sha256,data}` with base64 data; only complete evidence is readable |

Each record is `{kind,id,revision,created,updated,subject,value}`. Dates in wrapper fields are Unix seconds. `value.endpoints` contains endpoint UUID strings. List state returns at most 2,000 records per kind; timeline pages are 200 events, version history returns the latest 100 versions. All versions remain in custody. These are explicit response limits, not claims of fleet-scale pagination.

## Mutation endpoints

POST `/remote/ops/api/{operation}` with JSON body and X-CSRF-Token:

| operation | Additional body fields |
| --- | --- |
| `save` | `{kind,id?,revision:0,value}`; revision must match for updates |
| `note` | `{kind,id,text}` |
| `case_transition` | `{id,revision,status,outcome?,verification?}` |
| `case_task` | `{id,revision,task:{id?,title,assignee?,status,verification?}}` |
| `link_alert` | `{id:<case UUID>,revision,alert:<alert UUID>}` |
| `reconcile` | `{asset:<stable asset UUID>,endpoint,identity,reason}` |
| `pin_job` | `{case:<case UUID>,job:<management job UUID>}` |
| `upload_begin` | `{case,name,size,sha256,media_type,redacted:true,provenance?}` |
| `upload_chunk` | `{upload,index,data:<base64>,sha256:<chunk digest>}` |
| `upload_finish` | `{upload}` |
| `upload_cancel` | `{upload}` |

Save/task/transition/reconcile return `{record}`; notes `{event}`; upload operations `{upload}`; pin returns `{evidence}`. Keys are lowercase SHA-256 hex. Upload chunks can arrive in any order; all except the final chunk must be exactly 1 MiB. Retry a chunk with the same index and digest to adopt an already persisted identical chunk. Finalization independently verifies each stored chunk and the complete artifact digest before making it readable. Upload begin's response includes its UUID; use that value for subsequent requests. Only the initiating collector can resume/cancel an upload. Access to complete evidence follows case permissions.

### Record values

Common editable fields: `name`, `description`, `endpoints` (UUID array), `assets`, `services`, `networks` (related record UUID arrays), `owner`, `team`, `tags`.

| kind | Additional fields |
| --- | --- |
| `case` | `type` = it/soc/problem/request; `priority` = low/normal/high/critical; `assignee`; optional `response_due`, `resolve_due` as timezone-aware ISO timestamps |
| `asset` | `asset_type`, `site`, `environment`, `criticality`, `external_id`; `intended`, `observed`, `provenance` objects |
| `service` | `criticality`; `intended`, `observed`, `provenance` objects |
| `network` | `cidr`, integer `vlan`; `intended`, `observed`, `provenance` objects |
| `relationship` | `source:{kind,id}`, `target:{kind,id}`, `relation`, `confidence`, `verified_at`, `source_ref` |
| `document` | `document_type` = article/runbook/design/procedure, `content` (Markdown text), `review_due`, `source_ref` |
| `change` | `planned_at`, `implementation`, `rollback`, `verification`, `status`, `case_id` |
| `exercise` | `techniques`, `allowed_activities`, `expected_detections` arrays; `cleanup_verification`, `status`, `case_id` |

Every edit creates a retained version. Observed and intended objects are separate and no automatic overwrite is performed. Relationship types: hosted_on, depends_on, connected_to, member_of, protected_by, backs_up_to. Confidence: candidate/observed/verified. Changes/exercises allow planned/approved/running/review/closed/cancelled; closing requires verification/cleanup_verification. The approved status documents an approval; it is not authority to dispatch privileged jobs.

Cases are created with status new. State paths: new → triage/in_progress/waiting; triage/in_progress/waiting → resolved; resolved → closed/in_progress; closed → in_progress. Resolution/closure require non-empty outcome and verification, all tasks done/cancelled and no unfinished uploads. Task states are todo/in_progress/done/cancelled; done requires verification. Case metadata edits cannot directly set status, tasks, alerts or closure fields. Assignments require a known identity with operations view and case management scope for all case endpoints.

Reconciliation associates an exact current active endpoint/enrollment with a stable asset. An enrollment already bound elsewhere conflicts; the API never automatically merges on hostname/IP and never moves a credential. Every reconciliation records actor/reason and preserves previous associations.

### Retained evidence

`pin_job` copies a final authenticated management receipt into independently retained encrypted case evidence. It rejects dedicated secret actions, files.read payloads and privileged shell transport. The internal helper is `ops.pin_job(db, verified_actor, case_id, job_id)` inside an OperationsStore transaction; ordinary callers should use `dispatch(actor, 'pin_job', {...request_id...})` for idempotency. Do not pass an unverified principal.

Upload provenance permits endpoint_id, identity_id, source_job, collector_version, collected_at, tool_id, tool_version. Caller-supplied provenance is labelled as a claim, and its endpoint must belong to the case. Tool collection artifacts can stream into this API using bounded worker `tool.artifact.read` chunks and then aggregate them into 1 MiB upload chunks. That transfer orchestration is separate from custody.

No secret fields are accepted in structured records; common credential/PEM/BitLocker recovery patterns are rejected in records and text evidence. Secret-action receipts cannot be pinned. Binary uploads require the collector's explicit redaction assertion and are encrypted/restricted; pattern matching cannot prove arbitrary binaries or forensic logs contain no secrets. Do not describe this detector as data-loss prevention. No raw Wazuh full_log or arbitrary data object is retained by the intake.

## Wazuh intake

The separate `/remote/ops/intake/wazuh` endpoint accepts a dedicated persistent Bearer identity from a private registry. It rejects browser Origin and non-loopback callers, relying on the existing private reverse proxy. During deployment use an exact nginx location that preserves this Bearer token and does not pass it through human OAuth authentication. Do not expose the route publicly.

Registry shape (token hashes only):

```json
{"sources":[{"id":"wazuh-lab","enabled":true,"token_sha256":"64 lowercase hex characters","source_ref":"https://wazuh.example","agents":{"001":{"endpoint":"UUID","identity":"UUID"}}}]}
```

Only configured agent→endpoint/enrollment mappings are accepted; current enrollment/lifecycle is checked. Input is the ordinary Wazuh JSON object with id, timestamp, agent.id and rule.id/level/description/groups. Intake stores normalized metadata, not raw event content. Source+alert ID is the deduplication key; identical normalized retries return 202 with `{alert,duplicate:true}`, changed content under the same ID returns 409. All errors are retry-friendly status codes, but unmapped agents require operator reconciliation. Alerts stay separate until an operator creates a case and calls link_alert. They never close a case automatically.

Queue metrics include open/assigned/unassigned counts, case state counts, oldest age, response/resolution deadline violations and verified closure count. Deadlines are explicit per case; an SLA business-calendar engine and automatic escalations are outside this first implementation.
