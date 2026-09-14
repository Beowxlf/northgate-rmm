# Optional tools and bounded diagnostics

This module adds an optional catalog to the existing authenticated management worker. It does not enable continuous sensors at enrollment. Existing agent/worker/Wxlfgar update manifests remain unchanged.

## Server composition

Construct `ToolCatalog(management, root=None, case_authorizer=None, case_linker=None)` and call `register(app)`. The default catalog directory is `management.store.root / 'tool-catalog'`. The async case hooks receive `(principal, endpoint, case_id)` and `(principal, endpoint, case_id, job_id)` respectively. Nonempty case IDs fail closed if the authorizer is not wired. Hooks must check case permissions and asset association; the case linker should upsert by job ID.

Routes are `GET /remote/{endpoint}/tool-catalog` and `POST /remote/{endpoint}/tool-catalog/action`. The existing SSH/files `/tools` route is preserved. Load `tool_catalog_ui.js` and call `window.NorthGateTools.mount(container, endpoint)`; retain and call its returned cleanup callback when navigating away.

GET returns a reusable session/endpoint-bound CSRF token, available recipe descriptions and approved releases, worker state, and the user's tool job receipts. POST requires the CSRF token, same-origin request, action and a UUID `request_id`. Reuse that ID for uncertain retries. Installation/update/removal require `patch`; diagnostics require `manage`. Cancellation uses existing signed controls. Service integrations must apply the equivalent endpoint, case and action scopes before submitting jobs.

Job contracts:

| Action | Exact parameters |
|---|---|
| `tool.list` | `{}` |
| `tool.verify` / `tool.remove` | `tool_id` |
| `tool.install` / `tool.update` | base64 `manifest`, base64 `signature`; the browser selects an approved `tool_id` and `version` instead |
| `tool.run` | `tool_id`, `profile`, typed `inputs`, `case_id` (UUID or empty) |
| `tool.artifact.read` | `artifact_id`, `offset`, `size` (1–262144 bytes), `case_id` (approved source case UUID or empty) |

The server and worker both validate contracts. The worker verifies the manifest with its separately pinned update authority. The signature domain is `NorthGate-Tool-v1\0` followed by exact sorted-key compact ASCII JSON. Server catalog entries are `{manifest: object, signature: base64}` and `authority.pub` contains the base64 public key. Approval is for the exact package bytes, recipe, platform/architecture, privilege, provenance and resource budget. It does not permit supplying arbitrary commands or replacing the fixed recipe entrypoint.

Pre-queue input-validation failures carry `X-NorthGate-Request-Outcome:
rejected-before-queue` only when that request UUID has no existing job. The UI
allows correcting a marked first-attempt rejection and uses a new UUID for the
corrected request. Network errors, unmarked failures and post-queue case-link
failures retain the original body/UUID. Once an attempt has an uncertain outcome,
a subsequent validation rejection also retains uncertainty: an earlier attempt
may still be in flight before its database insert.

## Packaging and licensing

`scripts/publish-tool-package.py` accepts a reviewed local payload directory and metadata, a raw 32-byte Ed25519 signing seed, a catalog directory and the existing management release-blob directory. It performs no network downloads. `--license-reviewed` records the publisher's explicit license review in the invocation. A package must include upstream notices and any required runtimes/rules/configuration. Do not put signing seeds or private configuration in a payload.

Metadata fields are `id`, monotonic integer `revision`, upstream `version`, `platform`, `arch`, `entrypoint`, `license`, HTTPS `source`, `privilege: "system"`, and `budget` with `seconds`, `memory_mib`, `cpu_percent`, `output_kib`, `disk_mib`. The helper supplies schema, archive size and SHA-256. A monotonic revision controls update replay/downgrade independently of upstream version naming. Archives are limited to 64 MiB compressed, 128 MiB unpacked and 512 members. Paths, symlinks and duplicate names are rejected. The private store is capped before new installation. Updates retain one previous package directory for operator-led rollback; removal retains case evidence.

Example metadata for a locally qualified osquery bundle (the publisher must supply actual reviewed files; this does not claim an approved upstream release):

```json
{
  "id": "osquery", "revision": 1, "version": "5.19.0",
  "platform": "linux", "arch": "amd64", "entrypoint": "osqueryi",
  "license": "Apache-2.0", "source": "https://osquery.io/",
  "privilege": "system",
  "budget": {"seconds": 30, "memory_mib": 256, "cpu_percent": 10,
             "output_kib": 128, "disk_mib": 128}
}
```

The repository deliberately ships no third-party executable, invented digest or automatically trusted download. Sysinternals redistribution rights differ from installation on devices an operator supports; obtain the utilities directly from Microsoft and do not distribute them as part of a public RMM product. Nmap/Npcap also require specific license review. Packaging approval must include the upstream license, artifact authenticity and intended distribution model. This primitive accepts qualified private bundles; it does not claim a generic vendor dependency downloader is implemented.

## Supported recipes and exact qualification boundary

| Tool | Profiles / input | Qualification requirements |
|---|---|---|
| `health` | `snapshot`, `history`, `changes`; no inputs | Built in, Windows/Linux. Native CPU/memory/disk readings and network-address changes. Up to 120 samples at no more than one per 30 seconds, privately persisted across worker restarts with a 512 KiB state cap. Counter-derived CPU percentage is unavailable until two fresh samples exist. `changes` also collects normalized services, software and startup snapshots on demand, with three bounded 20-second steps and explicit collection outcomes. |
| `connectivity` | `dns`, `tcp`, `tls`; host, integer port | Built in. DNS results, bounded connection/handshake, certificate expiry and verified TLS identity; unsuccessful checks remain explicit observations. |
| `evidence` | `it`, `soc`; no inputs | Built in, selected existing read-only actions plus health/capabilities. Each member retains its own success/failure; snapshots are not atomic and are not disk images. |
| `wxlfgar` | `readiness`; no inputs | Built-in adapter for installed prerequisites and the manual Npcap state. Start/stop remains the existing signed capture API and its short lease. Interface enumeration remains authoritative. |
| `osquery` | `system`, `processes`, `users`, `listening`, `startup`; no inputs | `osqueryi`/`osqueryi.exe`; fixed bounded SQL only, extensions disabled. Qualify the selected version's tables on each platform. Missing tables return a failed query, never clean evidence. |
| `sysinternals` | `startup` (logon entries only), no inputs; `trust`, optional `path` | Windows only; `autorunsc.exe` and `sigcheck.exe`. Trust defaults to the single Windows PowerShell executable; explicit paths must be existing regular local files up to 64 MiB. Official executables and terms must be qualified. No VirusTotal upload/reputation switches. |
| `yara-x` | `scan`; absolute `path` | `yr`/`yr.exe` plus approved `rules.yar`. One scan thread, 16 MiB per-file skip bound, timeout, NDJSON without rule console logs. Nonrecursive selected-directory scan; output truncation is explicit. |
| `velociraptor` | `collect`; no inputs | `velociraptor`/`.exe` plus approved generic offline collector data named `collector.yaml`. The generic collector must write its archive in the working directory, avoid external uploads and remain inside the declared budget. No resident server is installed. |
| `iperf2` | `client`; one private host IP, integer port | Qualified `iperf`/`.exe`. Ten-second, 10 Mbit/s test to an existing explicitly prepared peer. This recipe does not open a listener or change firewall rules; paired endpoint orchestration can be added above it. |
| `openscap` | `assess`; no inputs | Linux only; qualified `oscap`, its shared dependencies and `profile.xml` (an approved XCCDF document/default profile). Evaluation only, no remediation. |
| `nmap` | `connect`; one private host IP, up to 16 comma-separated integer ports | Qualified `nmap`/`.exe` and data files under applicable terms. TCP connect only, no DNS, bounded rate/retry/time, no NSE or arbitrary options. |

Source checks for recipe flags: [YARA-X CLI](https://virustotal.github.io/yara-x/docs/cli/commands/), [Velociraptor generic offline invocation](https://docs.velociraptor.app/docs/deployment/offline_collections/running/). Supported recipe code is not a statement that every upstream package has been live-qualified. None of the new third-party packages is preapproved by this source change.

## Resource and concurrency model

Sysinternals **Logon startup** collects logon entries with `-a l -c`, without
hashing files or checking signatures. This bounded view excludes other Autoruns
categories; broader startup data remains in inventory/health and osquery.
The **Trust inspection** profile uses `-r -c -h -e -nobanner` against exactly
`SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe` by default. Existing
`inputs: {}` requests retain that default. Only this profile accepts an optional
`inputs: {"path": "C:\\Ops\\example.exe"}`; startup rejects path inputs.
The worker rejects directories, UNC/device/mapped-network paths, wildcard or
control characters, reparse points, and files larger than 64 MiB before starting
Sigcheck. It resolves and excludes worker state and identity directories, then
holds the selected regular file against writing/replacement and its parents
against rename through execution. Arguments remain a fixed recipe; a supplied
path cannot add switches. Online certificate revocation checks are disabled,
so the interface labels trust output as offline triage rather than a complete
certificate-trust verdict. Both profiles retain the original time and output limits. Redirected
UTF-16 output is decoded before serialization and remains bounded after UTF-8
conversion. See Microsoft's [Autorunsc flags](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
and [Sigcheck flags](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck).

The worker advertises `features.tool_catalog`, `features.health_history` and `features.diagnostic_lane`. Polling retains the original `active`/`job` fields and adds `diagnostic_active`/`diagnostic_job`. Both jobs get independently signed controls and authorization leases. Only health, connectivity and osquery runs, list/verify and artifact reads may use the diagnostic lane. It can overlap a shell; installers, updates, removal, collection and other mutations remain serialized. New servers must recognize the optional fields before new workers are rolled out.

Optional executable children use Windows Job Objects for CPU cap, aggregate memory, process count and process-tree cleanup. Linux uses transient systemd units with CPUQuota, MemoryMax, TasksMax, IOWeight, Nice and RuntimeMaxSec. A Linux runtime without systemd returns explicit unsupported status. CPU quota semantics differ: Windows percentage is aggregate available CPU; systemd CPUQuota is expressed relative to one core. These are resource controls, not containment against a malicious privileged executable.

Health history uses an atomic owner-private file in the existing worker state directory, bound to device/enrollment identity. Background persistence is limited to once per minute; explicit change collection also flushes its result. Keep at most 32 change records; inventory sets normalize ordering, limit to 500 records/rows and bound previews. This is observed drift, not a continuous event stream. Windows startup coverage includes machine Run/RunOnce and up to 400 scheduled tasks; Linux covers known systemd/cron/init startup directories. Persistence errors are reported by the history profile, while monitoring continues.

Disk usage is watched once per second, with a 2048-entry traversal limit and cancellation on excess. This is a cancellation threshold, not a filesystem hard quota; short write bursts can exceed it. Windows has no hard IO bandwidth limit in this implementation, while Linux uses relative IO priority. Tools keep the SYSTEM/root execution model; per-tool reduced-privilege identities require a later runner extension. Ordinary job deadlines, authorization renewal and output limits remain effective. The control channel continues reusing its existing cached TLS transport.

## Evidence and resumable transfer

Evidence and external collection receipts expose `artifacts` entries containing artifact ID, original name, SHA-256, size/content type, creation time, device/enrollment, case/job and tool/version. Artifacts reside under the protected worker tool store, bounded by a 128 MiB aggregate quota. A built-in evidence bundle is at most 16 MiB; external archives are at most 32 MiB each. Artifacts are retained when executable packages are removed.

`tool.artifact.read` returns a maximum 256 KiB base64 chunk, chunk SHA-256, offset/next offset, EOF and immutable metadata. Its signed case context must exactly match the worker's stored source case; an omitted or substituted case cannot read case evidence. The server authorizes the source case and its device association before signing. Resume by requesting the acknowledged offset; the central evidence store must verify the final whole-artifact SHA-256 and bind destination case permissions before publication. Endpoint ID or path is never supplied as an arbitrary artifact location. Quota exhaustion is explicit and does not erase evidence. Central archival/acknowledged endpoint deletion is a separate retention workflow.

## Validation required before deployment

Unit checks cover typed contracts, signature/platform rejection, archive escape/duplicates/quota, health caching, disk cancellation, form reuse, CSRF, denied case scope and idempotent jobs. Qualification must additionally exercise real approved packages on both target OSes, a shell concurrent with diagnostics, loss of authorization on each lane, cancellation of descendants, update interruption, actual runtime dependencies, evidence resume and busy-workstation resource impact. No new third-party engine is claimed live-tested by the code checks.
