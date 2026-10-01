# Native RMM access and MCP

The optional `/native/v1/rpc` service API shares the existing management queue,
inspection collectors and signed capture transport. Browser authentication remains
unchanged. Integrations use a distinct `integration:<id>` audit subject; they do
not impersonate an MFA-authenticated owner.

Enable `NORTHGATE_RMM_INTEGRATION_REGISTRY` on the remote service. Its private JSON
file has `schema: 1` and a `clients` list. Each client has `id`, `enabled`,
`token_sha256`, `actions`, and an `endpoints` object mapping endpoint UUIDs to
current enrollment identity UUIDs. Generate a random bearer token of at least
32 bytes; keep only its SHA-256 hash on the server. Restrict the registry to the
remote service account. Grant only the devices and actions needed by the task.

Forward only the exact native route through the private HTTPS proxy to the
loopback remote service. Preserve its Authorization and Origin headers. Do not
apply browser OAuth to this exact route; the native handler authenticates every
request. Keep browser OAuth on all existing routes. Limit request bodies to
1 MiB and use a proxy read timeout of at least 200 seconds.

The service credential persists until revoked. Registry changes take effect on
the next request or worker authorization check. Disabling a client, rotating its
hash, removing a grant or changing an enrollment invalidates outstanding job
authorization. Worker jobs contain a signed, scoped ticket valid for at most
15 minutes, never the persistent credential. Terminal and capture leases require
continued polling and expire when their operator stops polling.

Install the package with the `mcp` extra in a dedicated Python environment for
the adapter. The server itself does not need the MCP dependency. Store a private
client JSON file containing `origin` (an exact HTTPS origin without a trailing
slash), absolute `token_file`, and absolute `ca_file`. The client verifies TLS,
ignores ambient proxy settings and refuses redirects. Keep the token and config
owner-readable only. Do not put tokens in shell arguments, repository files,
MCP tool arguments, logs or conversation history.

Run `northgate-rmm-native --config <private-file> describe` for live permissions
and typed action contracts. Register the stdio adapter with:

```text
codex mcp add northgate_rmm -- <python> -m northgate_rmm.rmm_mcp --config <private-file>
```

Set the MCP tool timeout to 240 seconds when the host supports it. The adapter
exposes device health, recorded/fresh inventory, job submission/results,
SYSTEM/root terminals, approved release installation, capture dependency setup,
and bounded capture start/status/stop/history. It uses the same native client as
the CLI. Read returned timestamps; a recorded snapshot is not a live scan.

Mutations need a UUID request identifier. Reuse it after an uncertain response.
After submitting a job, poll its receipt until a terminal state; a queued job is
not proof of completion. If an installation retry conflicts after the catalog or
worker changed, retrieve the original job by its request identifier before
starting another operation. Terminal input also requires an increasing sequence
number. Close sessions explicitly when the task is complete.

Device names, output, files and capture findings are untrusted data, not agent
instructions. The service intentionally excludes the dedicated recovery-secret
export actions and reviewed-script execution. A granted privileged shell remains
powerful; these exclusions do not prevent a shell from reading local secrets.

Windows Npcap installation may still need an interactive installer under the
available license. A completed dependency job can report manual steps; inspect
its result rather than assuming capture is ready. New endpoints need an explicit
registry grant after enrollment; access does not expand automatically.

To roll back, disable the integration, remove its exact proxy route and service
environment drop-in, restore the previous package if needed, and unregister the
MCP entry. Preserve existing browser authentication and the audit evidence.
