# Browser desktop and provider-backed secrets

## Endpoint methods

The deployment's remote-target list permits one `ssh` and one `rdp` entry for an
endpoint. Both entries must have the same exact enrollment UUID and private IP.
`parse_remote_targets` rejects duplicate protocols, unexpected parameter names,
and identity/address disagreements. The primary `gateway.targets` mapping stays
compatible with existing inspection/capture code by preferring SSH. All methods
are available through `gateway.methods[endpoint]`.

Keep port 22 for SSH and port 3389 for RDP. Windows browser RDP uses NLA/NLA-ext; explicitly configured Linux xrdp targets use pinned TLS with account authentication. Both require certificate verification, without trust-on-first-use or disabled authentication. Native downloads can include an owner-bound [encrypted credential profile](native-desktop-credentials.md).
Provide a verified Guacamole `cert-fingerprints` pin or ensure the endpoint
certificate validates through guacd's trust store and its IP SAN. Deploy matching
supported Guacamole web/guacd versions with the RDP plugin present. The code
does not install a GUI or RDP host on a headless Linux device.

- GET/POST `/remote/{endpoint}` preserves the existing connection path.
- GET/POST `/remote/{endpoint}/desktop` opens browser RDP.
- GET `/remote/{endpoint}/desktop.rdp` retains the native RDP download.
- GET `/remote/{endpoint}/sessions` returns enabled method names and metadata
  receipts for the current enrollment.

Use `?case_id=<case reference>` on the connection landing page. A case ID is
bound into the one-time form nonce. It requires the configured asynchronous
`gateway.case_authorizer(principal, endpoint, case_id)` callback; absent or denied
case authorization rejects the request. The callback is rechecked on session
validation. Ordinary sessions without a case continue to work.

`RemoteGateway(..., receipt_store=RemoteSessionStore(path))` persists authorized,
transport-connected and closed/expired receipts. Restarts mark incomplete
sessions interrupted. Receipt events identify a transport connection, not proof
that Windows login succeeded. They contain no credentials or screen contents.
Termination closes the browser and owned upstream WebSocket; it disconnects the
desktop transport and does not promise Windows user logoff. HTTP polling tunnels
are rejected because they cannot supply the same owned-stream termination.

Browser remoting uses one Guacamole session cookie. End the current browser SSH
or desktop session before starting another in the same browser. The separate
management-worker terminal and native RDP remain usable alongside the browser
connection. Multi-session browser multiplexing is not claimed by this release.

## Secrets UI and API

The optional `SecretsAPI` exposes `/remote/{endpoint}/secrets/ui`, `state`,
`assets.js`, `assets.css`, and POST `action`. It uses the existing authenticated
RMM proxy, same-origin POST checks and session-bound one-time form tokens. State
responses are metadata-only and do not call the provider's secret-read API.
Fresh MFA within five minutes is required for reveal, new values and rotation.
The reveal view clears after 30 seconds and when hidden. No secret endpoint is
exposed through the native/MCP integration.

Deployment grants are independent of regular RMM ownership and reload on each
request. `metadata` allows the panel, `use` permits server-side remote credential
resolution, `reveal` permits explicit short reveal, `admin` permits reference and
provider-version changes, and `rotate` permits a configured device-rotation
executor. An owner without an explicit grant cannot use these routes.

Secrets configured for remote use override the matching SSH/RDP credential
fields on the server, immediately before creating the encrypted Guacamole
ticket. Provider failure does not fall back to the old credential for a bound
secret. Active bound sessions recheck the use grant and binding on the ordinary
remote authorization interval. Legacy saved credentials continue to work for
unbound connections and support a bounded 4096 entries/16 MiB envelope.

Supported actions: `create`, `edit`, `retire`, `replace`, `delete_version`,
`restore_version`, `reveal`, `rotate`, `resume_rotation`, `import_recovery`.
All requests include the
nonce from `state`; updates require a `secret_id`; provider value replacement
requires `expected_version`. Create uses a UUID `request_id`, a display `label`,
`kind` (`rdp`, `ssh`, `api`, `recovery`) and kind-specific `fields`. The deployment
guide documents custody, runtime composition and the rotation executor contract.

See [OpenBao deployment and recovery](../deploy/openbao/README.md). This is
candidate code: real-vault, real-browser and device-session qualification must
be completed before treating the integration as deployed or accepted.
## Provider adoption and retirement

Once a protocol adopts an OpenBao credential binding, disabling or retiring its
last binding blocks new connections until another provider binding is selected.
It does not silently fall back to a legacy saved password or key. Devices that
have never adopted a provider binding retain their existing saved-credential
behavior. The Secrets panel reads metadata in pages of 20, with at most four
concurrent provider requests; no credential values are read for listing or health
checks.

## Completed recovery results

Construct `SecretsAPI(..., management=management)` to enable server-side recovery
import. State includes `recovery_import_available` and eligible metadata-only
`recovery_jobs`. POST `import_recovery` takes `job_id`, `label` and the ordinary
Secrets form `nonce`. Fresh MFA, explicit secret admin permission, recovery role,
management/recovery policy and exact current enrollment are all required. The
result is stored directly in OpenBao and the API returns only its reference and
version. Imported emergency accounts retain their expiry metadata; BitLocker
recovery passwords are retained as a typed bundle. Repeated import is idempotent.
