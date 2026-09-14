# Endpoint credential rotation qualification

Windows local-account password rotation is implemented behind two explicit
deployment opt-ins. It remains **disabled without them** and is not live-qualified
merely because its unit tests pass. SSH key rotation, Linux password rotation,
domain accounts, and arbitrary account selection remain unsupported. Saving a
vault version changes only the provider value; the dedicated rotation action is
required to change the workstation account.

## Deployment and browser contract

The remote service accepts `--credential-rotation-config` only alongside
`--secrets-config`. Its exact JSON fields are `schema: 1`, an absolute `executable`
path, the qualified client's lowercase `executable_sha256`, and an integer
`timeout_seconds` from 1 through 30. The example in
`deploy/openbao/credential-rotation.example.json` deliberately has an invalid
placeholder hash. On Linux the configuration must be root-owned and not writable
by group or others (a public root-owned 0644 file is sufficient). The verifier
also checks the executable and its parent ownership, ELF format and hash every
use, retains its descriptor through execution, and bounds output and runtime.
Optional `xvfb_executable` and `xvfb_sha256` fields must appear together when the
qualified client requires a display even for authentication only. That mode uses
a new private authenticated Xvfb display per attempt, disables TCP listening,
never disables X authentication, and terminates both processes after the attempt.
Both executable hashes and argument compatibility are checked before staging or
dispatch as well as during the final authentication verification.

Use a reviewed FreeRDP build which supports headless `+auth-only`, NLA, forced
stdin password input, and an exact SHA256 certificate pin. Qualify that exact
build with the correct candidate, a wrong password, and a wrong pin before
enabling this configuration. Guacd `ready` or display messages can precede NLA
authentication and are not accepted as success. FreeRDP's authenticated core
success witness and exit status zero are both required. The process receives a
clean environment and scratch home; passwords enter stdin, never arguments.

On the Windows worker add this deployment-owned field to its existing protected
configuration, after verifying the local account's real SID:

```json
"credential_account": {
  "username": "rmmremote",
  "sid": "S-1-5-21-EXACT-LOCAL-MACHINE-ACCOUNT-RID"
}
```

The placeholder above is intentionally invalid. Only the literal local username
`rmmremote` and its pinned ordinary-account SID are supported in this first
implementation. The worker rejects built-in/trust identities, domain controllers,
disabled or locked accounts, account SID/name changes, and identities referenced
by a Windows service. It uses fixed `NetUserSetInfo` and `LogonUserW` network-logon
APIs and confirms the returned token SID. It does not invoke a shell or embed a
password in a command line. A local administrator remains able to modify the OS
or privileged worker state; this mechanism does not contain an administrator.

The worker creates a persistent X25519 recipient key in its protected state
directory. Only its public key and configured account metadata are reported in
`features.credential_rotation`. The Secrets UI shows rotation only for Windows
RDP records with a ready worker, explicit account binding, configured RDP pin,
and verifier. Candidate fields must preserve that configured username/computer
name and use a 16-128 character printable ASCII password without spaces.

The existing Secrets action API uses `action: rotate`, `secret_id`, a durable
`rotation_id` UUID, `expected_version`, and candidate `fields`. It requires the
normal same-origin form token, fresh human MFA, the exact enrollment's explicit
secret `rotate` grant, management/recovery permissions, and `recovery_operator`.
`resume_rotation` supplies the same secret and rotation IDs and rechecks those
permissions. Native/MCP and the generic management-operation endpoint cannot
submit this action or reveal its result. Reconciliation after an expired check
needs a fresh human session; it does not grant unattended rotation.

The candidate is written under an independent OpenBao staging path before any
dispatch. The ordinary durable job stores only an X25519/AES-GCM envelope bound
to endpoint, enrollment, job, rotation, phase, account SID, username and expected
version. Its original authenticated browser authorization is retained and
rechecked each worker poll, including the fresh-MFA and secret grant. Metadata
and audit records carry IDs and statuses, never candidate values. A definitive
failure before the OS setter permits a new rotation; an uncertain setter or
verification outcome retains the staged candidate for reconciliation.

The worker persists an append-only apply-once journal before the OS API. The
server's apply job ID is deterministic per rotation, and a retry cannot reapply.
A `check` job only authenticates the candidate; it is idempotent per fresh human
session. Both the worker's positive local authentication/SID result and the
separate pinned RDP/NLA verification must succeed before provider CAS promotion.
Conflicting provider versions retain the staging record and require investigation.
Concurrent rotations of duplicate RDP records for the same enrollment are blocked.

Backups must include the secret-reference/rotation database, staged OpenBao
versions, and the worker recipient/journal state. A restore that loses a pending
job cannot prove that a workstation was unchanged; the executor reports unknown
and never manufactures a replacement apply. Neither staging nor journal cleanup
is automatic in this initial implementation.

## Validation status

Focused tests exercise encryption context changes, apply-once behavior after lost
acknowledgment, cancellation, explicit scope, MFA/grant/enrollment changes,
duplicate-account rotation exclusion, vault CAS conflicts, withheld native
results, and the verifier's positive/negative process witnesses. Windows OS
password changes and full provider/worker/RDP promotion still require the
authorized disposable canary qualification. This code change performs no live
rotation, deployment, or change to `credential_account` on existing machines.

The current SSH broker uses a pinned maintenance key for bounded inspection and
file operations. It has no reviewed privileged password-change helper, and that
key authenticating successfully does not prove that a candidate Windows password
works over RDP/NLA. Adding an unrestricted privilege path to this broker would
duplicate the management worker's existing privileged authorization boundary.

The typed management-worker operation follows these acceptance requirements:

1. `credential.rotate` binds a durable rotation UUID, exact endpoint/enrollment,
   deployment-allowed local account, protocol and expected provider version. The
   ordinary job/case record contains a protected candidate reference, never the
   credential. Candidate delivery uses the worker's authenticated encrypted
   transport and a one-time authorization; do not place the password into command
   text, process arguments, telemetry, console output or ordinary result payloads.
2. Restrict account changes to explicitly managed local accounts. Reject domain,
   built-in, service, renamed/reused or non-managed identities. On Windows bind
   account SID; on Linux bind UID and management marker. Execute fixed OS account
   APIs with bounded inputs. Retain a durable state machine before changing the
   account so a restart or lease expiry reports uncertainty without reapplying.
3. Implement separate candidate verification. Windows must positively verify the
   local authentication identity (and separately qualify the intended RDP/NLA
   access path); Linux must verify the approved authentication mechanism under its
   PAM/SSH policy. A successful maintenance-key SSH connection, password setter
   exit code, worker heartbeat or Guacamole transport connection is insufficient.
   Include account-expiry/lockout/denied-network-logon outcomes without values.
4. `apply` dispatches at most once per rotation UUID. `check` retrieves/reconciles
   that operation and can retry verification without another password change.
   Return only UUID job reference and `pending`, `verified`, `failed` or `unknown`.
   Only positive candidate authentication yields `verified` and permits OpenBao
   compare-and-set promotion. Unknown outcomes preserve the staged candidate.
5. Review permission revocation, enrollment replacement, concurrent rotations,
   process interruption, lost responses, expired operator MFA, provider outages,
   post-verification CAS conflict and recovery after restoring an older snapshot.
   Qualify both Windows and Linux canaries using disposable managed accounts.

Existing `recovery.rotate` remains useful: it creates/rotates the worker-managed
temporary emergency account and returns its generated credential in the protected
escrow channel. The Secrets UI can now import that completed result into OpenBao
without exposing values to the browser, ordinary API, case or MCP. BitLocker
escrow results use the same import path. Import preserves source job and current
enrollment binding and is idempotent, but does not prove an interactive login or
transform this emergency-account operation into generic candidate rotation.
