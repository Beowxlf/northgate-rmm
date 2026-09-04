# Windows monitoring runtime — implementation candidate

Owner request on 2026-09-04 extends the next monitoring release to Windows as
well as Linux. This source candidate does not qualify a Windows release.

The candidate collects hostname, platform, architecture, native Windows build,
kernel boot identity, and system-volume capacity. Collection does not invoke a
shell. The protocol and enrollment-grant schema accept Windows amd64.

The executable registers with the Windows Service Control Manager when launched
as `NorthGateRMMAgent`, responds to stop/shutdown, and sends bounded agent events
to the Application log. The installer verifies an exact artifact digest and
Authenticode signer, uses a dedicated virtual service account, installs stopped,
and restricts the executable and state directories to administrators, SYSTEM,
and that service account. It creates no inbound network rule.

Startup rejects reparse points and broad state ACLs. Sequence and spool writers
use native process-level byte-range locks. Native directory metadata durability,
ancestor replacement defenses, hard-link alias checks, Windows upgrade/removal,
signed packaging and installed-service recovery remain qualification work;
the older non-Linux filesystem shims must not be mistaken for those guarantees.
Do not enable an installed Windows service until these gaps are resolved.

## Enrollment

The agent accepts `--config`, `--enroll` (an HTTPS origin), `--grant-file`,
`--server-roots`, and `--issuer-roots`. Secrets are read from bounded files,
never command-line values. Run once under the identity that owns the agent
state. The server assigns the endpoint ID. The example configuration's
`00000000-0000-4000-8000-000000000000` means use the installed identity ID;
an explicit different ID remains an exact-match constraint.

Enrollment generates its own P-256 key, sends a proof-of-possession CSR,
verifies the returned certificate against separately supplied issuer roots,
and installs the existing create-once identity bundle. Redirects, ambient
proxies, automatic enrollment retries, wrong keys, wrong targets, and malformed
responses are rejected. A failed or interrupted attempt needs grant/identity
reconciliation before retrying. The input grant file is not automatically
deleted; the deployment operator must remove it after verified enrollment.

Server-certificate online status, endpoint renewal, external audit anchoring,
operational issuer and operator identity integration remain release prerequisites.
