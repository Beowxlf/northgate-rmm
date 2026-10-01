# Privileged management candidate

This release adds a separate management worker. Windows runs it as LocalSystem;
Linux runs it as root. Monitoring remains unprivileged. Browser SSH and native
RDP continue using their existing identities. A SYSTEM shell does not attach to
the logged-in user's desktop.

## Installation

1. Install and enroll the normal monitoring agent using the existing installer.
2. Configure the private management TLS listener using the agent CA and a server
   certificate valid for its management hostname. Pass its configuration file to
   `northgate_rmm.remote_service --management-listener-config`. The listener
   requires TLS 1.3 and an enrolled, unrevoked client certificate. Keep it private.
3. From the endpoint's management workspace, export the public configuration.
   An administrator adds the fixed server origin/IP, trusted server CA path,
   identity bundle path, private state directory, independent release public key,
   and Windows Authenticode signer thumbprint. No agent private key is exported.
4. Run `agent/packaging/management/install-linux.py` or
   `Install-Management.ps1` with the reviewed binary and configuration. These
   are ordinary installations; they do not create a VM image. The privileged
   installer is a post-enrollment step and can be invoked by the VM bootstrap.
5. Verify the worker's actual execution identity and readiness in the website.
   The existing restricted agent cannot install this service itself.

Configuration fields: `endpoint_id`, `identity_id`, `signing_key`, `escrow_key`,
`update_key`, `update_signer` (Windows thumbprint; empty on Linux), `server_url`,
`server_ip`, `server_roots`, `identity_file`, `state_directory`.

Linux paths: `/etc/northgate-rmm-management/config.json`,
`/etc/northgate-rmm-management/server-ca.pem`,
`/var/lib/northgate-rmm/identity/identity.json`,
`/var/lib/northgate-rmm-management`.
Windows paths: `C:\ProgramData\NorthGateRMMManagement\config.json`,
`C:\ProgramData\NorthGateRMMManagement\server-ca.pem`,
`C:\ProgramData\NorthGate RMM\identity\identity.json`,
`C:\ProgramData\NorthGateRMMManagement`.

## Authorization and results

Existing owner, MFA, remote-operator, endpoint binding and session checks apply
to management. Each dispatch and active lease rechecks the operator's session.
BitLocker collection, recovery-account rotation and secret reveal additionally
require the `recovery_operator` role. Grant it explicitly in the IdP's verified
role mapping; do not weaken the verifier or reset owner MFA.

Workers poll outbound using the enrolled certificate and a separately pinned
server CA. Responses are signed with a purpose-separated Ed25519 key and bound
to a request nonce, endpoint, identity and expiry. Accepted jobs are recorded
before execution and are not replayed after restart. Encrypted receipts report
completion, failure, cancellation or an unknown outcome. Investigate an unknown
outcome before issuing another mutating job.

Jobs have bounded lifetime and output. Active jobs require a renewed 45-second
authorization lease. Browser terminals additionally require browser keepalive;
closing the page lets their lease expire. Terminal transport buffers expire
after completion and are not retained as a session transcript. Script and
command output may contain sensitive material; results are encrypted in custody.

BitLocker escrow collects **existing** recovery-password protectors. A successful
query with no such protector is not recovery coverage. Keys are encrypted under
the existing gateway master key with a separate cryptographic purpose, indexed
by endpoint/job, and revealed only through a separate audited request. Offline
retrieval uses previously escrowed data. An inaccessible locked disk cannot be
recovered by installing new RMM code. Existing LUKS passphrases cannot be read;
Linux reports encryption state and needs a separately authorized key-provisioning
workflow before claiming LUKS recovery coverage.

The managed local account `ng-rmm-recovery` has an explicit expiration. Its
password is generated on-device and sent only in an encrypted receipt. Rotation
refuses to take over an existing unmarked account. Linux uses a persistent
systemd expiry timer; Windows uses the account expiration property. Rotate after
use. Creating the account is not proof that a console recovery sign-in works;
qualify that procedure on each platform.

## Updates, packages and prerequisites

Use `python -m northgate_rmm.management_admin generate-release-key --out PATH`
on the protected release-signing host. Keep that private key off the web server.
Publish a candidate with `publish-release --binary PATH --signing-key PATH
--catalog PATH --component worker --platform linux --version VERSION --origin
https://MANAGEMENT:PORT`. Install the resulting immutable catalog files under
the server's private `management/releases` directory. The browser catalog selects
a release; running the operation deploys it to the selected endpoint only.

Updates verify the independent release signature, platform, digest and version;
Windows also verifies the pinned Authenticode signer. A separate service/task
performs the replacement, retains the old binary and attempts rollback if start
fails. Worker updates reconcile their result after service restart. A running
service alone does not prove product acceptance; check heartbeats and actions.

Linux package actions use APT and distro signature verification. Windows package
actions require WinGet to work under SYSTEM. Prerequisite installation requests
Wireshark and the Linux operation dependencies. Npcap's free installer is
interactive; silent installation requires the applicable OEM license. Missing
prerequisites must be reported, never silently bypassed. OS patches/package
changes may require reboot and may not have an automatic uninstall rollback.

## Recovery, isolation and evidence

Reboot jobs report scheduling separately from verified return with a new boot
identifier. Isolation creates dedicated temporary firewall rules, leaves other
rules intact, preserves the pinned management server address and schedules
independent automatic release before applying restrictions. Existing firewall
rules can still block management; qualify the canary before wider deployment.
Isolation expiry does not depend on browser connectivity.

Files default to NorthGateRMM-Ops. Privileged file jobs use explicit absolute
paths, 15 MiB upload and 16 MiB download bounds, and hashes; overwrite retains a uniquely named backup.
Worker identity/configuration state requires its dedicated recovery workflow.

The infrastructure view compares retained Wxlfgar observations and saved
baselines. IP-to-endpoint matches are candidates, not identity proof. Exercise
IDs link management actions and existing captures into exportable evidence.
Coverage limits and absent observations must not be presented as confirmed faults.

## Backups and retention

`python -m northgate_rmm.management_admin backup --root
/var/lib/northgate-rmm-remote --credentials PATH --key PATH --out NEW_ARCHIVE`
creates consistent SQLite snapshots plus encrypted remote credentials in an
authenticated encrypted archive. It requires every declared component. Back up
the gateway master key **separately** in the owner's recovery custody.
`restore --archive PATH --key PATH --out NEW_DIRECTORY` validates authentication,
member names, hashes and SQLite integrity and never overwrites live state.
Stop the remote service before explicitly promoting a qualified restore.

This supplements PostgreSQL and endpoint PCAP backups; it does not back up PCAP
files that remain on endpoints. Ordinary jobs retain 30 days, activity 90 days,
and recovery escrow is retained. Terminal transport expires after completion.
The 512 MiB management database bound and 10,000-entry endpoint deduplication
ledger require operator archival; full storage blocks new operations.

Keep the previous service/configuration and database snapshot for rollback.
Stopping/disabling the management worker leaves monitoring operational. Never
roll a database back while workers can submit jobs from the discarded timeline.

## Third-party terminal

The browser terminal vendors `@xterm/xterm` 6.0.0 under its MIT license. Its
license and registry integrity provenance ship in the Python package. No runtime
CDN is required, and remote terminal output cannot write the browser clipboard.

## Deployment qualification

Server and Linux canary qualification is recorded in the delivery evidence. Windows installation and owner-session acceptance remain open; built or signed binaries do not establish recovery coverage. Templates for the daily encrypted backup service, timer and helper are in server/packaging/management. Run the backup as the existing operator service identity with systemd credentials so private-file ownership checks remain enforced. Keep the nginx authentication subrequest limit unchanged: the management upload limit is 15 MiB, including room for its base64 envelope under the existing 21 MiB request boundary.
