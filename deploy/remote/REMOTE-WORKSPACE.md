# Device remote workspace

Open an active device and scroll to **Remote workspace**. The terminal has its own
section and remains embedded while the endpoint profile stays visible. Native RDP
continues to use the operating system's Remote Desktop client.

## Saved credentials

SSH uses the existing per-device saved private key. **Show RDP credentials** reveals
the provisioned username and password for the current enrollment. **Hide credentials**
removes them from that tools view. The RDP file includes the username, never the
password; the native client may save credentials if its local policy permits.

The server stores the RDP records in an authenticated AES-GCM encrypted envelope,
with a key derived from the protected gateway key. systemd supplies both files as
private credentials. Reveal requires the existing owner identity, MFA and remote
operator role, current enrollment binding, matching Origin and a one-use form token.
Reveal and upload actions are audited. Responses are not cached. Existing protected
provisioning/recovery files are not retroactively encrypted or deleted by this feature.

Administrators provision the envelope using `seal_credentials(key, records)` from
`northgate_rmm.remote_workspace`, where `key` is the decoded 16-byte gateway key and
records contain `endpoint_id`, `identity_id`, `username`, `password`. Validate the
result with `open_credentials`, write it atomically as root mode 0600 to the path in
`LoadCredential=remote-credentials`, and restart the remote gateway. Never put record
values in shell arguments, repository files, evidence or logs. The supplied lab
service expects `/etc/northgate-rmm/secrets/remote-credentials.aes`.

## File transfer

Select a file and choose **Upload file**. Maximum size is 20 MiB. Successful uploads
show the stored name, size and SHA-256. A random prefix keeps repeated filenames
separate. Files are not executed automatically. Only one upload per device and four
uploads across the gateway may run concurrently.

| Platform | Destination |
| --- | --- |
| Windows | `C:\Users\rmmremote\NorthGateRMM-Ops` |
| Linux | `/var/lib/NorthGateRMM-Ops` |

Transfers use the existing pinned SSH host key and dedicated `rmmremote` account.
SFTP writes a uniquely named staging file; the endpoint verifies its size and SHA-256
before publishing the final name without overwriting. Interrupted transfers can
leave `.upload-*` files. Inspect and remove only confirmed abandoned staging files.
The destination is an operational convention, not a sandbox for commands entered
in the user's SSH terminal.

The server needs OpenSSH client tools (`ssh` and `sftp`). Install
`tools/receive_ops_file.py` at `/usr/local/libexec/northgate-rmm/receive_ops_file.py`,
owned by root with mode 0644 on Linux, and create `/var/lib/NorthGateRMM-Ops` owned by
root:rmmremote with mode 1770. Windows uses the packaged PowerShell finalizer over SSH
and creates the folder under the existing remote user's profile; no additional
Windows service, administrator recovery or agent update is required. The supported
lab account is `rmmremote`; changing it requires updating the destination paths.

Use the updated gateway unit and nginx configuration together. Remote requests and
the bodyless OAuth authorization subrequest allow 21 MiB request bodies. The actual
file limit is enforced at 20 MiB; Guacamole API requests retain their smaller limit.
The application CSP permits only same-origin embedded content; identity checks still
apply to the individual tools and terminal requests.

## Verification and recovery

On 2026-09-06, Windows and Linux each accepted a 1 MiB binary qualification file and
an exact 20 MiB file, with matching SHA-256 at the destination. The 20 MiB run used
an unprivileged service with the gateway's private-temp, protected-home/system,
no-new-privileges and resource restrictions. These transfer checks are separate
from owner acceptance of the embedded terminal.

Before replacing server modules, retain the previous modules, service unit, nginx
configuration and Linux finalizer. Back up the encrypted envelope together with its
protected key through the private recovery process. To roll back this increment,
restore those components and restart the remote gateway/operator services and reload
nginx. Preserve uploaded files and monitoring enrollment. The gateway restart ends
browser leases. Existing monitoring agents remain at their prior version.
