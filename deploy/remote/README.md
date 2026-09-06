# Private lab remote access

Open an online endpoint's detail page and select:

- **Open Remote Desktop**: download and open a standard `.rdp` file in the native
  Remote Desktop client. Sign in with the dedicated workstation account. The file
  contains no password. Windows can lock its local console; Linux uses Xfce/xrdp.
- **Connect SSH Terminal**: confirm to open an SSH terminal in the browser through
  unmodified Apache Guacamole 1.6.0. Each endpoint has a separate SSH key kept on
  the RMM server and a pinned SSH host key. No additional client is needed.

The dedicated `rmmremote` accounts are nonadministrators. Browser terminal access
requires the existing MFA identity and the `remote_operator` client role, plus an
active, online endpoint with the exact configured enrollment identity. The owner
may need a fresh sign-in to receive the new role. Browser leases last one hour,
are revalidated every 30 seconds, and close on authorization failure. The browser
refreshes its authenticated gateway request every 20 seconds; the existing login
proxy refreshes its identity-provider token every minute.

Native RDP uses operating-system authentication and the lab firewall. Issuing a
connection file is audited, but an actual native login is recorded by the endpoint.
Native sessions do not inherit the browser lease, logout, or enrollment-revocation
termination behavior. Disable the OS account or its RDP rule to revoke that path.
Clipboard, drive redirection and printing are disabled in the supplied RDP file;
a user-controlled native client can change its own settings.

## Deployment

Guacamole and guacd use official unmodified images. Guacamole binds only loopback
8088, guacd has no published host port, and the Python adapter binds loopback8451.
The existing authenticated HTTPS operator listener proxies both through the
supplied nginx location. No custom image is required.

The systemd unit loads root-protected target configuration and a random 128-bit
Guacamole JSON key. Each target contains `endpoint_id`, `identity_id`, `address`,
`protocol: ssh`, `port: 22`, and `parameters` with `username`, `private-key`, and
`host-key`. The latter is a complete existing pinned OpenSSH known_hosts entry.
An optional domain is used for the native RDP username. Never put private keys,
passwords or complete target configurations in Git, access logs or evidence.

Use the included Windows/Linux desktop installers first. The lab terminal
scripts extend the existing bootstrap SSH allowlist with only
`rmmremote@10.10.150.22`; they preserve password-authentication denial and install
an authorized public key with `from`, `restrict`, and explicit PTY permission.
They assume the documented existing NorthGate bootstrap configuration and the
public key staging locations shown in the scripts. They allow native RDP from
owner workstation10.10.100.20 and RMM server10.10.150.22. Private keys are generated
on the server; only public keys are transferred to the endpoints.

The agent's `--remote-check` performs a fixed-local RDP negotiation without
credentials. It does not test SSH or prove an authenticated desktop session.
Qualify SSH authentication/PTY, RDP login, endpoint freshness and both owner UI
paths after deployment. This increment updates both agents to1.0.0-lab.5.

## Recovery and limits

Retain the previous server venv, signed Windows binary, Linux package/config,
SSH configuration, firewall exports and dedicated account recovery credentials.
To roll back, stop the remote adapter and gateway containers, restore nginx and
server code, remove the added SSH public keys/allowlist entries, restore firewall
rules and disable the dedicated accounts. Preserve monitoring enrollment state.

This private-lab implementation uses direct private-network SSH/RDP. It does not
implement reverse tunnels, console screen sharing, session recording or a JIT
credential authority. Guacamole copy/paste and its generic SFTP interface are disabled. The separate
[remote workspace](REMOTE-WORKSPACE.md) provides designated-folder uploads using
server-side SFTP. SSH commands have
the dedicated account's normal OS permissions.

References: [Guacamole connections](https://guacamole.apache.org/doc/gug/configuring-guacamole.html)
and [encrypted JSON authentication](https://guacamole.apache.org/doc/gug/json-auth.html).


## Embedded workspace

See [Remote workspace](REMOTE-WORKSPACE.md) for saved credentials, the embedded
terminal, designated upload folders, installation and recovery.


## Network capture candidate

[Wxlfgar capture integration](capture-integration.md) adds Windows/Linux managed capture jobs. This increment is implemented but not deployed or accepted; bug review is the next phase.
