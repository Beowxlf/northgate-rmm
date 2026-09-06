# Private lab remote desktop

This owner-authorized lab increment uses unmodified Apache Guacamole 1.6.0
images (`guacamole/guacd` and `guacamole/guacamole`), Windows RDP and Linux
Xfce/xrdp. No custom image or custom desktop protocol implementation is needed.
The Python adapter adds RMM identity, endpoint authorization and expiring leases.

Open an online device profile, choose **Connect**, then confirm the connection.
Guacamole opens the configured desktop. This is a dedicated login session,
not console screen sharing. Windows may lock the local console. The dedicated
desktop accounts are not administrators. File transfer and clipboard are disabled.

The IdP client role `remote_operator` is required in addition to existing viewer
and MFA checks. Assign it only to the approved owner. Existing tokens may require
a fresh sign-in to include the role. Targets must match both endpoint ID and
current enrollment identity, be active and online, and use configured private IPs.
The browser cannot select arbitrary destinations. Leases last at most one hour.
WebSocket access is rechecked every 30 seconds, and closes on denial or failure.

The adapter listens only on loopback port 8451. Guacamole's web service is mapped
only to loopback 8088; guacd has no published host port. Add the supplied nginx
location to the existing authenticated operator listener. RDP endpoint firewall
rules admit only the RMM server. RDP certificates are pinned by SHA-256; TLS
validation is not disabled.

Copy the existing operator JSON configuration to `remote-operator-service.json`,
replacing its systemd credential directory with `northgate-rmm-remote.service`.
Install the supplied unit. Its credentials contain a random 128-bit Guacamole
JSON key and an exact target list, including dedicated OS connection credentials.
They remain protected on the server, outside the application database. Guacamole
receives its matching key via a root-only environment file. No passwords should
appear in access logs, source control, or evidence notes.

The target-list JSON is an array of objects with `endpoint_id`, `identity_id`,
`address`, `protocol`, `port`, and `parameters`. Supported parameters are username,
password, domain, security, cert-fingerprints, server-layout, resize-method and
color-depth. See Apache's [connection documentation](https://guacamole.apache.org/doc/gug/configuring-guacamole.html)
and [encrypted authentication format](https://guacamole.apache.org/doc/gug/json-auth.html).

The agent's `--remote-check` command performs a fixed-local RDP negotiation without
credentials or opening a desktop. It returns a JSON readiness result. A successful
probe is not proof of desktop sign-in; qualify both backend login and owner UI.

Rollback: stop/disable the remote unit, restore the previous nginx config and
server venv, restore previous signed agent binaries, stop the two gateway
containers, disable the dedicated RDP firewall rules/listeners, and disable the
dedicated remote accounts. Retain backups and enrollment state. Do not reinstall
or revoke monitoring agents as part of a presentation/gateway rollback.

This simple lab implementation deliberately uses private server-to-endpoint RDP
and dedicated stored OS accounts. It does not claim the future architecture's
reverse tunnels, JIT credential authority, independent emergency gateway, session
recording or production remote-access qualification are implemented.
