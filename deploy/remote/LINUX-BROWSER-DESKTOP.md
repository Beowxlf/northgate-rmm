# Linux browser desktop

An enrolled Linux device with an explicit RDP target has a **Desktop** tab in
the device workspace. **Download RDP connection** opens a separate Windows
Remote Desktop window that can move between monitors. Browser desktop remains
available under an expandable section using the existing Guacamole client. SSH and
file transfer remain separate. The desktop is an XFCE session for the existing
nonadministrator `rmmremote` account; it does not mirror a physical console.

## Lab installation

Run `install-linux-browser-desktop.py EXPECTED_HOSTNAME PRIVATE_IPV4` as root
through the authorized, pinned guest administration path. This installer is
specific to the current NorthGate lab, not a general unattended enrollment hook.
It supports the enrolled Debian, Ubuntu, Kali and Parrot machines with APT.
The lab account must already exist; the installer never creates or exports a
password. Check memory and disk capacity before applying it to another device.

It installs xrdp, xorgxrdp and XFCE without a display manager. Desktop processes
start when somebody connects. Sessions are limited to two, idle sessions to
30 minutes, and disconnected sessions terminate after two minutes. Root login
is denied; only members of `northgate-rdp` can log in through xrdp.

The port is bound to the specified IPv4 address. A dedicated persistent firewall
service initially allows TCP 3389 only from the RMM server, `10.10.150.22`. On that server
itself, the current guacd container address `172.18.0.2` is also allowed. Reconcile
that exact address if the backend container is recreated with a different IP;
the rule fails closed. Existing unrelated firewall rules are preserved. Routed
guests require matching exact-source/target rules on OPNsense.

The owner subsequently requested native RDP. The current 10-device deployment
also permits the verified owner workstation `10.10.100.20`. After installing,
run `enable-linux-native-desktop.py EXPECTED_HOSTNAME PRIVATE_IPV4` through the
same authorized root path to apply this exact source exception persistently.
Reapply it if rerunning the base installer resets the source list. Routed
targets have matching source-specific OPNsense rules on the workstation ingress.

## Connection configuration

Add an RDP method for the device's current endpoint and identity IDs, preserving
the existing SSH method and matching its address. Configure `security: tls` and
`cert-fingerprints: sha256:<64 hex digits or 32 colon-separated hex octets>` using
the fingerprint returned by the installer. Never enable certificate bypass or
trust-on-first-use. Windows retains NLA by default; unpinned TLS is rejected.

Create an identity-bound **rdp** secret in OpenBao from the existing lab account,
verify its value, and enable its remote binding. Do not put the password in target
JSON, source control, logs or evidence. The generic account record remains
separate from protocol bindings. Future account rotations must update the RDP
binding too.

The existing human MFA, remote role, endpoint grant, online status, current
identity, CSRF and expiring browser lease checks continue to apply. Desktop
availability is advertised through `remote_methods`, not inferred from OS name.
Those RMM session controls govern browser remoting and downloading a connection
file. Native connections authenticate directly with the guest account and are
not tied to an RMM browser lease or its session audit. The downloaded file
contains no password. Use Access & secrets for the account password if prompted.
Native clients perform their own certificate validation; browser SHA-256 pins
are not a Windows RDP-file trust mechanism. No Linux monitoring-agent binary
change is needed.

## Verification and recovery

Verify a saved-credential connection through guacd, successful guest session
authentication, desktop frames, certificate mismatch rejection, and blocked
connections from another lab source. Confirm monitoring and worker freshness
after deployment. Browser layout and the owner's real MFA session are separate
acceptance checks.

The installer retains original xrdp configuration, package/service inventory and
the user's session file under `/var/lib/northgate-rdp-install/before`. Service
configuration, certificates and the firewall persist across service restarts.
Do not remove packages shared by existing desktop users during rollback; restore
the recorded configuration and remove only this deployment's RDP binding/rules.
Certificates expire after 825 days and require replacement plus an updated pin.

Parrot's September 2026 stable mirror returned 404 for xrdp. The lab uses the
signed `0.10.6.1-2~bpo13+1` package from its already configured official backports
repository. No distribution upgrade or signature bypass was performed.

References: [xrdp](https://github.com/neutrinolabs/xrdp),
[sesman configuration](https://manpages.debian.org/bookworm/xrdp/sesman.ini.5.en.html),
[Parrot repository documentation](https://docs.parrotsec.org/docs/mirrors/mirrors-list/).
