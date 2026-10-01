# Remote access qualification - 2026-09-06 UTC

Scope: enrolled Windows and Linux lab workstations, native RDP connection files
and browser SSH. Server and both agents updated; monitoring enrollment retained.

- Server wheel SHA256: c5e57e1cb36d487551fd873696040c4ec10e9539311288b85f971c299eefc6bb.
- Both agent builds: 1.0.0-lab.5. Windows package Authenticode validated;
  Linux installed as a standard Debian package. Both local RDP probes passed.
- 98 focused Python tests passed: remote policy/leases/CSRF, native RDP file,
  operator API/listener, endpoint views and version1 operations. Ruff passed.
- Existing Windows Go filesystem ACL test failed in the build workstation
  environment. It was not weakened; the complete Go suite is not claimed green.
- Both dedicated nonadministrator SSH accounts authenticated with separate keys.
- Sustained Guacamole SSH WebSocket checks returned terminal graphics on both
  platforms without errors. Initial blank-frame checks were insufficient and
  exposed a host-key algorithm mismatch during subsequent log inspection.
  Corrected by pinning ECDSA host keys collected through existing trusted SSH.
- Native RDP backends accepted dedicated-account login during gateway backend
  qualification. Native client launch and owner's browser terminal acceptance
  remain manual checks; backend qualification does not prove those UI paths.
- Both monitoring records active/online after deployment; heartbeat ages under
  one minute. Remote/login/operator/ingress services active.

Native sessions use OS authentication and are not terminated by browser logout
or RMM lease expiry. Issuing the native connection file is audited separately
from endpoint login events. Browser leases remain subject to MFA, remote role,
active enrollment identity, freshness and ongoing session verification.

Rollback artifacts include the previous server venv, previous Windows signed
agent, Linux agent/config, SSH config and firewall backups. Official Guacamole
images were imported unchanged; no custom image was built. Owner-only native
credential handoff is outside the repository. This increment does not close
unrelated release, identity-provider recovery, or production qualification gates.

Additional interaction check: keyboard events sent through each Guacamole SSH
WebSocket executed `whoami` as the dedicated remote account. Verified resulting
temporary files independently on both guests and removed them. Native RDP TCP
connections from the owner's workstation succeeded to both endpoints.
