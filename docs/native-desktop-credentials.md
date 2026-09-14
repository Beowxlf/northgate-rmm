# Native desktop credentials

An owner-scoped desktop profile can add a `password 51:b:` field to the RDP
download. Windows DPAPI creates that encrypted field on the owner's workstation
under the owner's Windows account. The server cannot create a portable password
blob. The lab profile is for **Smooth-Operator / bt49s**; copying the file to
another Windows account does not provision that account with credentials.

The same authorized import stores exact `TERMSRV/<IP>` entries in the current
user's Windows Credential Manager. OpenBao remains the authoritative source.
Plaintext passwords are never written into RDP files, command arguments, or the
Git repository. Certificate verification, NLA for Windows, and pinned TLS for
Linux browser desktops remain enabled.

`NORTHGATE_RMM_NATIVE_DESKTOP_PROFILES` selects a protected, service-owned JSON
profile file. Each record binds the RMM subject, endpoint, enrollment identity,
address, username, and encrypted password. A keyed credential binding is checked
against the current authorized OpenBao value on every download. Downloading an
encrypted profile requires remote permission plus secret use and reveal grants.
Other subjects receive password-free connection files.

Changing the account, password, address, or enrollment invalidates the profile.
Refresh the authorized workstation import after a rotation. A stale profile
returns a clear conflict instead of silently supplying an obsolete password.
This is a one-time import, not a background credential synchronization service.

Downloaded files and locally saved credentials remain usable until the OS
password or network access changes. Revoking a browser session cannot recall an
already downloaded file. Remove its `TERMSRV/<IP>` entry and downloaded files
when retiring local access; rotate the endpoint password to invalidate copies.

An RDP file is a connection artifact, not proof that Windows setup is complete,
that the listener is running, or that the user has completed an interactive login.

Microsoft documents the user/computer binding in
[CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).
