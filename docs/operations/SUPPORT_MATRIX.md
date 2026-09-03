# Platform Support Matrix

No operating-system release is operationally supported yet. Debian 12 package
and service behavior is qualified in isolated CI, but G2 installation and live
canary acceptance remain closed.

| Platform                     | Phase | Status                    | Required qualification                                         |
| ---------------------------- | ----: | ------------------------- | -------------------------------------------------------------- |
| Linux protocol simulator     |     1 | Qualified in CI           | completed contract, persistence, and failure tests             |
| Debian 12 amd64              |     2 | CI-qualified; unsupported | G2 PKI, enrollment, live canary, soak, and release acceptance  |
| Named RHEL-family release    |    2+ | Deferred                  | rpm, SELinux, systemd, collectors, upgrade/uninstall           |
| Named Windows client release |     3 | Not qualified             | service, ACL, event log, installer, update/uninstall           |
| Named Windows Server release |    3+ | Deferred                  | service/server-specific qualification                          |
| Windows RDP                  |     7 | Required, not qualified   | JIT credential, tunnel, gateway, redirection, termination      |
| Linux SSH                    |     7 | Required, not qualified   | host trust, JIT certificate/account, tunnel, transcript policy |
| Linux desktop backend        |     7 | Required, undecided       | distro/display/desktop/protocol-specific qualification         |

“Linux” and “Windows” are product families, not test cases. A platform becomes
supported only when version, architecture, packaging, security mechanism,
collector/action behavior, upgrade, rollback/recovery, and end-of-life policy are
continuously tested.
