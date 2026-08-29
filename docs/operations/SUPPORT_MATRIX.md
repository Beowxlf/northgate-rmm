# Platform Support Matrix

No operating-system release is qualified yet.

| Platform | Phase | Status | Required qualification |
| --- | ---: | --- | --- |
| Linux protocol simulator | 1 | Planned | contract and failure tests |
| Named Debian/Ubuntu release | 2 | Not qualified | package, systemd, identity, collectors, limits, upgrade/uninstall |
| Named RHEL-family release | 2+ | Deferred | rpm, SELinux, systemd, collectors, upgrade/uninstall |
| Named Windows client release | 3 | Not qualified | service, ACL, event log, installer, update/uninstall |
| Named Windows Server release | 3+ | Deferred | service/server-specific qualification |
| Windows RDP | 7 | Required, not qualified | JIT credential, tunnel, gateway, redirection, termination |
| Linux SSH | 7 | Required, not qualified | host trust, JIT certificate/account, tunnel, transcript policy |
| Linux desktop backend | 7 | Required, undecided | distro/display/desktop/protocol-specific qualification |

“Linux” and “Windows” are product families, not test cases. A platform becomes
supported only when version, architecture, packaging, security mechanism,
collector/action behavior, upgrade, rollback/recovery, and end-of-life policy are
continuously tested.
