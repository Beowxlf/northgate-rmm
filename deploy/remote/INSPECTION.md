# Endpoint inspection, baselines and diagnostics

This increment adds read-only inspection to each enrolled Windows/Linux endpoint.
Open **Inspection toolbox**, choose a category, and select **Run check / refresh**.
Results show collection/receipt times, agent version, execution identity, duration,
exit code, status and records. Download JSON for the full bounded result.

Categories: processes, services, TCP/UDP connections, local accounts, installed
software, scheduled tasks, startup configuration, storage and system diagnostics.
Linux coverage uses ps, systemd, ss, getent, dpkg-query and df. Windows coverage
uses fixed PowerShell and native read-only queries. Process command lines and password fields are
not collected. Linux tasks cover systemd timers, not cron; Windows startup covers
Run-entry names, not every persistence location. Software is Debian packages or
Windows machine-wide uninstall entries. The UI identifies these scope limits.

Select **Save this result as baseline** on a successful category result. A later
check shows added, removed and changed records, including before/after details.
Saving again replaces that category's baseline. Partial/failed collections cannot
be baselines and do not produce misleading removal comparisons. Volatile process,
connection and capacity changes require interpretation; differences are not alerts.

Execution uses the established SSH route, pinned host keys and dedicated
nonadministrator accounts. Only the fixed `--inspect CATEGORY` agent invocation
is accepted; HTTP input cannot supply arbitrary commands or destinations. MFA,
remote_operator and current enrollment identity are required. Online status is
required to run checks. Saved data is readable offline for active identities.

Collectors have a 25-second deadline, bounded output and a 2,000-row limit.
The server uses a 40-second SSH deadline, maximum 1 MiB response, one inspection
per endpoint and four concurrent endpoints. The web table shows 200 rows; downloads
include all collected rows. Request/complete audit events enter the existing RMM
audit path. History includes failed checks and retains the latest 100 checks across
the lab, with ten displayed per category. Baselines remain until replaced and are
bound to endpoint AND enrollment identity.

The remote service's private StateDirectory stores inspection.sqlite3 (SQLite,
0600 within a 0700 directory). This is independent of monitoring's PostgreSQL
schema. Back it up using SQLite's backup API while live, or copy it while the
remote service is stopped. Existing PostgreSQL-only backups do not cover it.
Keep this data private; it can contain host/account/software information.

Install the updated server wheel and unit with StateDirectory enabled; upgrade
both agents to 1.0.0-lab.7 using the existing signed Windows/deb Linux process.
Preserve monitoring credentials/enrollment. Rollback restores the previous server
venv/unit and agent package. Retain the inspection database for recovery.

Owner authorization: the owner requested implementation of the recommended next
increment: detailed inspection, baseline comparisons and diagnostic tools while
retaining the current RDP/browser SSH engine. This does not implement exercise
orchestration, SIEM ingestion, destructive response actions or unrestricted jobs.

Windows deployment also runs Enable-WindowsInspectionAccess.ps1 after each agent
upgrade to allow the dedicated account to execute the signed binary. Agent state
remains private. Enable-WindowsServiceInspection.ps1 grants only SCM CONNECT and
ENUMERATE_SERVICE (mask 0x5), preserving the original descriptor for rollback.
