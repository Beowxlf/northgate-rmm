# SOC and IT workspace

This release connects endpoint management to cases, infrastructure records,
retained evidence, optional tools, service runbooks and protected credentials.
Browser desktop access uses the existing Guacamole service with RDP and NLA.
SSH, file transfer and the separate privileged worker terminal remain available.

## Working a case

Open Cases and choose an IT incident, SOC investigation, recurring problem or
service request. Link the actual enrolled devices and related infrastructure.
Assign a permitted operator, set priorities and response/resolution deadlines,
then add tasks and timeline notes. A linked device can open system tools, SSH or
browser RDP alongside the case. Remote access still requires its own permission.
Changing an association never removes the historical record's access scope.

The case queue can be filtered by status, priority and type, then sorted by
priority, recent activity or age. Its summary shows open, critical, overdue,
unassigned and verified-closed work. Each case records a category, analyst
disposition, containment state and resolution code. Automated SOC cases start as
`security`, `undetermined`, `not_started` and `not_set`. Resolving a SOC case
requires a final disposition, a completed containment decision (including an
explicit `not_required` decision), a resolution code, outcome and verification.

Retain a completed diagnostic job by its job identifier, or attach a reviewed
file. Uploads retain indexed chunks and can resume with the same file in the
same browser session. Download verifies every chunk and the complete SHA-256.
Recovery passwords and keys belong in Access & secrets rather than case notes.
Resolution requires task completion, an outcome and verification; closure is
a separate transition. Reopen a closed case before dispatching new linked work.

## Infrastructure and knowledge

Infrastructure holds stable assets, services, networks and dependencies.
Enrollments are linked explicitly to assets with verification evidence; names
and IP addresses never automatically merge device identities. Intended and
observed properties have separate fields with observation sources. Each edit
retains its previous version. Mark dependency observations as candidate,
observed or verified and retain their supporting evidence reference.

Knowledge & changes holds articles, runbooks, change plans and lab exercises.
Changes have implementation, rollback and verification fields; exercises have
authorized scope, expected detections and cleanup verification. Links to the
authoritative infrastructure documentation are retained in source references.
These records document intent. They do not grant permission to run commands.

## Device tools and access

Open a device for System tools, SSH & files, Desktop (Windows), Access & secrets,
Network capture, Inventory & diagnostics and Installable tools. A tool is
usable only after its readiness result confirms its dependencies. Approved
optional packages have signed versioned manifests and platform checks. Built-in
health/connectivity/evidence profiles require no additional third-party package.
No Npcap silent-install entitlement or optional tool license is assumed.

The worker retains bounded health history and on-demand configuration changes.
A light diagnostic lane can run alongside a system terminal. Installers and
other heavy mutations remain serialized. CPU, memory, output and disk budgets
apply to tool processes; see [tool-catalog.md](tool-catalog.md) for platform
limits and the distinction between resource controls and process isolation.

Secrets are stored in OpenBao. RMM stores references, exact enrollment grants
and audited workflow state. Metadata, remote use, reveal and administration are
separate permissions; reveal and recovery imports require a fresh MFA session.
Replacing a vault version is distinct from changing a workstation password.
Endpoint password rotation is unavailable without a qualified executor that
independently verifies the new credential. Native/MCP APIs do not reveal secrets.

## Automation and integrations

Service runbooks dispatch deployment-approved typed steps under a genuine
service identity, exact enrolled-device grants, maintenance windows, bounded
concurrency and failure thresholds. Their job progress survives application
restart. Pause prevents further work and requests active-job cancellation.
Case-linked plans verify case permissions before dispatch and retain final
receipts before advancing. A browser login is never made into an unattended key.

The Wazuh intake requires its own protected service identity and explicit
agent-to-enrollment mapping. It keeps normalized alert metadata, deduplicates
retries and supports linking an alert to a case. Wazuh remains the source of raw
telemetry. The connector does not guess an agent mapping or automatically close
an investigation.

Security alert detail shows the source alert identifier, Project_Mati detection
and version, Wazuh rule and level, observed/received times, ATT&CK references,
mapped device and allowlisted context. From either an alert or its case, Response
tools opens the approved catalog with the case identifier locked in when one is
available. Every executable action has an adjacent information control that
explains its purpose, expected output and endpoint impact. These explanations do
not grant access: the server continues to enforce the existing case and endpoint
permissions, audit attribution, enrollment binding and idempotent request ID.

Native integration and MCP expose scoped case, asset, evidence and tool actions
using the existing persistent service credential. Every request and running job
continues to check revocation and current enrollment. See
[operations-workspace.md](operations-workspace.md) for API and custody limits,
[tool-catalog.md](tool-catalog.md) for optional package qualification, and
the OpenBao deployment guide for independent recovery custody.

## Operational limits

Deployment and live qualification are separate from code availability. The
single-node lab is not a highly available service. Case deadlines do not yet
implement business calendars or an SLA escalation engine. Completed evidence
has no purge API in this release; partial uploads expire after 24 hours.
Pattern checks and a collector's redaction assertion cannot guarantee binary
evidence contains no credentials. Optional engines need real package approval
and operating-system qualification before an installation can be offered.
