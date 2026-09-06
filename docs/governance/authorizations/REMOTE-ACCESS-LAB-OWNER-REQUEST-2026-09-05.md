# Remote access lab owner request - 2026-09-05

The owner requested implementation of remote access to enrolled workstations,
followed by server and agent updates and product testing, favoring simple,
established solutions. This expands the earlier monitoring-only delivery scope.
Historical phase restrictions do not override this explicit request.

Initial targets are the enrolled Windows and Linux lab workstations. Public
exposure, unrelated endpoints, credential sharing and broad network changes are
not required by this request. Existing MFA and endpoint identity checks remain
the foundation for access. The interaction choice (browser desktop, native
client or terminal) was requested from the owner during discovery.

Before-state: CRM presentation is visually confirmed by the owner's screenshot.
Both enrolled agents are online. Windows has Remote Desktop services available;
Linux has no installed desktop or xrdp service. The control plane has no remote
desktop gateway installed. Discovery was read-only.
