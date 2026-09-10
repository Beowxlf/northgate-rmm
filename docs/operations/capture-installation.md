# Install capture tools from the device workspace

Open a device, select **Network capture**, and use **Install / check dependencies**.
If the device has an older management worker, the same section offers **Update
management worker** first. Refresh the tab after that update completes.

Installation requires an authenticated operator session with management and
software-installation permission for that device. The existing privileged worker
downloads the approved, signed Wxlfgar release from the enrollment-authenticated
RMM catalog. Opening the tab never starts installation or packet capture.

- Debian/Ubuntu: installs `wireshark-common`, Wxlfgar and its dedicated service.
- Windows: installs the signed Wxlfgar service and Wireshark capture utility.
  When Npcap is absent, the verified free installer is staged under
  `C:\ProgramData\NorthGateWxlfgar\installers`. Its interactive installation must
  be completed through an administrator desktop session. Silent Npcap installation
  requires the vendor's OEM option and is not implemented by this action.

Review the installation output and select **Refresh readiness**. A completed
installation job does not mean a missing capture driver is ready. No capture or
reboot is started automatically. Existing configuration and captures are retained;
an enrollment mismatch or partial installation requires reconciliation. Existing
Wxlfgar versions require a matching catalog release for dependency repair; use the
component update workflow for version changes.

Administrators publish Wxlfgar and worker catalog entries with the existing
`management_admin.publish_release` utility and release authority. The release
signing private key is never placed in the web service. Worker release
`1.1.0-lab.4` introduces the capture installer capability.

Npcap behavior: https://npcap.com/guide/npcap-users-guide.html
