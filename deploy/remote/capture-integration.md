# Wxlfgar capture integration candidate

The endpoint profile links to Network capture. The private gateway registers capture jobs, progress, history, stop/delete actions and verified downloads through capture_ui.py, capture_store.py and capture_transport.py. remote_service.py registers the integration. The updated agent supplies a fixed --capture-request bridge and metadata-only --tools inventory.

Existing owner/MFA/remote-role and current-enrollment authorization gates every action. The gateway signs endpoint/job/session-bound Ed25519 requests with short expiry. Only the public key is installed on endpoints. Replay prevention persists across worker restarts. Wxlfgar uses a local loopback service behind the existing pinned SSH management connection; no additional externally reachable port is opened.

Capture is off until Start. The browser renews an authenticated 45-second lease every ten seconds. Missing renewal stops capture, while an independent maximum duration bounds it. Validated presets and optional host IP/port fields are supplied as structured arguments. Agent and tool installation does not elevate the SSH account.

Windows enrollment optionally accepts WxlfgarBinary, WxlfgarSha256, WxlfgarSignerThumbprint and RmmToolPublicKey, then installs the tool after enrollment. Linux has packaging/debian/enroll-with-tools.sh. Trusted installer copies are in packaging/tools; Windows release packaging includes them. For first enrollment, the installer reads the local endpoint ID and the first signed capability request binds the enrollment identity. Existing pinned SSH remote-access provisioning remains required.

Wireshark/dumpcap and Windows Npcap are separate prerequisites. No capture-driver installer is silently downloaded or bundled. Candidate binaries are unsigned; Windows installation requires the final signed hash and approved signer.

RMM history is in /var/lib/northgate-rmm-remote/captures/capture.sqlite3, in a private directory. Raw artifacts remain private on the endpoint until downloaded; temporary server copies are verified by size/SHA-256 and authorization is rechecked before delivery. Endpoint and RMM history have seven-day retention. Limits: twenty endpoint jobs, one active capture per endpoint, 32 MiB raw capture, five minutes, four gateway RPC slots and two download slots. Add SQLite to the private backup plan if report history must survive retention.

See the Wxlfgar README for service privileges, platform dependencies, artifact layout and parser coverage. This is a code-complete implementation candidate for the agreed first-release scope, not a tested release. Review signatures/replay/expiry, enrollment binding, session/revocation behavior, process containment, Windows driver and Linux capabilities, parser/counter accuracy, resource bounds, SSH framing, artifact integrity, UI actions, retention, installer failures and regression of existing RMM functionality next.

No deployment, capture or bug-scan suite was run during this implementation pass. Stop/disable the worker before rollback, restore prior gateway/agent packages and deliberately retain its configuration/artifacts.
