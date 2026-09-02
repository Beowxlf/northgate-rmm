# Debian 12 amd64 sandbox package candidate

These files build an ephemeral `.deb` containing the executable read-only agent
and hardened `systemd` unit. The package is installable only for the repository's
network-isolated Debian test. It is not signed, published, or approved for any
endpoint or VM. G2 remains closed.

The security workflow builds the agent as a static Linux amd64 executable,
builds the package twice with one source timestamp, rejects byte differences,
and installs one result in a Debian 12 container created from the pinned image
index in `Dockerfile.test`. The test container runs with Docker networking set
to `none` and receives only the package and test script as read-only mounts. It
contains no NorthGate route, live control-plane address, credential, certificate,
enrollment identity, or private infrastructure data.

The package must remain disabled after installation. Enrollment and explicit
operator authorization happen separately. A separately authorized workflow must
revoke the exact control-plane identity, remove its local material, and record a
fresh non-empty root-owned `0600` receipt before uninstall is accepted; a missing
identity file is not revocation proof. Configure and upgrade invalidate older
receipts. Ordinary uninstall preserves configuration and state for investigation
or recovery; purge additionally requires root-owned approval and evidence-export
markers and fails unless all retained state is removed. Every configure or
upgrade invalidates all three receipts so approval cannot cross lifecycle
generations. Before destructive purge work, the package durably records the
validated authorization in a root-only transaction outside the configuration
tree. It retains that record for recovery and invalidates it on the next
configure lifecycle.

Rejected messages use a separate bounded retention quota equal to the active
spool byte quota and at most 128 records. Before admitting a rejection that would
cross either limit, the oldest exact-payload rejected records move into a
separate durable rollover area using destination-first synchronization. Startup
recovers the valid dual-link intermediate state. The runtime replays pending
rollover audits after restart and deletes each payload only after its audit is
acknowledged. The active spool therefore remains available after prolonged
expiry or rejection.

The unit runs under a locked `northgate-rmm` system identity with no Linux
capabilities, a read-only host filesystem except for systemd-managed private
state/runtime directories, bounded memory/CPU/tasks/file descriptors, bounded
restart behavior, and JSON output to the journal. It permits only Unix, IPv4,
and IPv6 address families for outbound-only transport; the agent exposes no
listener.

The isolated test verifies package metadata, ownership and modes, disabled
service state, unit syntax, execution as the service user, rejection of
supplementary service-account access, root-receipt-gated uninstall, state
preservation, purge failure on account-removal error, and approval/evidence-gated
purge. It also injects service-stop and service-disable failures and proves
aborted removal restores prior activation and enablement while leaving the
installed executable in place. A failed purge manager reload retains its
authorization receipts for retry, as does failed runtime-marker cleanup. A
root-only purge transaction preserves retry authority through partial config
deletion. The test proves an enabled-but-inactive upgrade does not disable boot
activation and a stale interrupted-upgrade marker cannot start a fresh
installation. A container is not a full systemd boot; the test uses a
bounded mock to prove failed upgrade restart retains retry intent across repeated
upgrade preparation, an aborted upgrade restores a previously active service,
and verified recovery clears the marker. Live resource enforcement still
requires the separately authorized disposable G2 canary.
