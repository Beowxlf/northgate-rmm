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
operator authorization happen separately. Revocation must succeed before
uninstall removes the local identity. Ordinary uninstall preserves configuration
and state for investigation or recovery; purge requires separate approval,
revocation, and evidence export. Purge accepts only root-owned `0600` approval
and evidence markers in `/etc/northgate-rmm`, which the service cannot write,
and fails unless all retained state is removed.

The unit runs under a locked `northgate-rmm` system identity with no Linux
capabilities, a read-only host filesystem except for systemd-managed private
state/runtime directories, bounded memory/CPU/tasks/file descriptors, bounded
restart behavior, and JSON output to the journal. It permits only Unix, IPv4,
and IPv6 address families for outbound-only transport; the agent exposes no
listener.

The isolated test verifies package metadata, ownership and modes, disabled
service state, unit syntax, execution as the service user, identity-gated
uninstall, state preservation, and approval/evidence-gated purge. A container is
not a full systemd boot, so restart behavior and live resource enforcement still
require the separately authorized disposable G2 canary.
