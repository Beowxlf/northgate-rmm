# Debian 12 amd64 source draft

These files define a reviewable package lifecycle and hardened `systemd` unit.
They are not an installable package, do not contain an agent executable, and do
not authorize endpoint installation. G2 remains closed.

The package must remain disabled after installation. Enrollment and explicit
operator authorization happen separately. Revocation must succeed before
uninstall removes the local identity. Ordinary uninstall preserves configuration
and state for investigation or recovery; purge requires separate approval,
revocation, and evidence export.

The unit runs under a locked `northgate-rmm` system identity with no Linux
capabilities, a read-only host filesystem except for systemd-managed private
state/runtime directories, bounded memory/CPU/tasks/file descriptors, bounded
restart behavior, and JSON output to the journal. It permits only Unix, IPv4,
and IPv6 address families for the future outbound-only transport; the agent
still exposes no listener.
