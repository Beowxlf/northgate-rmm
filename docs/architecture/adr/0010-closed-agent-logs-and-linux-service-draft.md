# ADR 0010 — Closed Agent Logs and Linux Service Draft

Status: Accepted  
Date: 2026-08-31

## Decision

The Linux agent emits newline-delimited JSON through a closed event schema. The
schema permits only enumerated level, event, component, outcome, and sanitized
failure-class values plus canonical optional correlation/message UUIDs. It has no
free-form message, raw error, URL, hostname, endpoint identifier, inventory, or
arbitrary attribute field. Records are UTC timestamped, byte bounded, and written
serially as complete lines for the operating-system journal.

The first service integration is a source-only Debian 12 amd64 contract. Its
`systemd` unit runs as a locked non-root identity with no capabilities, hardened
filesystem/process/kernel boundaries, bounded resources, bounded restart policy,
and journal output. Installation remains disabled by default. Revocation precedes
identity removal and uninstall; ordinary uninstall preserves state; purge requires
separate approval and evidence export.

## Consequences

Callers cannot accidentally attach raw errors or dynamic key/value data to agent
logs. New event fields or values require a reviewed code change, reducing the
chance that credentials or collected endpoint data enter logs. This does not
redact data elsewhere or complete runtime observability until the logger is wired
into an executable agent.

The lifecycle and unit can be reviewed and mutation-tested without touching a
host, but they do not prove Debian packaging or `systemd` compatibility. There is
no executable package, installer, activation path, or operational revocation yet.
Those require isolated package tests and a separate G2 authorization before the
first disposable canary installation.
