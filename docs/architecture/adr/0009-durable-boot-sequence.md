# ADR 0009 — Durable Per-Boot Message Sequence

Status: Accepted  
Date: 2026-08-31

## Decision

The Linux agent reserves message sequence numbers in a private, exclusively
locked local store before message construction. The state binds one canonical
kernel boot UUID to its last reserved positive 64-bit sequence. It continues
monotonically across agent restart for that boot and starts at one only when the
kernel boot UUID changes.

Publication writes and syncs a restrictive temporary file, atomically replaces
the prior state through a stable directory handle, and syncs the directory before
returning the reservation. The directory and files must be owned by the effective
agent UID, files must have one link, and group or other permission bits are not
accepted. Corrupt, unknown, permissive, oversized, concurrently opened, or
ambiguous state fails closed. A final directory-sync failure returns a typed
uncertainty and the candidate sequence must not be emitted; reopening and
reserving again may safely leave a gap.

## Consequences

Agent process restart cannot normally reuse a message sequence, and competing
instances cannot reserve the same number. An in-process mutex covers sequence
reservation through queue publication so concurrent snapshots cannot invert
durable delivery order. Sequence reservation precedes message ID generation,
encoding, and durable spooling, so failures after reservation can create harmless
gaps.

The unkeyed digest detects accidental corruption but is not an authenticity or
anti-rollback mechanism. Restoring a VM or filesystem may restore a lower local
counter; the server's durable identity/boot maximum then rejects reuse. This
fail-closed behavior may require operator recovery. It is distinct from the G6
update-status floor, which remains dependent on an external monotonic allocator
and independent Z5/Z6 anchors.
