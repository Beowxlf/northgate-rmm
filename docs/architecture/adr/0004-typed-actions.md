# ADR 0004 — Typed Actions Without a General Shell Primitive

Status: Accepted  
Date: 2026-08-29

## Decision

Every remote capability is a versioned typed handler with a strict schema,
explicit privilege, time/output/resource limits, idempotency class, postcondition,
and audit fields. The product will not implement an arbitrary shell action in the
initial phases.

## Consequences

Features require more design work but are individually testable and authorizable.
Remote shell, if ever considered, requires a Class 3 change and separate phase
gate rather than being assembled from existing handlers.
