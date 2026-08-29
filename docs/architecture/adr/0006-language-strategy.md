# ADR 0006 — Python Control Plane and Go Endpoint Agent

Status: Accepted  
Date: 2026-08-29

## Decision

Use modern Python with strict typing for the modular control plane and protocol
simulator. Use Go for the production-intent cross-platform endpoint agent beginning
in Phase 2.

## Rationale

Python supports rapid, readable domain development and the existing contextual
learning goal. Go produces a small cross-platform service binary with strong
concurrency support and fewer endpoint runtime dependencies.

## Consequences

The protocol is language-neutral and contract-tested. Phase 1 must not create a
Python endpoint agent that accidentally becomes a production dependency. Go
toolchain installation and supply-chain controls are part of the Phase 2 gate.
