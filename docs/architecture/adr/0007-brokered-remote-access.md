# ADR 0007 — Brokered Native Protocols for Remote Access

Status: Accepted  
Date: 2026-08-29

## Context

The product must remotely access both Windows and Linux. Implementing custom
desktop capture, input injection, terminal emulation, cryptography, and protocol
translation inside the core agent would create a large, high-risk attack surface.

## Decision

Use an isolated free-software session gateway, initially Apache Guacamole or an
equivalently reviewed alternative, to broker RDP, SSH, and a qualified Linux
desktop protocol. Reach endpoints through expiring, single-target outbound tunnels
authorized by the RMM. Disable clipboard, file transfer, device redirection, and
credential persistence by default.

## Consequences

Windows and Linux remote access become required Phase 7 outcomes. The system gains
new dependencies and credential/session privacy risks but reuses mature protocols
and isolates them from the core control plane. Remote access requires its own gate,
threat model, penetration test, JIT credentials, forced termination, and evidence.
