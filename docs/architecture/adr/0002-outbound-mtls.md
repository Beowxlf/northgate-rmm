# ADR 0002 — Outbound Mutually Authenticated Agent Channel

Status: Accepted  
Date: 2026-08-29

## Decision

Agents initiate outbound TLS connections. Enrollment uses server-authenticated
TLS and a single-use grant; normal operation uses mutual TLS with one revocable
endpoint identity. Endpoints expose no RMM listener.

## Consequences

NAT traversal and endpoint firewall exposure are simpler. The control plane must
handle reconnect storms, certificate lifecycle, revocation, and offline work.
