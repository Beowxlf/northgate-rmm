# ADR 0003 — Durable Endpoint Identity

Status: Accepted  
Date: 2026-08-29

## Decision

Use an opaque endpoint ID and cryptographic identity. Hostname, IP address, serial
number, and labels are mutable observations or attributes and cannot authorize
work.

## Consequences

Renames and address changes preserve history. Cloning and reinstallation require
explicit identity-reconciliation rules and cannot silently reuse identity.
