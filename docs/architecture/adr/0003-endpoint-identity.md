# ADR 0003 — Durable Endpoint Identity

Status: Accepted  
Date: 2026-08-29

## Decision

Use an opaque endpoint ID and cryptographic identity. Hostname, IP address, serial
number, and labels are mutable observations or attributes and cannot authorize
work. Endpoint client certificates bind that ID in one exact URI SAN. The Linux
agent publishes already-enrolled identity material only once into a private
directory and file after validating the endpoint binding, certificate lifetime
and purpose, key match and strength, chain, and explicit server trust roots.

## Consequences

Renames and address changes preserve history. Cloning and reinstallation require
explicit identity-reconciliation rules and cannot silently reuse identity.
Permission-restricted local storage is an initial defense, not encrypted or
hardware-backed protection; that stronger policy, rotation, status, revocation,
and live enrollment remain separately qualified work.
