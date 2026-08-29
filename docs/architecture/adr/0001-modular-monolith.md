# ADR 0001 — Modular Monolith Control Plane

Status: Accepted  
Date: 2026-08-29

## Context

The control plane has multiple security boundaries, but the initial load and team
size do not justify distributed deployment complexity.

## Decision

Implement one repository and deployable control plane with explicit modules for
API, authorization, registry, observations, jobs, gateway, scheduler, and audit.
Modules expose typed interfaces and own their invariants.

## Consequences

Development, transactions, tests, and recovery begin simpler. Module boundaries
must not be bypassed through shared database access. Components may be separated
later when a measured trust, availability, or scale need exists.
