# ADR 0005 — PostgreSQL-Backed Job Queue First

Status: Accepted  
Date: 2026-08-29

## Decision

Use PostgreSQL transactions, row claims, leases, and fencing tokens for the first
job state machine. Do not introduce a dedicated broker until measured reliability,
isolation, or throughput requirements justify it.

## Consequences

The first deployment has fewer services and one transactional source of truth.
Database contention, lease correctness, and reconnect load require explicit tests.
