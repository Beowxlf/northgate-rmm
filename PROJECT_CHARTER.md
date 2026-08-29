# NorthGate RMM Project Charter

## Purpose

Build a security-first remote monitoring and management system that can monitor
and eventually perform explicitly authorized administration on supported Linux
and Windows endpoints.

## Product promise

The system will make endpoint state understandable, management actions bounded,
and every security-relevant transition attributable and recoverable.

## Initial users

- NorthGate lab operator;
- security and infrastructure engineering learner;
- future authorized lab administrators.

## Initial success condition

One disposable Linux canary can enroll with a unique cryptographic identity,
send authenticated read-only health observations, become stale or offline by an
explicit freshness rule, be revoked, and produce a correlated audit trail.

## Required mature-product outcomes

- manage supported Windows and Linux endpoints through one protocol and policy
  model;
- provide brokered, time-limited remote terminal and remote desktop sessions to
  both operating-system families;
- use OS-native remote protocols through an isolated session gateway rather than
  embedding an unrestricted remote-control primitive in the core agent;
- make session authorization, connection, operator presence, recording policy,
  termination, and evidence explicit.

## Non-goals for the initial release

- arbitrary unattended shell in the initial phases;
- remote desktop before the dedicated remote-session phase;
- arbitrary file transfer;
- mass patching;
- public-internet exposure;
- multi-tenancy;
- an agent running permanently as root or LocalSystem;
- replacement of EDR, SIEM, backup, identity, or configuration management.

## Safety principles

1. Observation and change are separate authorities.
2. Missing evidence remains unknown, never success.
3. Display names are never authorization identities.
4. Every action is typed, bounded, expiring, target-bound, and auditable.
5. Privilege is introduced only for a proven capability and isolated behind a
   narrower boundary.
6. Updates are a privileged fleet-wide action and use separate trust.
7. No phase begins until its authorization gate has objective evidence.

## Authority

The project owner is `Beowxlf`. CODEOWNERS review is required for security,
protocol, workflow, release, and authorization-gate changes. Automation may
enforce gates, but it may not approve its own exceptions.

## References

- [Development phases](docs/governance/PHASES.md)
- [Authorization gates](docs/governance/AUTHORIZATION_GATES.md)
- [Architecture overview](docs/architecture/OVERVIEW.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Security requirements](docs/security/SECURITY_REQUIREMENTS.md)
