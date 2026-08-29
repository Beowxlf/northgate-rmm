# NorthGate RMM

This workspace begins a security-first, cross-platform remote monitoring and
management (RMM) software project.

The first objective is not to reproduce every feature in TacticalRMM. It is to
learn the problem deeply and build one trustworthy vertical slice:

1. enroll one Linux test endpoint;
2. give it a durable cryptographic identity;
3. collect read-only inventory and health data;
4. display whether the endpoint is healthy, stale, or offline;
5. revoke its access; and
6. preserve an audit trail explaining every state change.

Unrestricted remote shells, desktop control, arbitrary file transfer, mass
patching, and multi-tenant administration are intentionally outside the first
version. Those features sharply increase the security and operational risk.

Start with [the learning and build program](docs/RMM_LEARNING_AND_BUILD_PROGRAM.md),
then complete [Module 1: The RMM Problem Map](docs/modules/01_RMM_PROBLEM_MAP.md).
The first executable lesson is
[Module 2: The Synthetic Trust Slice](docs/modules/02_PHASE1_SYNTHETIC_SLICE.md).

## Project controls

- [Project charter](PROJECT_CHARTER.md)
- [Development phases](docs/governance/PHASES.md)
- [Authorization gates](docs/governance/AUTHORIZATION_GATES.md)
- [Licensing policy](docs/governance/LICENSING.md)
- [Required free-software checks](docs/governance/REQUIRED_CHECKS.md)
- [Architecture overview](docs/architecture/OVERVIEW.md)
- [Infrastructure and microsegmentation](docs/architecture/INFRASTRUCTURE_AND_MICROSEGMENTATION.md)
- [Cross-platform remote access](docs/architecture/REMOTE_ACCESS.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Security requirements](docs/security/SECURITY_REQUIREMENTS.md)
- [Incident response](docs/operations/INCIDENT_RESPONSE.md)
- [Backup and restore](docs/operations/BACKUP_RESTORE.md)

The repository is in **Phase 1: Trustworthy vertical-slice simulation**. G1
authorizes bounded product coding with synthetic data. Endpoint installation,
remote jobs, privileged actions, agent updates, interactive remote access, and
production deployment remain closed behind later gates.

## Phase 1 developer checks

```powershell
python -m pip install --requirement requirements-dev.txt
ruff format --check src tests
ruff check src tests
mypy src tests
pytest --cov=northgate_rmm --cov-branch --cov-fail-under=90
bandit --recursive src --severity-level medium
```

## License

NorthGate RMM is available under the [Apache License 2.0](LICENSE). See the
[licensing policy](docs/governance/LICENSING.md) for contribution, dependency,
notice, and relicensing controls.
