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
- [Third-party notice inventory](THIRD_PARTY_NOTICES.md)
- [Required free-software checks](docs/governance/REQUIRED_CHECKS.md)
- [Phase 2 data inventory](docs/security/PHASE2_DATA_INVENTORY.md)
- [Architecture overview](docs/architecture/OVERVIEW.md)
- [Infrastructure and microsegmentation](docs/architecture/INFRASTRUCTURE_AND_MICROSEGMENTATION.md)
- [NorthGate VM and network change packet](docs/change-plans/NORTHGATE_RMM_VM_AND_NETWORK_PACKET_2026-08-30.md)
- [Cross-platform remote access](docs/architecture/REMOTE_ACCESS.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Security requirements](docs/security/SECURITY_REQUIREMENTS.md)
- [Incident response](docs/operations/INCIDENT_RESPONSE.md)
- [Backup and restore](docs/operations/BACKUP_RESTORE.md)

The Phase 1 trustworthy vertical-slice simulation is complete. A separate,
bounded authorization now permits **Phase 2 Linux-agent source development**.
G2 remains closed: endpoint or VM installation, live identity, live collection,
networking, and infrastructure changes remain prohibited.

The Phase 1 implementation includes a strict message decoder, transactional
PostgreSQL adapter and migrations, restart/concurrency/recovery tests, escaped
server-rendered read models, and an in-memory test-only certificate authority.
It remains a synthetic control-plane proof: no HTTP listener, real endpoint
collector, job scheduler, or command-execution primitive is present.

The in-progress Go agent source adds strict non-secret configuration, bounded
allowlisted Linux collectors, the Phase 1-compatible inventory envelope, an
checksum-validated quota spool, and an outbound-only transport interface. It
also includes a source-tested TLS 1.3 mutual-authentication sender with exact
message acknowledgement and bounded jittered retry policy. It has no listener,
enrollment implementation, identity persistence, command runner, privileged
helper, package, or service installation. Operational PKI, protected sequence
persistence, encryption, and keyed spool integrity remain G2 blockers.

## Phase 1 developer checks

```powershell
python -m pip install --requirement requirements-dev.txt
ruff format --check src tests
ruff check src tests
mypy src tests
pytest --cov=northgate_rmm --cov-branch --cov-fail-under=90
bandit --recursive src --severity-level medium
```

## Phase 2 agent developer checks

Run these commands from `agent/` with the pinned Go version in `go.mod`:

```powershell
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

## License

NorthGate RMM is available under the [Apache License 2.0](LICENSE). See the
[licensing policy](docs/governance/LICENSING.md) for contribution, dependency,
notice, and relicensing controls.
