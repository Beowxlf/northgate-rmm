# NorthGate RMM

NorthGate RMM is a deployed private-lab platform for Windows and Linux endpoint
management, SOC/IT cases, infrastructure records, and protected remote access.
It is a lab product, not a claim of enterprise certification or unrestricted
production readiness.

## Current capabilities

- Fleet inventory, heartbeat and management-worker health, device groups,
  monitoring alerts, policies, and bounded rollout operations.
- SYSTEM/root tools, audited terminals, service and process management,
  inventory snapshots, diagnostics, file transfer, software and update actions.
- Native RDP downloads and browser desktops for configured Windows and Linux
  devices; SSH terminals and files remain available alongside desktop access.
- OpenBao-backed lab accounts and recovery secrets, exact enrollment bindings,
  scoped use/reveal permissions, and optional workstation-encrypted RDP profiles.
- Wxlfgar capture installation, dependency checks, bounded capture sessions,
  network observations, and retained analysis results.
- SOC and IT cases, Wazuh detection intake, evidence, case disposition and
  resolution, infrastructure relationships, knowledge records, and changes.
- Signed installable tools, diagnostic profiles, resource budgets, service
  runbooks, and a scoped native API/MCP integration.

Capabilities are qualified by device and identity. Missing Npcap, a package
manager unavailable to SYSTEM, a stopped worker, and incomplete Windows setup
must not be represented as successful operations. Native desktop sessions use
the endpoint's OS account and network rules; they are not terminated by signing
out of the RMM browser session.

## Deployment and audit status

The lab inventory contains 16 enrolled machines: six Windows and ten Linux.
The [current audit](docs/audits/SYSTEM_UX_AUDIT_2026-09-14.md) separates verified
behavior, remediations, pending acceptance, and platform limitations. Read it
before treating a source-level test as proof of live product behavior.

The original Linux-only and monitoring-only phase documents describe historical
milestones. Their statements that deployment, the identity provider, remote
shells, or the issuer do not exist are **not current deployment status**. Later
owner authorizations expanded the lab product to both operating systems and
remote management. Historical evidence remains available under `docs/audits/`
and `docs/governance/authorizations/`.

Daily backup schedules are disabled at the owner's request. Manual and
change-specific recovery services remain available. A verified backup archive
does not by itself prove a full-system restore.

## Operator and developer guides

- [Modern fleet workspace](docs/modern-workspace.md)
- [SOC/IT workspace](docs/soc-it-workspace.md)
- [Operations workspace](docs/operations-workspace.md)
- [Wazuh intake](docs/wazuh-intake.md)
- [Tool catalog](docs/tool-catalog.md)
- [Browser desktops and secrets](docs/browser-rdp-and-secrets.md)
- [Linux desktop installation](deploy/remote/LINUX-BROWSER-DESKTOP.md)
- [Native desktop credentials](docs/native-desktop-credentials.md)
- [Recovery archive and restore](docs/operations-backup-and-restore.md)
- [Original runtime architecture](docs/operations/V1_SOURCE_RUNTIME.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## Development checks

Use Python 3.11 or later and the pinned dependencies in `requirements-dev.txt`.
PostgreSQL tests need a **separate UTF-8 test database**; never point them at a
deployed RMM database. `DATABASE_URL` and `RMM_OPERATIONS_TEST_DSN` select that
isolated database. Tests skipped for lack of a database are not database proof.

```text
ruff check src tests
pytest -q
node --test tests/tool_catalog_ui.test.cjs
```

From `agent/`, use the Go toolchain version in `go.mod`:

```text
go vet ./...
go test ./...
go test -race ./...
```

The full CI workflow includes dependency, packaging, security, and governance
checks. Platform-specific tests and live acceptance are separate from unit tests.

## License

NorthGate RMM is available under the [Apache License 2.0](LICENSE). See the
[licensing policy](docs/governance/LICENSING.md) for dependency and notice controls.
