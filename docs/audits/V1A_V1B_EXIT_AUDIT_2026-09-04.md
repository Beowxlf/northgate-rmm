# V1A and V1B Exit Audit — 2026-09-04

Status: V1A pass; V1B source qualification pass  
Integrated reviewed head: `690e30a77b5fca00115570042730ff9774139cc3`  
Protected main merge: `7ef3ab28b4c03ea2e7f3b58f75097966bc044694`  
Deployment gates: G2 and G6 remain closed

## Executive conclusion

The version 1.0 release contract and bounded source authority satisfy V1A. The
integrated control-plane source satisfies V1B: it composes the private agent,
one-time enrollment, and read-only operator services with PostgreSQL; packages
the three disabled services for Debian 12; and passes fail-closed, recovery,
cross-package lifecycle, security, and independent review checks.

This is a source and isolated-package qualification. It does not identify an
operational issuer or human identity provider, create production credentials,
publish a package, deploy a server, install an endpoint, change NorthGate, open
G2 or G6, or satisfy V1C through V1F.

## V1A evidence

| Criterion                                 | Evidence                                                                                                                                                                                                                                                                                                                             | State |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----- |
| Release contract on protected main        | [PR #18](https://github.com/Beowxlf/northgate-rmm/pull/18), reviewed head `192ee5bf244457a5883f87b6879438a5387cb614`, merge `e3de8cf44f11e2192989d5ff0150582dde349b9a`                                                                                                                                                               | Pass  |
| Status agrees with executable behavior    | README and operations documents distinguish executable source, isolated packages, missing operational integrations, and closed deployment gates                                                                                                                                                                                      | Pass  |
| Bounded control-plane source authority    | [`P2-CONTROL-PLANE-SOURCE-DEVELOPMENT.md`](../governance/authorizations/P2-CONTROL-PLANE-SOURCE-DEVELOPMENT.md) authorizes isolated source and package tests while explicitly withholding G2 through G8                                                                                                                              | Pass  |
| Required checks on release-contract merge | [Governance](https://github.com/Beowxlf/northgate-rmm/actions/runs/33821856043), [security](https://github.com/Beowxlf/northgate-rmm/actions/runs/33821855935), [G2A](https://github.com/Beowxlf/northgate-rmm/actions/runs/33821855930), and [G2B](https://github.com/Beowxlf/northgate-rmm/actions/runs/33821855931) checks passed | Pass  |

## V1B criteria mapping

| Criterion                     | Integrated evidence                                                                                                                                                                                                                | State |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- |
| Bounded service endpoints     | Agent `POST /v1/agent/messages`, enrollment `POST /v1/enrollment`, operator `GET /endpoints` and `GET /endpoints/<uuid>`; no operator mutation route                                                                               | Pass  |
| Grant safety                  | Digest-only secret storage, exact target/platform binding, absolute expiry, atomic single-winner consumption, and generic rejection tests                                                                                          | Pass  |
| Authenticated message binding | TLS-verified URI SAN and public-key binding, certificate-to-endpoint authorization, exact payload endpoint comparison, exact message-ID acknowledgement, and digest-bound idempotent retry                                         | Pass  |
| PostgreSQL state              | Seven checksum-protected migrations cover endpoints, identities and rotation lineage, grants, sequences, observations, message idempotency, revocation, and append-oriented audit events                                           | Pass  |
| Safe operator view            | External MFA-session revalidation on every request, pinned single-operator tuple, bounded keyset pages, receipt-time freshness, escaped list/detail output, and audited decisions                                                  | Pass  |
| Fail-closed inputs            | Isolated tests cover malformed and oversized requests, ambiguous framing, replay and duplicate writers, expiry, unknown and revoked certificates, cross-endpoint binding, rate/admission limits, deadlines, and dependency failure | Pass  |

The primary test evidence is in `tests/test_listener.py`,
`tests/test_enrollment.py`, `tests/test_enrollment_listener.py`,
`tests/test_operator_api.py`, `tests/test_operator_listener.py`, and
`tests/test_postgres_control_plane.py`. The executable composition boundaries
are exercised by `tests/test_agent_service.py`,
`tests/test_enrollment_service.py`, and `tests/test_operator_service.py`.

## Integrated protected evidence

Pull request [#29](https://github.com/Beowxlf/northgate-rmm/pull/29) integrated
the complete V1B source and offline server package at reviewed head
`690e30a77b5fca00115570042730ff9774139cc3`.

- [Pre-code governance audit run 33872164671](https://github.com/Beowxlf/northgate-rmm/actions/runs/33872164671): pass.
- [Free-software security run 33872164789](https://github.com/Beowxlf/northgate-rmm/actions/runs/33872164789): pass; 355 Python tests, PostgreSQL integration and restore tests, 91.60% branch coverage, Go race/fuzz/static/vulnerability checks, Bandit, Semgrep, Gitleaks, actionlint, Zizmor, dependency audits, and link checks.
- [Debian 12 systemd qualification run 33872164666](https://github.com/Beowxlf/northgate-rmm/actions/runs/33872164666): pass.
- [Release-candidate trust run 33872164869](https://github.com/Beowxlf/northgate-rmm/actions/runs/33872164869): pass.
- Exact-head code review: no major issues; unresolved threads: zero.
- Exact-head security review: no security issues found.

The security run built byte-identical pairs and then tested the real packages
with networking disabled. Ephemeral evidence digests were:

- endpoint package `northgate-rmm-agent_0.2.0_amd64.deb`:
  `e12ce054e42515b312fcdfd61899989e3ff4e80a043e894e79dbc445f5af3d09`;
- server application wheel:
  `271b5426827e6ae91eb17bae554560f32dc63fde2cde6bff86cad5d12759e269`;
- server package `northgate-rmm-server_0.1.0~dev0_amd64.deb`:
  `e54961122f96adb176fe6b19d0d18d1c01c5f4925f4efb4ae4de4790648d62ed`.

The network-isolated Debian test installed the real endpoint and server
packages together. It proved server purge preserves endpoint artifacts and the
reverse endpoint purge preserves server configuration, credentials, TLS
material, unit, launcher, package registration, identities, and state root. It
did not verify application site-package contents or a retained state payload in
the reverse-purge sequence; those deeper preservation assertions remain V1D
operational-recovery work.

These are qualification artifacts, not a G6-authorized release or distribution
record.

## Remaining release ladder

- V1C remains open: production signing custody, independently pinned trust,
  protected distribution, compromise recovery, and exact G6 authorization.
- V1D remains open: every in-scope infrastructure value and owner must be exact;
  backup/restore, monitoring, capacity, certificate status, and containment
  need operational evidence.
- V1E remains closed behind a separate exact G2 authorization and fresh VM
  Factory plans for one disposable canary.
- V1F remains open until the authorized soak, restore and incident drills,
  final independent review, known-risk reconciliation, and immutable G6 release
  approval are complete.

## Stop conditions retained

No `1.0.0` tag or public artifact may be created from this audit. Any live VM,
network, identity, PKI, database, service, agent, signing, or publication action
still requires its exact gate and change evidence.
