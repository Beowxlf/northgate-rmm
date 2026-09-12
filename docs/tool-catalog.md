# Endpoint tool catalog

The catalog exposes approved, bounded endpoint diagnostics through the existing
management worker. It is not an unrestricted command launcher. Each request is
authorized for the current user and endpoint, bound to the active enrollment,
audited, limited by the worker budget and assigned an idempotent request ID.

Built-in health, connectivity, evidence and WxlfGar-readiness adapters require no
third-party installation. Optional tools are available only when an administrator
publishes a signed platform-specific manifest and package. Install, update and
remove actions require patch permission. Running a profile or checking readiness
requires management permission.

The interface describes what each tool does, when to use it, its expected output
and its endpoint impact. Every executable action also has an adjacent information
control. Those explanations are guidance only and never change authorization.
When opened from a case or linked security alert, the case identifier is fixed in
the tool form so the resulting job is audited and associated with that case.

## Safety boundaries

- Tool profiles accept only their documented, validated inputs.
- Connectivity and Nmap profiles use explicit destinations; Nmap accepts at most
  16 ports on one private IP.
- YARA-X reads the selected path but does not quarantine or delete files.
- Sysinternals trust inspection is offline and does not check certificate
  revocation.
- iperf2 generates bounded client traffic and never starts a listener.
- Results can contain sensitive operational context. Review them before retaining
  them as case evidence; credentials remain in Access & secrets.
- A lost or ambiguous response is retried with the original request ID. Operators
  must not create a new request until the earlier outcome is known.

See [management-operations.md](management-operations.md) for worker identity,
leases, packages, receipt protection and recovery behavior.
