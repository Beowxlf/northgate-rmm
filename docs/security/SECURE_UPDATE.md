# Secure Agent Update Design

Updates are deferred until Phase 6 but designed now because the updater can
replace a privileged fleet component.

## Threats

- malicious artifact;
- repository or online signing compromise;
- rollback to a vulnerable version;
- indefinite freeze on an old version;
- metadata/artifact mix-and-match;
- wrong platform or architecture;
- partial install, power loss, or incompatible schema;
- canary health misinterpretation;
- compromised CI provenance.

## Release flow

1. Build from a reviewed immutable source commit in an isolated workflow.
2. Run required tests and scans.
3. Generate SBOM and provenance.
4. Produce platform-specific signed packages.
5. Authorize artifacts through separated update metadata/signing roles.
6. Verify signatures, provenance, version, platform, and policy before publishing.
7. Roll out to development, test, canary, then approved broader rings.
8. Pause automatically on defined health or security failures.
9. Preserve a separately verified recovery artifact and procedure.

## Agent behavior

The agent verifies trusted root/metadata chain, signatures, digest, length,
platform, architecture, version policy, expiry, rollout assignment, and disk
preconditions. Installation is atomic where possible and leaves a recoverable
prior version. A failed update does not erase identity, revocation, or audit state.

## Key compromise

Update-root and release-key compromise procedures are mandatory before G6. The
control plane cannot simply tell agents to ignore signature failures.
