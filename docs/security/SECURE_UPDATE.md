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
5. Authorize artifacts through separated update metadata/signing roles only after
   the signer validates an exact protected signing-intent acknowledgement.
6. Verify signatures, provenance, version, platform, policy, and both protected
   signing acknowledgements before publishing.
7. Require an independent protected audit acknowledgement before every
   authority-increasing signing, publication, rollout-start/advance, or resumption
   transition. Never block an emergency freeze, revocation, or pause because both
   audit sinks are unavailable; retain signed recovery-client evidence, raise
   incident severity, and reconcile it after recovery.
8. Roll out to development, test, canary, then approved broader rings.
9. Pause automatically on defined health or security failures.
10. Preserve a separately signature/digest-verified signed package, its metadata,
    trust material, and recovery procedure in the immutable Z6 recovery set.

The permitted hardware-backed service flow and the alternative offline exchange,
including request contents and evidence, are defined in the
[infrastructure signing handoff](../architecture/INFRASTRUCTURE_AND_MICROSEGMENTATION.md#separated-signing-handoff).
The normal Z5 acknowledgement, independently controlled Z6 fallback, fail-closed
behavior, and reconciliation requirement are defined in
[release-transition audit acknowledgement](../architecture/INFRASTRUCTURE_AND_MICROSEGMENTATION.md#release-transition-audit-acknowledgement).

## Agent behavior

The agent verifies trusted root/metadata chain, signatures, digest, length,
platform, architecture, version policy, expiry, rollout assignment, and disk
preconditions. Immediately before replacement it also retrieves and verifies the
current independently signed release-status object, whose exact artifact, ring,
sequence, and freeze/revocation state expire within 60 seconds. Missing, stale,
unavailable, replayed, rolled-back, frozen, or revoked status blocks installation
even when the package was downloaded earlier. Installation is atomic where
possible and leaves a recoverable prior version. A failed update does not erase
identity, revocation, or audit state.
Each download also requires the short-lived, single-use, endpoint-key and
artifact-bound authorization defined in the
[infrastructure flow](../architecture/INFRASTRUCTURE_AND_MICROSEGMENTATION.md#revocation-aware-update-download-and-installation).

## Key compromise

Update-root and release-key compromise procedures are mandatory before G6. The
control plane cannot simply tell agents to ignore signature failures.
