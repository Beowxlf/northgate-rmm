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
6. Require both the publisher and repository to verify signatures, provenance,
   version, platform, policy, and both protected signing acknowledgements before
   publishing.
7. Require an independent protected audit acknowledgement before every
   authority-increasing signing, publication, rollout-start/advance, or resumption
   transition. Rollout start/advance/resume also requires a request-bound decision
   from a separate authorized approver and current signed health-gate evidence.
   Never block an emergency freeze, revocation, or pause because both audit sinks
   are unavailable; retain signed recovery-client evidence, raise incident
   severity, and reconcile it after recovery.
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
The separated metadata/status authority submits the sequence-free request core to
the external monotonic allocator, which adds the authority epoch and next
sequence and returns the completed acknowledgement-free status payload plus a
signed receipt bound to both digests. Z5/Z6, the status signer, and the repository
independently verify that receipt. The authority then verifies the pre-action
acknowledgement carried beside the payload and receipt in a separate envelope,
appends its signed result to Z5 or Z6, and obtains a result acknowledgement that
the repository verifies before activating any status. Neither acknowledgements
nor the receipt are included in the payload whose digest they bind. Only a
Z1-authorized higher-sequence freeze/revocation/pause may proceed when both
evidence sinks are unavailable, and
only after the external monotonic allocator durably records a signed pending
anchor bound to that restrictive payload and authorization. Authority-increasing
status remains disabled until the pending anchor is acknowledged by a restored
sink and reconciled.
An audit acknowledgement alone is not rollout authority. The publication
envelope carries the independently signed approval and exact current-ring or
pre-deployment health attestation beside the signed status. The status signer and
repository independently pin and verify those signatures, authorization roles,
separation of duties, scope, freshness, outcome, and the evidence digests bound
into the acknowledgement-free status payload before activation. The decision and
status payload also bind the same single-use correlation and exact predecessor
status digest. The signer and repository reject reuse, and the repository
atomically consumes both identifiers when it activates a transition.

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

The highest accepted release-status sequence lives in OS-protected,
rollback-resistant state outside the replaceable agent payload. It survives
restart, reinstall, and agent-version rollback. After VM/OS restore or any
missing, corrupt, or inconsistent sequence state, the agent must obtain a current
signed checkpoint plus the corresponding signed allocator receipt directly from
the separated status authority over mTLS. It pins both keys, verifies the exact
status digest, epoch, and sequence binding, and atomically raises its floor;
repository or authority data alone cannot reinitialize or lower it. Failure to
verify either object blocks installation.

The status authority allocates sequences through a non-rollbackable counter kept
outside its VM, operating-system image, database, and ordinary restore set. Each
allocation has a signed allocator receipt bound to the exact status-payload
digest and is independently verified by Z5/Z6, the repository, and checkpoint
consumers before being anchored in the protected Z5 sequence ledger or immutable
Z6 fallback. When both sinks are down, only a Z1-authorized restrictive transition
may use the allocator's append-only pending anchor, which must survive authority
restore and reconcile later. After authority restore, rollback, rebuild, counter
replacement, or uncertain state, general signing
remains disabled until a separate recovery process reconciles the allocator and
all available anchors, establishes their maximum as the floor, and proves the
next sequence is greater. When both anchors are unavailable, dual-controlled Z1
recovery may verify the allocator epoch, counter, continuity, and pending-anchor
chain and enable only higher-sequence freeze/revoke/pause signing. Every
authority-increasing, unfreeze, and install-authorizing checkpoint operation
remains disabled until a sink returns and reconciliation succeeds. Missing or
inconsistent allocator state fails even the restrictive mode closed. Replacing
the allocator requires dual control, a monotonically later authority epoch, and
protected linkage to the prior anchor; it is forbidden in restrictive-only mode.
The recovery identity has narrowly scoped read-only access to the allocator's
current counter/epoch and the exact Z5/Z6 sequence anchors; it cannot allocate,
reset, sign, release, restore, delete, alter, or read unrelated audit evidence.
Each download also requires the short-lived, single-use, endpoint-key and
artifact-bound authorization defined in the
[infrastructure flow](../architecture/INFRASTRUCTURE_AND_MICROSEGMENTATION.md#revocation-aware-update-download-and-installation).

## Key compromise

Update-root and release-key compromise procedures are mandatory before G6. The
control plane cannot simply tell agents to ignore signature failures.
