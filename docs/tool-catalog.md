# Optional tools and bounded diagnostics

The optional catalog presents approved diagnostic and evidence tools alongside
existing management capabilities. Catalog availability is not approval to install,
run or redistribute a third-party tool on an arbitrary device.

## Server composition

Integrations require a reviewed release and an approved deployment design.
Installation-specific API wiring, authorization configuration and operational
architecture are omitted from this public overview.

## Packaging and licensing

Review upstream authenticity, licensing, intended use and redistribution rights
before approving a package. Do not include private configuration or credentials
in a distributable payload. A catalog listing does not substitute for vendor
license review or qualification of the actual selected binaries.

Useful upstream references include the [YARA-X CLI](https://virustotal.github.io/yara-x/docs/cli/commands/),
[Velociraptor offline collection guidance](https://docs.velociraptor.app/docs/deployment/offline_collections/running/),
and Microsoft's [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
and [Sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck)
documentation.

## Supported recipes and exact qualification boundary

The product supports categories such as health and connectivity checks,
configuration inspection, artifact collection and approved third-party analysis.
Platform, version and prerequisite compatibility must be tested for the exact
selected package. Missing capabilities and failed checks remain explicit; they
are not clean security findings.

## Resource and concurrency model

Diagnostic jobs need bounded execution and clear interruption behavior. Qualify
resource usage, competing work and child-process cleanup in the intended test
environment. Resource controls are not proof of containment against a malicious
privileged executable. Private execution configuration and operational capacity
limits are omitted here.

## Evidence and resumable transfer

Evidence collection and transfer require authorization, integrity verification
and appropriate retention. Verify resumed and interrupted transfers before
claiming completeness. Review content and recipients before exporting or
publishing collected material; never assume an artifact is safe to share merely
because collection succeeded.

## Validation required before deployment

Use synthetic test inputs and isolated devices to qualify installation,
authorization denial, interruption, cancellation, upgrade compatibility, evidence
transfer and resource impact. Unit tests and supported recipe code do not prove
that every upstream package has been live-qualified.

See the [PR verification record](audits/PR36_VERIFICATION_2026-10-01.md) for recorded
engineering checks and remaining review requirements.
