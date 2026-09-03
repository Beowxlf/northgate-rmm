# G2B Release-Candidate Trust Qualification

Status: Implemented; exact CI evidence pending  
Parent gate: G2 remains closed  
Scope: Non-published Debian release candidate with test-only signing

## Purpose

G2B proves that a release candidate can bind its exact Debian package, SPDX
SBOM, SLSA provenance, source commit, build invocation, version, architecture,
and non-deployment boundary into a signed manifest. It qualifies the evidence
format and verifier before any production signing key or package repository is
introduced.

## Required evidence

- Two package builds from the exact source commit are byte-identical.
- Syft and Cosign binaries are version-pinned and checksum-verified before use.
- The SPDX 2.3 SBOM identifies the package name and version and is digest-bound
  by the release manifest.
- The SLSA provenance statement binds the package digest, source commit, build
  type, invocation, version, architecture, and source date epoch.
- Cosign verifies the manifest with a public key whose digest is itself bound
  by the manifest.
- The verifier checks an exact file set, safe filenames, package metadata,
  hashes, sizes, source identity, build identity, SBOM semantics, and provenance
  semantics.
- Package, manifest, SBOM, provenance, private-key escape, and wrong-source
  negative tests all fail closed.
- Ephemeral private signing material is destroyed and never uploaded or
  committed.

## Implementation

The `G2B release-candidate trust qualification` workflow creates the package and
evidence on a disposable GitHub-hosted runner. It uses an ephemeral,
password-protected Cosign key only to qualify signing and verification behavior.
Transparency-log upload is disabled, and the workflow has read-only repository
permission and no artifact-upload or release-publication step.

Cosign verification supplies the exact local public key and uses
`--insecure-ignore-tlog` because the test signature is intentionally prohibited
from entering a public log. This bypasses only log-inclusion verification; the
detached signature and signed manifest digest remain mandatory. That flag is not
an accepted production-signing profile.

The candidate manifest explicitly records `publicationAuthorized: false`,
`deploymentAuthorized: false`, and the `test-only-ephemeral` signing profile.
The candidate directory is deleted with the runner.

## Closure rule

G2B is complete only when the exact reviewed pull-request head passes:

1. `Release-candidate trust qualification`;
2. `Debian 12 systemd qualification`;
3. `Free-software security checks`; and
4. `Pre-code governance audit`.

The final evidence record must name the exact head, workflow run and job IDs,
artifact and evidence hashes, negative-test results, review disposition, and
merge commit.

## Explicit exclusions

G2 and G6 remain closed. G2B does not create or authorize a production signing
key, GitHub release, package repository, transparency-log entry, trusted update
root, live endpoint identity, NorthGate VM or network change, agent installation,
update rollout, or VM Factory apply.
