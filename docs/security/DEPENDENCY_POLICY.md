# Dependency and Supply-Chain Policy

## Selection

Prefer standard-library or focused maintained dependencies with clear license,
security policy, release history, minimal transitive graph, and compatible
platform support. A dependency that handles identity, cryptography, parsing,
serialization, database access, updates, or remote sessions receives explicit
review.

## Locking and provenance

- commit lockfiles;
- pin direct production dependencies to compatible controlled ranges and resolve
  exact versions in lockfiles;
- pin GitHub Actions to full commit SHAs with version comments;
- verify downloaded release checksums/signatures/provenance when available;
- generate SBOMs for releases;
- record license and source for distributed components.

## Continuous review

Dependabot proposes updates. OSV-Scanner plus language-native audits identify known
vulnerabilities. Semgrep/SAST and tests assess code use. High/critical findings are
triaged for reachability and remain blocking until remediated or formally excepted.

## Update policy

Security updates are prioritized and tested through the active phase gate.
Automated dependency PRs do not bypass review, compatibility, threat-model, or
release requirements. Abandoned critical dependencies trigger replacement or
feature containment.

## Licenses

The repository is public under Apache-2.0. A dependency license scan and
third-party notice update are required before merge, and the exact release
artifact receives a fresh compatibility and notice review before distribution.
“Source available” is not assumed to mean redistributable.
