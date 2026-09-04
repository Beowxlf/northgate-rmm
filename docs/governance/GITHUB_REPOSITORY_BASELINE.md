# GitHub Repository Security Baseline

The machine-readable desired state is `governance/github-baseline.json`. The
repository is not considered established until live API evidence matches this
baseline or a plan-limited control is replaced by the documented local check.

## Identity and visibility

- owner: `Beowxlf`;
- repository: `northgate-rmm`;
- visibility: public under Apache License 2.0;
- default branch: `main`;
- issues enabled; projects and wiki disabled initially;
- no secrets, private endpoint data, or production infrastructure details.

## Merge policy

- squash merge only;
- delete merged branches;
- web commit sign-off required;
- no direct pushes to protected `main` after bootstrap;
- no force pushes or branch deletion;
- pull requests are mandatory;
- while `Beowxlf` is the only maintainer, external approval and CODEOWNERS review
  are not required because an author cannot approve their own pull request;
- when a second trusted maintainer is onboarded, require one approval and
  CODEOWNERS review before merge;
- stale approvals dismissed;
- all review conversations resolved;
- linear history;
- strict status checks require the pull-request branch to be current with
  `main`, forcing revocation validation to rerun when the protected base moves;
- administrators included where the account plan permits enforcement.

Required status checks after their first successful run:

- `Pre-code governance audit`;
- `Free-software security checks`;
- `Debian 12 systemd qualification`;
- `Release-candidate trust qualification`.

Initial repository creation and baseline push are the only bootstrap direct push.
The bootstrap exception ends when protection is verified.

## GitHub Actions

- default token permission is read-only;
- workflows cannot approve pull requests;
- external actions are restricted where account settings allow and are pinned to
  full commit SHAs in repository workflows;
- no `pull_request_target` workflow;
- no untrusted code runs with write-capable tokens;
- automatic dependency caching is disabled for privileged workflows;
- scheduled security scan remains enabled.

## Security features

- private vulnerability reporting enabled;
- Dependabot alerts and security updates enabled;
- dependency graph enabled if required by Dependabot;
- secret scanning and push protection enabled if available on the account plan;
- if unavailable for the private repository, Gitleaks history and directory scans
  remain blocking locally and in CI;
- CodeQL is not assumed available for a private repository; Semgrep Community
  Edition plus language-specific free checks provide the initial SAST baseline.

GitHub feature availability does not permit weakening the repository-controlled
checks. A plan limitation is recorded as evidence, not silently treated as pass.

## Verification evidence

After authentication and push, capture sanitized API results for:

1. repository visibility and merge settings;
2. Actions policy and default workflow permission;
3. repository visibility, vulnerability-reporting applicability, and Dependabot
   configuration;
4. branch protection or ruleset state;
5. workflow run conclusions for the exact baseline commit;
6. remote commit SHA matching the audited local commit.

The evidence is summarized in the pre-code audit. Tokens and raw sensitive account
metadata are never stored in the repository.

## Account-plan and maintainer constraints

GitHub documents that GitHub Free supports protected branches on public
repositories. The repository is public under the approved Apache-2.0 license so
the server-side rule must be verified before G1 opens. Local convention alone is
not branch protection.

The temporary single-maintainer review mode is not a waiver of required CI. It
exists to avoid an impossible self-review requirement. Onboarding a second trusted
maintainer automatically triggers a baseline change requiring one independent
approval and CODEOWNERS review.
