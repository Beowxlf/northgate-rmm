# Contributing

## Before changing the repository

1. Read `PROJECT_CHARTER.md`, `GOVERNANCE.md`, and the active phase gate.
2. Open or reference an issue describing the user outcome and authority change.
3. For security-significant changes, create or update an ADR and threat model.
4. Never place real credentials, endpoint data, or private infrastructure details
   in examples, tests, issues, commits, or CI logs.

## Local checks

Run:

```powershell
npm ci
npm run audit:pre-code
```

After the coding gate is authorized, also run the checks documented in
`docs/governance/REQUIRED_CHECKS.md` for the active phase.

## Pull requests

Use the pull request template. Keep changes focused. Explain failures honestly;
do not suppress a scanner or weaken a test merely to obtain a green check.

## Commit messages

Use an imperative summary and include the governing issue or decision when one
exists. Never include secrets in a commit message.
