# PUB-001 Authorization — Public Repository

Status: Authorized  
Date: 2026-08-29  
Approver: Project owner (`Beowxlf`)  
Source: Explicit instruction to approve licensing and make the repository public

## Scope

Publish `Beowxlf/northgate-rmm` under Apache License 2.0, enable public security
features, and enforce protected `main` using GitHub Free.

## Conditions

- publish no secrets, credentials, private endpoint data, or internal
  infrastructure details;
- retain `LICENSE`, `NOTICE`, security reporting, and dependency-license review;
- require pull requests and both mandatory CI checks on `main`;
- prohibit force pushes and branch deletion;
- enforce the rule for administrators; and
- keep product and operational capabilities behind their existing gates.

## Evidence

- licensed baseline commit: `f426a7a1fc9108145de1d1456e6cdc4cd175fa2a`;
- governance workflow run: `33262548272`;
- security workflow run: `33262548264`;
- live GitHub API verification of visibility, license recognition, security
  features, Actions restrictions, and branch protection.

## Supersession

This authorization is superseded by repository privatization, relicensing, an
ownership change, or a later public-release authorization with a different
scope.
