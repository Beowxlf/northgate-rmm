# Modern workspace

The modern workspace brings inventory, device tools, policies, jobs and alert
review into one operator interface. This public overview describes product
capabilities; it is not evidence that a particular installation is deployed,
configured or accepted.

## Implemented capability

- Inventory search, grouping, filtering and saved views
- Device workspaces for supported management and diagnostic tools
- Policy previews, scheduled work, canary review and job outcomes
- Monitoring, alert review, baseline comparison and evidence export
- IT/SOC operations records and links to related device work
- Responsive navigation, loading states and accurate refresh indicators

Feature availability depends on the authorized operator, endpoint capabilities
and the actual installation. Unsupported or unavailable operations must remain
explicit; the interface must not imply a successful action from a request alone.

## Access configuration

An installation needs its own reviewed access configuration. Authentication and
authorization must be verified independently of interface visibility. Keep
installation-specific identities, grants and configuration in private operational
records. This overview does not provide a ready-to-deploy access template.

## Execution and recovery semantics

Operators review proposed targets and changes before starting work. Job status
must distinguish pending, completed, failed and uncertain outcomes. Cancellation
cannot undo changes that already completed. Recovery and rollback require their
own tested procedures and evidence.

## Routes and future deployment integration

Integration and deployment require review against the exact selected release.
Do not infer compatibility or operational readiness from screenshots, unit tests
or a package build. Installation-specific routes and deployment instructions are
omitted from this public overview.

## SIEM event export

The product includes an event-export capability. Qualify the destination,
permissions, record selection and failure recovery before using an export in an
operational workflow. Public examples must contain only synthetic data.

## Explicit qualification limits

This documentation makes no fleet-capacity, availability, regulatory-compliance
or production-readiness claim. Platform support, accessibility, performance and
recovery must be established in the intended environment. Private operational
architecture, capacity limits and recovery procedures are intentionally omitted.

## Next testing phase

1. Run the required repository tests and security checks against the exact commit
2. Exercise authorized and denied requests with synthetic test identities
3. Review browser navigation, stale-state handling and representative workflows
4. Test interruption, cancellation and recovery in isolated test environments
5. Record interactive and deployment acceptance separately from unit-test results

See the [historical workspace review](audits/MODERN_WORKSPACE_REVIEW_2026-09-09.md)
and [current PR verification](audits/PR36_VERIFICATION_2026-10-01.md) for the
boundaries of recorded engineering evidence.
