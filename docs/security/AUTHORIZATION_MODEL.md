# Authorization Model

## Subjects

- human operator;
- approver;
- service workload;
- endpoint identity;
- release signer;
- session gateway;
- recovery operator.

## Resources

Endpoint, observation, finding, job, action, approval, audit event, policy,
artifact, update ring, remote session, tunnel, recording, and secret reference.

## Decision inputs

Authorization evaluates:

- authenticated subject and assurance level;
- role and explicit scope;
- exact resource IDs and tenant/administrative zone;
- requested operation and immutable parameter digest;
- active phase/gate and feature flag;
- target lifecycle and revocation state;
- maintenance window, canary ring, and concurrency;
- risk/action class and required independent approval;
- source network/device context where supported;
- request time, not-before, expiry, and policy version.

## Roles

- **Viewer:** read approved endpoint state and non-sensitive evidence.
- **Operator:** request low-risk read-only actions within assigned scope.
- **Approver:** independently approve policy-designated actions; cannot approve
  their own high-risk request.
- **Security administrator:** manage identities, revocation, security policy, and
  incident containment.
- **Release manager:** authorize signed releases and rollout rings; no ordinary
  endpoint-operation authority by implication.
- **Auditor:** read/export protected audit evidence without operational authority.
- **Recovery operator:** perform isolated restore and reconciliation under a
  recovery authorization.

## Separation rules

- request and approval identities differ for high-risk actions;
- release signing differs from code author and online deployment identity;
- audit storage writer differs from ordinary audit reader/exporter;
- remote credential broker differs from session requester;
- break-glass use requires strong authentication, reason, short expiry, immediate
  alert, and retrospective review.

## Enforcement points

API request, approval creation, scheduler claim, agent dispatch, agent acceptance,
result ingestion, artifact access, session grant, tunnel creation, gateway
redemption, reconnect, update selection, and audit export.

Z2 revalidates the current IdP subject, session, and client on every privileged
request with no more than a 60-second positive cache. During G7, Z8 performs the
same check directly with the IdP at least every 60 seconds. Revoked, unknown,
unavailable, or stale status terminates browser/API authority, the remote stream
and tunnel, and the associated JIT credential without waiting for Z2.

## Denials

Denials are structured and audited without revealing secrets or cross-scope
resource existence. Policy failures do not fall back to a more permissive mode.
