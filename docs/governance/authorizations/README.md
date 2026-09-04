# Authorization Records

Records in this directory authorize a bounded phase transition. Templates are not
authorization. A valid record names the gate, exact commit, evidence, approver,
date, scope, expiration or supersession condition, and unresolved accepted risks.

Every G2 through G8 opening uses a gate-prefixed record based on the
[product-gate authorization template](../templates/PRODUCT-GATE-AUTHORIZATION-TEMPLATE.md).
An open gate without its own exact active record fails governance validation;
another gate's authorization cannot be reused.
Operational consumers must refresh `origin/main`, use the exact clean
protected-main checkout, and revalidate the active time window and every bound
record immediately before acting.

`PUB-001-PUBLIC-REPOSITORY.md` records the separately approved licensing and
public-repository transition. `G1-PRODUCT-CODING.md` authorizes only the bounded
Phase 1 simulation and development scope named in that record.

`P2-LINUX-AGENT-SOURCE-DEVELOPMENT.md` authorizes reviewable Phase 2 Linux-agent
source and hermetic packaging-test work only. It does not open G2, authorize
installation on any endpoint or VM, or approve any VM Factory or infrastructure
decision.

`P2-CONTROL-PLANE-SOURCE-DEVELOPMENT.md` authorizes the isolated, synthetic
version 1.0 service, enrollment, persistence, and operator-view source work. It
does not authorize a live listener, identity, database, deployment, release, or
Factory action.
