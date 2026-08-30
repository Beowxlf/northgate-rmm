# Deployment Architecture

## Environments

`development`, `test`, `lab-canary`, and future `production` are distinct trust
environments. They do not share endpoint CAs, signing keys, databases, secrets,
or privileged service identities.

## Phase 1 topology

- one private control-plane host;
- API/UI, gateway, and scheduler as separately invocable modules;
- PostgreSQL with authenticated backup;
- local test CA only;
- simulated agent in the same isolated test environment;
- central application logs, metrics, traces, and audit records;
- no public ingress and no managed endpoint command execution.

## Phase 2 lab-canary topology

- private reverse proxy or gateway listener;
- one disposable Linux canary on an approved lab segment;
- outbound-only agent path;
- firewall limited to required source/destination/port;
- administrative access through the approved NorthGate management path;
- recovery storage separated from the service data path.

## Future separation triggers

Split the modular monolith only when evidence shows a trust, availability, or
capacity requirement:

- agent gateway isolated from operator UI/API;
- scheduler workers scaled independently;
- dedicated broker introduced for measured queue needs;
- primary/standby database for approved availability objective;
- artifact service isolated from application credentials;
- offline or hardware-backed release signing.

## Network requirements

- deny by default;
- no database access from endpoint networks;
- no inbound agent management port on endpoints;
- operator and agent ingress have separate authentication and rate limits;
- internal service calls are authenticated when split across hosts;
- egress destinations are documented and minimized;
- certificate and DNS failure behavior is observable and fail-safe.

The authoritative trust-zone model, minimum flow policy, provisioning sequence,
and network acceptance evidence are defined in
[Infrastructure and Microsegmentation](INFRASTRUCTURE_AND_MICROSEGMENTATION.md).

## Secrets

Configuration references secrets supplied at runtime. Secrets are not embedded in
images, manifests, repositories, logs, or diagnostic bundles. See
[Cryptography and Keys](../security/CRYPTOGRAPHY_AND_KEYS.md).
