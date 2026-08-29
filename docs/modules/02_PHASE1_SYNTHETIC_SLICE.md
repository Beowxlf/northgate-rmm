# Module 2 — The Synthetic Trust Slice

## Mission

Understand the smallest useful RMM data path without installing software on a
real Windows or Linux endpoint:

1. create a synthetic endpoint and identity;
2. construct typed heartbeat or inventory messages;
3. bind each message to the authenticated identity;
4. reject expiry, replay, mismatched target, and revoked identity failures;
5. derive online, stale, and offline state from server receipt time; and
6. preserve accepted and rejected decisions in append-only audit history.

The implementation lives in `src/northgate_rmm/`. It is a domain simulator, not
an endpoint agent or deployable service.

## Why this answers an RMM problem

An RMM console has to distinguish four ideas that are often blurred together:

- **identity:** which enrolled endpoint is speaking;
- **observation:** what that endpoint reported;
- **freshness:** when the control plane actually received a heartbeat; and
- **authorization:** whether the identity was still allowed to communicate.

If those ideas are merged, a renamed host can look like a new endpoint, a replay
can look like current health, an incorrect endpoint field can redirect data, or a
restored credential can silently undo revocation.

## Code map

### `domain.py`

Defines bounded, immutable values:

- Windows and Linux platform identifiers;
- endpoint and identity records;
- protocol envelopes;
- heartbeat and inventory payloads;
- accepted observations;
- lifecycle and communication-health status; and
- audit events.

Timestamp values must be timezone-aware. Message lifetimes, field counts, string
sizes, protocol versions, and sequences are bounded before ingestion.

### `simulator.py`

Produces Windows or Linux fixtures without reading the host operating system. It
does not open a socket, collect actual inventory, install a service, execute a
command, or hold a real private key. A synthetic boot ID and monotonic sequence
let tests model restarts and replays safely.

### `control_plane.py`

Treats the supplied authenticated identity as the transport identity. The
endpoint ID inside a message is checked against that binding and is never trusted
by itself. Accepted messages reserve their message ID and sequence, become
append-only observations, and create correlated audit evidence.

Revocation is immediate and idempotent. Communication health remains separate
from lifecycle: an endpoint can have a recent heartbeat while its identity is
already revoked.

## Freshness example

With the default policy:

| Age since trusted receipt | Derived health |
| ------------------------- | -------------- |
| no heartbeat              | `offline`      |
| 0–90 seconds              | `online`       |
| over 90 seconds–5 minutes | `stale`        |
| over 5 minutes            | `offline`      |

Endpoint-provided time is retained as source time, but server receipt time drives
freshness. This prevents a bad endpoint clock from claiming current health.

## Run the evidence

From the repository root with the development requirements installed:

```powershell
python -m pip install --requirement requirements-dev.txt
ruff format --check src tests
ruff check src tests
mypy src tests
pytest --cov=northgate_rmm --cov-branch --cov-fail-under=90
bandit --recursive src --severity-level medium
```

The negative tests are as important as the success test. Read
`tests/test_control_plane.py` and explain why each rejection must fail closed.

## Gate boundary

G1 permits this local simulation. It does not authorize a web listener, real
certificate authority, database deployment, endpoint installation, OS inventory
collector, command execution, remote shell, desktop control, or production
service. Those require later evidence and gates.

## Completion check

You understand this module when you can answer:

1. Why does transport identity override the endpoint ID in the payload?
2. Why are message ID replay and sequence replay separate checks?
3. Why does inventory receipt not make an endpoint online?
4. Why are lifecycle and communication health separate?
5. What evidence remains after a rejected message?
