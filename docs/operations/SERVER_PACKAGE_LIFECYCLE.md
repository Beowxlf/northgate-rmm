# Server Package Lifecycle

## Scope and gate

The source-built `northgate-rmm-server` Debian package contains the three
private read-only control-plane services. It is a Debian 12 amd64 qualification
artifact, not a published release or deployment authorization. G2 remains
required for any NorthGate installation, identity, listener, database, or
network change, and G6 remains required for production signing or publication.

## Reproducible offline package

The build accepts one application wheel and an exact runtime wheelhouse. Every
runtime wheel filename and SHA-256 digest is committed, and extra, missing,
changed, or symlinked inputs fail the build. The package expands those wheels
under a root-owned application directory and uses an isolated CPython 3.11
launcher. Installation performs no package-index or network access.

The package is deliberately restricted to Debian 12's CPython 3.11 ABI. It
contains the agent-ingress, one-time enrollment, and operator-view services,
their disabled hardened systemd units, and non-secret example configurations.
It does not contain PostgreSQL, an issuer, an IdP, credentials, certificates,
live configuration, an endpoint agent, or an activation action.

## Installation and activation boundary

A fresh installation creates three distinct system identities:

- `northgate-rmm-agent`;
- `northgate-rmm-enrollment`; and
- `northgate-rmm-operator`.

The control-plane ingress unit is named `northgate-rmm-agent-ingress.service`,
so it cannot collide with the endpoint package's `northgate-rmm-agent.service`.
Each identity has one private state directory and no supplementary groups. Code
and configuration roots remain root-owned. All three units remain disabled and
must not be started until an exact G2 change supplies approved configuration,
credentials, TLS identities, database state, microsegmentation, validation, and
rollback.

Installation and package upgrade refuse to proceed while any same-named service
is active. This is an intentional no-automatic-update boundary: an authorized
operator must stop and validate the services before replacing code.

## Removal and purge

Removal refuses unless all services are inactive and root-controlled, nonempty
revocation and evidence-export receipts exist. Removal deletes code and units
but retains configuration, state, receipts, and the three identities for
recovery.

Purge additionally requires server-specific root-controlled approval and
evidence receipts. Before deleting retained server state, exact server
configuration and credentials, and service identities, it writes a durable
root-only transaction marker outside the deletion target. An interrupted purge
can resume only when that marker is exact; a malformed marker fails closed.
The marker is not silently erased by a later install: it must first be archived
and cleared through the approved evidence process.
The shared `/etc/northgate-rmm` directory and endpoint-agent configuration or
receipts are never recursively removed; the directory is deleted only when it
is empty after exact server-owned paths are removed.

## Isolated qualification

The protected security workflow builds the application wheel and Debian package
twice and requires byte identity. It downloads only the named hash-locked
CPython 3.11 Linux wheels, then installs the real endpoint-agent and server
packages together in a Debian 12 container with no network interface beyond
loopback. It verifies exact runtime versions and systemd units, imports every
service as its dedicated identity, proves configuration is not writable,
exercises receipt-gated removal and purge, confirms no server identity remains,
and proves the endpoint-agent package, unit, configuration, and receipts survive
approved server purge.
