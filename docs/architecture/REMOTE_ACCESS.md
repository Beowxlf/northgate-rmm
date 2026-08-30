# Cross-Platform Remote Access Architecture

## Required outcome

Authorized operators can open interactive sessions to supported Windows and Linux
endpoints without exposing endpoint management ports to operator networks, sharing
durable endpoint passwords, or turning the core RMM agent into an unrestricted
remote-control channel.

## Chosen pattern

Use an isolated browser-accessible session gateway based on Apache Guacamole or an
equivalently reviewed free-software gateway. It brokers established OS-native
protocols:

- Windows desktop: RDP;
- Linux terminal: SSH;
- Linux desktop: qualified RDP, VNC, or Wayland-native service;
- Windows terminal: OpenSSH or a separately approved constrained PowerShell path.

The RMM control plane authorizes sessions but does not proxy desktop pixels or
terminal streams itself.

```mermaid
sequenceDiagram
  participant O as Operator browser
  participant C as RMM control plane
  participant G as Session gateway
  participant B as Credential broker
  participant I as OS identity authority
  participant E as Protected session evidence (Z5)
  participant X as Independent incident destination
  participant A as Endpoint agent/tunnel
  participant P as OS-native protocol
  O->>C: Request session to exact endpoint
  C->>C: Authenticate, authorize, approve, audit
  C->>G: Grant binds exact IdP tuple, actor, target, protocol, expiry
  C->>A: Request expiring reverse tunnel
  A->>A: Validate grant, target, protocol, policy
  A->>G: Establish outbound encrypted tunnel
  O->>G: Redeem single-use browser session
  G->>B: Request exact-session JIT credential
  B->>I: Signed grant for exact IdP tuple/actor/endpoint/protocol
  I->>E: Append signed issuance receipt and opaque handle
  alt Authority receipt confirmed
    E-->>I: Immutable append receipt
    I-->>B: Credential plus opaque revocation handle
    B->>E: Append broker delivery event linked to authority receipt
  else Authority receipt unavailable or rejected
    E--xI: No valid append receipt
    I--xB: No credential issued
  end
  alt Broker delivery event confirmed
    E-->>B: Immutable append receipt
    B-->>G: Deliver JIT credential plus non-secret opaque handle
  else Broker delivery event unavailable or rejected
    E--xB: No valid delivery receipt
    B->>I: Compensating revoke by opaque handle
    I-->>B: Signed revocation result
    B->>X: Signed handle/session/cleanup-state alert
    B--xG: Credential withheld
  end
  G->>P: Connect through tunnel with JIT credential
  G-->>C: Start, activity, termination events
  C-->>O: Authorized interactive session
  C->>G: Force termination on expiry/revocation
  G->>B: Revoke exact session/grant/opaque handle
```

## Trust separation

- human identity provider authenticates the operator;
- RMM policy decides whether the actor may request and approve a session;
- session gateway handles interactive protocol translation;
- tunnel broker limits connectivity to one endpoint, protocol, port, and expiry;
- credential broker issues or retrieves a just-in-time credential without exposing
  it to the browser and may revoke only that session-issued credential by its
  returned opaque handle;
- OS identity authority retains a signed exact-session/grant-to-handle mapping so
  the independent recovery identity can retrieve one handle when Z5 is
  unavailable or untrusted, without listing or inspecting credentials;
- endpoint agent authorizes only the tunnel capability, not arbitrary local
  socket forwarding;
- audit service records lifecycle metadata independently of the gateway.

## Session authorization

Every session grant binds:

- operator and approver identities;
- operator IdP issuer/tenant and exact subject, session, and client identifiers;
- endpoint cryptographic ID;
- protocol and local destination;
- allowed capabilities;
- creation, not-before, idle timeout, absolute expiry;
- reason/ticket;
- source administrative zone;
- recording/transcript policy;
- immutable policy and request digests;
- single-use redemption and revocation ID.

Authorization is rechecked at request, approval, tunnel establishment, browser
redemption, and reconnect. An open UI page is not authorization to reconnect.
Z2 cannot issue the grant until protected Z5 evidence acknowledges the signed IdP
tuple, RMM session correlation, and non-secret opaque revocation handle. Z8
revalidates the exact tuple carried by the grant directly with the IdP at least
every 60 seconds during an active session. Revoked, unknown, unavailable, or
stale status closes the browser stream and endpoint tunnel and starts exact
JIT-credential revocation without waiting for Z2.

## Default-denied capabilities

- clipboard synchronization;
- file upload/download;
- drive, printer, smart-card, USB, camera, microphone, and audio redirection;
- credential saving;
- concurrent viewers;
- unattended persistent tunnels;
- arbitrary destination/port forwarding;
- session sharing by URL.

Each future capability requires a separate threat-model and policy decision.

## Credentials

Preferred order:

1. short-lived SSH certificates for terminal access;
2. short-lived or just-in-time OS account credentials held only by a credential
   broker and gateway;
3. no shared administrator passwords stored in the RMM database;
4. no credential material delivered to browser JavaScript or session recordings.

Credential issuance and revocation are separate from endpoint enrollment keys.
The broker's workload identity cannot enumerate or inspect credentials, revoke a
credential from another session/grant, or change OS identity policy. The OS
identity authority enforces the exact session/grant/opaque-handle binding.
The gateway may trigger broker revocation only for its exact active session,
grant, and opaque handle. The broker rejects a missing or cross-session binding.
Every credential profile must enforce revocation at the endpoint through online
authority validation or the signed, monotonically versioned KRL/status mechanism
defined in the
[infrastructure specification](INFRASTRUCTURE_AND_MICROSEGMENTATION.md#jit-credential-revocation-propagation).
A profile that relies only on credential expiry is not eligible for G7.

## Linux desktop variability

Linux does not provide one universal desktop protocol. Support is declared per
distribution, display stack, desktop environment, and selected backend. Headless
Linux can be terminal-only. Wayland security behavior, session ownership, display
manager integration, and user consent require explicit qualification.

## Session evidence and privacy

Always record metadata: requester, approver, endpoint, protocol, source zone,
start/end, termination reason, policy, gateway/tunnel IDs, capability flags,
credential issuer, the signed IdP issuer/tenant/subject/session/client binding,
and opaque non-secret IdP and JIT credential revocation identifiers.
The OS identity authority validates the signed session grant and appends its own
signed issuance receipt and identifier directly to protected Z5 evidence before
returning credential material or the handle to Z8. The broker then appends a
separate delivery event linked to the authority receipt before releasing the
credential to the gateway. Failure of either append fails session establishment
closed, so a compromised broker cannot be the sole source of the recovery handle.
Before returning any credential or handle, the authority also durably and
atomically retains the signed, non-secret exact session/grant, issuer, opaque
handle, status, and expiry mapping for bounded recovery retention. If Z5 is
unavailable or untrusted, a case-scoped independent MFA identity may retrieve
only that exact session/grant's issuer and handle directly from the authority;
listing, wildcard/time-range queries, credential inspection, issuance, renewal,
and policy change remain denied.

If the broker delivery append fails after issuance, the broker retains the
non-secret handle, performs compensating revocation, and verifies the authority's
revocation receipt before discarding the handle. If cleanup cannot be confirmed,
it sends a signed, bounded alert containing issuer, handle, session/grant, and
cleanup state directly to the approved independent incident destination; the
alert contains no credential secret. It also retains a host-protected
pending-revocation record for retry and operator reconciliation.

Independent emergency termination does not rely on the Z8-to-Z2 lifecycle path.
The Z1 recovery client appends signed intent and observed/result evidence to the
protected Z5 recovery-audit intake before and after the action. If Z5 is
unavailable, suspected, or otherwise untrusted, the client instead writes the
same signed bundle to the independent immutable Z6 evidence intake and requires
that trusted intake's acknowledgement. A responsive but untrusted Z5
acknowledgement is not sufficient. The gateway sends its signed termination event
directly to protected Z5 session evidence when that route is available; when Z5
is untrusted, the Z1 bundle carried to Z6 includes the gateway-claimed result and
the independently observed teardown so the evidence preserves their distinction.

Screen recording and terminal transcription are not universally enabled. The
project must decide retention, access, notification, redaction, and legal/privacy
requirements before activation. Sensitive fields and credentials must never be
recorded intentionally.

## Failure and containment

- gateway, agent, or control-plane loss closes or expires the tunnel;
- revoking an endpoint identity pairs issuer revocation with independent Z8
  termination of every session bound to that identity, or endpoint-facing PEP
  isolation when Z8 is unavailable or suspected;
- revoking an operator or session terminates active access;
- session gateway has no standing network route to arbitrary endpoints;
- tunnel allowlist prevents loopback/service pivoting beyond the approved target;
- reconnect requires a current authorization decision;
- failed Z5 issuance evidence triggers verified compensating credential
  revocation; unconfirmed cleanup produces an independent incident alert and a
  retained pending-revocation record;
- emergency stop terminates all sessions without relying on the compromised
  component under investigation;
- recordings and session logs are protected as sensitive evidence.

## Implementation gate

Remote access begins only in Phase 7 after monitoring, identity, audit, typed-job,
packaging, update, and recovery foundations pass their prior gates. This document
defines a required destination, not authorization to deploy remote sessions now.
