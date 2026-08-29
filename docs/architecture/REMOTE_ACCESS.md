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
  C->>G: Create expiring one-target session grant
  C->>A: Request expiring reverse tunnel
  A->>A: Validate grant, target, protocol, policy
  A->>G: Establish outbound encrypted tunnel
  O->>G: Redeem single-use browser session
  G->>B: Request exact-session JIT credential
  B->>I: Issue exact actor/endpoint/protocol credential
  I-->>B: Credential plus opaque revocation handle
  B->>E: Append issuance metadata and revocation handle
  alt Immutable append confirmed
    E-->>B: Append receipt
    B-->>G: Deliver JIT credential
  else Append unavailable or rejected
    E--xB: No valid append receipt
    B->>I: Compensating revoke by opaque handle
    I-->>B: Signed revocation result
    B->>X: Signed handle/session/cleanup-state alert
    B--xG: Credential withheld
  end
  G->>P: Connect through tunnel with JIT credential
  G-->>C: Start, activity, termination events
  C-->>O: Authorized interactive session
  C->>G: Force termination on expiry/revocation
```

## Trust separation

- human identity provider authenticates the operator;
- RMM policy decides whether the actor may request and approve a session;
- session gateway handles interactive protocol translation;
- tunnel broker limits connectivity to one endpoint, protocol, port, and expiry;
- credential broker issues or retrieves a just-in-time credential without exposing
  it to the browser;
- endpoint agent authorizes only the tunnel capability, not arbitrary local
  socket forwarding;
- audit service records lifecycle metadata independently of the gateway.

## Session authorization

Every session grant binds:

- operator and approver identities;
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
credential issuer, and an opaque non-secret credential/revocation identifier.
The broker must append the issuance metadata and identifier to protected Z5
evidence before releasing credential material to the gateway. Failure to confirm
that append fails session establishment closed. The broker retains the non-secret
handle, performs compensating revocation, and verifies the authority's revocation
receipt before discarding the handle. If cleanup cannot be confirmed, it sends a
signed, bounded alert containing issuer, handle, session/grant, and cleanup state
directly to the approved independent incident destination; the alert contains no
credential secret. It also retains a host-protected pending-revocation record for
retry and operator reconciliation.

Screen recording and terminal transcription are not universally enabled. The
project must decide retention, access, notification, redaction, and legal/privacy
requirements before activation. Sensitive fields and credentials must never be
recorded intentionally.

## Failure and containment

- gateway, agent, or control-plane loss closes or expires the tunnel;
- revoking operator, endpoint, or session terminates active access;
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
