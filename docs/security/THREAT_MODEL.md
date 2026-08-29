# Threat Model

Status: Phase 0 baseline  
Method: asset, actor, trust-boundary, abuse-case, and control analysis  
Review trigger: every Class 2/3 change and each phase gate

## Security objectives

- only authenticated, authorized actors and endpoints participate;
- authorization binds exact actor, target, action/session, time, and policy;
- compromise is contained by separated identities and least privilege;
- observations, jobs, results, audit, and releases are attributable and tamper
  evident;
- failure produces bounded, honest state and recoverable operation;
- secrets and endpoint data are minimized and protected;
- emergency revocation does not depend solely on a suspected component.

## Assets

1. operator identities, sessions, approvals, and recovery factors;
2. endpoint private keys and certificates;
3. enrollment grants and revocation state;
4. release/update signing keys and provenance;
5. job intent, action definitions, results, and audit events;
6. endpoint inventory, health, logs, transcripts, and recordings;
7. control-plane and database service identities;
8. backup and recovery artifacts;
9. remote-session credentials, grants, tunnels, and gateway state;
10. source, dependencies, CI credentials, and build artifacts.

## Actors

- authorized operator;
- approver/security administrator;
- enrolled endpoint agent;
- compromised endpoint or cloned agent;
- malicious or compromised operator account;
- external unauthenticated attacker;
- compromised control-plane, gateway, worker, database, or CI component;
- dependency or build-system attacker;
- insider with repository, infrastructure, or backup access.

## Trust boundaries

- browser to operator API;
- agent to agent gateway;
- API/gateway/worker to database;
- service to audit pipeline;
- control plane to identity, PKI, secrets, and artifact services;
- build system to signing/release system;
- control plane to session gateway and credential broker;
- session gateway through tunnel to OS-native protocol;
- primary environment to backup/restore environment.

## Primary abuse cases and controls

| ID | Abuse case | Primary controls | Detection/recovery |
| --- | --- | --- | --- |
| TM-01 | Stolen operator session issues fleet action | phishing-resistant MFA, short session, RBAC, target scope, second approval, canary | behavior/audit alert, terminate sessions, revoke identity, cancel jobs |
| TM-02 | Enrollment token enrolls attacker endpoint | single-use short expiry, hashed storage, intended scope, rate limit | failed/reused-grant alert, revoke identity, invalidate grant family |
| TM-03 | Endpoint key is copied or VM cloned | OS key protection, device/boot signals, duplicate-session policy, rotation | identity anomaly, revoke and re-enroll, reconcile asset |
| TM-04 | Message replay or duplicate job execution | message IDs, sequence/session binding, expiry, action digest, idempotency class | duplicate/replay audit, quarantine identity, result reconciliation |
| TM-05 | Agent input enables root/system code execution | unprivileged core, typed handlers, strict schemas, no shell, helper isolation | SAST/fuzz/negative tests, revoke action, update/recover agent |
| TM-06 | Compromised server sends malicious update | separate offline signing, threshold roles, provenance, staged rings, downgrade defense | signature/metadata alerts, freeze rollout, revoke keys, recovery release |
| TM-07 | Database tampering rewrites history | least privilege, append audit, integrity checkpoints, backup separation | audit gap/integrity alert, isolate and restore, external evidence |
| TM-08 | Observations or outputs leak secrets | allowlisted collection, redaction, size limits, restricted access/retention | DLP/secret scans, delete/rotate under incident process |
| TM-09 | Reconnect storm exhausts gateway/database | jitter, backoff, rate limits, admission control, bounded queues | saturation metrics, shed load, scale/recover |
| TM-10 | Tenant/target confusion exposes another endpoint | opaque IDs, scope in every query, target digest, policy at each hop | isolation tests, audit alert, revoke session and investigate |
| TM-11 | Remote-session URL or grant is shared | single-use redemption, browser/operator binding, short expiry, no credential in URL | failed redemption alert, terminate/revoke grant |
| TM-12 | Session gateway pivots to arbitrary hosts/ports | isolated network, one-target tunnel, destination allowlist, no generic forwarding | flow/tunnel audit, emergency gateway isolation |
| TM-13 | Clipboard/file/device redirection exfiltrates data | disabled by default, independent authorization, size/type controls | session capability audit, terminate and investigate |
| TM-14 | Recording captures credentials/private data | explicit policy, user notice, restricted encryption/retention, secret redaction | access audit, incident deletion/rotation process |
| TM-15 | CI workflow executes untrusted code with write token | least permissions, SHA-pinned actions, no unsafe pull_request_target, environment approvals | workflow scan, token revoke, rebuild from trusted commit |
| TM-16 | Backup restores revoked identities or old trust | revocation-aware restore test, backup metadata, recovery reconciliation | post-restore invariant audit, keep service isolated until reconciled |

## Denial-of-service considerations

Every externally reachable operation has authentication where possible, request
and decompression limits, rate limits, bounded parsing, timeouts, backpressure, and
observable rejection. Endpoint spool and result output have hard quotas.

## Residual Phase 0 risks

- implementation does not yet exist, so controls are design requirements rather
  than verified behavior;
- selected identity provider, PKI, secrets service, and session gateway versions
  are not yet qualified;
- Linux desktop backend remains support-matrix dependent;
- independent penetration testing is deferred to the relevant operational gate.

These residual risks prevent operational deployment but do not prevent a simulated
Phase 1 after G1 authorization.
