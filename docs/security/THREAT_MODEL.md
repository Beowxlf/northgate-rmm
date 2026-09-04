# Threat Model

Status: Phase 2 source-development review  
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
11. network policy, policy-enforcement configuration, and segmentation evidence;
12. protected audit archive, integrity checkpoints, and independent export state;
13. recovery identities and emergency revocation credentials.

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
- each Z0-Z9 logical zone to every other zone and external dependency;
- audit writer to protected audit archive and archive to recovery storage;
- recovery operator to PKI, firewall/policy enforcement, artifact, audit, and
  session emergency interfaces.

## Primary abuse cases and controls

| ID    | Abuse case                                                        | Primary controls                                                                                                                 | Detection/recovery                                                                                            |
| ----- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| TM-01 | Stolen operator session issues fleet action                       | phishing-resistant MFA, short session, RBAC, target scope, second approval, canary                                               | behavior/audit alert, terminate sessions, revoke identity, cancel jobs                                        |
| TM-02 | Enrollment token enrolls attacker endpoint                        | single-use short expiry, hashed storage, intended scope, rate limit                                                              | failed/reused-grant alert, revoke identity, invalidate grant family                                           |
| TM-03 | Endpoint key is copied or VM cloned                               | OS key protection, device/boot signals, duplicate-session policy, rotation                                                       | identity anomaly, revoke and re-enroll, reconcile asset                                                       |
| TM-04 | Message replay or duplicate job execution                         | message IDs, sequence/session binding, expiry, action digest, idempotency class                                                  | duplicate/replay audit, quarantine identity, result reconciliation                                            |
| TM-05 | Agent input enables root/system code execution                    | unprivileged core, typed handlers, strict schemas, no shell, helper isolation                                                    | SAST/fuzz/negative tests, revoke action, update/recover agent                                                 |
| TM-06 | Compromised server sends malicious update                         | separate offline signing, threshold roles, provenance, staged rings, downgrade defense                                           | signature/metadata alerts, freeze rollout, revoke keys, recovery release                                      |
| TM-07 | Database tampering rewrites history                               | least privilege, append audit, integrity checkpoints, backup separation                                                          | audit gap/integrity alert, isolate and restore, external evidence                                             |
| TM-08 | Observations or outputs leak secrets                              | allowlisted collection, redaction, size limits, restricted access/retention                                                      | DLP/secret scans, delete/rotate under incident process                                                        |
| TM-09 | Reconnect storm exhausts gateway/database                         | jitter, backoff, rate limits, admission control, bounded queues                                                                  | saturation metrics, shed load, scale/recover                                                                  |
| TM-10 | Tenant/target confusion exposes another endpoint                  | opaque IDs, scope in every query, target digest, policy at each hop                                                              | isolation tests, audit alert, revoke session and investigate                                                  |
| TM-11 | Remote-session URL or grant is shared                             | single-use redemption, browser/operator binding, short expiry, no credential in URL                                              | failed redemption alert, terminate/revoke grant                                                               |
| TM-12 | Session gateway pivots to arbitrary hosts/ports                   | isolated network, one-target tunnel, independent endpoint-facing PEP, no generic forwarding                                      | isolate PEP, verify tunnel teardown independently, revoke JIT credential                                      |
| TM-13 | Clipboard/file/device redirection exfiltrates data                | disabled by default, independent authorization, size/type controls                                                               | session capability audit, terminate and investigate                                                           |
| TM-14 | Recording captures credentials/private data                       | explicit policy, user notice, restricted encryption/retention, secret redaction                                                  | access audit, incident deletion/rotation process                                                              |
| TM-15 | CI workflow executes untrusted code with write token              | least permissions, SHA-pinned actions, no unsafe pull_request_target, environment approvals                                      | workflow scan, token revoke, rebuild from trusted commit                                                      |
| TM-16 | Backup restores revoked identities or old trust                   | revocation-aware restore test, backup metadata, recovery reconciliation                                                          | post-restore invariant audit, keep service isolated until reconciled                                          |
| TM-17 | Segmentation error grants unintended lateral reach                | default-deny matrix, exact flows, layered enforcement, separate network approval                                                 | flow-deny tests, policy-hash drift alert, isolate and restore policy                                          |
| TM-18 | Compromised runtime suppresses or rewrites audit                  | dedicated append-only writer, integrity chain/checkpoints, protected Z5 archive                                                  | gap/sequence alert, independent export and immutable backup                                                   |
| TM-19 | Compromised TLS service blocks its own containment                | disable issuance client first; signed client-change/denial evidence; then revoke served cert                                     | deny reissuance, rebuild Z2, provision new client, preserve evidence                                          |
| TM-20 | Signing handoff is substituted or over-authorized                 | digest-bound request, signer-verified Z5/Z6 intent ack, separate quorum, result ack                                              | reject signing/publication, chain-of-custody audit, freeze release                                            |
| TM-21 | Revoked endpoint reuses an old update assignment                  | fresh revocation check, single-use endpoint-key/artifact-bound authorization, short expiry                                       | deny/replay audit, emergency token revocation, freeze rollout                                                 |
| TM-22 | Compromised broker leaves a JIT credential usable                 | authority-direct signed Z5 receipt plus non-enumerable authority fallback mapping, short expiry                                  | retrieve exact handle outside Z5/Z8, revoke at OS authority, isolate gateway                                  |
| TM-23 | Authorized audit export occurs without accountability             | immutable intent/result events, exact case/time scope, result digest, fail-closed export                                         | audit gap alert, revoke auditor, investigate destination and access                                           |
| TM-24 | Revoked Z2 server certificate remains trusted                     | independent signed status, hard-fail clients, five-minute freshness, short-lived certificate                                     | propagation test, isolate Z2, revoke/roll over, investigate connections                                       |
| TM-25 | Release transition bypasses protected audit                       | Z5/Z6 ack for authority increase; containment proceeds with signed pending evidence                                              | raise severity, freeze/revoke, reconcile fallback and Z5 evidence                                             |
| TM-26 | Revoked SSH certificate remains valid at endpoint                 | online validation or signed monotonic KRL, 60-second freshness, atomic update, fail closed                                       | isolate tunnel, refresh KRL/status, prove endpoint rejection                                                  |
| TM-27 | Established TLS channel outlives server revocation                | five-minute absolute channel lifetime, full re-handshake/status check, no bypass by resumption                                   | force close, deny reconnect, investigate traffic after revocation                                             |
| TM-28 | Failed evidence append leaves orphaned JIT credential             | exact handle-bound broker revoke, verified receipt, independent signed failure alert                                             | reconcile pending-revocation journal, revoke externally, isolate Z8                                           |
| TM-29 | Emergency PKI containment bypasses protected audit                | signed intent/result receipts, Z5 append, immutable Z6 fallback, mandatory acknowledgement                                       | raise severity, retain/reconcile receipts, review exact PKI action                                            |
| TM-30 | Emergency Z8 termination is suppressed by Z2                      | Z1 signed intent/result, Z8 direct protected event, Z6 fallback, observed-vs-claimed outcome                                     | reconcile tunnel/session state, preserve receipts, isolate Z2 and Z8                                          |
| TM-31 | Suspected artifact service suppresses recovery audit              | Z1 signed intent/result, independent observation, Z5 protected intake, immutable Z6 fallback                                     | isolate artifact path, reconcile metadata/PEP state, preserve receipts                                        |
| TM-32 | Suspected Z2 blocks operator-session revocation                   | independent exact-scope Z1-to-IdP revoke, signed IdP receipt, Z5/Z6 emergency evidence                                           | invalidate session at IdP, verify rejection, preserve/reconcile receipt                                       |
| TM-33 | Revoked operator session remains accepted by Z2/Z8                | direct IdP status, 60-second bound, stream/tunnel/JIT teardown, independent PEP isolation                                        | deny work, terminate access, isolate suspected Z2, preserve evidence                                          |
| TM-34 | Gateway revokes another session's JIT credential                  | exact session/grant/opaque-handle binding at gateway, broker, and authority                                                      | deny request, alert on binding mismatch, terminate suspect gateway                                            |
| TM-35 | Staged update installs after release freeze/revoke                | fresh signed release status, monotonic sequence, 60-second expiry, fail-closed install                                           | reject replacement, preserve package/status evidence, freeze rollout                                          |
| TM-36 | Same operator's valid login masks revoked RMM session             | exact IdP tuple in grant, protected opaque handle, direct Z8 status, case-scoped recovery lookup                                 | revoke exact handle, isolate Z2, terminate Z8 session, preserve evidence                                      |
| TM-37 | Status signer bypasses protected release audit                    | intent ack verified by signer; signer appends result; repository verifies both acknowledgements                                  | reject status activation, freeze rollout, preserve/reconcile evidence                                         |
| TM-38 | Compromised coordinator bypasses rollout health gates             | one-use approval plus dedicated failed-threshold pause key; repository verifies exact scope                                      | reject status, isolate coordinator, pause/freeze rollout, preserve evidence                                   |
| TM-39 | Agent rollback erases the release-status sequence                 | nonce-bound agreement across authority, allocator, anchored ledger, and repository activation head                               | reject lower status, block install, investigate state rollback                                                |
| TM-40 | Status authority fabricates or restores sequence                  | independently verified payload-bound allocator receipt; max-floor/restrictive recovery                                           | reject status/checkpoint, keep general signing disabled, preserve chain                                       |
| TM-41 | Endpoint revocation leaves an active G7 tunnel                    | issuer revoke plus identity-bound Z8 termination; independent PEP isolation fallback                                             | verify tunnel/JIT teardown, preserve Z5/Z6 evidence, investigate session                                      |
| TM-42 | Malformed local input spoofs or exhausts collection               | exact config schema, fixed-path allowlist, byte/field/time bounds, no shell, fuzz tests                                          | bounded issue code, reject or mark partial, preserve local test evidence                                      |
| TM-43 | Local spool is altered, replayed, or rolled back                  | private path, quota, no-overwrite IDs, corruption checksum; no operational use before G2                                         | fail closed on malformed/digest mismatch; add keyed integrity and sequence                                    |
| TM-44 | Transport redirect or acknowledgement confusion                   | exact HTTPS origin/path, no proxy/redirect/reuse, TLS 1.3 mTLS, exact ID acknowledgement                                         | reject permanently, retain spool item, investigate trust or routing                                           |
| TM-45 | Local identity is replaced, mismatched, or half-written           | create-once publication, private modes, stable-root reads, exact URI binding, bounded strict decode                              | fail closed, do not reenroll, quarantine and reconcile uncertain local state                                  |
| TM-46 | Logs or service packaging expose secrets or excess host authority | closed log schema; no raw errors; unprivileged hardened unit; bounded resources; lifecycle validation                            | reject event/package drift; preserve state; revoke identity before removal                                    |
| TM-47 | Agent listener accepts downgraded or ambiguous transport          | TLS 1.3 only; mTLS; tickets off; exact URI/SPKI/Host; no pipelining; bounded strict parser                                       | reject connection/request; preserve bounded audit; rotate suspect identity                                    |
| TM-48 | Peer exhausts listener or database capacity                       | TLS/header/request deadlines; global/per-identity admission and rate; database timeouts                                          | return retryable bounded error; retain admission until store exit; investigate                                |
| TM-49 | Pre-G2 server validation becomes an unapproved endpoint path      | closed-by-default V1D-SV authority; exact server/plan/state hash; synthetic-only issuer profile; blocked endpoint routes; expiry | stop services; revoke synthetic and workload identities; restore policy; prove no residual endpoint authority |

## Denial-of-service considerations

Every externally reachable operation has authentication where possible, request
and decompression limits, rate limits, bounded parsing, timeouts, backpressure,
and observable rejection. The agent listener closes stalled TLS and partial
headers on deadline, admits bounded global and per-certificate body readers
before buffering, caps the HTTP parser queue at two messages and closes on a
second parsed request, applies global and endpoint-certificate rate ceilings, and
configures PostgreSQL connection, statement, and lock deadlines. Endpoint spool
and result output have hard quotas.

## Residual risks

- Phase 1 and Phase 2 source now exist, and the Debian 12 package and service
  lifecycle passed evidence-complete isolated G2A/G2B qualification, but no
  operational agent has been authorized, installed, or accepted as supported;
- the current spool checksum detects accidental corruption but does not provide
  keyed integrity, encryption, or rollback resistance;
- a permission-restricted create-once identity bundle, crash-durable per-boot
  message sequence store, and externally issued server enrollment lifecycle now
  exist, but the agent enrollment client, encrypted or hardware-backed identity
  protection, online status, externally rollback-protected sequence state, and
  encrypted spool remain unimplemented; an executable Debian
  package and service lifecycle are qualified only in isolated CI and remain
  blocked from publication and live installation by G6 and G2;
- the mTLS sender and private listener adapter are source-tested against real
  loopback TLS sockets only; endpoint certificate status, operational PKI,
  service configuration, runtime logging integration, and live revocation remain
  G2 blockers;
- an external-verifier operator application now pins the complete session tuple,
  MFA, role, expiry, and maximum age for every read, but the production IdP,
  private operator listener, source/device policy, and exact revocation-status
  integration are not yet selected or qualified;
- selected PKI, secrets service, and session gateway versions are not yet
  qualified;
- Linux desktop backend remains support-matrix dependent;
- independent penetration testing is deferred to the relevant operational gate.

These residual risks keep G2 closed. The bounded V1D-SV authority also remains
closed until V1C, every external dependency record, exact post-issued Factory
plan approval, negative tests, and rollback/recovery prerequisites pass. If it
is later opened, it permits only the named private server with synthetic
validation identities and blocked endpoint routes; all endpoint deployment
remains prohibited while G2 is closed.
