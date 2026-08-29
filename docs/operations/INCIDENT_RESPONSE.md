# Incident Response Plan

## Incident classes

- operator account/session compromise;
- endpoint identity or enrollment compromise;
- malicious/unauthorized job or remote session;
- control-plane, gateway, database, or audit compromise;
- update/build/signing compromise;
- data exposure;
- availability failure or reconnect storm;
- vulnerable dependency or agent flaw;
- backup/recovery compromise.

## Priorities

1. protect people and managed systems;
2. stop unauthorized authority and propagation;
3. preserve trustworthy evidence;
4. determine scope and trustworthiness;
5. recover through an independent path;
6. communicate and prevent recurrence.

## Universal response

1. Declare an incident ID, commander, time, and suspected trust boundary.
2. Avoid using a component or identity suspected compromised for containment.
3. Preserve relevant audit, identity, gateway, network, build, and artifact evidence.
4. Revoke affected operator sessions, endpoint identities, grants, jobs, tunnels,
   release keys, or service credentials.
5. Stop dispatch/update/session capability at the narrowest safe boundary; use the
   global emergency stop when scope is unknown.
6. Identify endpoints, actions, sessions, versions, and data affected.
7. Recover from known-good source, artifacts, trust roots, and backups.
8. Verify invariants before reconnecting endpoints or resuming dispatch.
9. Document timeline, decisions, uncertainty, impact, notification, and follow-up.

Direct endpoint/server PKI recovery, G6 release freeze/revocation, and independent
Z8 emergency termination record signed intent, component response, and
independently observed result in protected Z5 evidence or, when Z5 is unavailable,
the append-only Z6 emergency evidence intake. Failure of both paths is incomplete
containment and must not be reported as a fully evidenced recovery.

## Mandatory emergency capabilities before operational gates

- disable new enrollment;
- revoke one or all endpoint identity families;
- cancel queued jobs and prevent new dispatch;
- terminate one or all remote sessions/tunnels;
- freeze updates and revoke release metadata/keys;
- place control plane in read-only evidence-preservation mode;
- export protected audit evidence through an independently authorized path.

## Remote-session incident

Terminate the gateway session and endpoint tunnel, revoke the grant and JIT
credential, disable redirection, preserve session metadata/authorized recording,
inspect endpoint authentication and network logs, and determine whether the
gateway or endpoint was used to pivot.
If the gateway or credential broker is suspected, revoke the exact JIT credential
at the OS identity authority through the independent Z1 session-recovery route;
do not use the suspected broker for containment.

## Recovery criteria

Recovery is complete only when root cause and scope are sufficiently understood,
compromised authority is revoked, replacement trust is independently established,
required data is restored and reconciled, security invariants pass, canary
validation succeeds, and residual risk is accepted.
