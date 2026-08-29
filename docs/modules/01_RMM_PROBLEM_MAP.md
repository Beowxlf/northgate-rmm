# Module 1 — The RMM Problem Map

Estimated time: 60–90 minutes  
Build stage: before code  
Outcome: describe an RMM as a problem-solving loop rather than a feature list

## The operating loop

Almost every RMM capability belongs somewhere in this loop:

`discover -> observe -> evaluate -> decide -> authorize -> act -> verify -> record`

### Discover

Find a machine and establish what it is.

Examples:

- an agent enrollment;
- an imported asset;
- a newly observed operating system;
- reconciliation of hostname, serial number, and agent identity.

Output: an **asset identity**.

### Observe

Collect a fact at a particular time.

Examples:

- free disk space was 12 GiB at 14:05;
- the SSH service reported active;
- package version 3.2.1 was installed;
- the last agent heartbeat arrived 38 seconds ago.

Output: an **observation**, including source and time.

### Evaluate

Compare observations with a rule, baseline, or expectation.

Examples:

- disk space is below an approved threshold;
- the service differs from desired state;
- the endpoint has missed three heartbeat intervals;
- the installed package is older than the approved version.

Output: a **finding** or state assessment.

### Decide

Select a response based on impact, confidence, risk, and policy.

Examples:

- wait for a second failed check;
- open an alert;
- request a diagnostic bundle;
- schedule maintenance;
- take no action because a maintenance window is active.

Output: an **intent** or proposed job.

### Authorize

Prove that this actor may perform this action against this exact target now.

Examples:

- a read-only collector is allowed automatically;
- a service restart requires approval;
- a high-risk action requires step-up authentication;
- an expired approval cannot be reused.

Output: an **authorization decision** bound to scope and time.

### Act

Deliver and execute a typed capability.

Examples:

- collect a diagnostic bundle;
- restart one named service;
- install one signed approved package;
- revoke an agent identity.

Output: an **execution result**, which may be success, failure, timeout,
cancellation, expiry, or unknown.

### Verify

Measure the intended postcondition independently.

Examples:

- after restart, the service is active and its health endpoint responds;
- after cleanup, free disk space exceeds the required minimum;
- after revocation, the endpoint can no longer authenticate;
- after update, the running agent reports the expected signed version.

Output: **postcondition evidence**.

### Record

Preserve enough context to explain and investigate what happened.

Examples:

- actor and approver;
- target identity;
- action type and content hash;
- timestamps and correlation ID;
- before/after observations;
- sanitized result and reason for failure.

Output: an **audit event** and related operational evidence.

## Why this loop matters

A feature-first description says, “I want a restart button.”

A problem-first description asks:

- What observation proves a restart is justified?
- Which service identity is allowed?
- Who can approve it?
- How do we prevent restarting the wrong endpoint?
- What happens if the connection drops after the restart?
- How do we verify recovery?
- What evidence proves what occurred?

That second description can be designed, tested, and secured.

## The seven core records

### 1. Endpoint

The durable managed identity. It should not change merely because the hostname or
IP address changes.

### 2. Observation

A fact reported or measured at a time, with a source and freshness.

### 3. Desired state

The approved expectation against which an observation can be evaluated.

### 4. Finding

A meaningful difference, threshold breach, or health conclusion.

### 5. Job

The server-side lifecycle of intended work, including target, authorization,
lease, timeout, cancellation, and final knowledge state.

### 6. Action

The exact typed capability the endpoint understands. A job schedules an action;
an action is not arbitrary shell text.

### 7. Audit event

An immutable security-relevant account of who or what caused a state transition.

## Worked scenario: low disk space

Suppose a Linux endpoint is running out of storage.

1. **Discover:** endpoint `ep_019` is enrolled with its own key pair.
2. **Observe:** its agent reports 8 GiB free on `/var` at 14:05.
3. **Evaluate:** the approved rule requires at least 15 GiB free.
4. **Decide:** collect disk-usage diagnostics before proposing cleanup.
5. **Authorize:** the read-only diagnostic action is allowed for `ep_019` and
   expires in ten minutes.
6. **Act:** the agent runs the fixed `collect_disk_usage` handler.
7. **Verify:** the result contains a complete, size-bounded inventory of approved
   directories. No cleanup has occurred yet.
8. **Record:** the system stores the rule, target identity, action hash, result,
   timestamps, and actor.

Notice what the RMM has not yet done. It has not deleted files merely because a
threshold was crossed. Observation and repair are different authorities.

## Development lesson hidden in the scenario

Even this simple workflow produces difficult questions:

- What if the endpoint reports the same observation twice?
- What if its clock is wrong?
- What if the threshold changes during evaluation?
- What if the job is delivered twice?
- What if the diagnostic finishes but the result upload is interrupted?
- What if output includes a secret-bearing filename?
- What if the endpoint identity was revoked while the job was queued?

These are normal distributed-systems and security-engineering problems. They are
not edge cases to postpone until after the UI is built.

## Exercise A — Translate features into problems

For each desired capability, fill in all five columns. The first three examples
are completed.

| Desired capability | Problem answered | Required observation | New authority | Proof of success |
|---|---|---|---|---|
| Endpoint status | Is the monitoring path alive and fresh? | Authenticated heartbeat receipt time | Store endpoint observations | Fresh heartbeat accepted for the correct endpoint identity |
| Service health | Is a required service operating? | OS service state plus optional application health | Read named service state | Observation includes source, time, and supported state |
| Restart service | Can one failed service be recovered remotely? | Failure evidence and maintenance context | Change service state on one endpoint | Service active and independent health check passes |
| Software inventory |  |  |  |  |
| Patch installation |  |  |  |  |
| Remote terminal |  |  |  |  |
| File transfer |  |  |  |  |
| Agent update |  |  |  |  |
| Endpoint isolation |  |  |  |  |
| Scenario reset |  |  |  |  |

## Exercise B — Classify what you dislike in TacticalRMM

List five points where TacticalRMM feels unclean, limited, confusing, or unsafe.
For each one, identify whether it is primarily:

- an information architecture problem;
- a workflow problem;
- an observability problem;
- an automation problem;
- a security or authorization problem;
- a reliability problem;
- an integration problem;
- a visual design problem.

Then write the user outcome without naming a UI component.

Example:

- Feature complaint: “The agent page feels cluttered.”
- Underlying problem: important health and freshness facts are not prioritized.
- User outcome: “Within ten seconds I can tell whether the endpoint, the agent,
  or a monitored service needs attention, and why.”

## Exercise C — Draw the authority ladder

Put the following in order from lowest to highest operational authority:

- view a stored observation;
- request a new read-only observation;
- change an unprivileged application setting;
- restart a service;
- install a signed package;
- transfer a file;
- execute arbitrary shell text;
- control the interactive desktop;
- isolate a network interface.

For each step, name one additional preventive control, one detection, and one
recovery mechanism that becomes necessary.

There is no universal correct ordering for every environment. The lesson is that
features create different kinds of authority and therefore need different gates.

## Knowledge check

You should be able to answer these without referring back to the lesson:

1. Why is a heartbeat an observation rather than proof that the whole endpoint is
   healthy?
2. Why is an exit code not a postcondition?
3. Why must endpoint identity be separate from hostname and IP address?
4. What is the difference between a job and an action?
5. Why is `result_unknown` an honest and necessary state?
6. Why should read-only observation and repair have different authority?
7. What makes an RMM agent structurally attractive to attackers?

## Completion gate

Module 1 is complete when:

- the feature map has no empty “problem answered” cells;
- five TacticalRMM complaints have been translated into user outcomes;
- every desired action names the authority it adds;
- the initial v0 exclusions still make sense after the exercise; and
- the seven core records can be explained in your own words.

The outputs from this lesson become inputs to Module 2, where they are converted
into trust boundaries and abuse cases.
