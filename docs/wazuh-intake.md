# Wazuh alert intake

Qualifying Project_Mati detections now create or update SOC cases automatically. Policies are private RMM source-registry configuration, not caller input. Each policy selects exact Wazuh rule IDs and a minimum level, defines grouping fields and a 300–86400 second fixed window, and requires `closed_behavior: new_case`; resolved or closed cases are never silently reopened.

The source registry owns detection ID/version, ATT&CK mapping, context allowlist, and investigation checklist. The Wazuh connector forwards only that allowlisted metadata. Exact source IDs are idempotent; a retry returns the original alert and case. Related new IDs group only when policy criteria and fixed window match.

Unmapped devices and case-creation faults create owner-visible intake-health records and return HTTP 503. The Wazuh queue retains and exponentially retries them. Network and authentication failures remain visible in queue status and the service journal. Hard payload conflicts remain rejected for operator review.

Wazuh remains the raw-event source. RMM accepts selected alert metadata, links it
to an exact current RMM enrollment, and lets operators attach the alert to a case.
This connector does not run response actions or automatically create/close cases.

## Components

`deploy/wazuh/custom-northgate-rmm` is a standalone Python 3.10+ custom integration
with no pip dependencies. Wazuh invokes it with the JSON alert-file path. It
filters unmapped agent IDs and levels below `minimum_level`, strips all raw event
fields, and places metadata in a local private SQLite queue. No network request
runs in the Integrator invocation. Only id, timestamp, agent.id and rule
id/level/description/groups leave the manager. Known secret patterns in descriptive
text are redacted; this is not a general data-loss-prevention filter. Raw alerts
and logs are never copied to RMM or printed by the connector.

Wazuh's compact timezone offsets (for example `+0000`) are normalized to `+00:00`
before parsing for Python 3.10 compatibility. The original local time and offset
are preserved; malformed or timezone-free timestamps remain rejected.

The oneshot sender runs ten alerts at most, with a three-second socket timeout
and a 35-second loop budget. Its systemd unit has a 45-second timeout, 64 MiB
memory cap, 10% CPU quota, eight tasks and lower scheduling priority. It uses a
verified private server IP while validating the configured HTTPS hostname and
lab CA. Environment proxies, redirects, invalid certificates, browser cookies
and human OAuth credentials are not accepted. A dedicated bearer is read from a
protected file, never from argv or the Wazuh XML configuration.

The timer waits 15 seconds after each completed send. Queue limits are 1,000
records and 8 MiB of metadata; SQLite is limited to 4,096 default 4 KiB pages.
The rollback journal can temporarily add disk space within this small queue
budget. Records include the approved enrollment binding that existed when queued;
changing that binding quarantines older pending records rather than assigning
them to the replacement device. Queue-full errors leave the original event in
Wazuh; this is bounded forwarding, not lossless infinite retention or automatic
historical backfill.

202 with a valid RMM receipt removes an acknowledged queue record. Identical
network retries are deduplicated by RMM source+alert ID. 400/409/413/422 leave the
record rejected for reconciliation; authentication/network/other failures use
backoff up to 15 minutes. `--status` shows counts and oldest age without event
content. Rejected events require an operator to investigate the original Wazuh
alert and mapping; no automatic discard/reassignment API is provided.

## Identity and mapping

Generate an independent 48-byte random URL-safe bearer. Store its value only on
the Wazuh manager in `/etc/northgate-rmm-intake/bearer`; RMM receives only the
SHA-256 in its private `wazuh_intake_registry` file. Both connector `agents` and
the RMM source `agents` map a **verified Wazuh ID** to `{endpoint,identity}` UUIDs.
Start with an empty map and a disabled source. Confirm the Wazuh registration
and RMM active enrollment independently before populating and enabling it.
Hostname/IP matches alone do not authorize linkage. RMM rechecks active
enrollment identity on every receipt.

## Reviewed deployment sequence

1. Confirm the manager identity, free space, current agents and component health.
   Back up `ossec.conf` into a timestamped root-only recovery directory; retain its
   original ownership/mode and SHA-256. Do not print protected configuration.
2. Stage the reviewed executable at
   `/var/ossec/integrations/custom-northgate-rmm`, `root:wazuh`, mode 0750.
   Create `/etc/northgate-rmm-intake` root:wazuh 0750; config, bearer and CA are
   root:wazuh 0640. Create `/var/lib/northgate-rmm-intake` wazuh:wazuh 0700.
   The hook and sender run as the manager's `wazuh` integration identity; do not
   expose or grant ordinary users access to the queue or bearer.
3. Install the exact private nginx intake location on RMM, preserving its bearer,
   bypassing human OAuth only for that route, and allowing the actual Wazuh
   manager source address. Upstream is the existing loopback operations service.
   RMM intake rejects Origin and direct non-loopback callers. Keep other routes
   behind existing authentication and do not open public listeners.
4. Verify the CA/hostname and an authorized metadata-only synthetic alert using
   an exact active mapping. Verify unauthenticated requests fail, retries dedupe,
   raw fields are absent, and an incorrect enrollment fails. Synthetic events
   should use a clearly labelled unique ID/description.
5. Merge `ossec-integration.xml` inside one existing `ossec_config` section.
   Wazuh permits multiple top-level `ossec_config` blocks; generic XML tools must
   account for that. Validate with the deployed manager binaries before one
   controlled manager restart. Install/enable the timer and recheck all central
   services and queue status. No indexer/dashboard restart is needed.
6. Verify a genuine agent alert is forwarded with the intended endpoint binding.
   Report added agent services and measured memory/CPU after baseline collection.
   Preserve unrelated agent registrations, rules, index retention and sources.

For rollback disable the intake timer and the RMM source, restore the reviewed
manager config backup, validate, and restart only the manager. Retain the queue
and source events for investigation. Stop a newly added canary sensor if needed;
do not delete existing Wazuh registrations or raw evidence.

## Sources

- [Wazuh custom integration contract](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
- [Integrator configuration and filters](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)
- [Official agent package catalog and checksums](https://documentation.wazuh.com/current/installation-guide/packages-list.html)
- [Windows agent installation](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)
- [Linux agent installation](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html)

See `docs/operations-workspace.md` for the intake payload, source registry and
server authentication contract. Unit tests exercise filtering, redaction,
queue/retry limits, conflict custody, enrollment changes and the HTTPS receipt.
