# Phase 2 Linux-Agent Data Inventory

Status: Source-development allowlist; not approved for live collection  
Date: 2026-08-30

Every field becomes Sensitive when bound to an endpoint, even if its standalone
value appears generic. The source implementation may collect only the following
fields. G2 must approve their exact handling before any endpoint installation.

| Field                        | Source                                 | Purpose                                  | Server retention target  |
| ---------------------------- | -------------------------------------- | ---------------------------------------- | ------------------------ |
| `host.hostname`              | operating-system hostname API          | operator-recognizable endpoint display   | current plus 90 days     |
| `host.platform`              | compiled Go runtime target             | protocol and support-policy selection    | current plus 90 days     |
| `host.architecture`          | compiled Go runtime target             | compatibility and package selection      | current plus 90 days     |
| `os.id`                      | allowlisted `/etc/os-release` key      | distribution support decision            | current plus 90 days     |
| `os.version_id`              | allowlisted `/etc/os-release` key      | qualified-version and patch context      | current plus 90 days     |
| `os.pretty_name`             | optional `/etc/os-release` display key | operator-readable OS label               | current plus 90 days     |
| `boot.id`                    | Linux kernel boot UUID                 | boot/session replay boundary             | current plus 90 days     |
| `root_disk.total_bytes`      | read-only root-filesystem statistics   | capacity and low-space monitoring        | current plus 90 days     |
| `root_disk.free_bytes`       | read-only root-filesystem statistics   | capacity and low-space monitoring        | current plus 90 days     |
| `agent.version`              | compiled agent metadata                | compatibility and vulnerability response | current plus 90 days     |
| `agent.inventory_schema`     | compiled agent metadata                | decoder compatibility                    | current plus 90 days     |
| collector completion boolean | local collector runner                 | distinguish complete from partial data   | with each observation    |
| bounded issue code           | local failure classification           | diagnose incomplete collection safely    | local only in this slice |

## Local structured-log allowlist

The source-only logger can emit only the fields below. It is not yet wired to an
executable agent, and G2 must define the journal retention/access policy.

| Field                           | Source                      | Treatment                                      |
| ------------------------------- | --------------------------- | ---------------------------------------------- |
| schema version                  | compiled logger constant    | non-sensitive compatibility metadata           |
| UTC timestamp                   | local clock                 | sensitive when linked to endpoint activity     |
| level/code/component/outcome    | closed compiled enumeration | no free-form values                            |
| sanitized failure class         | closed compiled enumeration | never contains a raw error                     |
| optional correlation/message ID | protocol-generated UUID     | sensitive; canonical UUID only; no endpoint ID |

## Handling rules

- source reads are fixed-path, byte-bounded, read-only, and never invoke a shell;
- configuration and collected values reject duplicate, malformed, oversized,
  invalid UTF-8, NUL, and control-character input where applicable;
- raw operating-system errors and file content do not enter issue codes, logs,
  protocol messages, or audit evidence;
- structured logs accept no arbitrary attributes, free-form message, URL,
  hostname, endpoint ID, inventory value, or raw error;
- endpoint identity, hostname, and boot ID must not be used as authorization;
- operator access, export, deletion, backup, and holds follow the Sensitive data
  controls in `DATA_CLASSIFICATION_RETENTION.md`; and
- endpoint removal must delete current/history data after the approved retention
  and hold rules, without deleting protected security evidence.

## Explicit non-collection

This slice does not collect machine ID, serial numbers, IP or MAC addresses,
users, groups, processes, services, packages, command lines, environment
variables, file content, browser data, user activity, security findings, or
arbitrary paths. Adding a field requires a reviewed purpose, classification,
source bound, retention decision, tests, and an updated authorization if scope
changes.
