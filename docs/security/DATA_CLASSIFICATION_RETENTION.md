# Data Classification and Retention

## Classes

### Public

Published documentation, release notes, public schemas, and sanitized examples.

### Internal

Architecture details, non-sensitive test results, generic inventory, and
operational metrics without endpoint-identifying detail.

### Sensitive

Endpoint identities, hostnames, addresses, software inventory, findings, job
results, audit events, session metadata, support bundles, and topology.

### Restricted

Secrets, private keys, enrollment grants, session credentials, credential-broker
data, recordings/transcripts, vulnerability exploit details, and recovery keys.

Restricted secrets are not ordinary application data and must not be stored in
the RMM database unless a separately approved secret-management design requires
an encrypted reference or ciphertext.

## Collection rules

Every field needs owner, purpose, source, classification, access scope, retention,
redaction, export, and deletion behavior. Process command lines, environment
variables, browser history, file content, and user activity are not collected by
default.

## Initial retention targets

These are design defaults to validate before operational use:

- heartbeat detail: 30 days, with longer aggregate availability if needed;
- inventory versions: current plus 90 days of change history;
- application logs/traces: 30 days;
- security/audit events: one year in lab, subject to storage and incident holds;
- job outputs: 30 days unless evidence policy requires more;
- enrollment plaintext: never retained after display/transfer;
- remote-session metadata: one year in lab;
- recordings/transcripts: disabled until a separate policy authorizes retention;
- backups: documented rotating schedule with tested expiry and secure deletion.

## Access and deletion

Access is least privilege and audited. Deletion must cover primary, cache, search,
artifact, and backup lifecycle without erasing active incident/legal holds.
Sanitized evidence should be preferred over retaining broad raw output.
