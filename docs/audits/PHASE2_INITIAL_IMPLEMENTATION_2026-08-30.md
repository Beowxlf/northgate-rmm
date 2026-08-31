# Phase 2 Initial Linux-Agent Implementation Audit

Status: In progress; source development only  
Date: 2026-08-30  
Authorization:
`docs/governance/authorizations/P2-LINUX-AGENT-SOURCE-DEVELOPMENT.md`

## Boundary

This audit covers repository source and synthetic/local tests. It does not open
G2 or authorize installation on an endpoint or VM, use of live identity, contact
with a control plane, collection from a real endpoint, or any VM Factory or
infrastructure artifact or decision.

## Toolchain provenance

- selected version: Go 1.27.0;
- authoritative version source: <https://go.dev/dl/?mode=json>;
- local archive: `go1.27.0.windows-amd64.zip`;
- authoritative SHA-256:
  `f0c0a0d33ba94f4d2c5dbc887334ce678b21813504ddb3aafcb06e60a5a667c4`;
- observed local SHA-256: identical;
- observed executable: `go version go1.27.0 windows/amd64`;
- workspace-local location: ignored `.tools/` directory; and
- CI setup action: `actions/setup-go` v7.0.0 pinned to commit
  `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e`.

The agent module currently has no non-standard runtime dependency. CI audit tools
are invoked at exact module versions: Staticcheck v0.8.1 and govulncheck v1.7.0.

## Implemented source boundary

- strict, size-bounded JSON configuration with no secret fields;
- HTTPS-only control-plane origin validation;
- allowlisted hostname, OS release, boot ID, root-disk, architecture, and agent
  metadata collection;
- fixed-path file reads with byte limits and no shell or subprocess;
- a documented field allowlist in
  `docs/security/PHASE2_DATA_INVENTORY.md`;
- bounded partial-collection state using non-sensitive issue codes;
- exact Phase 1-compatible inventory JSON encoding and message limits;
- quota-bounded, checksum-validated, no-overwrite local spool with restrictive
  permissions and explicit acknowledgement removal; this detects accidental
  corruption but is not yet the keyed-integrity or encryption control required
  for G2;
- cryptographic version-4 message and correlation identifiers;
- a private, exclusively locked per-boot sequence store that durably reserves
  each message sequence before construction, continues across process restart,
  resets only for a new canonical Linux boot ID, and exposes sync uncertainty
  without permitting the candidate value to be emitted;
- outbound-only TLS 1.3 mTLS sender accepting only injected endpoint identity
  and explicit roots, with environment proxies, redirects, connection reuse,
  compression, TLS resumption, and retry on permanent failures disabled;
- exact message-ID acknowledgement, bounded response parsing, sanitized error
  classes, and bounded exponential retry with cryptographic jitter; and
- a create-once identity store that validates the exact endpoint URI binding,
  certificate lifetime and client purpose, key match and strength, certificate
  chain, and explicit server roots before durable permission-restricted
  publication; partial, unknown, permissive, malformed, expired, and mismatched
  stores fail closed without automatic reenrollment; and
- no executable service, listener, command runner, privileged helper, package,
  or endpoint installation path.

## Validation

- `go fmt ./...`: passed;
- `go test ./...`: passed;
- `go vet ./...`: passed;
- Linux amd64 standard-library cross-build and vet: passed;
- Staticcheck v0.8.1: passed;
- govulncheck v1.7.0: no vulnerabilities found;
- five-second configuration fuzz campaign: passed with 88,882 executions;
- five-second OS-release fuzz campaign: passed with 324,982 executions;
- five-second identity-bundle fuzz campaign: passed locally with 430,577
  executions;
- five-second sequence-state fuzz campaign: passed locally with 371,132
  executions; and
- local Windows race test: not evidenced because the available local C compiler
  cannot build 64-bit race instrumentation. The required Ubuntu CI race run is
  the authoritative blocking check.

The repository security workflow also runs gofmt, module verification, vet, race
tests, Staticcheck, govulncheck, and Semgrep for Go. A passing exact-head CI run
is required before merge.

The mTLS transport slice uses only ephemeral synthetic certificates and a local
loopback test server. Tests prove TLS 1.2 rejection, mutual client
authentication, explicit-root server validation, disabled proxy/redirect/reuse
and TLS-resumption behavior, exact acknowledgement binding, response bounds,
permanent/transient classification, retry limits, jitter, entropy failure, and
context cancellation. No live endpoint identity or NorthGate control plane was
used.

The first exact-head review identified and blocked five boundary defects. The
follow-up change enforces file and disk source allowlists in the native adapter,
validates every existing spool record during startup, syncs Linux directory
mutations before success, rejects an empty URL query delimiter, and rejects
invalid UTF-8 before protocol encoding. A fresh exact-head review and CI run are
required for those corrections.

The second exact-head review found five additional cases. The follow-up change
adds raw configuration UTF-8 validation, duplicate-key validation shared by
configuration and spool records, nil-map rejection for protocol object shape,
and a lifetime-held Linux file lock that serializes quota check/publication
across processes. Queue creation now requires an existing real parent and syncs
that parent before success. Non-Linux queue locking and sync remain development
test shims and make no operational durability claim.

The third exact-head review found two final edge cases. The follow-up change
syncs the queue directory after temporary-file cleanup on every post-creation
enqueue failure and applies strict UTF-8 validation to the architecture field as
well as inventory keys and values.

The fourth exact-head review found three final cases. The follow-up change rejects
all control characters in state paths and protocol text, durably rolls back a
published record when final sync fails, exposes a typed exact-ID uncertainty when
rollback durability cannot be proven, and preserves the generated message ID in
the snapshot result on every queue error.

The fifth exact-head review found that direct callers of the exported
configuration validator could supply invalid UTF-8 in the state path even though
the JSON decoder already rejected it. The follow-up change applies the same UTF-8
boundary to both configuration entry paths and adds a direct-validation
regression test.

The sixth exact-head review found the same direct-call consistency issue for the
control-plane URL and found that URL parsing alone accepted out-of-range numeric
ports. The follow-up change rejects invalid UTF-8 before URL parsing and limits
explicit ports to the TCP range of 1 through 65535.

The seventh exact-head review found that a percent-encoded host could decode to
invalid UTF-8, an explicit empty port could be silently normalized, and an
acknowledgement could become crash-durability ambiguous after removal if the
directory sync failed. The follow-up change validates the decoded hostname,
rejects empty ports, and returns a typed uncertainty with the exact queue record
ID so restart recovery can reconcile the acknowledgement.

The eighth exact-head review found that an empty fragment delimiter could be
silently normalized and that the OS-release collector used Go string-literal
rules instead of the Linux file's shell-compatible quoting rules. The follow-up
change rejects the raw fragment delimiter and uses a bounded format-specific
decoder supporting single or double quotes and literal shell-style escapes
without interpolation or execution.

The ninth exact-head review found that trimming assignment values accepted
invalid whitespace after `=` and that the decoder applied double-quote escape
semantics to single-quoted content. The follow-up change preserves the source
line boundary, rejects surrounding value whitespace, treats single-quoted
content literally, and limits double-quoted escape removal to shell-special
characters.

The tenth exact-head review found a path-replacement race between validating and
opening the spool directory, a missing distribution-ID grammar check, and a
year-zero timestamp mismatch with the Python control plane. The follow-up change
opens and verifies both parent and queue by stable directory handles with
same-file checks, enforces the lowercase OS ID grammar, and constrains both
message timestamps to years 1 through 9999.

The eleventh exact-head review found that `VERSION_ID` lacked field-specific
grammar validation and that hostname collection normalized surrounding control
text. The follow-up change rejects hostname normalization and enforces the
official `VERSION_ID` character set. Uppercase remains accepted because the
systemd specification recommends, but does not require, lowercase for this
field.

The twelfth exact-head review found that deferred directory-entry metadata could
escape the nested root descriptor on Linux and that Go's JSON decoder replaces
unpaired surrogate escapes before schema validation. The follow-up change stats
every spool entry relative to the stable queue root and rejects unpaired high or
low surrogates in raw JSON strings before decoding.

The thirteenth exact-head review found that HTTP IDNA handling can silently
remove Unicode format characters from a configured hostname. The follow-up
change restricts control-plane authorities to canonical ASCII DNS names,
IPv4/IPv6 literals, or explicit ASCII punycode and rejects percent-escaped
authorities.

The fourteenth exact-head review found that Linux's native resolver can interpret
noncanonical decimal, octal-looking, or hexadecimal numeric hostnames as IPv4
addresses even when Go's strict IP parser does not. The follow-up change rejects
all-numeric legacy IPv4 candidates unless the authority is already a canonical
IP literal.

The fifteenth exact-head review found that a restarted process could validate
persisted records but could not discover their IDs for delivery. The follow-up
change adds a bounded, ordered `ListIDs` recovery API that revalidates every
record and exposes no payload during enumeration.

The sixteenth exact-head review found that UUID sorting could reverse protocol
sequence after restart and that reading the whole directory exceeded the queue's
memory bound before its entry-count check. The follow-up change adds a required
durable enqueue ordinal to spool schema 2, returns records in that order, rejects
duplicate ordinals, and streams at most `MaxEntries+1` directory entries through
the stable root. The schema 2 corruption checksum binds the record ID, durable
order, and payload so order changes cannot pass integrity validation.

The seventeenth exact-head review found two certificate-purpose edge cases in
the new identity store. The follow-up change rejects a client certificate whose
EKU extension contains only unknown purposes and rejects an explicit server
trust root restricted away from server authentication. Synthetic regression
certificates cover both cases.

The eighteenth exact-head review extended those checks across the complete
chain. The follow-up change rejects a client issuer restricted away from client
authentication and rejects leaf, issuer, or server-root certificates containing
an unhandled critical extension. Synthetic regression certificates cover the
restricted issuer and critical-root cases.

The nineteenth exact-head review found that manual per-hop signature checks did
not enforce issuer-name matching or CA path-length constraints. The follow-up
change replaces the manual client-chain walk with Go's full X.509 path verifier,
an explicit client-authentication purpose, the supplied chain's final CA as the
explicit trust anchor, and the supplied intermediates. The store also requires a
complete chain and a signing-capable leaf key usage before publication.

## Remaining before G2

This is not a complete Phase 2 qualification. At minimum, enrollment, identity
encryption or an approved OS-backed alternative, certificate status/revocation,
rotation, externally rollback-protected sequence state, encrypted-spool policy,
logging/redaction, package and unprivileged `systemd` lifecycle, resource-limit
evidence, revoke behavior, clean removal, Debian 12 qualification, and the exact
canary/network/recovery authorization remain unresolved. The identity store,
mTLS sender, and retry behavior are source-tested only and have not used a live
credential or contacted a live control plane.
