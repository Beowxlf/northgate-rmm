# OpenBao deployment and recovery

These are deployment templates, not a deployed vault. No keys, root tokens,
unseal shares, or credentials are included. The integration is optional and
requires a real healthy OpenBao KV v2 service before credential actions work.

## Single-node lab installation

1. Select a supported OpenBao release from the official distribution, verify its
   published signature/checksum, and install its `bao` executable. Preserve its
   exact version/checksum in deployment evidence. Do not run dev mode.
2. Create a dedicated `openbao` service identity and private data/log directories
   matching `openbao.service.example`. Install `openbao.hcl.example` as a private
   configuration file. For the co-located example, resolve `vault.rmm.internal`
   to loopback on the RMM server. If hosted separately, bind the vault's private
   interface and allow only the RMM server and designated administrators.
3. Provision a certificate with the configured vault hostname in its SAN and
   mount the reviewed CA into the RMM service. Preserve hostname verification.
   Do not configure TLS bypass or insecure HTTP. Keep port 8201 private.
4. Initialize OpenBao interactively under its operational owner, distribute seal
   recovery material to the designated custodians, and record the tested unseal
   procedure outside the RMM. Never store the only unseal material inside the
   vault it unlocks. For a single-owner lab, retain protected offline recovery
   material independently of both VM disks and RMM backups.
5. Enable KV v2 at mount `rmm`, require CAS, retain an agreed version count, and
   enable the provider's audit device. Keep raw secret logging disabled. Install
   `rmm-policy.hcl`; create a dedicated least-privilege RMM service credential
   using that policy. Do not run the RMM with the initialization/root token.
6. Deliver the service token through a protected file or an OpenBao Agent token
   sink. The client rereads the token file on every operation, so renewal or
   replacement needs no application restart. Prefer an automatically renewed,
   policy-scoped token. Seal/root recovery must not depend on this token.
7. Place `rmm-secrets.json.example` in the deployment-owned RMM configuration and
   add exact grants: each entry has `subject`, `endpoints` mapping endpoint UUIDs
   to current enrollment UUIDs, and `permissions` drawn from `metadata`, `use`,
   `reveal`, `rotate`, `admin`. No implicit owner/admin grant exists. Protect the
   config and token with mode 0600 and the service identity's ownership. All
   grants are reloaded on each request; a re-enrollment requires a new grant.
8. Compose `SecretsAPI(gateway, config_path, state_path=Path(".../secrets.sqlite3"), management=management)`
   and register it on the existing authenticated remote service. The RMM state
   database stores references and workflow status, never secret values. The
   exact source service flag/environment name is in `remote_service.py`.
9. Qualify create, denied metadata access, fresh-MFA reveal, automatic remote
   credential use, token rotation, provider seal/unseal, role revocation, version
   conflict, soft delete/restore, and vault outage. Confirm logs, case records,
   ordinary metadata APIs and MCP output contain no secret values.

Single-node storage is not highly available. It is sufficient for an explicit
lab dependency if recovery is tested. Use a separately assessed three-node Raft
deployment when availability requirements justify it.

## Backups and restoration

- Take provider-native Raft snapshots with `bao operator raft snapshot save`
  using a separate backup identity. Do not grant snapshot or restore authority
  to the RMM application token. Store snapshots in protected off-host storage,
  retain hashes/time/version records, and keep unseal material under separate
  custody. Use the CLI's approved address/CA configuration and protected token
  helper; never put a token in a shell command argument or evidence record.
- Back up `secrets.sqlite3` consistently using SQLite backup, its deployment
  configuration, provider policies and TLS trust references. Back up secret
  values through OpenBao snapshots, not by exporting them into RMM evidence.
- Test restore in an isolated instance with the original compatible seal
  configuration and preserved recovery material. Use the normal Raft snapshot
  restore path; do not automate `snapshot-force` or skip seal consistency checks.
- After restore, verify seal state, provider identity/TLS, KV versions, exact RMM
  grants and the reference database. Test a synthetic secret without revealing
  a live credential in evidence. Revoke and reissue the application token if
  restore changed its custody assumptions.
- Reconcile every incomplete device rotation. A restored vault may contain an
  older password than a device now uses. Staged rotation values remain in the
  provider until an operator has reconciled their outcome; do not delete them
  merely because a job timed out. Keep a documented retention process for those
  staged values and record only IDs/status in the case timeline.

### Optional snapshot prerequisite for operations backups

The default operations backup is unchanged when `openbao_snapshot_receipt` is
absent and the drop-in below is not installed. This optional Linux/Python 3.11+
integration takes a new independently encrypted vault snapshot before each
systemd operations backup. It does not start or enable a backup timer during
installation, grant vault authority to RMM, or copy vault contents into a case.

Prerequisites are an existing qualified operations backup, the `openbao.service`
unit, `northgate-rmm-operator` account, and a root-controlled snapshot producer at
`/usr/local/lib/northgate-rmm-openbao/snapshot.py`. The supplied `snapshot.py`
producer streams the provider response through age encryption and hashes the
ciphertext with a bounded read buffer. Provision it and its dedicated OpenBao
backup credential separately: `/etc/northgate-rmm/secrets/openbao-backup.token`,
the pinned CA `/etc/northgate-rmm/openbao-ca.pem`, and the approved public recovery
recipient `/etc/openbao/recovery-recipient.txt`. The producer uses the fixed
`https://vault.rmm.internal:8200` address and requires the `age` executable.
Keep the private recovery
identity and seal material outside both RMM and its ordinary operations archive.
The RMM application token must not acquire snapshot/restore permissions.

The producer prints one JSON object with `snapshot_id` (canonical UUID), `file`,
`sha256`, and timezone-qualified `created_at`. Its ciphertext must be exactly
`/var/lib/openbao-maintenance/snapshots/openbao-raft-<UUID>.snap.age`. The
`operations-snapshot-prerequisite.py` wrapper invokes only that fixed producer,
requires successful completion within 240 seconds, validates its receipt at
16 KiB maximum, verifies a regular non-symlink ciphertext no larger than
1 GiB + 32 MiB, hashes its contents, and rejects future or five-minute-old
receipts. These filesystem checks assume root-controlled, non-writable-by-others
helper and parent directories. The stdout check occurs after process capture;
it is not a streaming output limiter. Keep the fixed producer's output limited
to the receipt. The service additionally enforces 256 MiB memory, 20% CPU,
16 tasks, and a 300-second timeout.

Install these exact assets:

| Repository asset | Installed path |
|---|---|
| `snapshot.py` (separately provisioned prerequisite) | `/usr/local/lib/northgate-rmm-openbao/snapshot.py` |
| `operations-snapshot-prerequisite.py` | `/usr/local/lib/northgate-rmm-openbao/operations-snapshot.py` |
| `northgate-rmm-openbao-snapshot.service` | `/etc/systemd/system/northgate-rmm-openbao-snapshot.service` |
| `20-vault-snapshot.conf` | `/etc/systemd/system/northgate-rmm-operations-backup.service.d/20-vault-snapshot.conf` |

The script and unit are root-owned mode 0644. The unit runs as root to read the
separate backup identity and write the private encrypted snapshot. It writes
only `{snapshot_id, sha256, created_at}` atomically to
`/etc/northgate-rmm/operations-openbao-snapshot.json`, mode 0600 owned by
`northgate-rmm-operator`. No token, secret value, recovery key, or snapshot bytes
appear in that metadata receipt or its stdout.

Set this optional field in the existing private operations backup configuration:

```json
"openbao_snapshot_receipt": "/etc/northgate-rmm/operations-openbao-snapshot.json"
```

The drop-in is deliberately `Requires` plus `After`, not an independent timer:

```ini
[Unit]
Requires=northgate-rmm-openbao-snapshot.service
After=northgate-rmm-openbao-snapshot.service
```

The snapshot service is oneshot without `RemainAfterExit`. A later backup start
therefore requests a fresh snapshot. A producer failure, invalid receipt, stale
timestamp, missing ciphertext, or hash mismatch fails the prerequisite and
prevents the operations service from starting. The old metadata file may remain
after a failed prerequisite; its existence is not success. Directly invoking
the operations backup CLI bypasses systemd ordering and does not enforce this
prerequisite's freshness check. Use the service for coordinated backups.

For installation, pause and disable the existing backup timer within the
authorized maintenance window. Build a bundle from the two reviewed source
assets and retain its approved SHA-256 with the release:

```sh
tar -C deploy/openbao -czf operations-backup-link.tgz \
  operations-snapshot-prerequisite.py northgate-rmm-openbao-snapshot.service
sudo python3 deploy/openbao/install-operations-backup-link.py \
  --bundle /absolute/path/operations-backup-link.tgz \
  --bundle-sha256 REVIEWED_BUNDLE_SHA256 \
  --expected-host VERIFIED_SERVER_HOSTNAME \
  --expected-config-sha256 REVIEWED_CURRENT_BACKUP_CONFIG_SHA256
```

Replace the placeholders using the independently reviewed release and current
target inventory. A digest computed from an untrusted received bundle is not
approval. The installer checks the target hostname, original configuration hash,
disabled timer, exact bounded bundle members and unused destination paths. It
retains a private timestamped configuration backup, installs the fixed drop-in,
validates units, and reloads systemd. On installation failure it restores the
prior configuration and removes only files it created. Its receipt contains
public digests, paths and identity labels. It never starts a backup, handles a
vault token, or changes the existing timer schedule.

Qualify with `systemctl start northgate-rmm-operations-backup.service`, then
verify both service results, the new snapshot ID/hash in the operations manifest,
and independently recoverable copies of both encrypted artifacts off-host.
Enable the existing timer only after that qualification. The metadata link does
not copy the encrypted OpenBao snapshot off-host or prove a restore. Vault and
operations snapshots are sequential, not one distributed transaction; coordinate
secret rotations during the backup window and reconcile in-flight rotations
after restore. For the broader recovery procedure see
[operations backup and restore](../../docs/operations-backup-and-restore.md).

To remove this optional dependency, pause the timer, restore the recorded prior
operations configuration (without `openbao_snapshot_receipt`), remove this
installation's drop-in and snapshot unit/wrapper, and reload systemd. Retain
encrypted snapshots and custody material according to the backup policy. Do not
disable OpenBao or delete secret recovery artifacts as part of removing this link.

## Version changes versus device rotation

The interface can save a new provider version, edit its label and remote-use
preference, soft-delete/restore versions, and retire a reference. It deliberately
does not permanently destroy recovery values from the RMM UI.

Saving a provider version does **not** change a password on the endpoint.
Device rotation is unavailable until a qualified executor is supplied. The
executor contract is asynchronous `apply(record, rotation_id, fields, principal)`
and `check(record, rotation_id, job_id, principal)`, using keyword arguments.
Both return `status` (`pending`, `verified`, `failed`, `unknown`) and an optional
UUID `job_id`. `apply` must use `rotation_id` as its durable idempotency key,
bind execution to the current enrollment, and avoid persisting plaintext input
in ordinary job/case receipts. `check` must reconcile the same attempt rather
than dispatch another operation. Only `verified` authorizes promotion of the
staged credential, with an exact expected-version compare-and-set. “Verified”
must mean the new credential has actually authenticated successfully.

An uncertain apply result is retained as `unknown` and only reconciled; a vault
commit conflict remains `commit_conflict` with the staged credential preserved.
The RMM's existing emergency-account rotation generates its own credential and
is not a compatible generic executor without a separately reviewed adapter.

## Recovery result import

With the existing management service supplied to `SecretsAPI`, the Secrets tab
lists completed BitLocker escrow and emergency-account rotation jobs for the
device's current enrollment. Import requires an explicit secret `admin` grant,
MFA within five minutes, the recovery-operator role, and the existing management
and recovery endpoint policies. An RMM owner alone is insufficient.

The server reads the protected worker result and writes it directly into OpenBao:
an emergency account becomes an RDP credential reference with its expiry metadata;
BitLocker passwords become a recovery bundle. No secret values are returned by
the import API, metadata listing, audit events, case records or MCP. Import uses
a stable ID derived from the source job and enrollment and CAS0, so a retry does
not create another provider version. Incomplete provider writes retain a
discoverable reference for reconciliation. Import neither changes the endpoint
credential nor claims to verify a login.

See [typed worker rotation requirements](../../docs/credential-rotation-worker-contract.md)
for the remaining OS executor and independent authentication qualification.

Official references: [KV v2](https://openbao.org/docs/secrets/kv/kv-v2/),
[TLS listener](https://openbao.org/docs/configuration/listener/tcp/),
[Raft configuration](https://openbao.org/docs/configuration/storage/raft/),
[snapshot commands](https://openbao.org/docs/commands/operator/raft/).
