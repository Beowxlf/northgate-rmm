# Operations and workspace recovery

`python -m northgate_rmm.operations_backup` adds the `northgate-operations-v1`
bundle. Existing core PostgreSQL backups and the legacy management archive remain
compatible and unchanged. This bundle covers operations PostgreSQL records,
completed evidence chunks, selected workspace SQLite databases (including remote
session receipts and secret references), and optional encrypted legacy credentials.
It does not back up OpenBao values or the independent decryption identities.

## Backup consistency and memory

The PostgreSQL connection exports one repeatable-read snapshot. `pg_dump` uses
that exact snapshot for `public.ops_*`; the completed-artifact index is read from
the same transaction. Completed artifact files are immutable. Each encrypted chunk
is read within a 1 MiB bound, authenticated with the existing evidence key, checked
against its chunk hash, and included in the artifact-wide size/hash verification
before its existing encrypted bytes are archived. Orphans and incomplete uploads
are not treated as retained evidence. Incomplete uploads present in the database
snapshot are explicitly cancelled when verifying an isolated restore.

SQLite's online backup API provides consistent individual snapshots. SQLite and
PostgreSQL are separate stores: this does not claim a distributed atomic snapshot
across them. Take an application maintenance window if a case-to-job transaction
must have an exact coordinated cutoff. Preserve the independently backed-up
remote JSON/evidence key and deployment configuration alongside custody records;
neither the key nor offline age identity is placed into this online bundle.
The remote key credential uses the existing service format: 32 hexadecimal
characters representing its 128-bit key, with an optional trailing newline.

`pg_dump` streams to a bounded private staging file. Tar writes directly into
the installed `age` process, encrypted to the public recipient already defined
in `/etc/northgate-rmm/recovery.json`. There is no archive-sized Python byte string
or plaintext tar on backup. A member-count limit, file/index/manifest limits,
archive budget, subprocess deadline and capacity precheck bound resource use.
The manifest contains every archived file's SHA-256 and size. A separate signed
manifest binds the ciphertext hash/size and encrypted manifest hash using the
existing Ed25519 backup signing key. Only a complete successful backup has that
signed completion manifest. Partial directories are retained for diagnosis.

## Installation and backup

Review `deploy/operations-backup.example.json` and the service/timer templates.
The sample selects every current workspace SQLite database. If an optional
feature is not configured, explicitly remove its absent SQLite source; missing
declared components fail the backup rather than silently disappearing. Create a
private backup output directory owned by the service identity. The sample runs as
the current remote-state owner and grants only read access to the state mount;
do not broaden state-file permissions to make another account read them.

The backup database identity needs `SELECT` on all operations tables; see
`deploy/operations-backup-grants.sql`. The existing core dump also includes those
tables after this grant, but only this operations bundle pairs them with verified
completed evidence files and new SQLite snapshots. The systemd job uses separate
loaded credentials for its database and signing key. It never receives an age
decryption identity or OpenBao root/token/unseal secret.

```sh
python -m northgate_rmm.operations_backup --config /etc/northgate-rmm/operations-backup.json \
  backup-auto /var/backups/northgate-rmm-operations
```

Copy successful encrypted archives and signed manifests off-host using the
existing backup custodian. Keep a dated ledger linking core, management/workspace
and OpenBao recovery artifacts. A local archive is not proof of off-host recovery.

## Isolated restore verification

Use a separate protected restore configuration with `isolated_restore: true`, an
independently pinned `manifest_public_key`, offline `recovery_identity`, preserved
`remote_key_credential`, and a dedicated database credential whose database name
begins `northgate_restore_`. The database must exist and have an empty public
schema. The configuration's `remote_root` remains an existing trusted directory;
the restore destination is a separate new absolute directory and must not exist.

```sh
python -m northgate_rmm.operations_backup --config /protected/restore-config.json \
  verify-restore /protected/backup-set /protected/new-restore-directory
```

Verification checks the independent signature and ciphertext before creating the
destination, then decrypts into bounded private disk staging. It extracts only
fixed allowlisted regular-file names, with no symlink/hardlink/path traversal or
existing-file overwrite. It verifies all member hashes, SQLite integrity, the
isolated PostgreSQL restore, the exact completed-artifact index and chunk/aggregate
plaintext hashes again. It writes `restore-verification.json` only after success.
It does not reconnect services, overwrite live paths, restore over a nonempty
database, or bypass an independent audit gate. Failed isolated state is retained
without a verification marker for reconciliation.

## Independent OpenBao snapshot linkage

OpenBao values require their own Raft snapshot, compatible seal configuration and
independent unseal custody. The RMM application token must not gain snapshot or
restore authority. The vault backup custodian can supply a private JSON receipt
with exactly `snapshot_id` (UUID), `sha256` (lowercase hexadecimal SHA-256 of the
custodied snapshot artifact) and timezone-bearing `created_at`. Set
`openbao_snapshot_receipt` to its path to bind that reference into both manifests.

This is a linkage record, not a copy or proof of a restored OpenBao snapshot. A
missing linkage is recorded as null. Qualify the independent provider restore
and then reconcile secret references, provider versions and pending rotations;
a restored older vault version may differ from a device's current password.
See [OpenBao recovery](../deploy/openbao/README.md) for custody and restore steps.

Unit tests use a transparent archive transport and a synthetic database snapshot
to exercise streaming packaging, hashes, custody, integrity failures and restore
path rejection. Deployment qualification must additionally use the real installed
age and PostgreSQL tools and an actual isolated database restore.
