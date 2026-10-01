"""Publish a fresh metadata-only vault snapshot link before an operations backup."""
import datetime
import hashlib
import json
import os
import pwd
import subprocess
import tempfile
from pathlib import Path
from uuid import UUID

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

root = Path('/var/lib/openbao-maintenance/snapshots')
destination = Path('/etc/northgate-rmm/operations-openbao-snapshot.json')
result = subprocess.run(
    ['/usr/bin/python3', '/usr/local/lib/northgate-rmm-openbao/snapshot.py'],
    check=True, capture_output=True, timeout=240,
)
if len(result.stdout) > 16384:
    raise RuntimeError('Snapshot receipt exceeded its bound')
detail = json.loads(result.stdout)
identifier = str(UUID(detail['snapshot_id']))
require(detail['snapshot_id'] == identifier, 'Snapshot identity is not canonical')
snapshot = root / ('openbao-raft-' + identifier + '.snap.age')
require(snapshot.is_file() and not snapshot.is_symlink(), 'Snapshot must be a regular file')
require(snapshot.stat().st_size <= 1024**3 + 32*1024**2, 'Snapshot exceeds capacity bound')
require(detail['file'] == str(snapshot), 'Snapshot path does not match its identity')
with snapshot.open('rb') as stream:
    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
require(digest == detail['sha256'], 'Snapshot ciphertext hash mismatch')
created = datetime.datetime.fromisoformat(detail['created_at'].replace('Z', '+00:00'))
require(created.tzinfo and 0 <= (datetime.datetime.now(datetime.timezone.utc)-created).total_seconds() < 300, 'Snapshot receipt is not fresh')
receipt = {name: detail[name] for name in ('snapshot_id','sha256','created_at')}
account = pwd.getpwnam('northgate-rmm-operator')
descriptor, name = tempfile.mkstemp(prefix='.operations-vault-link-', dir=destination.parent)
try:
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(receipt, stream)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(name, 0o600)
    os.chown(name, account.pw_uid, account.pw_gid)
    os.replace(name, destination)
    directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    if os.path.exists(name):
        os.unlink(name)
print(json.dumps(receipt))
