#!/bin/sh
# Install after enrollment; dependency installation is a separate explicit package step.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root' >&2; exit 1; }
[ "$#" = 3 ] || { echo 'Usage: install-linux.sh BINARY EXPECTED_SHA256 PUBLIC_CONFIG_JSON' >&2; exit 2; }
binary=$1
expected=$2
configuration=$3
case "$expected" in *[!a-fA-F0-9]*|'') exit 2;; esac
[ "${#expected}" = 64 ] || exit 2
expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
[ "$(sha256sum "$binary" | cut -d ' ' -f 1)" = "$expected" ] || { echo 'Tool checksum mismatch' >&2; exit 1; }
[ ! -e /etc/northgate-wxlfgar ] && [ ! -e /usr/local/libexec/northgate-wxlfgar ] && [ ! -e /var/lib/northgate-wxlfgar ] || { echo 'Existing tool requires controlled upgrade/reconciliation' >&2; exit 1; }
getent passwd northgate-wxlfgar >/dev/null || useradd --system --user-group --home-dir /var/lib/northgate-wxlfgar --shell /usr/sbin/nologin northgate-wxlfgar
tool_uid=$(id -u northgate-wxlfgar)
tool_gid=$(id -g northgate-wxlfgar)
[ "$tool_uid" -ge 100 ] && [ "$tool_uid" -lt 1000 ] && [ "$tool_gid" -gt 0 ] || { echo 'Unsafe tool account identity' >&2; exit 1; }
[ "$(id -G northgate-wxlfgar)" = "$tool_gid" ] || { echo 'Tool account has unexpected supplementary groups' >&2; exit 1; }
[ "$(getent passwd northgate-wxlfgar | cut -d: -f6-7)" = '/var/lib/northgate-wxlfgar:/usr/sbin/nologin' ] || { echo 'Tool account is not the dedicated service identity' >&2; exit 1; }
install -d -o root -g northgate-wxlfgar -m 0750 /etc/northgate-wxlfgar
install -d -o root -g root -m 0755 /usr/local/libexec/northgate-wxlfgar
install -o root -g root -m 0755 "$binary" /usr/local/libexec/northgate-wxlfgar/wulfgar
[ "$(sha256sum /usr/local/libexec/northgate-wxlfgar/wulfgar | cut -d ' ' -f 1)" = "$expected" ] || { echo 'Installed checksum mismatch' >&2; exit 1; }
python3 - "$configuration" <<'PY'
import base64,json,os,sys,uuid
from pathlib import Path
cfg=json.loads(Path(sys.argv[1]).read_text())
identity=json.loads(Path('/var/lib/northgate-rmm/identity/identity.json').read_text())
endpoint=str(uuid.UUID(identity['endpoint_id']))
assert not cfg.get('endpoint_id') or cfg['endpoint_id']==endpoint
assert len(base64.b64decode(cfg['public_key'],validate=True))==32
cfg.update(endpoint_id=endpoint,identity_id=cfg.get('identity_id',''),root='/var/lib/northgate-wxlfgar',dumpcap='/usr/bin/dumpcap')
if cfg['identity_id']:uuid.UUID(cfg['identity_id'])
p=Path('/etc/northgate-wxlfgar/config.json');p.write_text(json.dumps(cfg));p.chmod(0o640)
PY
chown root:northgate-wxlfgar /etc/northgate-wxlfgar/config.json
install -o root -g root -m 0644 "$(dirname "$0")/northgate-wxlfgar.service" /etc/systemd/system/northgate-wxlfgar.service
systemctl daemon-reload
systemctl enable --now northgate-wxlfgar.service
echo 'Wxlfgar installed; capture remains off. Install the distribution dumpcap package if capability discovery reports a missing dependency.'
