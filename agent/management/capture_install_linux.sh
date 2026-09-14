#!/bin/sh
set -eu
binary=$1
expected=$2
config=$3
test "$(id -u)" = 0
test -x /usr/bin/apt-get || { echo 'This installer supports Debian/Ubuntu package dependencies.'; exit 1; }
# Validate existing identity before modifying packages or touching the service.
python3 - "$config" <<'PY'
import json,os,sys
from pathlib import Path
expected=json.loads(Path(sys.argv[1]).read_text())
paths=[Path('/etc/northgate-wxlfgar'),Path('/usr/local/libexec/northgate-wxlfgar'),Path('/var/lib/northgate-wxlfgar')]
for p in paths:
 for component in [p,*p.parents]:
  if component.is_symlink():raise RuntimeError('Symlink installation path rejected')
if any(p.exists() for p in paths):
 p=paths[0]/'config.json'
 if p.is_symlink() or not p.is_file():raise RuntimeError('Partial installation needs reconciliation; existing data retained')
 actual=json.loads(p.read_text())
 if any(actual.get(k)!=expected[k] for k in ('endpoint_id','identity_id','public_key')):raise RuntimeError('Existing capture identity differs; existing data retained')
 if (paths[1]/'wulfgar').is_symlink() or not (paths[1]/'wulfgar').is_file():raise RuntimeError('Partial installation needs reconciliation; existing data retained')
PY
echo 'Installing capture dependencies...'
/usr/bin/apt-get -o DPkg::Lock::Timeout=60 update
/usr/bin/apt-get -o DPkg::Lock::Timeout=60 -y install wireshark-common
if [ ! -f /usr/local/libexec/northgate-wxlfgar/wulfgar ]; then
 echo 'Installing Wxlfgar and its dedicated service...'
 /bin/sh "$(dirname "$0")/install-linux.sh" "$binary" "$expected" "$config"
else
 echo 'Wxlfgar is already installed; preserving its configuration and captures.'
 systemctl start northgate-wxlfgar
fi
systemctl is-active --quiet northgate-wxlfgar
test -x /usr/bin/dumpcap
echo 'Installation completed. Refresh capture readiness to verify available interfaces. Capture remains off.'
