#!/bin/sh
# Optional enrollment profile: enroll the monitoring agent, then install its capture capability.
set -eu
[ "$(id -u)" = 0 ] || exit 1
[ "$#" = 9 ] || { echo 'Usage: enroll-with-tools.sh CONFIG ORIGIN GRANT SERVER_ROOTS ISSUER_ROOTS WXLF_BINARY WXLF_SHA256 RMM_PUBLIC_KEY AGENT_BINARY' >&2; exit 2; }
config=$1; origin=$2; grant=$3; server_roots=$4; issuer_roots=$5; wxlf_binary=$6; wxlf_sha=$7; public_key=$8; agent_binary=$9
if systemctl is-active --quiet northgate-rmm-agent; then echo 'Stop the agent before first enrollment' >&2; exit 1; fi
[ ! -e /var/lib/northgate-rmm/identity ] || { echo 'Existing enrollment requires reconciliation' >&2; exit 1; }
stage=$(mktemp -d /run/northgate-rmm-enrollment.XXXXXX)
cleanup(){ rm -f -- "$stage/grant" "$stage/server.pem" "$stage/issuer.pem" "$stage/tool-public.json"; rmdir -- "$stage"; }
trap cleanup EXIT
chown root:northgate-rmm "$stage"; chmod 0750 "$stage"
install -o northgate-rmm -g northgate-rmm -m 0600 "$grant" "$stage/grant"
install -o northgate-rmm -g northgate-rmm -m 0600 "$server_roots" "$stage/server.pem"
install -o northgate-rmm -g northgate-rmm -m 0600 "$issuer_roots" "$stage/issuer.pem"
runuser -u northgate-rmm -- "$agent_binary" --config "$config" --enroll "$origin" --grant-file "$stage/grant" --server-roots "$stage/server.pem" --issuer-roots "$stage/issuer.pem"
python3 - "$public_key" "$stage/tool-public.json" <<'PY'
import base64,json,sys
from pathlib import Path
assert len(base64.b64decode(sys.argv[1],validate=True))==32
Path(sys.argv[2]).write_text(json.dumps({'public_key':sys.argv[1],'endpoint_id':'','identity_id':''}))
PY
sh "$(dirname "$0")/../tools/install-linux.sh" "$wxlf_binary" "$wxlf_sha" "$stage/tool-public.json"
echo 'Enrollment and capture tool installation finished. Monitoring remains stopped for acceptance; capture is off.'
