#!/bin/sh
set -eu

package="${1:?package path is required}"
agent_package="${2:?endpoint agent package path is required}"

awk -F: 'NR > 2 {gsub(/[[:space:]]/, "", $1); if ($1 != "lo") exit 1}' /proc/net/dev
dpkg-deb --info "$package" >/dev/null
dpkg-deb --info "$agent_package" >/dev/null
dpkg -i "$agent_package" >/dev/null
dpkg -i "$package" >/dev/null

test "$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')" = "3.11"
test "$(stat -c '%U:%G:%a' /usr/lib/northgate-rmm-server/site-packages)" = "root:root:755"
test "$(stat -c '%U:%G:%a' /etc/northgate-rmm/secrets)" = "root:root:700"
for service in agent enrollment operator; do
  identity="northgate-rmm-$service"
  unit="northgate-rmm-${service}.service"
  if [ "$service" = "agent" ]; then
    unit=northgate-rmm-agent-ingress.service
  fi
  launcher="/usr/libexec/northgate-rmm-server/northgate-rmm-${service}-service"
  test "$(stat -c '%U:%G:%a' "$launcher")" = "root:root:755"
  test "$(stat -c '%U:%G:%a' "/usr/lib/systemd/system/$unit")" = "root:root:644"
  test "$(stat -c '%U:%G:%a' "/var/lib/northgate-rmm-server/$service")" = "$identity:$identity:700"
  test "$(id -Gn "$identity")" = "$identity"
  test "$(systemctl is-enabled "$unit" 2>/dev/null || true)" = "disabled"
  PYTHONPATH=/tmp su --shell /bin/sh --command "$launcher --help >/dev/null" "$identity"
  if su --shell /bin/sh --command "touch /etc/northgate-rmm/.unexpected" "$identity" 2>/dev/null; then
    echo "$identity modified protected configuration" >&2
    exit 1
  fi
  if su --shell /bin/sh --command "touch /usr/lib/northgate-rmm-server/.unexpected" "$identity" 2>/dev/null; then
    echo "$identity modified packaged code" >&2
    exit 1
  fi
done
test "$(for service in agent enrollment operator; do id -u "northgate-rmm-$service"; done | sort -u | wc -l)" = "3"
systemd-analyze verify \
  /usr/lib/systemd/system/northgate-rmm-agent-ingress.service \
  /usr/lib/systemd/system/northgate-rmm-enrollment.service \
  /usr/lib/systemd/system/northgate-rmm-operator.service
test -e /usr/libexec/northgate-rmm/northgate-rmm-agent
test -e /usr/lib/systemd/system/northgate-rmm-agent.service

python3 - <<'PY'
import importlib.metadata

expected = {
    "aiohappyeyeballs": "2.7.1",
    "aiohttp": "3.14.3",
    "aiosignal": "1.4.0",
    "attrs": "26.1.0",
    "cffi": "2.1.1",
    "cryptography": "50.0.1",
    "frozenlist": "1.8.0",
    "idna": "3.19",
    "multidict": "6.7.1",
    "northgate-rmm": "0.1.0.dev0",
    "propcache": "0.5.2",
    "psycopg": "3.3.4",
    "psycopg-binary": "3.3.4",
    "pycparser": "3.0",
    "typing_extensions": "4.16.0",
    "yarl": "1.24.5",
}
root = "/usr/lib/northgate-rmm-server/site-packages"
actual = {
    distribution.metadata["Name"].lower(): distribution.version
    for distribution in importlib.metadata.distributions(path=[root])
}
if actual != expected:
    raise SystemExit(f"packaged runtime mismatch: {actual!r}")
PY

install -d -m 0755 /run/systemd/system
mv /usr/bin/systemctl /usr/bin/systemctl.real
printf '%s\n' '#!/bin/sh' \
  'if [ "$1" = is-active ] && [ "$3" = northgate-rmm-operator.service ]; then exit 0; fi' \
  'exit 1' > /usr/bin/systemctl
chmod 0755 /usr/bin/systemctl
if /var/lib/dpkg/info/northgate-rmm-server.preinst install >/dev/null 2>&1; then
  echo "server package installation ignored an active service" >&2
  exit 1
fi
if /var/lib/dpkg/info/northgate-rmm-server.prerm upgrade 0.1.1 >/dev/null 2>&1; then
  echo "server package upgrade ignored an active service" >&2
  exit 1
fi
mv /usr/bin/systemctl.real /usr/bin/systemctl
rm -rf -- /run/systemd/system

printf '%s\n' 'retained endpoint agent configuration' > /etc/northgate-rmm/agent.json
for receipt in .identity-revoked .evidence-exported .purge-approved; do
  printf '%s\n' "retained endpoint agent $receipt" > "/etc/northgate-rmm/$receipt"
done
if dpkg -r northgate-rmm-server >/dev/null 2>&1; then
  echo "server package removal ignored missing revocation/evidence receipts" >&2
  exit 1
fi
for receipt in \
  .server-identities-revoked \
  .server-evidence-exported \
  .server-purge-approved; do
  printf '%s\n' "synthetic isolated-package $receipt receipt" > "/etc/northgate-rmm/$receipt"
  chown root:root "/etc/northgate-rmm/$receipt"
  chmod 0600 "/etc/northgate-rmm/$receipt"
done
dpkg -r northgate-rmm-server >/dev/null
test ! -e /usr/lib/northgate-rmm-server
test ! -e /usr/libexec/northgate-rmm-server
test -d /etc/northgate-rmm
for service in agent enrollment operator; do
  getent passwd "northgate-rmm-$service" >/dev/null
done

dpkg --purge northgate-rmm-server >/dev/null
test "$(cat /etc/northgate-rmm/agent.json)" = "retained endpoint agent configuration"
test -e /etc/northgate-rmm/agent.json.example
test -e /usr/libexec/northgate-rmm/northgate-rmm-agent
test -e /usr/lib/systemd/system/northgate-rmm-agent.service
test "$(dpkg-query -W -f='${Status}' northgate-rmm-agent)" = "install ok installed"
for receipt in .identity-revoked .evidence-exported .purge-approved; do
  test -f "/etc/northgate-rmm/$receipt"
done
test ! -e /etc/northgate-rmm/.server-identities-revoked
test ! -e /etc/northgate-rmm/.server-evidence-exported
test ! -e /etc/northgate-rmm/.server-purge-approved
test ! -e /var/lib/northgate-rmm-server
test "$(cat /var/lib/northgate-rmm-server-purge-transaction)" = \
  "northgate-rmm-server-purge-v1:authorized"
test "$(stat -c '%U:%G:%a' /var/lib/northgate-rmm-server-purge-transaction)" = \
  "root:root:600"
for service in agent enrollment operator; do
  if getent passwd "northgate-rmm-$service" >/dev/null; then
    echo "server service identity remains after purge" >&2
    exit 1
  fi
done
