#!/bin/sh
set -eu

base_package="${1:?base package path is required}"
upgrade_package="${2:?upgrade package path is required}"
failed_upgrade_package="${3:?failed-upgrade package path is required}"
identity_fixture="${4:?identity fixture path is required}"
result_file="${5:?result file path is required}"
endpoint_id=00000000-0000-4000-8000-000000000002
unit=northgate-rmm-agent.service

fail() {
  printf '%s\n' "G2A qualification failed: $*" >&2
  exit 1
}

wait_for_state() {
  expected="$1"
  attempts="$2"
  while [ "$attempts" -gt 0 ]; do
    state="$(systemctl is-active "$unit" 2>/dev/null || true)"
    if [ "$state" = "$expected" ]; then
      return 0
    fi
    attempts=$((attempts - 1))
    sleep 1
  done
  return 1
}

test "$(ps -p 1 -o comm= | tr -d ' ')" = systemd || fail "systemd is not PID 1"
awk -F: 'NR > 2 {gsub(/[[:space:]]/, "", $1); if ($1 != "lo") exit 1}' /proc/net/dev ||
  fail "qualification sandbox has a non-loopback interface"

dpkg -i "$base_package" >/dev/null
test "$(systemctl is-enabled "$unit" 2>/dev/null || true)" = disabled ||
  fail "fresh installation did not leave the service disabled"
test "$(systemctl is-active "$unit" 2>/dev/null || true)" = inactive ||
  fail "fresh installation unexpectedly started the service"

config_temp="$(mktemp)"
cat >"$config_temp" <<EOF
{
  "endpoint_id": "$endpoint_id",
  "control_plane_url": "https://127.0.0.1:8443/",
  "state_directory": "/var/lib/northgate-rmm",
  "collection_interval": "5m",
  "request_timeout": "2s",
  "max_spool_bytes": 1048576
}
EOF
install -o root -g northgate-rmm -m 0640 "$config_temp" /etc/northgate-rmm/agent.json
rm -f "$config_temp"
runuser -u northgate-rmm -- "$identity_fixture" \
  /var/lib/northgate-rmm/identity "$endpoint_id"
test "$(stat -c '%U:%G:%a' /var/lib/northgate-rmm/identity)" = \
  northgate-rmm:northgate-rmm:700 || fail "identity directory permissions differ"
test "$(stat -c '%U:%G:%a' /var/lib/northgate-rmm/identity/identity.json)" = \
  northgate-rmm:northgate-rmm:600 || fail "identity bundle permissions differ"

config_hash="$(sha256sum /etc/northgate-rmm/agent.json | cut -d' ' -f1)"
identity_hash="$(sha256sum /var/lib/northgate-rmm/identity/identity.json | cut -d' ' -f1)"
systemctl enable --now "$unit" >/dev/null
wait_for_state active 15 || fail "agent did not become active"
sleep 5
wait_for_state active 1 || fail "agent did not remain active after its first cycle"

test "$(systemctl show "$unit" -p User --value)" = northgate-rmm || fail "service user differs"
test "$(systemctl show "$unit" -p Group --value)" = northgate-rmm || fail "service group differs"
test "$(systemctl show "$unit" -p NoNewPrivileges --value)" = yes || fail "NoNewPrivileges is off"
test "$(systemctl show "$unit" -p ProtectSystem --value)" = strict || fail "ProtectSystem differs"
test "$(systemctl show "$unit" -p ProtectHome --value)" = yes || fail "ProtectHome is off"
test "$(systemctl show "$unit" -p PrivateTmp --value)" = yes || fail "PrivateTmp is off"
test "$(systemctl show "$unit" -p PrivateDevices --value)" = yes || fail "PrivateDevices is off"
test "$(systemctl show "$unit" -p MemoryDenyWriteExecute --value)" = yes ||
  fail "MemoryDenyWriteExecute is off"
test "$(systemctl show "$unit" -p MemoryMax --value)" = 134217728 || fail "MemoryMax differs"
test "$(systemctl show "$unit" -p TasksMax --value)" = 64 || fail "TasksMax differs"
test "$(systemctl show "$unit" -p LimitNOFILE --value)" = 1024 || fail "LimitNOFILE differs"

pid="$(systemctl show "$unit" -p MainPID --value)"
case "$pid" in
  ''|*[!0-9]*|0) fail "service PID is invalid" ;;
esac
test "$(ps -o user= -p "$pid" | tr -d ' ')" = northgate-rmm || fail "process user differs"
test "$(awk '/^NoNewPrivs:/ {print $2}' "/proc/$pid/status")" = 1 || fail "process may gain privilege"
test "$(awk '/^CapEff:/ {print $2}' "/proc/$pid/status")" = 0000000000000000 ||
  fail "process has effective capabilities"
test "$(awk '/^CapBnd:/ {print $2}' "/proc/$pid/status")" = 0000000000000000 ||
  fail "process has a capability bounding set"

memory_current="$(systemctl show "$unit" -p MemoryCurrent --value)"
tasks_current="$(systemctl show "$unit" -p TasksCurrent --value)"
cpu_usage_nsec="$(systemctl show "$unit" -p CPUUsageNSec --value)"
fd_count="$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 | wc -l)"
spool_bytes="$(du -sb /var/lib/northgate-rmm/spool | cut -f1)"
journal_records="$(journalctl -u "$unit" --no-pager -o cat | grep -c '"component"' || true)"
case "$memory_current:$tasks_current:$cpu_usage_nsec:$fd_count:$spool_bytes:$journal_records" in
  *[!0-9:]*) fail "resource observation contains a nonnumeric value" ;;
esac
test "$memory_current" -le 134217728 || fail "observed memory exceeded MemoryMax"
test "$tasks_current" -le 64 || fail "observed tasks exceeded TasksMax"
test "$fd_count" -le 1024 || fail "observed descriptors exceeded LimitNOFILE"
test "$journal_records" -ge 2 || fail "structured lifecycle and collection events were not journaled"

dpkg -i "$upgrade_package" >/dev/null
wait_for_state active 15 || fail "service did not restart after upgrade"
test "$(systemctl is-enabled "$unit")" = enabled || fail "upgrade lost enablement"
test "$(/usr/libexec/northgate-rmm/northgate-rmm-agent --version)" = 0.2.1 ||
  fail "upgrade did not install the expected executable"
test "$(sha256sum /etc/northgate-rmm/agent.json | cut -d' ' -f1)" = "$config_hash" ||
  fail "upgrade changed configuration"
test "$(sha256sum /var/lib/northgate-rmm/identity/identity.json | cut -d' ' -f1)" = "$identity_hash" ||
  fail "upgrade changed identity"

if dpkg -i "$failed_upgrade_package" >/dev/null 2>&1; then
  fail "injected failed upgrade unexpectedly succeeded"
fi
wait_for_state active 15 || fail "service was not recovered after the failed upgrade"
test "$(dpkg-query -W -f='${Version}' northgate-rmm-agent)" = 0.2.1 ||
  fail "failed upgrade changed the installed package version"
test ! -e /run/northgate-rmm-agent.was-active || fail "failed upgrade left a restart marker"
test "$(sha256sum /etc/northgate-rmm/agent.json | cut -d' ' -f1)" = "$config_hash" ||
  fail "failed upgrade changed configuration"
test "$(sha256sum /var/lib/northgate-rmm/identity/identity.json | cut -d' ' -f1)" = "$identity_hash" ||
  fail "failed upgrade changed identity"

install -d -m 0755 /etc/systemd/system/northgate-rmm-agent.service.d
cat >/etc/systemd/system/northgate-rmm-agent.service.d/g2a-restart.conf <<'EOF'
[Unit]
StartLimitIntervalSec=10
StartLimitBurst=3

[Service]
RestartSec=100ms
EOF
cp /etc/northgate-rmm/agent.json /qualification/agent.json.valid
printf '%s\n' '{"invalid":true}' >/etc/northgate-rmm/agent.json
chown root:northgate-rmm /etc/northgate-rmm/agent.json
chmod 0640 /etc/northgate-rmm/agent.json
systemctl daemon-reload
systemctl restart "$unit" >/dev/null 2>&1 || true
wait_for_state failed 20 || fail "restart storm did not reach a bounded failed state"
restart_result="$(systemctl show "$unit" -p Result --value)"
restart_count="$(systemctl show "$unit" -p NRestarts --value)"
test "$restart_result" = start-limit-hit || fail "restart bound result was $restart_result"
case "$restart_count" in
  ''|*[!0-9]*) fail "restart count is invalid" ;;
esac
test "$restart_count" -ge 2 || fail "restart bound did not exercise retries"
install -o root -g northgate-rmm -m 0640 /qualification/agent.json.valid \
  /etc/northgate-rmm/agent.json
rm -f /qualification/agent.json.valid
rm -f /etc/systemd/system/northgate-rmm-agent.service.d/g2a-restart.conf
rmdir /etc/systemd/system/northgate-rmm-agent.service.d
systemctl daemon-reload
systemctl reset-failed "$unit"
systemctl start "$unit"
wait_for_state active 15 || fail "service did not recover after restart-bound test"

systemctl stop "$unit"
systemctl disable "$unit" >/dev/null
rm -f /var/lib/northgate-rmm/identity/identity.json
printf '%s\n' 'synthetic G2A revocation receipt' >/etc/northgate-rmm/.identity-revoked
chown root:root /etc/northgate-rmm/.identity-revoked
chmod 0600 /etc/northgate-rmm/.identity-revoked
dpkg -r northgate-rmm-agent >/dev/null
test ! -e /usr/libexec/northgate-rmm/northgate-rmm-agent || fail "removal retained executable"
test -d /etc/northgate-rmm || fail "removal deleted configuration"
test -d /var/lib/northgate-rmm || fail "removal deleted retained state"
getent passwd northgate-rmm >/dev/null || fail "removal deleted service identity"

install -o root -g root -m 0600 /dev/null /etc/northgate-rmm/.evidence-exported
install -o root -g root -m 0600 /dev/null /etc/northgate-rmm/.purge-approved
dpkg --purge northgate-rmm-agent >/dev/null
test ! -e /etc/northgate-rmm || fail "purge retained configuration"
test ! -e /var/lib/northgate-rmm || fail "purge retained service state"
if getent passwd northgate-rmm >/dev/null; then
  fail "purge retained service identity"
fi
test "$(cat /var/lib/northgate-rmm-purge-transaction)" = \
  northgate-rmm-purge-transaction-v1:authorized || fail "purge recovery transaction differs"
test "$(stat -c '%U:%G:%a' /var/lib/northgate-rmm-purge-transaction)" = root:root:600 ||
  fail "purge recovery transaction permissions differ"

base_sha256="$(sha256sum "$base_package" | cut -d' ' -f1)"
upgrade_sha256="$(sha256sum "$upgrade_package" | cut -d' ' -f1)"
cat >"$result_file" <<EOF
{
  "schema_version": 1,
  "gate": "G2A",
  "result": "passed",
  "os": "Debian GNU/Linux 12",
  "systemd_pid1": true,
  "network_interfaces": ["lo"],
  "base_package_sha256": "$base_sha256",
  "upgrade_package_sha256": "$upgrade_sha256",
  "service_user": "northgate-rmm",
  "memory_current_bytes": $memory_current,
  "memory_max_bytes": 134217728,
  "tasks_current": $tasks_current,
  "tasks_max": 64,
  "open_file_descriptors": $fd_count,
  "open_file_descriptor_limit": 1024,
  "cpu_usage_nanoseconds": $cpu_usage_nsec,
  "spool_bytes": $spool_bytes,
  "structured_journal_records": $journal_records,
  "restart_attempts_before_bound": $restart_count,
  "restart_result": "$restart_result",
  "upgrade_recovery": "passed",
  "revocation_removal": "passed",
  "approved_purge": "passed"
}
EOF

printf '%s\n' "G2A full-system Debian qualification passed"
