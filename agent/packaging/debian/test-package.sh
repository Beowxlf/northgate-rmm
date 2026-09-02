#!/bin/sh
set -eu

package="${1:?package path is required}"

awk -F: 'NR > 2 {gsub(/[[:space:]]/, "", $1); if ($1 != "lo") exit 1}' /proc/net/dev
dpkg-deb --info "$package" >/dev/null
dpkg -i "$package" >/dev/null

test "$(stat -c '%U:%G:%a' /usr/libexec/northgate-rmm/northgate-rmm-agent)" = "root:root:755"
test "$(stat -c '%U:%G:%a' /usr/lib/systemd/system/northgate-rmm-agent.service)" = "root:root:644"
test "$(stat -c '%U:%G:%a' /etc/northgate-rmm)" = "root:root:755"
test "$(stat -c '%U:%G:%a' /var/lib/northgate-rmm)" = "northgate-rmm:northgate-rmm:700"
test ! -e /etc/northgate-rmm/agent.json
test "$(systemctl is-enabled northgate-rmm-agent.service 2>/dev/null || true)" = "disabled"
systemd-analyze verify /usr/lib/systemd/system/northgate-rmm-agent.service
test "$(su --shell /bin/sh --command '/usr/libexec/northgate-rmm/northgate-rmm-agent --version' northgate-rmm)" = "0.2.0"
if su --shell /bin/sh --command 'touch /etc/northgate-rmm/.purge-approved' northgate-rmm 2>/dev/null; then
  echo "service account created a purge approval marker" >&2
  exit 1
fi
if su --shell /bin/sh --command 'touch /etc/northgate-rmm/.identity-revoked' northgate-rmm 2>/dev/null; then
  echo "service account created a revocation receipt" >&2
  exit 1
fi

install -d -o northgate-rmm -g northgate-rmm -m 0700 /var/lib/northgate-rmm/identity
install -o northgate-rmm -g northgate-rmm -m 0600 /dev/null /var/lib/northgate-rmm/identity/identity.json
if dpkg -r northgate-rmm-agent >/dev/null 2>&1; then
  echo "package removal unexpectedly ignored retained identity" >&2
  exit 1
fi
rm -f /var/lib/northgate-rmm/identity/identity.json
if dpkg -r northgate-rmm-agent >/dev/null 2>&1; then
  echo "package removal unexpectedly accepted missing identity as revocation proof" >&2
  exit 1
fi
: > /etc/northgate-rmm/.identity-revoked
chown root:root /etc/northgate-rmm/.identity-revoked
chmod 0600 /etc/northgate-rmm/.identity-revoked
if dpkg -r northgate-rmm-agent >/dev/null 2>&1; then
  echo "package removal unexpectedly accepted an empty revocation receipt" >&2
  exit 1
fi
printf '%s\n' 'synthetic sandbox revocation receipt' > /etc/northgate-rmm/.identity-revoked
chown root:root /etc/northgate-rmm/.identity-revoked
chmod 0600 /etc/northgate-rmm/.identity-revoked
dpkg -r northgate-rmm-agent >/dev/null
test ! -e /usr/libexec/northgate-rmm/northgate-rmm-agent
test ! -e /usr/lib/systemd/system/northgate-rmm-agent.service
test -d /etc/northgate-rmm
test -d /var/lib/northgate-rmm
getent passwd northgate-rmm >/dev/null

if dpkg --purge northgate-rmm-agent >/dev/null 2>&1; then
  echo "package purge unexpectedly ignored approval and evidence gates" >&2
  exit 1
fi
install -d -o northgate-rmm -g northgate-rmm -m 0700 /var/lib/northgate-rmm/spool
install -d -o northgate-rmm -g northgate-rmm -m 0700 /var/lib/northgate-rmm/spool/rejected
install -d -o northgate-rmm -g northgate-rmm -m 0700 /var/lib/northgate-rmm/sequence
install -o northgate-rmm -g northgate-rmm -m 0600 /dev/null /var/lib/northgate-rmm/spool/.lock
install -o northgate-rmm -g northgate-rmm -m 0600 /dev/null /var/lib/northgate-rmm/spool/queued.json
install -o northgate-rmm -g northgate-rmm -m 0600 /dev/null /var/lib/northgate-rmm/spool/rejected/expired.json
install -o northgate-rmm -g northgate-rmm -m 0600 /dev/null /var/lib/northgate-rmm/sequence/state.json
install -o root -g root -m 0600 /dev/null /etc/northgate-rmm/.purge-approved
install -o root -g root -m 0600 /dev/null /etc/northgate-rmm/.evidence-exported
dpkg --purge northgate-rmm-agent >/dev/null
test ! -e /etc/northgate-rmm
test ! -e /var/lib/northgate-rmm
if getent passwd northgate-rmm >/dev/null; then
  echo "service account remains after approved purge" >&2
  exit 1
fi

addgroup --system --quiet northgate-rmm
adduser --system --quiet --ingroup northgate-rmm --home /var/lib/northgate-rmm \
  --no-create-home --shell /usr/sbin/nologin --disabled-password northgate-rmm
adduser northgate-rmm daemon >/dev/null
if dpkg -i "$package" >/dev/null 2>&1; then
  echo "package accepted a pre-existing service account with supplementary access" >&2
  exit 1
fi

printf '%s\n' "isolated Debian package lifecycle passed"
