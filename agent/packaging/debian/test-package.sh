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

install -d -m 0755 /run/systemd/system
mv /usr/bin/systemctl /usr/bin/systemctl.real
printf '%s\n' '#!/bin/sh' 'case "$1" in' \
  '  is-active) exit 1 ;;' '  is-enabled) exit 0 ;;' '  disable) touch /tmp/unexpected-disable; exit 0 ;;' \
  '  *) exit 0 ;;' 'esac' > /usr/bin/systemctl
chmod 0755 /usr/bin/systemctl
/var/lib/dpkg/info/northgate-rmm-agent.prerm upgrade 0.2.1
/var/lib/dpkg/info/northgate-rmm-agent.postinst configure 0.1.0
test ! -e /tmp/unexpected-disable

install -o root -g root -m 0600 /dev/null /etc/northgate-rmm/.identity-revoked
install -o root -g root -m 0600 /dev/null /etc/northgate-rmm/.evidence-exported
install -o root -g root -m 0600 /dev/null /etc/northgate-rmm/.purge-approved
: > /run/northgate-rmm-agent.was-active
printf '%s\n' '#!/bin/sh' 'case "$1" in' \
  '  disable) touch /tmp/fresh-disable; exit 0 ;;' \
  '  is-enabled) echo disabled; exit 1 ;;' \
  '  start) touch /tmp/unexpected-start; exit 0 ;;' \
  '  *) exit 0 ;;' 'esac' > /usr/bin/systemctl
chmod 0755 /usr/bin/systemctl
/var/lib/dpkg/info/northgate-rmm-agent.postinst configure
test -e /tmp/fresh-disable
test ! -e /tmp/unexpected-start
test ! -e /run/northgate-rmm-agent.was-active
test ! -e /etc/northgate-rmm/.identity-revoked
test ! -e /etc/northgate-rmm/.evidence-exported
test ! -e /etc/northgate-rmm/.purge-approved

printf '%s\n' '#!/bin/sh' 'case "$1" in' \
  '  is-active) test -e /tmp/upgrade-active ;;' \
  '  stop) rm -f /tmp/upgrade-active; exit 0 ;;' \
  '  *) exit 0 ;;' 'esac' > /usr/bin/systemctl
chmod 0755 /usr/bin/systemctl
: > /tmp/upgrade-active
/var/lib/dpkg/info/northgate-rmm-agent.prerm upgrade 0.2.1
/var/lib/dpkg/info/northgate-rmm-agent.prerm upgrade 0.2.1
test -e /run/northgate-rmm-agent.was-active
printf '%s\n' '#!/bin/sh' 'case "$1" in' \
  '  start) exit 75 ;;' '  *) exit 0 ;;' 'esac' > /usr/bin/systemctl
chmod 0755 /usr/bin/systemctl
if /var/lib/dpkg/info/northgate-rmm-agent.postinst abort-upgrade 0.2.1 >/dev/null 2>&1; then
  echo "aborted upgrade unexpectedly ignored restored-service restart failure" >&2
  exit 1
fi
test -e /run/northgate-rmm-agent.was-active
printf '%s\n' '#!/bin/sh' 'case "$1" in' \
  '  start) touch /tmp/rollback-started; exit 0 ;;' \
  '  is-active) test -e /tmp/rollback-started ;;' \
  '  *) exit 0 ;;' 'esac' > /usr/bin/systemctl
chmod 0755 /usr/bin/systemctl
/var/lib/dpkg/info/northgate-rmm-agent.postinst abort-upgrade 0.2.1
test -e /tmp/rollback-started
test ! -e /run/northgate-rmm-agent.was-active

printf '%s\n' '#!/bin/sh' 'case "$1" in' \
  '  is-active) test -e /tmp/upgrade-active ;;' \
  '  stop) rm -f /tmp/upgrade-active; exit 0 ;;' \
  '  *) exit 0 ;;' 'esac' > /usr/bin/systemctl
chmod 0755 /usr/bin/systemctl
: > /tmp/upgrade-active
/var/lib/dpkg/info/northgate-rmm-agent.prerm upgrade 0.2.1
test -e /run/northgate-rmm-agent.was-active
printf '%s\n' '#!/bin/sh' 'case "$1" in' \
  '  start) exit 75 ;;' '  *) exit 0 ;;' 'esac' > /usr/bin/systemctl
chmod 0755 /usr/bin/systemctl
if /var/lib/dpkg/info/northgate-rmm-agent.postinst configure 0.1.0 >/dev/null 2>&1; then
  echo "upgrade configure unexpectedly ignored restart failure" >&2
  exit 1
fi
test -e /run/northgate-rmm-agent.was-active
printf '%s\n' '#!/bin/sh' 'case "$1" in' \
  '  start) touch /tmp/upgrade-started; exit 0 ;;' \
  '  is-active) test -e /tmp/upgrade-started ;;' \
  '  *) exit 0 ;;' 'esac' > /usr/bin/systemctl
chmod 0755 /usr/bin/systemctl
/var/lib/dpkg/info/northgate-rmm-agent.postinst configure 0.1.0
test -e /tmp/upgrade-started
test ! -e /run/northgate-rmm-agent.was-active
mv /usr/bin/systemctl.real /usr/bin/systemctl
rm -rf -- /run/systemd/system

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
install -d -m 0755 /run/systemd/system
mv /usr/bin/systemctl /usr/bin/systemctl.real
printf '%s\n' '#!/bin/sh' 'case "$1" in' \
  '  is-active) exit 0 ;;' '  stop) exit 75 ;;' '  *) exit 0 ;;' 'esac' > /usr/bin/systemctl
chmod 0755 /usr/bin/systemctl
if dpkg -r northgate-rmm-agent >/dev/null 2>&1; then
  echo "package removal unexpectedly ignored service stop failure" >&2
  exit 1
fi
test -e /usr/libexec/northgate-rmm/northgate-rmm-agent
mv /usr/bin/systemctl.real /usr/bin/systemctl
rm -rf -- /run/systemd/system
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
mv /usr/sbin/deluser /usr/sbin/deluser.real
printf '%s\n' '#!/bin/sh' 'exit 75' > /usr/sbin/deluser
chmod 0755 /usr/sbin/deluser
if dpkg --purge northgate-rmm-agent >/dev/null 2>&1; then
  echo "package purge unexpectedly ignored service-account deletion failure" >&2
  exit 1
fi
mv /usr/sbin/deluser.real /usr/sbin/deluser
test -d /etc/northgate-rmm
test ! -e /var/lib/northgate-rmm
getent passwd northgate-rmm >/dev/null
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
