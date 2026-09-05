#!/bin/sh
# Debian Installer only: validate both disks before allowing partitioning.
set -eu
umask 077
test "$(id -u)" -eq 0
test -d /sys/firmware/efi
modprobe tpm_crb 2>/dev/null || true
test -c /dev/tpmrm0 -o -c /dev/tpm0
for required in list-devices blockdev blkid od debconf-set; do command -v "$required" >/dev/null; done
test "$(cat /sys/class/dmi/id/product_uuid | tr A-F a-f)" = "d1c8820e-16d7-42d6-be8f-cbbf41cb04d4"
test "$(list-devices disk | wc -l)" -eq 2
test "$(blockdev --getsize64 /dev/sda)" = 85899345920
test "$(blockdev --getsize64 /dev/sdb)" = 107374182400
# Refuse a restart against partially installed or previously used media.
blank_rc=0; blkid -p /dev/sda >/dev/null 2>&1 || blank_rc=$?
test "$blank_rc" -eq 2
blank_rc=0; blkid -p /dev/sdb >/dev/null 2>&1 || blank_rc=$?
test "$blank_rc" -eq 2
mkdir -m 0700 /run/northgate-rmm-install
od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > /run/northgate-rmm-install/os.key
test "$(wc -c < /run/northgate-rmm-install/os.key)" -eq 64
debconf-set partman-auto/disk /dev/sda
# The passphrase is generated inside installer RAM, never shipped in the ISO.
debconf-set partman-crypto/passphrase "$(cat /run/northgate-rmm-install/os.key)"
debconf-set partman-crypto/passphrase-again "$(cat /run/northgate-rmm-install/os.key)"
