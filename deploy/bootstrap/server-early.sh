#!/bin/sh
# Debian Installer only: validate both disks before allowing partitioning.
set -eu
umask 077
test "$(id -u)" -eq 0
test -d /sys/firmware/efi
test -c /dev/tpmrm0 -o -c /dev/tpm0
test "$(cat /sys/class/dmi/id/product_uuid | tr A-F a-f)" = "fd5c00e3-e90d-4730-8e27-819585e7aaaa"
test "$(list-devices disk | wc -l)" -eq 2
test "$(blockdev --getsize64 /dev/sda)" = 85899345920
test "$(blockdev --getsize64 /dev/sdb)" = 107374182400
# Refuse a restart against partially installed or previously used media.
test -z "$(blkid -p /dev/sda 2>/dev/null || true)"
test -z "$(blkid -p /dev/sdb 2>/dev/null || true)"
mkdir -m 0700 /run/northgate-rmm-install
od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > /run/northgate-rmm-install/os.key
test "$(wc -c < /run/northgate-rmm-install/os.key)" -eq 64
debconf-set partman-auto/disk /dev/sda
# The passphrase is generated inside installer RAM, never shipped in the ISO.
debconf-set partman-crypto/passphrase "$(cat /run/northgate-rmm-install/os.key)"
debconf-set partman-crypto/passphrase-again "$(cat /run/northgate-rmm-install/os.key)"
