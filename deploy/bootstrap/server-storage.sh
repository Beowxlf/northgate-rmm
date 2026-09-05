#!/bin/sh
# Run inside the new guest's installation chroot after package installation.
set -eu
umask 077
test "$(id -u)" -eq 0
test "$(cat /sys/class/dmi/id/product_uuid | tr A-F a-f)" = "d1c8820e-16d7-42d6-be8f-cbbf41cb04d4"
keys=/run/northgate-rmm-install
media=/root/northgate-media
test -f "$keys/os.key"
test ! -e /boot/northgate-rmm-recovery.age
test "$(blockdev --getsize64 /dev/sda)" = 85899345920
test "$(blockdev --getsize64 /dev/sdb)" = 107374182400
blank_rc=0; blkid -p /dev/sdb >/dev/null 2>&1 || blank_rc=$?
test "$blank_rc" -eq 2
root_devices=$(lsblk -rpn -o NAME,TYPE /dev/sda | awk '$2 == "crypt" {print $1}')
test "$(printf '%s\n' "$root_devices" | wc -l)" -eq 1
test -n "$root_devices"
root_parent=$(lsblk -dnpo PKNAME "$root_devices")
test -b "$root_parent"
# Reject unsupported installer encryption instead of booting an unprotected OS.
cryptsetup luksDump --dump-json-metadata "$root_parent" >/dev/null
cryptsetup open --test-passphrase --key-file "$keys/os.key" "$root_parent"
od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$keys/data.key"
test "$(wc -c < "$keys/data.key")" -eq 64
cryptsetup luksFormat --type luks2 --batch-mode --key-file "$keys/data.key" /dev/sdb
cryptsetup open --key-file "$keys/data.key" /dev/sdb rmm-data
mkfs.ext4 -q -L rmm-data /dev/mapper/rmm-data
install -d -m 0750 /var/lib/northgate-rmm
mount /dev/mapper/rmm-data /var/lib/northgate-rmm
systemd-cryptenroll --unlock-key-file="$keys/os.key" --tpm2-device=auto --tpm2-pcrs=7 "$root_parent"
systemd-cryptenroll --unlock-key-file="$keys/data.key" --tpm2-device=auto --tpm2-pcrs=7 /dev/sdb
root_uuid=$(cryptsetup luksUUID "$root_parent")
data_uuid=$(cryptsetup luksUUID /dev/sdb)
root_name=$(basename "$root_devices")
printf '%s UUID=%s none luks,tpm2-device=auto\nrmm-data UUID=%s none luks,tpm2-device=auto\n' \
    "$root_name" "$root_uuid" "$data_uuid" > /etc/crypttab
printf '/dev/mapper/rmm-data /var/lib/northgate-rmm ext4 defaults 0 2\n' >> /etc/fstab
recipient=$(cat "$media/recovery-recipient.txt")
printf '%s\n' "$recipient" | grep -Eq '^age1[0-9a-z]{58}$'
tar -C "$keys" -cf "$keys/recovery.tar" os.key data.key
age -r "$recipient" -o /boot/northgate-rmm-recovery.age "$keys/recovery.tar"
test -s /boot/northgate-rmm-recovery.age
chmod 0600 /boot/northgate-rmm-recovery.age
install -d -m 0755 /etc/dracut.conf.d
printf 'add_dracutmodules+=" crypt tpm2-tss "\n' > /etc/dracut.conf.d/northgate-rmm.conf
dracut --regenerate-all --force
cat > /etc/systemd/system/northgate-console-identity.service <<'UNIT'
[Unit]
Description=Publish bootstrap public host identity to the Hyper-V serial console
After=ssh.service
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo NORTHGATE_HOST_IDENTITY_BEGIN; cat /etc/ssh/ssh_host_ed25519_key.pub; echo NORTHGATE_HOST_IDENTITY_END'
StandardOutput=tty
TTYPath=/dev/ttyS0
[Install]
WantedBy=multi-user.target
UNIT
systemctl enable northgate-console-identity.service
# Public identity only, readable through a read-only host mount for initial pinning.
test -d /boot/efi/EFI
install -m 0644 /etc/ssh/ssh_host_ed25519_key.pub /boot/efi/northgate-hostkey.pub
sync
# Only transient installer key files are removed. The encrypted escrow survives.
rm -f "$keys/os.key" "$keys/data.key" "$keys/recovery.tar"
rmdir "$keys"
printf '%s\n' 'encrypted-storage-configured; recovery-export-and-boot-test-pending' > /etc/northgate-rmm-storage-status
