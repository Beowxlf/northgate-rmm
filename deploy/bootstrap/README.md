# RMM server installation candidate

This is unfinished installation code for the exact NG-RMM-CP01 VM, not a built
or accepted installation image. Do not boot it before payload rendering, secret
handling review, and image verification are complete.

The server preseed replaces the historical single-disk unencrypted recipe.
Early checks bind the VM UUID and the 80-GiB OS / 100-GiB data disks. The storage
hook requires LUKS2, enrolls TPM unlock, and encrypts separate recovery keys to
an independently held age recipient. The private age identity must never enter
the payload. Only the public recipient belongs in recovery-recipient.txt.

The normal access payload is still required: authorized management public key,
SSH configuration, firewall, role hook, and request/provenance records. Rendering
must resolve every template placeholder and hash the complete payload.

Current validation: server-early.sh and server-storage.sh passed shell syntax
checks on the Linux build guest. No partitioning, installation, cryptographic
recovery, TPM boot, or guest service test has been performed. The late wrapper
and preseed integration still require qualification.

Remaining checks include Debian Installer command availability, blank-disk and
wrong-VM rejection, installer passphrase archive cleanup, correct root mapping,
dracut TPM support, first boot, off-guest recovery export, and recovery-key boot.
Existing or partially installed disks must be inspected before any rerun.

References: [Debian systemd-cryptenroll](https://manpages.debian.org/bookworm/systemd/systemd-cryptenroll.1.en.html),
[Debian dracut](https://packages.debian.org/bookworm/dracut),
[Debian age](https://packages.debian.org/bookworm/age).
