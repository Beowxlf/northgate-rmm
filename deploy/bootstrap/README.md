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

Current validation: the exact lab VM was installed with targeted recovery
repairs. Both encrypted volumes were unlocked using independently decrypted
recovery material, and a subsequent normal boot unlocked both volumes through
the TPM without console input. Key-only SSH, mounted storage, time synchronization,
and an empty failed-service list were verified. RMM application acceptance is
separate and remains pending.

The installer-generated boot image originally omitted crypttab. Explicitly
include crypttab and cryptsetup in the generic dracut image. TPM enrollment from
the installer also did not match the installed system's PCR 7 state; this VM
required reenrollment after a recovery boot. These results qualify the repaired
VM, not unattended first boot of this installer. A first-boot enrollment workflow
and the observed installer device-manager notification wait remain unresolved.

Disk letters changed across boots. Post-installation operations must resolve
the recorded LUKS UUIDs, not assume that sda is the OS disk. The initial blank-disk
guards are not permission to rerun installation against populated disks.

Remaining checks include Debian Installer command availability, blank-disk and
wrong-VM rejection, installer passphrase archive cleanup, correct root mapping,
dracut TPM support, first boot, off-guest recovery export, and recovery-key boot.
Existing or partially installed disks must be inspected before any rerun.

References: [Debian systemd-cryptenroll](https://manpages.debian.org/bookworm/systemd/systemd-cryptenroll.1.en.html),
[Debian dracut](https://packages.debian.org/bookworm/dracut),
[Debian age](https://packages.debian.org/bookworm/age).
