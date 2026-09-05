#!/bin/sh
set -eu
umask 077
test -f /run/northgate-rmm-install/os.key
test ! -e /target/root/northgate-media
cp -a /cdrom/northgate /target/root/northgate-media
install -d -m 0700 /target/run/northgate-rmm-install
install -m 0600 /run/northgate-rmm-install/os.key /target/run/northgate-rmm-install/os.key
in-target /bin/sh /root/northgate-media/late-command.sh
in-target /bin/sh /root/northgate-media/server-storage.sh
# Clear installer passphrase answers before its database is archived.
debconf-set partman-crypto/passphrase ''
debconf-set partman-crypto/passphrase-again ''
rm -f /run/northgate-rmm-install/os.key
rmdir /run/northgate-rmm-install
# Only the exact copied installation payload is removed.
test -d /target/root/northgate-media
test ! -L /target/root/northgate-media
rm -rf /target/root/northgate-media
