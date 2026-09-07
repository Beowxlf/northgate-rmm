set -euo pipefail
test "$(hostname)" = ng-rmm-can01
test ! -d /root/rmm-remote-bootstrap
install -d -m 0700 /root/rmm-remote-bootstrap
cp -a /etc/xrdp /root/rmm-remote-bootstrap/xrdp.before
if id rmmremote >/dev/null 2>&1; then echo 'Remote account exists; reconcile'; exit 1; fi
useradd --create-home --shell /bin/bash rmmremote
python3 - <<'PY'
import json,secrets,subprocess
from pathlib import Path
password=secrets.token_urlsafe(32)
subprocess.run(['chpasswd'],input='rmmremote:'+password+'\n',text=True,check=True)
Path('/root/rmm-remote-bootstrap/password.json').write_text(json.dumps({'password':password}))
Path('/root/rmm-remote-bootstrap/password.json').chmod(0o600)
PY
printf '%s\n' 'exec startxfce4' > /home/rmmremote/.xsession
chown rmmremote:rmmremote /home/rmmremote/.xsession
chmod 0600 /home/rmmremote/.xsession
openssl req -x509 -newkey rsa:3072 -nodes -days 90 -subj /CN=ng-rmm-can01 -keyout /etc/xrdp/rmm.key -out /etc/xrdp/rmm.crt >/dev/null 2>&1
chown root:xrdp /etc/xrdp/rmm.key
chmod 0640 /etc/xrdp/rmm.key
python3 - <<'PY'
import configparser,json,subprocess
from pathlib import Path
p=Path('/etc/xrdp/xrdp.ini')
s=p.read_text().replace('certificate=','certificate=/etc/xrdp/rmm.crt',1).replace('key_file=','key_file=/etc/xrdp/rmm.key',1)
s=s.replace('security_layer=negotiate','security_layer=tls')
p.write_text(s)
p=Path('/etc/xrdp/sesman.ini');s=p.read_text().replace('KillDisconnected=false','KillDisconnected=true').replace('DisconnectedTimeLimit=0','DisconnectedTimeLimit=60');p.write_text(s)
raw=subprocess.check_output(['openssl','x509','-in','/etc/xrdp/rmm.crt','-noout','-fingerprint','-sha256'],text=True).strip().split('=',1)[1].lower()
value=json.loads(Path('/root/rmm-remote-bootstrap/password.json').read_text())
value.update(username='rmmremote',security='tls',**{'cert-fingerprints':'sha256:'+raw})
p=Path('/home/northgate-bootstrap/rmm-remote-connection.json');p.write_text(json.dumps(value));p.chmod(0o600)
subprocess.run(['chown','northgate-bootstrap:northgate-bootstrap',str(p)],check=True)
PY
install -d -m 0755 /etc/nftables.d
cat > /etc/nftables.d/northgate-rmm-desktop.nft <<'EOF'
table inet northgate_rmm_desktop {
 chain input {
  type filter hook input priority -20; policy accept;
  iifname "lo" tcp dport 3389 accept
  ip saddr 10.10.150.22 tcp dport 3389 accept
  tcp dport 3389 drop
 }
}
EOF
nft -f /etc/nftables.d/northgate-rmm-desktop.nft
if ! grep -q 'include "/etc/nftables.d/\*.nft"' /etc/nftables.conf; then
 printf '\ninclude "/etc/nftables.d/*.nft"\n' >> /etc/nftables.conf
fi
systemctl unmask xrdp.service
systemctl enable --now xrdp.service
echo 'Linux native desktop enabled with dedicated non-admin account, server-only firewall and pinned public certificate.'
