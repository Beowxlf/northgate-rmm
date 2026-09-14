set -euo pipefail
config=/etc/ssh/sshd_config.d/00-northgate-bootstrap.conf
test -f /root/rmm-remote-bootstrap/ssh.before || cp -a "$config" /root/rmm-remote-bootstrap/ssh.before
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/ssh/sshd_config.d/00-northgate-bootstrap.conf');s=p.read_text()
assert 'AllowUsers northgate-bootstrap@10.10.100.11' in s
if 'rmmremote@10.10.150.22' not in s:s=s.replace('AllowUsers northgate-bootstrap@10.10.100.11','AllowUsers northgate-bootstrap@10.10.100.11 rmmremote@10.10.150.22')
p.write_text(s)
k=Path('/home/northgate-bootstrap/terminal.pub').read_text().strip();assert k.startswith('ssh-rsa ')
p=Path('/home/rmmremote/.ssh');p.mkdir(mode=0o700,exist_ok=True)
(p/'authorized_keys').write_text('from="10.10.150.22",restrict,pty '+k+'\n')
PY
chown -R rmmremote:rmmremote /home/rmmremote/.ssh
chmod 700 /home/rmmremote/.ssh
chmod 600 /home/rmmremote/.ssh/authorized_keys
sshd -t
systemctl reload ssh
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/nftables.d/northgate-rmm-desktop.nft');s=p.read_text();s=s.replace('ip saddr 10.10.150.22 tcp dport 3389 accept','ip saddr { 10.10.150.22, 10.10.100.20 } tcp dport 3389 accept');p.write_text(s)
PY
nft -c -f /etc/nftables.d/northgate-rmm-desktop.nft
nft delete table inet northgate_rmm_desktop
nft -f /etc/nftables.d/northgate-rmm-desktop.nft
printf 'Linux terminal account enabled for RMM server; native RDP allowed for owner workstation.\n'
