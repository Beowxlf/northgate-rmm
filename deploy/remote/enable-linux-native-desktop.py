import hashlib,json,os,pathlib,shutil,socket,subprocess,sys
P=pathlib.Path
hostname,address=sys.argv[1:3]
assert os.geteuid()==0 and socket.gethostname().lower()==hostname.lower()
root=P('/var/lib/northgate-rdp-install');result=json.loads((root/'result.json').read_text())
assert result['address']==address and result['state']=='installed'
source='10.10.100.20';allowed=list(dict.fromkeys(result['allowed_sources']+[source]))
backup=root/'before-native-20260913';backup.mkdir(mode=0o700,exist_ok=True)
paths=['/usr/local/sbin/northgate-rdp-firewall','/etc/northgate-rdp-firewall.nft',str(root/'result.json')]
for name in paths:
 p=P(name)
 if p.exists():
  b=backup/p.name
  if not b.exists():shutil.copy2(p,b)
script=P('/usr/local/sbin/northgate-rdp-firewall');nft=P('/etc/northgate-rdp-firewall.nft')
if nft.exists():
 old=nft.read_text();expected='ip saddr { '+', '.join(result['allowed_sources'])+' }'
 assert old.count(expected)==1
 nft.write_text(old.replace(expected,'ip saddr { '+', '.join(allowed)+' }'))
else:
 old=script.read_text();needle='iptables -w 5 -A NG_RMM_RDP -j DROP\n'
 assert old.count(needle)==1
 addition='iptables -w 5 -A NG_RMM_RDP -s '+source+' -j ACCEPT\n'
 if addition not in old:script.write_text(old.replace(needle,addition+needle))
subprocess.run(['systemctl','restart','northgate-rdp-firewall'],check=True)
if shutil.which('ufw') and 'Status: active' in subprocess.run(['ufw','status'],capture_output=True,text=True).stdout:
 subprocess.run(['ufw','allow','from',source,'to','any','port','3389','proto','tcp','comment','NorthGate native RDP workstation'],check=True,stdout=subprocess.DEVNULL)
assert subprocess.run(['systemctl','is-active','--quiet','xrdp','northgate-rdp-firewall']).returncode==0
result['allowed_sources']=allowed;(root/'result.json').write_text(json.dumps(result))
print(json.dumps({'name':hostname,'address':address,'allowed_sources':allowed,'service':'active','backup':str(backup),'firewall_sha256':hashlib.sha256((nft if nft.exists() else script).read_bytes()).hexdigest()}))
