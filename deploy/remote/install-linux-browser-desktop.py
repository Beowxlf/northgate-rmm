import json,os,socket,sys,subprocess,shutil,pathlib,pwd,grp,re,hashlib
P=pathlib.Path
hostname,address=sys.argv[1:3]
assert os.geteuid()==0 and socket.gethostname().lower()==hostname.lower(),'Wrong guest'
root=P('/var/lib/northgate-rdp-install');root.mkdir(mode=0o700,exist_ok=True)
log=(root/'install.log').open('a')
def run(args,**kw):return subprocess.run(args,check=True,stdout=log,stderr=log,timeout=1200,**kw)
def write(path,text,mode=0o644):
 p=P(path);p.parent.mkdir(parents=True,exist_ok=True);assert not p.is_symlink();p.write_text(text);p.chmod(mode)
def ini(path,section,values):
 p=P(path);lines=p.read_text().splitlines();start=next(i for i,l in enumerate(lines) if l.strip().lower()=='['+section.lower()+']')+1
 end=next((i for i in range(start,len(lines)) if lines[i].strip().startswith('[')),len(lines))
 keep=[l for l in lines[start:end] if not any(re.match(r'\s*'+re.escape(k)+r'\s*=',l,re.I) for k in values)]
 lines[start:end]=keep+[k+'='+str(v) for k,v in values.items()]
 p.write_text('\n'.join(lines)+'\n')
try:
 backup=root/'before'
 if not backup.exists():
  backup.mkdir(mode=0o700)
  if P('/etc/xrdp').exists():shutil.copytree('/etc/xrdp',backup/'xrdp',symlinks=True)
  (backup/'packages.txt').write_text(subprocess.check_output(['dpkg-query','-W','-f=${Package} ${Version}\n'],text=True))
  (backup/'services.txt').write_text(subprocess.run(['systemctl','is-enabled','xrdp','xrdp-sesman'],capture_output=True,text=True).stdout)
 user=pwd.getpwnam('rmmremote');assert user.pw_uid>=1000
 allowed=['10.10.150.22']+(['172.18.0.2'] if address=='10.10.150.22' else [])
 # Dedicated port-only rules are installed before packages may start xrdp.
 if shutil.which('nft'):
  rule='table inet northgate_rdp {\n chain input {\n type filter hook input priority -20; policy accept;\n ip saddr { '+', '.join(allowed)+' } tcp dport 3389 accept;\n tcp dport 3389 drop;\n }\n}\n'
  write('/etc/northgate-rdp-firewall.nft',rule)
  firewall="#!/bin/sh\nset -eu\nif /usr/sbin/nft list table inet northgate_rdp >/dev/null 2>&1; then { printf 'delete table inet northgate_rdp\\n'; cat /etc/northgate-rdp-firewall.nft; } | /usr/sbin/nft -f -; else /usr/sbin/nft -f /etc/northgate-rdp-firewall.nft; fi\n"
 else:
  assert shutil.which('iptables'),'No supported firewall'
  firewall='#!/bin/sh\nset -eu\niptables -w 5 -I INPUT 1 -p tcp --dport 3389 -m comment --comment NG_RMM_RDP_rebuild -j DROP\niptables -w 5 -N NG_RMM_RDP 2>/dev/null || true\niptables -w 5 -F NG_RMM_RDP\n'
  firewall+=''.join('iptables -w 5 -A NG_RMM_RDP -s '+ip+' -j ACCEPT\n' for ip in allowed)
  firewall+='iptables -w 5 -A NG_RMM_RDP -j DROP\niptables -w 5 -C INPUT -p tcp --dport 3389 -j NG_RMM_RDP 2>/dev/null || iptables -w 5 -I INPUT 1 -p tcp --dport 3389 -j NG_RMM_RDP\n'
  firewall+='while iptables -w 5 -C INPUT -p tcp --dport 3389 -m comment --comment NG_RMM_RDP_rebuild -j DROP 2>/dev/null; do iptables -w 5 -D INPUT -p tcp --dport 3389 -m comment --comment NG_RMM_RDP_rebuild -j DROP; done\n'
 write('/usr/local/sbin/northgate-rdp-firewall',firewall,0o700)
 write('/etc/systemd/system/northgate-rdp-firewall.service','[Unit]\nDescription=NorthGate RDP source restriction\nBefore=xrdp.service\nAfter=network-pre.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/local/sbin/northgate-rdp-firewall\n[Install]\nWantedBy=multi-user.target\n')
 write('/etc/systemd/system/xrdp.service.d/northgate.conf','[Unit]\nRequires=northgate-rdp-firewall.service\nAfter=northgate-rdp-firewall.service\n')
 run(['systemctl','daemon-reload']);run(['systemctl','enable','northgate-rdp-firewall.service']);run(['systemctl','restart','northgate-rdp-firewall.service'])
 if shutil.which('ufw') and 'Status: active' in subprocess.run(['ufw','status'],capture_output=True,text=True).stdout:
  run(['ufw','allow','from','10.10.150.22','to','any','port','3389','proto','tcp','comment','NorthGate browser RDP'])
 env={**os.environ,'DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_MODE':'l'}
 run(['apt-get','-o','Acquire::Retries=2','-o','Acquire::http::Timeout=30','update'],env=env)
 run(['apt-get','-y','--no-install-recommends','-o','Dpkg::Options::=--force-confold','install','xrdp','xorgxrdp','xfce4','xfce4-terminal','dbus-x11','xserver-xorg-core','fonts-dejavu-core'],env=env)
 run(['systemctl','stop','xrdp','xrdp-sesman'])
 certdir=P('/etc/xrdp/northgate');certdir.mkdir(mode=0o750,exist_ok=True)
 group=grp.getgrnam('xrdp');os.chown(certdir,0,group.gr_gid)
 cert=certdir/'cert.pem';key=certdir/'key.pem'
 if not cert.exists():
  run(['openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes','-days','825','-keyout',str(key),'-out',str(cert),'-subj','/CN='+hostname,'-addext','subjectAltName=IP:'+address])
 key.chmod(0o640);os.chown(key,0,group.gr_gid);cert.chmod(0o644)
 ini('/etc/xrdp/xrdp.ini','Globals',{'port':'tcp://'+address+':3389','security_layer':'tls','crypt_level':'high','certificate':str(cert),'key_file':str(key),'ssl_protocols':'TLSv1.2, TLSv1.3','autorun':'Xorg'})
 ini('/etc/xrdp/sesman.ini','Globals',{'ListenAddress':'127.0.0.1'})
 try:grp.getgrnam('northgate-rdp')
 except KeyError:run(['groupadd','--system','northgate-rdp'])
 run(['usermod','-a','-G','northgate-rdp','rmmremote'])
 ini('/etc/xrdp/sesman.ini','Security',{'AllowRootLogin':'false','TerminalServerUsers':'northgate-rdp','AlwaysGroupCheck':'true','MaxLoginRetry':'3'})
 ini('/etc/xrdp/sesman.ini','Sessions',{'MaxSessions':'2','KillDisconnected':'true','DisconnectedTimeLimit':'120','IdleTimeLimit':'1800'})
 session=P(user.pw_dir)/'.xsession'
 if session.exists() and not (backup/'rmmremote.xsession').exists():shutil.copy2(session,backup/'rmmremote.xsession')
 write(session,'#!/bin/sh\nunset DBUS_SESSION_BUS_ADDRESS SESSION_MANAGER\nexec startxfce4\n',0o700);os.chown(session,user.pw_uid,user.pw_gid)
 run(['systemctl','enable','xrdp','xrdp-sesman']);run(['systemctl','restart','xrdp-sesman','xrdp']);run(['systemctl','is-active','--quiet','xrdp','xrdp-sesman','northgate-rdp-firewall'])
 der=subprocess.check_output(['openssl','x509','-in',str(cert),'-outform','DER'])
 result={'hostname':socket.gethostname(),'address':address,'state':'installed','certificate_sha256':hashlib.sha256(der).hexdigest(),'allowed_sources':allowed,'desktop':'XFCE','username':'rmmremote','backup':str(backup),'packages':subprocess.check_output(['dpkg-query','-W','-f=${Package} ${Version}\n','xrdp','xorgxrdp','xfce4'],text=True)}
 (root/'result.json').write_text(json.dumps(result));print(json.dumps(result))
except BaseException as exc:
 (root/'failure.txt').write_text(type(exc).__name__+': '+str(exc));raise
finally:log.close()
