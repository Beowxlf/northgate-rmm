"""Provider-native snapshot export, encrypted as a stream with a scoped identity."""
import datetime,hashlib,json,os,pathlib,ssl,subprocess,urllib.request,uuid
os.umask(0o077)
directory=pathlib.Path('/var/lib/openbao-maintenance/snapshots')
directory.mkdir(mode=0o700,exist_ok=True)
identifier=str(uuid.uuid4())
path=directory/('openbao-raft-'+identifier+'.snap.age')
token=pathlib.Path('/etc/northgate-rmm/secrets/openbao-backup.token').read_text().strip()
recipient=pathlib.Path('/etc/openbao/recovery-recipient.txt').read_text().strip()
request=urllib.request.Request('https://vault.rmm.internal:8200/v1/sys/storage/raft/snapshot',headers={'X-Vault-Token':token})
context=ssl.create_default_context(cafile='/etc/northgate-rmm/openbao-ca.pem')
raw_hash=hashlib.sha256();raw_size=0
with path.open('xb') as out:
    os.chmod(path,0o600)
    process=subprocess.Popen(['age','-r',recipient],stdin=subprocess.PIPE,stdout=out,stderr=subprocess.PIPE)
    try:
        with urllib.request.urlopen(request,context=context,timeout=30) as response:
            while block:=response.read(1024*1024):
                raw_size+=len(block)
                assert raw_size<=1024*1024*1024,'Snapshot exceeded bounded 1 GiB limit'
                raw_hash.update(block);process.stdin.write(block)
        process.stdin.close()
        assert process.wait(timeout=30)==0,'Snapshot encryption failed'
    finally:
        if process.poll() is None:process.kill();process.wait()
assert raw_size>1024
with path.open('rb') as ciphertext:
    encrypted_hash=hashlib.file_digest(ciphertext,'sha256').hexdigest()
receipt={'snapshot_id':identifier,'sha256':encrypted_hash,'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
(directory/(identifier+'.receipt.json')).write_text(json.dumps(receipt)+'\n')
details={**receipt,'file':str(path),'encrypted_size':path.stat().st_size,'raw_sha256':raw_hash.hexdigest(),'raw_size':raw_size,'identity':'northgate-rmm-backup'}
(directory/(identifier+'.details.json')).write_text(json.dumps(details,indent=2)+'\n')
print(json.dumps(details))
