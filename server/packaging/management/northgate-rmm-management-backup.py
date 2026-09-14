from pathlib import Path
from datetime import datetime,UTC
import os,json
from northgate_rmm.management_admin import backup,read_private
root=Path('/var/lib/northgate-rmm-remote');credentials=Path(os.environ['CREDENTIALS_DIRECTORY'])
key=bytes.fromhex(read_private(credentials/'remote-key',64).decode().strip())
out=root/'backups'/('management-'+datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')+'.aes')
result=backup(root,credentials/'remote-credentials',key,out)
print(json.dumps({'archive':out.name,'sha256':result['sha256'],'components':sorted(result['files'])}))
# Retain 31 successful archives; no deletion occurs until a new backup succeeds.
for old in sorted((root/'backups').glob('management-*.aes'))[:-31]:
 if old.is_file() and not old.is_symlink():old.unlink()
