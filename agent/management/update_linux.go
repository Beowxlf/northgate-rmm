//go:build linux

package management

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func platformScheduleUpdate(ctx context.Context, j Job, c Config, plan string) Result {
	binary, e := os.Executable()
	if e != nil {
		return safeResultError("Updater executable unavailable")
	}
	helper := filepath.Join(filepath.Dir(plan), "updater")
	b, e := readBounded(binary, 64*1024*1024)
	if e != nil {
		return safeResultError("Updater copy failed")
	}
	if e = os.WriteFile(helper, b, 0700); e != nil {
		return safeResultError("Updater staging failed")
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--unit=northgate-rmm-update-"+j.ID, "--on-active=3s", "--timer-property=AccuracySec=1s", helper, "--apply-update", plan)
	return runCommand(ctx, cmd, 4096)
}
func applyPlatformUpdate(ctx context.Context, p UpdatePlan, c Config) Result {
	targets := map[string][2]string{"agent": {"/usr/libexec/northgate-rmm/northgate-rmm-agent", "northgate-rmm-agent"}, "worker": {"/usr/local/libexec/northgate-rmm-management/northgate-rmm-management", "northgate-rmm-management"}, "wxlfgar": {"/usr/local/libexec/northgate-wxlfgar/wulfgar", "northgate-wxlfgar"}}
	target := targets[p.Manifest.Component]
	script := `import hashlib,json,os,pathlib,shutil,subprocess,sys
v=json.load(sys.stdin);dest=pathlib.Path(v['destination']);backup=dest.with_name(dest.name+'.previous.'+v['job']);pending=dest.with_name(dest.name+'.pending.'+v['job'])
import re,time
reported=subprocess.run([v['candidate'],'--version'],check=True,timeout=5,capture_output=True,text=True).stdout
if re.search(r'\b\d+\.\d+\.\d+(?:-lab\.\d+)?\b',reported).group(0)!=v['version']:raise RuntimeError('Candidate version does not match signed manifest')
if not dest.is_file() or dest.is_symlink() or backup.exists() or pending.exists():raise RuntimeError('Unsafe or unreconciled update paths')
shutil.copy2(dest,backup)
shutil.copyfile(v['candidate'],pending);pending.chmod(0o755)
if hashlib.sha256(pending.read_bytes()).hexdigest()!=v['hash']:raise RuntimeError('Staged checksum mismatch')
subprocess.run(['/usr/bin/systemctl','stop',v['service']],check=True,timeout=45)
try:
 os.replace(pending,dest)
 subprocess.run(['/usr/bin/systemctl','start',v['service']],check=True,timeout=40)
 time.sleep(3)
 subprocess.run(['/usr/bin/systemctl','is-active','--quiet',v['service']],check=True,timeout=10)
 print(json.dumps({'installed':v['component'],'version':v['version'],'backup':str(backup)}))
except BaseException:
 subprocess.run(['/usr/bin/systemctl','stop',v['service']],timeout=45)
 shutil.copy2(backup,dest)
 subprocess.run(['/usr/bin/systemctl','start',v['service']],timeout=40)
 raise
`
	b, _ := json.Marshal(map[string]string{"destination": target[0], "service": target[1], "candidate": p.Binary, "hash": p.Manifest.SHA256, "job": p.Job, "component": p.Manifest.Component, "version": p.Manifest.Version})
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", script)
	cmd.Stdin = strings.NewReader(string(b))
	return runCommand(ctx, cmd, 8192)
}
