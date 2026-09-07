//go:build windows

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
	helper := filepath.Join(filepath.Dir(plan), "updater.exe")
	b, e := readBounded(binary, 64*1024*1024)
	if e != nil {
		return safeResultError("Updater copy failed")
	}
	if e = os.WriteFile(helper, b, 0700); e != nil {
		return safeResultError("Updater staging failed")
	}
	script := `$ErrorActionPreference='Stop';$v=[Console]::In.ReadToEnd()|ConvertFrom-Json;$a=New-ScheduledTaskAction -Execute $v.helper -Argument ('--apply-update "'+$v.plan+'"');$p=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest;$s=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5);Register-ScheduledTask -TaskName ('NorthGate-RMM-Update-'+$v.job) -Action $a -Principal $p -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)) -Settings $s|Out-Null;Write-Output 'Signed update scheduled'`
	raw, _ := json.Marshal(map[string]string{"helper": helper, "plan": plan, "job": j.ID})
	cmd := exec.CommandContext(ctx, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedScript(script))
	cmd.Stdin = strings.NewReader(string(raw))
	return runCommand(ctx, cmd, 4096)
}
func applyPlatformUpdate(ctx context.Context, p UpdatePlan, c Config) Result {
	targets := map[string][2]string{"agent": {`C:\Program Files\NorthGate RMM\northgate-rmm-agent.exe`, "NorthGateRMMAgent"}, "worker": {`C:\Program Files\NorthGateRMMManagement\northgate-rmm-management.exe`, "NorthGateRMMManagement"}, "wxlfgar": {`C:\Program Files\NorthGateWxlfgar\wulfgar.exe`, "NorthGateWxlfgar"}}
	target := targets[p.Manifest.Component]
	script := `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$v=[Console]::In.ReadToEnd()|ConvertFrom-Json
$destination=$v.destination;$backup=$destination+'.previous.'+$v.job;$pending=$destination+'.pending.'+$v.job
foreach($p in @($destination,(Split-Path $destination),$v.candidate)){if((Get-Item -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse update path rejected'}}
if((Test-Path $backup) -or (Test-Path $pending)){throw 'Existing update transaction'}
$signature=Get-AuthenticodeSignature -LiteralPath $v.candidate
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $v.signer){throw 'Authenticode signer rejected'}
if((Get-FileHash -LiteralPath $v.candidate).Hash -ne $v.hash){throw 'Candidate checksum mismatch'}
$reported=& $v.candidate --version
if($LASTEXITCODE -ne 0 -or [regex]::Match(($reported -join ' '),'\b\d+\.\d+\.\d+(?:-lab\.\d+)?\b').Value -ne $v.version){throw 'Candidate version does not match signed manifest'}
Copy-Item -LiteralPath $destination -Destination $backup
Copy-Item -LiteralPath $v.candidate -Destination $pending
Stop-Service -Name $v.service
(Get-Service -Name $v.service).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(45))
try {
 Move-Item -LiteralPath $pending -Destination $destination -Force
 Start-Service -Name $v.service
 (Get-Service -Name $v.service).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
 Start-Sleep -Seconds 3
 if((Get-Service -Name $v.service).Status -ne 'Running'){throw 'Updated service did not remain running'}
 @{installed=$v.component;version=$v.version;backup=$backup}|ConvertTo-Json -Compress
} catch {
 Stop-Service -Name $v.service -ErrorAction SilentlyContinue
 Copy-Item -LiteralPath $backup -Destination $destination -Force
 Start-Service -Name $v.service
 throw 'Update failed; prior binary restored. Reconcile service status.'
}`
	b, _ := json.Marshal(map[string]string{"destination": target[0], "service": target[1], "candidate": p.Binary, "hash": p.Manifest.SHA256, "job": p.Job, "signer": c.UpdateSigner, "component": p.Manifest.Component, "version": p.Manifest.Version})
	cmd := exec.CommandContext(ctx, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedScript(script))
	cmd.Stdin = strings.NewReader(string(b))
	return runCommand(ctx, cmd, 8192)
}
