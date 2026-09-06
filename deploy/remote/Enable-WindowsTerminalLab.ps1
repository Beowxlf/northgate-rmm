$ErrorActionPreference='Stop'
$root='C:\ProgramData\NorthGateRMM-RemoteBootstrap'
$config='C:\ProgramData\ssh\sshd_config'
if(!(Test-Path "$root\sshd.before")){Copy-Item $config "$root\sshd.before"}
$s=[IO.File]::ReadAllText($config)
if(!$s.Contains('AllowUsers northgate-bootstrap@10.10.100.11')){throw 'Unexpected SSH allowlist'}
if(!$s.Contains('rmmremote@10.10.150.22')){$s=$s.Replace('AllowUsers northgate-bootstrap@10.10.100.11','AllowUsers northgate-bootstrap@10.10.100.11 rmmremote@10.10.150.22')}
[IO.File]::WriteAllText($config,$s,(New-Object Text.UTF8Encoding($false)))
$sid=(Get-LocalUser rmmremote).SID.Value
$profile=(Get-CimInstance Win32_UserProfile | Where-Object SID -eq $sid).LocalPath
if(!$profile){throw 'Dedicated remote user profile not present'}
$dir=Join-Path $profile '.ssh'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$key=[IO.File]::ReadAllText("$root\terminal.pub").Trim()
if(!$key.StartsWith('ssh-rsa ')){throw 'Unexpected public key format'}
[IO.File]::WriteAllText((Join-Path $dir 'authorized_keys'),('from="10.10.150.22",restrict,pty '+$key+"`n"),(New-Object Text.UTF8Encoding($false)))
& icacls.exe $dir /inheritance:r /grant:r "*$($sid):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){throw 'Terminal key ACL failed'}
& C:\Windows\System32\OpenSSH\sshd.exe -t
if($LASTEXITCODE -ne 0){throw 'SSH configuration check failed'}
if(!(Get-NetFirewallRule -Name NorthGate-RMM-Terminal -ErrorAction SilentlyContinue)){
 New-NetFirewallRule -Name NorthGate-RMM-Terminal -DisplayName 'NorthGate RMM browser terminal' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -RemoteAddress 10.10.150.22 -Profile Any | Out-Null
}
Set-NetFirewallRule -Name NorthGate-RMM-Desktop -RemoteAddress 10.10.150.22,10.10.100.20
Restart-Service sshd
Write-Output 'Windows terminal configured with dedicated nonadministrator key; native RDP allowed for owner workstation.'
