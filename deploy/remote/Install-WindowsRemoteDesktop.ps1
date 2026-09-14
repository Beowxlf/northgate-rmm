$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:COMPUTERNAME -ne 'NG-RMM-WIN01'){throw 'Wrong lab workstation'}
$root='C:\ProgramData\NorthGateRMM-RemoteBootstrap'
if(Test-Path $root){throw 'Remote bootstrap already exists; reconcile before retry'}
New-Item -ItemType Directory -Path $root | Out-Null
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){throw 'Private staging ACL failed'}
if(Get-LocalUser -Name rmmremote -ErrorAction SilentlyContinue){throw 'Remote account already exists'}
Get-NetFirewallRule -Name 'RemoteDesktop-*' | Select-Object Name,Enabled | Export-Clixml (Join-Path $root 'firewall.before.xml')
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections | Export-Clixml (Join-Path $root 'rdp.before.xml')
$bytes=New-Object byte[] 24
$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes); $rng.Dispose()
$password='Aa1!'+[Convert]::ToBase64String($bytes)
New-LocalUser -Name rmmremote -Password (ConvertTo-SecureString $password -AsPlainText -Force) -Description 'NorthGate private RMM desktop account' -UserMayNotChangePassword | Out-Null
$group=Get-LocalGroup -SID 'S-1-5-32-555'
Add-LocalGroupMember -Group $group.Name -Member rmmremote
Get-NetFirewallRule -Name 'RemoteDesktop-*' | Disable-NetFirewallRule
New-NetFirewallRule -Name NorthGate-RMM-Desktop -DisplayName 'NorthGate RMM server desktop only' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -RemoteAddress 10.10.150.22 -Profile Any | Out-Null
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Set-Service TermService -StartupType Automatic
Start-Service TermService
$cert=Get-ChildItem 'Cert:\LocalMachine\Remote Desktop' | Sort-Object NotAfter -Descending | Select-Object -First 1
if(-not $cert){throw 'RDP server certificate unavailable'}
$sha=[Security.Cryptography.SHA256]::Create()
$fingerprint=([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-',':').ToLowerInvariant()
$sha.Dispose()
$data=@{username='rmmremote';password=$password;domain=$env:COMPUTERNAME;security='nla';'cert-fingerprints'=('sha256:'+ $fingerprint)}
[IO.File]::WriteAllText((Join-Path $root 'connection.json'),($data|ConvertTo-Json -Compress))
$password=$null
Write-Output 'Windows native desktop enabled with NLA, dedicated non-admin account, server-only firewall and pinned public certificate.'
