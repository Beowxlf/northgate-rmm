$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$v=[Console]::In.ReadToEnd()|ConvertFrom-Json
$p=$v.params
function Invoke-Operation {
 switch($v.action){
  'prerequisites.install' {
   $winget=Get-Command winget.exe -ErrorAction SilentlyContinue
   if(-not $winget){throw 'WinGet is not available under SYSTEM. Install the signed Wireshark package and Npcap using the administrator installation workflow; do not run an unverified bootstrap downloader.'}
   $output=& $winget.Source install --id WiresharkFoundation.Wireshark --exact --silent --disable-interactivity --accept-package-agreements --accept-source-agreements 2>&1|Out-String
   if($LASTEXITCODE -ne 0){throw ('Wireshark installation failed: '+$output)}
   return @{wireshark_installed=$true;npcap_ready=[bool](Get-Service npcap -ErrorAction SilentlyContinue);note='Npcap free edition requires its interactive installer. Silent installation requires the appropriate OEM license.'}
  }
  'services.list' { return @(Get-Service|Select-Object Name,DisplayName,Status,StartType) }
  'service.control' {
   switch($p.operation){'start'{Start-Service -Name $p.name};'stop'{Stop-Service -Name $p.name};'restart'{Restart-Service -Name $p.name}}
   return Get-Service -Name $p.name|Select-Object Name,Status,StartType
  }
  'processes.list' {return @(Get-Process -IncludeUserName|Select-Object Id,ProcessName,SessionId,UserName,Path,@{Name='start_token';Expression={try{$_.StartTime.ToUniversalTime().Ticks.ToString()}catch{'unavailable'}}})}
  'process.stop' {
   $process=Get-Process -Id $p.pid
   if($process.Id -eq $PID -or $process.ProcessName -match '^(System|Registry|Idle|smss|csrss|wininit|winlogon|lsass|services|svchost|sshd|northgate.*)$'){throw 'Protected process'}
   $handle=$process.Handle
   if($process.StartTime.ToUniversalTime().Ticks.ToString() -ne $p.start_token){throw 'Process changed; refresh inventory before terminating'}
   $process.Kill()
   return @{pid=$p.pid;termination_requested=$true}
  }
  'logs.read' {
   $channels=@{System='System';Application='Application';Security='Security';Sysmon='Microsoft-Windows-Sysmon/Operational';Defender='Microsoft-Windows-Windows Defender/Operational'}
   if(-not $channels.ContainsKey($p.channel)){throw 'Unsupported Windows log'}
   return @(Get-WinEvent -FilterHashtable @{LogName=$channels[$p.channel];StartTime=(Get-Date).AddMinutes(-[int]$p.since)} -MaxEvents $p.limit|Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message)
  }
  'reboot.status' {
   $old=$ErrorActionPreference;$ErrorActionPreference='Continue'
   try{$sessions=& "$env:WINDIR\System32\quser.exe" 2>&1|Out-String;$sessionExit=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
   return @{last_boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime;pending_reboot=((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'));sessions=$sessions;session_query_exit_code=$sessionExit}
  }
  'reboot' {
   $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
   & "$env:WINDIR\System32\shutdown.exe" /r /t $p.delay /d p:4:1 /c 'NorthGate RMM authorized maintenance'
   if($LASTEXITCODE -ne 0){throw 'Restart scheduling failed'}
   return @{reboot_scheduled=$true;delay_seconds=$p.delay;previous_boot_id=$boot}
  }
  'posture' {
   $data=@{execution_identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;administrators=@(Get-LocalGroupMember -SID 'S-1-5-32-544'|Select-Object Name,ObjectClass);firewall=@(Get-NetFirewallProfile|Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction);patches=@(Get-HotFix|Select-Object HotFixID,InstalledOn,Description)}
   foreach($check in @('Defender','TPM','SecureBoot','BitLocker')){
    try {switch($check){'Defender'{$data[$check]=Get-MpComputerStatus|Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,IsTamperProtected};'TPM'{$data[$check]=Get-Tpm|Select-Object TpmPresent,TpmReady,TpmEnabled};'SecureBoot'{$data[$check]=Confirm-SecureBootUEFI};'BitLocker'{$data[$check]=@(Get-BitLockerVolume|Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage)}}}
    catch {$data[$check]=@{available=$false;reason='Query unavailable on this system'}}
   }
   return $data
  }
  'encryption.status' {
   return @(Get-BitLockerVolume|ForEach-Object {@{mount_point=$_.MountPoint;volume_status=[string]$_.VolumeStatus;protection_status=[string]$_.ProtectionStatus;encryption_percentage=$_.EncryptionPercentage;protectors=@($_.KeyProtector|Select-Object KeyProtectorId,KeyProtectorType)}})
  }
  'bitlocker.escrow' {
   $volumes=@(Get-BitLockerVolume)
   return @{collected_utc=[DateTime]::UtcNow.ToString('o');volumes=@($volumes|ForEach-Object {@{mount_point=$_.MountPoint;protection_status=[string]$_.ProtectionStatus;recovery_passwords=@($_.KeyProtector|Where-Object KeyProtectorType -eq 'RecoveryPassword'|ForEach-Object {@{protector_id=$_.KeyProtectorId;recovery_password=$_.RecoveryPassword}})}})}
  }
  'recovery.rotate' {
   $name='ng-rmm-recovery';$stamp=Join-Path $v.root 'recovery-account.json'
   $existing=Get-LocalUser -Name $name -ErrorAction SilentlyContinue
   if($existing -and -not(Test-Path -LiteralPath $stamp)){throw 'Existing account is not managed by this worker'}
   $bytes=New-Object byte[] 36;$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
   try {$rng.GetBytes($bytes);$password=[Convert]::ToBase64String($bytes)+'!aA9'} finally {$rng.Dispose();[Array]::Clear($bytes,0,$bytes.Length)}
   $secure=ConvertTo-SecureString $password -AsPlainText -Force
   $expiry=(Get-Date).AddHours($p.hours)
   try {
    if($existing){Set-LocalUser -Name $name -Password $secure -AccountExpires $expiry;Enable-LocalUser -Name $name}
    else {New-LocalUser -Name $name -Password $secure -AccountExpires $expiry -UserMayNotChangePassword -Description 'NorthGate RMM managed emergency administrator'|Out-Null}
    $group=Get-LocalGroup -SID 'S-1-5-32-544'
    if(-not(Get-LocalGroupMember -Group $group -Member $name -ErrorAction SilentlyContinue)){Add-LocalGroupMember -Group $group -Member $name}
    @{name=$name;expires=$expiry.ToUniversalTime().ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $stamp
    return @{username=$name;password=$password;expires=$expiry.ToUniversalTime().ToString('o');rotation=$v.job}
   } finally {$secure.Dispose();$password=$null}
  }
  'packages.list' {
   return @(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'|Where-Object DisplayName|Select-Object DisplayName,DisplayVersion,Publisher,PSChildName)
  }
  'package.install' {
   $winget=Get-Command winget.exe -ErrorAction Stop
   $output=& $winget.Source install --id $p.name --exact --silent --disable-interactivity --accept-package-agreements --accept-source-agreements 2>&1|Out-String
   if($LASTEXITCODE -ne 0){throw ('Package installation failed: '+$output)}
   return @{installed=$p.name;output=$output}
  }
  'package.remove' {
   $winget=Get-Command winget.exe -ErrorAction Stop
   $output=& $winget.Source uninstall --id $p.name --exact --silent --disable-interactivity 2>&1|Out-String
   if($LASTEXITCODE -ne 0){throw ('Package removal failed: '+$output)}
   return @{removed=$p.name;output=$output}
  }
  'patches.scan' {
   $session=New-Object -ComObject Microsoft.Update.Session
   $search=$session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
   return @{updates=@($search.Updates|ForEach-Object {@{title=$_.Title;id=$_.Identity.UpdateID;downloaded=$_.IsDownloaded;reboot_behavior=[int]$_.InstallationBehavior.RebootBehavior}})}
  }
  'patches.install' {
   $session=New-Object -ComObject Microsoft.Update.Session
   $found=$session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
   $updates=New-Object -ComObject Microsoft.Update.UpdateColl
   foreach($update in $found.Updates){if(-not $update.EulaAccepted){$update.AcceptEula()};$null=$updates.Add($update)}
   if($updates.Count -eq 0){return @{installed=0;reboot_required=$false}}
   $download=$session.CreateUpdateDownloader();$download.Updates=$updates;$dr=$download.Download()
   if([int]$dr.ResultCode -ne 2){throw 'Not all selected updates downloaded successfully'}
   $installer=$session.CreateUpdateInstaller();$installer.Updates=$updates;$result=$installer.Install()
   $items=@();for($i=0;$i -lt $updates.Count;$i++){$items+=@{title=$updates.Item($i).Title;result_code=[int]$result.GetUpdateResult($i).ResultCode;hresult=$result.GetUpdateResult($i).HResult}}
   if([int]$result.ResultCode -ne 2){throw ('Some updates failed: '+($items|ConvertTo-Json -Compress))}
   return @{updates=$items;reboot_required=$result.RebootRequired}
  }
  'isolation.release' {
   $stamp=Join-Path $v.root 'isolation.json'
   if(-not(Test-Path -LiteralPath $stamp)){return @{isolated=$false}}
   Get-NetFirewallRule -Group 'NorthGate RMM temporary isolation' -ErrorAction SilentlyContinue|Remove-NetFirewallRule
   if(Get-NetFirewallRule -Group 'NorthGate RMM temporary isolation' -ErrorAction SilentlyContinue){throw 'Isolation cleanup incomplete'}
   Remove-Item -LiteralPath $stamp
   return @{isolated=$false}
  }
  'isolation.start' {
   $stamp=Join-Path $v.root 'isolation.json'
   if((Test-Path -LiteralPath $stamp) -or (Get-NetFirewallRule -Group 'NorthGate RMM temporary isolation' -ErrorAction SilentlyContinue)){throw 'Isolation already exists; release first'}
   $ip=[Net.IPAddress]::Parse($v.server_ip);if($ip.AddressFamily -ne 'InterNetwork'){throw 'Pinned IPv4 management address required'}
   $octets=$ip.GetAddressBytes();[Array]::Reverse($octets);$value=[BitConverter]::ToUInt32($octets,0)
   function As-IP([uint32]$n){$b=[BitConverter]::GetBytes($n);[Array]::Reverse($b);return ([Net.IPAddress]::new($b)).ToString()}
   $blocks=@(('0.0.0.0-'+(As-IP ($value-1))),((As-IP ($value+1))+'-255.255.255.255'),'::/0')
   $expiry=(Get-Date).AddSeconds($p.seconds)
   $task='NorthGate-RMM-Isolation-'+$v.job
   $a=New-ScheduledTaskAction -Execute $v.binary -Argument ('--release-isolation "'+$v.config+'"')
   $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
   $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
   Register-ScheduledTask -TaskName $task -Action $a -Principal $principal -Trigger (New-ScheduledTaskTrigger -Once -At $expiry) -Settings $settings|Out-Null
   @{expires=$expiry.ToUniversalTime().ToString('o');management_ip=$v.server_ip;task=$task}|ConvertTo-Json|Set-Content -LiteralPath $stamp
   try {
    foreach($direction in @('Inbound','Outbound')){New-NetFirewallRule -Name ('NorthGate-RMM-Isolation-'+$direction) -DisplayName ('NorthGate RMM temporary '+$direction+' isolation') -Group 'NorthGate RMM temporary isolation' -Direction $direction -Action Block -RemoteAddress $blocks -Profile Any|Out-Null}
    return @{isolated=$true;expires=$expiry.ToUniversalTime().ToString('o');management_ip=$v.server_ip}
   } catch {Get-NetFirewallRule -Group 'NorthGate RMM temporary isolation' -ErrorAction SilentlyContinue|Remove-NetFirewallRule;Remove-Item -LiteralPath $stamp;throw}
  }
  default {throw 'Unsupported Windows operation'}
 }
}
try {$result=Invoke-Operation;ConvertTo-Json -InputObject $result -Depth 12 -Compress}
catch {ConvertTo-Json -InputObject @{error=$_.Exception.Message} -Compress;exit 1}
