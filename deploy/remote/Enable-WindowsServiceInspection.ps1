#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$sid=(Get-LocalUser -Name rmmremote).SID
$lines=& sc.exe sdshow scmanager
if($LASTEXITCODE -ne 0){throw 'Service manager permissions query failed'}
$sddl=($lines | Where-Object {$_ -like 'D:*'}) -join ''
if(!$sddl){throw 'Service manager descriptor missing'}
$backup='C:\ProgramData\NorthGateRMM-RemoteBootstrap\scmanager-before-inspection.sddl'
if(!(Test-Path -LiteralPath $backup)){[IO.File]::WriteAllText($backup,$sddl)}
$descriptor=New-Object Security.AccessControl.RawSecurityDescriptor($sddl)
$exists=$false
foreach($ace in $descriptor.DiscretionaryAcl){if($ace.SecurityIdentifier -eq $sid -and $ace.AceQualifier -eq 'AccessAllowed' -and ($ace.AccessMask -band 5) -eq 5){$exists=$true}}
if(!$exists){
 # 0x1 CONNECT + 0x4 ENUMERATE_SERVICE. No create, lock, start/stop or config rights.
 $ace=New-Object Security.AccessControl.CommonAce([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessAllowed,5,$sid,$false,$null)
 $descriptor.DiscretionaryAcl.InsertAce($descriptor.DiscretionaryAcl.Count,$ace)
 & sc.exe sdset scmanager $descriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
 if($LASTEXITCODE -ne 0){throw 'Service enumeration permission update failed'}
}
Write-Output 'Dedicated inspection account granted service-manager connect and enumerate only; original descriptor retained.'
