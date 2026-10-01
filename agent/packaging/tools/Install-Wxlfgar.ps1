#Requires -RunAsAdministrator
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$Binary,
 [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
 [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$ExpectedSignerThumbprint,
 [Parameter(Mandatory)][string]$Configuration,
 [string]$AgentIdentity='C:\ProgramData\NorthGate RMM\identity\identity.json'
)
$ErrorActionPreference='Stop'
$install='C:\Program Files\NorthGateWxlfgar'
$state='C:\ProgramData\NorthGateWxlfgar'
if(Get-Service NorthGateWxlfgar -ErrorAction SilentlyContinue){throw 'Existing tool requires a controlled upgrade; stop and retain its configuration first.'}
if((Test-Path -LiteralPath $install) -or (Test-Path -LiteralPath $state)){throw 'Existing tool files require reconciliation.'}
$binaryPath=(Resolve-Path -LiteralPath $Binary).Path
if((Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash -ne $ExpectedSha256){throw 'Tool package checksum mismatch'}
$signature=Get-AuthenticodeSignature -LiteralPath $binaryPath
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint){throw 'Tool signature mismatch'}
$config=Get-Content -LiteralPath $Configuration -Raw | ConvertFrom-Json
if([Convert]::FromBase64String($config.public_key).Length -ne 32){throw 'Invalid RMM signing public key'}
# The enrollment bundle is read locally; its key/certificate values are never copied or printed.
$identity=Get-Content -LiteralPath $AgentIdentity -Raw | ConvertFrom-Json
if($identity.endpoint_id -notmatch '^[a-f0-9-]{36}$'){throw 'Agent is not enrolled'}
if($config.endpoint_id -and $config.endpoint_id -ne $identity.endpoint_id){throw 'Tool configuration belongs to another endpoint'}
$config | Add-Member -Force NoteProperty endpoint_id $identity.endpoint_id
if(-not $config.identity_id){$config | Add-Member -Force NoteProperty identity_id ''}
$config | Add-Member -Force NoteProperty root 'C:\ProgramData\NorthGateWxlfgar\state'
$config | Add-Member -Force NoteProperty dumpcap 'C:\Program Files\Wireshark\dumpcap.exe'
foreach($directory in @($install,$state)){
 New-Item -ItemType Directory -Path $directory | Out-Null
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
 $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
 if($directory -eq $install){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))}
 Set-Acl -LiteralPath $directory -AclObject $acl
}
Copy-Item -LiteralPath $binaryPath -Destination (Join-Path $install 'wulfgar.exe')
if((Get-FileHash -LiteralPath (Join-Path $install 'wulfgar.exe') -Algorithm SHA256).Hash -ne $ExpectedSha256){throw 'Installed checksum mismatch'}
[IO.File]::WriteAllText((Join-Path $state 'config.json'),($config|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
# Npcap admin-only access is confined to this fixed signed-job service, never the SSH account.
New-Service -Name NorthGateWxlfgar -BinaryPathName '"C:\Program Files\NorthGateWxlfgar\wulfgar.exe" --service' -StartupType Automatic -Description 'RMM-authorized bounded network capture' | Out-Null
Start-Service NorthGateWxlfgar
Write-Output 'Wxlfgar installed. Capture remains off. RMM capability discovery reports any missing Wireshark/Npcap prerequisite.'
