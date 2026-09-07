#Requires -RunAsAdministrator
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$Binary,
 [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
 [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$ExpectedSignerThumbprint,
 [Parameter(Mandatory)][string]$Configuration,
 [Parameter(Mandatory)][string]$ServerRoots
)
$ErrorActionPreference='Stop'
$serviceName='NorthGateRMMManagement'
$installRoot='C:\Program Files\NorthGateRMMManagement'
$stateRoot='C:\ProgramData\NorthGateRMMManagement'
if((Get-Service $serviceName -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath $stateRoot)){throw 'Existing management installation requires the signed update workflow or explicit reconciliation'}
$source=(Resolve-Path -LiteralPath $Binary).Path
if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $ExpectedSha256){throw 'Worker digest rejected'}
$signature=Get-AuthenticodeSignature -LiteralPath $source
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint){throw 'Worker signer rejected'}
$config=Get-Content -LiteralPath $Configuration -Raw|ConvertFrom-Json
if($config.state_directory -ne $stateRoot -or $config.server_roots -ne "$stateRoot\server-ca.pem" -or $config.identity_file -ne 'C:\ProgramData\NorthGate RMM\identity\identity.json' -or $config.update_signer -ne $ExpectedSignerThumbprint){throw 'Configuration paths or update signer do not match the dedicated installation'}
$identity=Get-Content -LiteralPath $config.identity_file -Raw|ConvertFrom-Json
if($config.endpoint_id -ne $identity.endpoint_id -or $config.identity_id -notmatch '^[a-f0-9-]{36}$'){throw 'Worker enrollment binding mismatch'}
foreach($directory in @($installRoot,$stateRoot)){
 New-Item -ItemType Directory -Path $directory|Out-Null
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
 $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
 Set-Acl -LiteralPath $directory -AclObject $acl
}
$destination="$installRoot\northgate-rmm-management.exe"
Copy-Item -LiteralPath $source -Destination $destination
if((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $ExpectedSha256){throw 'Installed worker digest mismatch'}
Copy-Item -LiteralPath $ServerRoots -Destination $config.server_roots
[IO.File]::WriteAllText("$stateRoot\config.json",($config|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
New-Service -Name $serviceName -DisplayName 'NorthGate RMM privileged management' -BinaryPathName ('"'+$destination+'" --config "'+$stateRoot+'\config.json"') -StartupType Automatic|Out-Null
& "$env:WINDIR\System32\sc.exe" failure $serviceName reset= 86400 actions= restart/30000/restart/60000/restart/120000|Out-Null
if($LASTEXITCODE -ne 0){throw 'Cannot set worker recovery policy'}
Start-Service $serviceName
(Get-Service $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
Write-Output 'SYSTEM worker installed. Verify its authenticated readiness in RMM before running management actions. Existing monitoring and SSH identities are unchanged.'
