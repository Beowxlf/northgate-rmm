#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Binary,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$ExpectedSignerThumbprint,
    [Parameter(Mandatory)][string]$Configuration
)
$ErrorActionPreference = 'Stop'
$serviceName = 'NorthGateRMMAgent'
$installRoot = Join-Path $env:ProgramFiles 'NorthGate RMM'
$stateRoot = Join-Path $env:ProgramData 'NorthGate RMM'
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'Service exists; use the reviewed upgrade procedure.' }
if ((Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath $stateRoot)) { throw 'Existing installation or state requires reconciliation.' }
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
if ((Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash -ne $ExpectedSha256) { throw 'Package hash mismatch.' }
$signature = Get-AuthenticodeSignature -LiteralPath $binaryPath
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint) { throw 'Package signer verification failed.' }
$configurationText = Get-Content -LiteralPath $Configuration -Raw
$config = $configurationText | ConvertFrom-Json
if ($config.state_directory -ne $stateRoot) { throw 'Configuration state directory must match the dedicated installation path.' }
$createdService = $false
try {
    New-Item -ItemType Directory -Path $installRoot | Out-Null
    New-Item -ItemType Directory -Path $stateRoot | Out-Null
    $destination = Join-Path $installRoot 'northgate-rmm-agent.exe'
    Copy-Item -LiteralPath $binaryPath -Destination $destination
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $ExpectedSha256) { throw 'Installed hash mismatch.' }
    $configPath = Join-Path $installRoot 'agent.json'
    [IO.File]::WriteAllText($configPath, $configurationText, [Text.UTF8Encoding]::new($false))
    & sc.exe create $serviceName binPath= ('"{0}" --config "{1}"' -f $destination, $configPath) start= demand obj= "NT SERVICE\$serviceName"
    if ($LASTEXITCODE -ne 0) { throw 'Service registration failed.' }
    $createdService = $true
    foreach ($directory in @($installRoot, $stateRoot)) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        $rights = if ($directory -eq $stateRoot) { 'Modify' } else { 'ReadAndExecute' }
        $rule = [Security.AccessControl.FileSystemAccessRule]::new("NT SERVICE\$serviceName", $rights, 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $directory -AclObject $acl
    }
    if (-not [Diagnostics.EventLog]::SourceExists($serviceName)) {
        New-EventLog -LogName Application -Source $serviceName
    }
    Write-Output 'Installed stopped. Complete one-time enrollment under the service identity before enabling automatic start.'
} catch {
    if ($createdService) { & sc.exe delete $serviceName | Out-Null }
    # Retain exact created paths for inspection; never recursively remove state.
    throw 'Installation did not complete. Created files were retained for reconciliation.'
}
