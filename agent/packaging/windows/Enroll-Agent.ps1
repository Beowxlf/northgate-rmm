#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri]$EnrollmentOrigin,
    [Parameter(Mandatory)][string]$GrantFile,
    [Parameter(Mandatory)][string]$ServerRoots,
    [Parameter(Mandatory)][string]$IssuerRoots,
    [string]$WxlfgarBinary,
    [string]$WxlfgarSha256,
    [string]$WxlfgarSignerThumbprint,
    [string]$RmmToolPublicKey
)
$ErrorActionPreference = 'Stop'
if($WxlfgarBinary -and (-not $WxlfgarSha256 -or -not $WxlfgarSignerThumbprint -or -not $RmmToolPublicKey)){throw 'Tool enrollment requires binary checksum, signer and RMM tool public key.'}

$name = 'NorthGateRMMAgent'
$service = Get-Service -Name $name
if ($service.Status -ne 'Stopped') { throw 'Enrollment requires the service to be stopped.' }
if ($EnrollmentOrigin.Scheme -ne 'https' -or $EnrollmentOrigin.UserInfo -or $EnrollmentOrigin.Query -or $EnrollmentOrigin.Fragment -or $EnrollmentOrigin.AbsolutePath -ne '/') { throw 'Enrollment requires a plain HTTPS origin.' }
$installRoot = Join-Path $env:ProgramFiles 'NorthGate RMM'
$stateRoot = Join-Path $env:ProgramData 'NorthGate RMM'
$identityPath = Join-Path $stateRoot 'identity\identity.json'
if (Test-Path -LiteralPath (Join-Path $stateRoot 'identity')) { throw 'Existing identity state requires reconciliation.' }
foreach ($inputFile in @($GrantFile, $ServerRoots, $IssuerRoots)) {
    if ($inputFile -notmatch '^[A-Za-z]:\\' -or $inputFile.Contains('"') -or [IO.Path]::GetFullPath($inputFile) -ne $inputFile) { throw 'Inputs require absolute clean paths without quotes.' }
    $item = Get-Item -LiteralPath $inputFile
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Input must be a regular file.' }
}
$executable = Join-Path $installRoot 'northgate-rmm-agent.exe'
$config = Join-Path $installRoot 'agent.json'
$normal = '"{0}" --config "{1}"' -f $executable, $config
$bootstrap = '{0} --enroll "{1}" --grant-file "{2}" --server-roots "{3}" --issuer-roots "{4}"' -f $normal, $EnrollmentOrigin.AbsoluteUri, $GrantFile, $ServerRoots, $IssuerRoots
try {
    $registration = Invoke-CimMethod -InputObject (Get-CimInstance Win32_Service -Filter "Name='$name'") -MethodName Change -Arguments @{PathName=$bootstrap; StartMode='Manual'}
    if ($registration.ReturnValue -ne 0) { throw 'Bootstrap registration failed.' }
    & sc.exe start $name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Bootstrap start failed.' }
    $deadline = [DateTime]::UtcNow.AddSeconds(75)
    do {
        Start-Sleep -Milliseconds 500
        $service.Refresh()
    } while ($service.Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline)
    $finished = Get-CimInstance Win32_Service -Filter "Name='NorthGateRMMAgent'"
    if ($service.Status -ne 'Stopped' -or $finished.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $identityPath)) { throw 'Enrollment outcome requires reconciliation.' }
} finally {
    $registration = Invoke-CimMethod -InputObject (Get-CimInstance Win32_Service -Filter "Name='$name'") -MethodName Change -Arguments @{PathName=$normal; StartMode='Manual'}
    if ($registration.ReturnValue -ne 0) { throw 'Could not restore normal service configuration; leave service stopped.' }
}
Write-Output 'Identity installed. Service remains stopped for acceptance. Securely remove the single-use grant file after verification.'

if($WxlfgarBinary){
    $profile=Join-Path $stateRoot 'wxlfgar-enrollment-public.json'
    try {
        [IO.File]::WriteAllText($profile,(@{public_key=$RmmToolPublicKey;endpoint_id='';identity_id=''}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
         $toolInstaller=Join-Path $PSScriptRoot 'tools/Install-Wxlfgar.ps1'
        if(-not(Test-Path -LiteralPath $toolInstaller)){$toolInstaller=Join-Path $PSScriptRoot '../tools/Install-Wxlfgar.ps1'}
        & $toolInstaller -Binary $WxlfgarBinary -ExpectedSha256 $WxlfgarSha256 -ExpectedSignerThumbprint $WxlfgarSignerThumbprint -Configuration $profile -AgentIdentity $identityPath
    } finally {if(Test-Path -LiteralPath $profile){Remove-Item -LiteralPath $profile -Force}}
}
