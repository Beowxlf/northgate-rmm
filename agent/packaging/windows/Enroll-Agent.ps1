#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri]$EnrollmentOrigin,
    [Parameter(Mandatory)][string]$GrantFile,
    [Parameter(Mandatory)][string]$ServerRoots,
    [Parameter(Mandatory)][string]$IssuerRoots
)
$ErrorActionPreference = 'Stop'
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
    & sc.exe config $name binPath= $bootstrap start= demand | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Bootstrap registration failed.' }
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
    & sc.exe config $name binPath= $normal start= demand | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restore normal service configuration; leave service stopped.' }
}
Write-Output 'Identity installed. Service remains stopped for acceptance. Securely remove the single-use grant file after verification.'
