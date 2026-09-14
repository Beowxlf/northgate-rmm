#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Binary,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$ExpectedSignerThumbprint
)
$ErrorActionPreference = 'Stop'
$serviceName = 'NorthGateRMMAgent'
$installRoot = Join-Path $env:ProgramFiles 'NorthGate RMM'
$destination = Join-Path $installRoot 'northgate-rmm-agent.exe'
$previous = Join-Path $installRoot 'northgate-rmm-agent.previous.exe'
$staged = Join-Path $installRoot 'northgate-rmm-agent.pending.exe'
foreach ($path in @($installRoot, $destination)) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points are not supported.' }
}
if ((Test-Path -LiteralPath $previous) -or (Test-Path -LiteralPath $staged)) { throw 'Previous upgrade requires reconciliation.' }
$service = Get-Service -Name $serviceName
$wasRunning = $service.Status -eq 'Running'
Copy-Item -LiteralPath (Resolve-Path -LiteralPath $Binary).Path -Destination $staged
$signature = Get-AuthenticodeSignature -LiteralPath $staged
if ((Get-FileHash -LiteralPath $staged -Algorithm SHA256).Hash -ne $ExpectedSha256 -or $signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint) {
    throw 'Staged package verification failed; service has not been changed.'
}
Stop-Service -Name $serviceName
$service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(45))
try {
    # Fixed paths have been checked inside the protected installation directory.
    Move-Item -LiteralPath $destination -Destination $previous
    Move-Item -LiteralPath $staged -Destination $destination
    if ($wasRunning) {
        Start-Service -Name $serviceName
        (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    }
} catch {
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $previous) {
        if (Test-Path -LiteralPath $destination) { Move-Item -LiteralPath $destination -Destination $staged }
        Move-Item -LiteralPath $previous -Destination $destination
        if ($wasRunning) { Start-Service -Name $serviceName }
    }
    throw 'Upgrade failed; prior binary restored where available. Inspect service state.'
}
Write-Output 'Upgrade installed. Prior binary retained; product validation remains required.'
