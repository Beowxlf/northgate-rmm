#Requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$serviceName = 'NorthGateRMMAgent'
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    Stop-Service -Name $serviceName
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(45))
    & sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Service removal failed.' }
}
# Retain the protected identity and spool for evidence/recovery. The operator
# must revoke the endpoint identity through northgate-rmm-admin before disposal.
Write-Output 'Service removed. Revoke its server identity; protected files remain for recovery and controlled disposal.'
