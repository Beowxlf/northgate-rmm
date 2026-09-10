#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$root='C:\Program Files\NorthGate RMM'
$binary=Join-Path $root 'northgate-rmm-agent.exe'
foreach($p in @($root,$binary)) {if((Get-Item -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse point rejected'}}
$signature=Get-AuthenticodeSignature -LiteralPath $binary
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne '15F460AB7B71F04D73F6622A2866BD7EC0B27C09'){throw 'Expected signed lab agent required'}
$sid=(Get-LocalUser -Name rmmremote).SID.Value
foreach($p in @($root,$binary)) {
 & icacls.exe $p /grant:r "*$($sid):RX" | Out-Null
 if($LASTEXITCODE -ne 0){throw 'Inspection executable access failed'}
}
Write-Output 'Dedicated remote account has read/execute access to the signed executable only; agent state ACLs unchanged.'
