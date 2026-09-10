[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Directory,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$ExpectedSignerThumbprint,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedSourceCommit
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $Directory).Path
foreach ($name in @('release.json','release.p7s')) {
    $file = Get-Item -LiteralPath (Join-Path $root $name)
    if ($file.Length -gt 1048576 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Release envelope invalid.' }
}
$encoded = [IO.File]::ReadAllBytes((Join-Path $root 'release.json'))
try { Add-Type -AssemblyName System.Security.Cryptography.Pkcs }
catch { Add-Type -AssemblyName System.Security }
$cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($encoded), $true)
$cms.Decode([IO.File]::ReadAllBytes((Join-Path $root 'release.p7s')))
$cms.CheckSignature($false)
if ($cms.SignerInfos.Count -ne 1 -or $cms.SignerInfos[0].Certificate.Thumbprint -ne $ExpectedSignerThumbprint) { throw 'Release signer mismatch.' }
$manifest = [Text.Encoding]::UTF8.GetString($encoded) | ConvertFrom-Json
if ($manifest.format -ne 1 -or $manifest.platform -ne 'windows-amd64' -or $manifest.source_commit -ne $ExpectedSourceCommit) { throw 'Release identity mismatch.' }
$names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($record in $manifest.files) {
    if ($record.name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -or -not $names.Add($record.name)) { throw 'Release filename invalid.' }
    $file = Get-Item -LiteralPath (Join-Path $root $record.name)
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -ne $record.bytes -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne $record.sha256) { throw 'Release file mismatch.' }
    if ($file.Extension -in @('.exe','.ps1')) {
        $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint -or $null -eq $signature.TimeStamperCertificate) { throw 'Authenticode identity or timestamp mismatch.' }
    }
}
if (-not $names.Contains('northgate-rmm-agent.exe') -or @(Get-ChildItem -LiteralPath $root -Force).Count -ne $names.Count+2) { throw 'Release file set mismatch.' }
Write-Output 'Release contents and independently pinned signer/source verified.'
