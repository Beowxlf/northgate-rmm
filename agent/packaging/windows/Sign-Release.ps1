[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Directory,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory)][uri]$TimestampServer
)
$ErrorActionPreference = 'Stop'
# The native Authenticode timestamp API supports HTTP, not HTTPS. The signed
# countersignature is authenticated by Windows, and is required below.
# https://learn.microsoft.com/powershell/module/microsoft.powershell.security/set-authenticodesignature#-timestampserver
if ($TimestampServer.Scheme -ne 'http' -or $TimestampServer.UserInfo -or $TimestampServer.Fragment) { throw 'A credential-free HTTP Authenticode timestamp authority is required.' }
$root = (Resolve-Path -LiteralPath $Directory).Path
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint"
if (-not $certificate.HasPrivateKey) { throw 'Signing custody is unavailable.' }
if (Test-Path -LiteralPath (Join-Path $root 'release.json')) { throw 'Release manifest already exists.' }
$files = @(Get-ChildItem -LiteralPath $root -File)
foreach ($file in $files) {
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point rejected.' }
    if ($file.Extension -in @('.exe', '.ps1')) {
        $signed = Set-AuthenticodeSignature -LiteralPath $file.FullName -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer.AbsoluteUri
        if ($signed.Status -ne 'Valid' -or $null -eq $signed.TimeStamperCertificate) { throw 'Authenticode signing or timestamp verification failed.' }
    }
}
foreach ($file in $files) { $file.Refresh() }
$records = @($files | Sort-Object Name | ForEach-Object {
    @{ name=$_.Name; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); bytes=$_.Length }
})
$manifest = @{format=1; source_commit=$SourceCommit; platform='windows-amd64'; files=$records} | ConvertTo-Json -Depth 5 -Compress
$encoded = [Text.UTF8Encoding]::new($false).GetBytes($manifest)
try { Add-Type -AssemblyName System.Security.Cryptography.Pkcs }
catch { Add-Type -AssemblyName System.Security }
$content = [Security.Cryptography.Pkcs.ContentInfo]::new($encoded)
$cms = [Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
$signer = [Security.Cryptography.Pkcs.CmsSigner]::new($certificate)
$signer.DigestAlgorithm = [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
$cms.ComputeSignature($signer)
[IO.File]::WriteAllBytes((Join-Path $root 'release.json'), $encoded)
[IO.File]::WriteAllBytes((Join-Path $root 'release.p7s'), $cms.Encode())
Write-Output 'Release signed; independently verify before publication or installation.'
