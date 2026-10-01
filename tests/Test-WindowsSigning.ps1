$ErrorActionPreference = 'Stop'
$signer = Join-Path $PSScriptRoot '..\agent\packaging\windows\Sign-Release.ps1'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('rmm-signing-test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $scratch
$testFile = Join-Path $scratch 'test.exe'
[IO.File]::WriteAllBytes($testFile, [byte[]]@(0))
$rmmSigningCounter = [pscustomobject]@{Calls=0}
function Get-Item {
    param([string]$LiteralPath)
    if ($LiteralPath.StartsWith('Cert:\CurrentUser\My\')) { return [pscustomobject]@{HasPrivateKey=$true} }
    Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath
}
function Set-AuthenticodeSignature {
    param($LiteralPath, $Certificate, $HashAlgorithm, $TimestampServer)
    $rmmSigningCounter.Calls++
    [pscustomobject]@{Status='Valid'; TimeStamperCertificate=$null}
}
try {
    foreach ($url in @('https://timestamp.digicert.com','http://user:secret@timestamp.digicert.com','http://timestamp.digicert.com/#fragment')) {
        $rejected = $false
        try { & $signer -Directory $scratch -CertificateThumbprint ('0'*40) -SourceCommit ('0'*40) -TimestampServer $url }
        catch { if ($_.Exception.Message -like '*credential-free HTTP*') { $rejected=$true } else { throw } }
        if (-not $rejected) { throw 'Unsupported timestamp authority was accepted.' }
    }
    if ($rmmSigningCounter.Calls -ne 0) { throw 'Rejected input reached signing custody.' }
    $rejected = $false
    try { & $signer -Directory $scratch -CertificateThumbprint ('0'*40) -SourceCommit ('0'*40) -TimestampServer 'http://timestamp.digicert.com' }
    catch { if ($_.Exception.Message -like '*timestamp verification failed*') { $rejected=$true } else { throw } }
    if (-not $rejected -or $rmmSigningCounter.Calls -ne 1 -or (Test-Path (Join-Path $scratch 'release.json'))) { throw 'A missing timestamp was not rejected before manifest publication.' }
    'Windows signing failure-path checks passed.'
} finally {
    Remove-Item -LiteralPath $testFile -Force
    Remove-Item -LiteralPath $scratch
}
