# RMM verifies an SFTP-staged file before publishing its final name.
$ErrorActionPreference='Stop'
$root='C:\Users\rmmremote\NorthGateRMM-Ops'
try {
    $name=[string]$metadata.name
    if($name -cnotmatch '^[a-f0-9]{12}-[A-Za-z0-9][A-Za-z0-9._-]{0,99}$' -or $name.EndsWith('.')){throw 'Invalid name'}
    $size=[long]$metadata.size
    if($size -lt 0 -or $size -gt 20971520 -or $metadata.sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid metadata'}
    $folder=Get-Item -LiteralPath $root -Force
    $temp=Join-Path $root ('.upload-'+$name)
    $file=Get-Item -LiteralPath $temp -Force
    if((($folder.Attributes -bor $file.Attributes) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Unsafe path'}
    if($file.Length -ne $size){throw 'Size mismatch'}
    $hash=(Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash.ToLowerInvariant()
    if($hash -cne $metadata.sha256){throw 'Checksum mismatch'}
    [IO.File]::Move($temp,(Join-Path $root $name))
    [Console]::Out.WriteLine((@{name=$name;size=$size;sha256=$hash}|ConvertTo-Json -Compress))
    exit 0
} catch {
    [Console]::Error.WriteLine('Staged file was not accepted')
    exit 1
}
