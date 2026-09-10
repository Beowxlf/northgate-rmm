$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$v=[Console]::In.ReadToEnd()|ConvertFrom-Json
$state='C:\ProgramData\NorthGateWxlfgar';$install='C:\Program Files\NorthGateWxlfgar'
foreach($path in @($state,$install)){
 $current=$path
 while($current){if((Test-Path -LiteralPath $current) -and ((Get-Item -LiteralPath $current).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse installation path rejected'};$current=Split-Path $current}
}
$signature=Get-AuthenticodeSignature -LiteralPath $v.binary
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $v.signer){throw 'Capture binary signer rejected'}
if((Get-FileHash -LiteralPath $v.binary).Hash -ne $v.sha256){throw 'Capture binary integrity rejected'}
if((Test-Path -LiteralPath $state) -or (Test-Path -LiteralPath $install)){
 $configPath=Join-Path $state 'config.json'
 if(-not(Test-Path -LiteralPath $configPath) -or -not(Test-Path -LiteralPath (Join-Path $install 'wulfgar.exe'))){throw 'Partial installation requires reconciliation; existing data retained'}
 if((Get-Item -LiteralPath (Join-Path $install 'wulfgar.exe')).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse capture binary rejected'}
 if((Get-Item -LiteralPath $configPath).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse configuration rejected'}
 $actual=Get-Content -LiteralPath $configPath -Raw|ConvertFrom-Json
 $expected=Get-Content -LiteralPath $v.configuration -Raw|ConvertFrom-Json
 foreach($key in @('endpoint_id','identity_id','public_key')){if($actual.$key -cne $expected.$key){throw 'Capture identity differs; existing data retained'}}
 'Wxlfgar already installed; preserving configuration and captures.'
}else{
 'Installing Wxlfgar and its signed-job service...'
 & $v.installer -Binary $v.binary -ExpectedSha256 $v.sha256 -ExpectedSignerThumbprint $v.signer -Configuration $v.configuration -AgentIdentity $v.identity
}
$stage=Join-Path $state 'installers'
if(Test-Path -LiteralPath $stage){if((Get-Item -LiteralPath $stage).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse installer directory rejected'}}else{New-Item -ItemType Directory -Path $stage|Out-Null}
function Get-VerifiedInstaller([string]$url,[string]$name,[string]$publisher){
 $path=Join-Path $stage $name
 if(Test-Path -LiteralPath $path){if((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse installer rejected'}}else{
  [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $path -TimeoutSec 180
 }
 $sig=Get-AuthenticodeSignature -LiteralPath $path
 if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -ne $publisher){throw 'Dependency publisher signature rejected'}
 return $path
}
if(-not(Test-Path 'C:\Program Files\Wireshark\dumpcap.exe')){
 'Installing the signed Wireshark capture utility...'
 $package=Get-VerifiedInstaller 'https://2.na.dl.wireshark.org/win64/Wireshark-4.6.8-x64.exe' 'Wireshark-4.6.8-x64.exe' 'Wireshark Foundation'
 $process=Start-Process -FilePath $package -ArgumentList '/S','/desktopicon=no' -WindowStyle Hidden -PassThru
 if(-not $process.WaitForExit(240000)){throw 'Dependency installer still running; inspect before retrying'}
 if($process.ExitCode -notin @(0,3010)){throw ('Wireshark installer exit '+$process.ExitCode)}
 if(-not(Test-Path 'C:\Program Files\Wireshark\dumpcap.exe')){throw 'Capture utility not present after installation'}
}
Start-Service NorthGateWxlfgar
if(-not(Get-Service npcap -ErrorAction SilentlyContinue)){
 $npcap=Get-VerifiedInstaller 'https://npcap.com/dist/npcap-1.88.exe' 'npcap-1.88.exe' 'Nmap Software LLC'
 'ACTION REQUIRED: Wxlfgar and Wireshark are installed. Npcap free edition requires its interactive installer.'
 'Connect through RDP as an administrator, run the verified installer below, then select Refresh readiness in Network capture.'
 $npcap
 'Capture is not ready until that driver is installed. No reboot was initiated.'
}else{'Installation completed. Refresh capture readiness to verify interfaces. Capture remains off.'}
