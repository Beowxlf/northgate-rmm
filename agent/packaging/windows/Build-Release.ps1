[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Go,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?$')][string]$Version,
    [Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$agentRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Output directory must be new.' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory).Path
$binary = Join-Path $resolvedOutput 'northgate-rmm-agent.exe'
$oldGOOS, $oldGOARCH, $oldCGO = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED
Push-Location $agentRoot
try {
    & git diff --quiet HEAD -- .
    if ($LASTEXITCODE -ne 0) { throw 'Release build requires committed agent source.' }
    $env:GOOS = 'windows'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
    & $Go build -mod=readonly -trimpath -buildvcs=true -ldflags "-s -w -buildid= -X main.version=$Version" -o $binary ./cmd/northgate-rmm-agent
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' | Copy-Item -Destination $resolvedOutput
    Copy-Item -LiteralPath (Join-Path $agentRoot '..\LICENSE') -Destination $resolvedOutput
    foreach ($relative in @('NOTICE','THIRD_PARTY_NOTICES.md','third_party\golang-x-sys-LICENSE')) {
        Copy-Item -LiteralPath (Join-Path $agentRoot "..\$relative") -Destination $resolvedOutput
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'agent.json.example') -Destination $resolvedOutput
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '../tools') -Destination (Join-Path $resolvedOutput 'tools') -Recurse
    $moduleLines = @(& $Go list -m '-f={{.Path}}|{{.Version}}' all)
    if ($LASTEXITCODE -ne 0) { throw 'Module inventory failed.' }
    $packages = @()
    $relationships = @(@{spdxElementId='SPDXRef-DOCUMENT'; relationshipType='DESCRIBES'; relatedSpdxElement='SPDXRef-Package-0'})
    for ($index=0; $index -lt $moduleLines.Count; $index++) {
        $parts = $moduleLines[$index].Split('|')
        $packageVersion = if ($parts[1]) { $parts[1] } else { $Version }
        $packages += @{SPDXID="SPDXRef-Package-$index"; name=$parts[0]; versionInfo=$packageVersion; downloadLocation='NOASSERTION'; filesAnalyzed=$false; licenseConcluded='NOASSERTION'; licenseDeclared='NOASSERTION'; copyrightText='NOASSERTION'; externalRefs=@(@{referenceCategory='PACKAGE-MANAGER'; referenceType='purl'; referenceLocator="pkg:golang/$($parts[0])@$packageVersion"})}
        if ($index -gt 0) { $relationships += @{spdxElementId='SPDXRef-Package-0'; relationshipType='DEPENDS_ON'; relatedSpdxElement="SPDXRef-Package-$index"} }
    }
    $sbom = @{spdxVersion='SPDX-2.3'; dataLicense='CC0-1.0'; SPDXID='SPDXRef-DOCUMENT'; name="northgate-rmm-agent-$Version"; documentNamespace="https://northgate.invalid/spdx/$([guid]::NewGuid())"; creationInfo=@{creators=@('Tool: NorthGate-RMM-Build'); created=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')}; packages=$packages; relationships=$relationships}
    $sbom | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $resolvedOutput 'sbom.spdx.json') -Encoding UTF8
    & $Go version -m $binary | Set-Content -LiteralPath (Join-Path $resolvedOutput 'build-provenance.txt') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { throw 'Build provenance failed.' }
    Get-FileHash -LiteralPath $binary -Algorithm SHA256 | Select-Object Hash | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $resolvedOutput 'unsigned-build.json')
} finally {
    Pop-Location
    $env:GOOS = $oldGOOS; $env:GOARCH = $oldGOARCH; $env:CGO_ENABLED = $oldCGO
}
Write-Output 'Unsigned source build produced. Use authorized signing custody, then independently pin the signed file hash and certificate before installation.'
