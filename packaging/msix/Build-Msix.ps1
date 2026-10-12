[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64')]
    [string]$Architecture = 'x64',
    [ValidatePattern('^[1-9][0-9]*\.[0-9]+\.[0-9]+\.0$')]
    [string]$PackageVersion,
    [string]$MakeAppxPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $MakeAppxPath) {
    $sdkBin = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $MakeAppxPath = Get-ChildItem -LiteralPath $sdkBin -Directory |
        Where-Object Name -Match '^10\.0\.\d+\.0$' |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName 'x64\makeappx.exe' } |
        Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $MakeAppxPath -or -not (Test-Path -LiteralPath $MakeAppxPath)) {
    throw 'Install the Windows SDK with MakeAppx, or pass -MakeAppxPath.'
}
[xml]$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'AppxManifest.xml') -Raw
if (-not $PackageVersion) { $PackageVersion = $manifest.Package.Identity.Version }
$version = [version]$PackageVersion
if ($version.Major -lt 1 -or $version.Revision -ne 0 -or
    $version.Major -gt 65535 -or $version.Minor -gt 65535 -or $version.Build -gt 65535) {
    throw 'Store versions need four components, a nonzero major, components <= 65535, and revision 0.'
}
$target = if ($Architecture -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
$targetDir = Join-Path $repoRoot 'target'
$previousRustFlags = $env:RUSTFLAGS
Push-Location $repoRoot
try {
    # Include the CRT in the binary so the MSIX needs no VC runtime installer.
    $env:RUSTFLAGS = "$previousRustFlags -C target-feature=+crt-static".Trim()
    # Override Cargo configuration so the build and staging paths always agree.
    & cargo build --release --locked --target $target --target-dir $targetDir --bin locksmith
    if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }
    $binary = Join-Path $targetDir "$target\release\locksmith.exe"
    if ($Architecture -eq 'x64' -or $env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
        & $binary --help
        if ($LASTEXITCODE -ne 0) { throw 'Release CLI help smoke check failed.' }
    } else {
        Write-Warning 'ARM64 binary built by cross compilation; runtime validation requires Windows on ARM64.'
    }
    # Use a fresh staging directory; never package the whole build directory.
    $buildRoot = Join-Path $targetDir 'msix'
    $null = New-Item -ItemType Directory -Force -Path $buildRoot
    $stage = Join-Path $buildRoot "stage-$([guid]::NewGuid().ToString('N'))"
    $null = New-Item -ItemType Directory -Path $stage
    Copy-Item -LiteralPath $binary -Destination $stage
    Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE') -Destination $stage
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Assets') -Destination $stage -Recurse
    $manifest.Package.Identity.Version = $PackageVersion
    $manifest.Package.Identity.ProcessorArchitecture = $Architecture
    $manifest.Save((Join-Path $stage 'AppxManifest.xml'))
    $packagePath = Join-Path $buildRoot "locksmith_${PackageVersion}_${Architecture}.msix"
    & $MakeAppxPath pack /d $stage /p $packagePath /h SHA256 /o
    if ($LASTEXITCODE -ne 0) { throw 'MSIX manifest validation or packaging failed.' }
    Get-FileHash -LiteralPath $packagePath -Algorithm SHA256
    Write-Output "Store upload package: $packagePath"
} finally {
    $env:RUSTFLAGS = $previousRustFlags
    Pop-Location
}
