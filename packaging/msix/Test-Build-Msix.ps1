[CmdletBinding()]
param(
    [string]$MakeAppxPath,
    [ValidateSet('environment', 'configuration')]
    [string[]]$Modes = @('environment', 'configuration')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$testRoot = Join-Path $repoRoot "target\msix-tests\$([guid]::NewGuid().ToString('N'))"
$previousTargetDir = $env:CARGO_TARGET_DIR
$previousRustFlags = $env:RUSTFLAGS
$previousOffline = $env:CARGO_NET_OFFLINE
$target = 'x86_64-pc-windows-msvc'

try {
    $env:CARGO_NET_OFFLINE = 'true'
    $env:RUSTFLAGS = '-C target-feature=+crt-static'
    foreach ($mode in $Modes) {
        $env:CARGO_TARGET_DIR = $null
        $fixtureRoot = Join-Path $testRoot "$mode fixture"
        $fixturePackaging = Join-Path $fixtureRoot 'packaging\msix'
        $sourceDir = Join-Path $fixtureRoot 'src'
        $null = New-Item -ItemType Directory -Force -Path $fixturePackaging, $sourceDir
        foreach ($name in @('Build-Msix.ps1', 'AppxManifest.xml', 'Assets')) {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $fixturePackaging -Recurse
        }
        Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE') -Destination $fixtureRoot
        @'
[package]
name = "msix-target-dir-fixture"
version = "0.1.0"
edition = "2024"

[[bin]]
name = "locksmith"
path = "src/main.rs"

[workspace]
'@ | Set-Content -LiteralPath (Join-Path $fixtureRoot 'Cargo.toml') -Encoding utf8
        $sourcePath = Join-Path $sourceDir 'main.rs'
        'fn main() { println!("stale"); }' | Set-Content -LiteralPath $sourcePath -Encoding utf8
        $defaultTargetDir = Join-Path $fixtureRoot 'target'
        Push-Location $fixtureRoot
        try {
            & cargo generate-lockfile --offline
            if ($LASTEXITCODE -ne 0) { throw 'Fixture lockfile generation failed.' }
            & cargo build --release --locked --offline --target $target --target-dir $defaultTargetDir --bin locksmith
            if ($LASTEXITCODE -ne 0) { throw 'Stale fixture build failed.' }
            $expected = "fresh-$mode"
            "fn main() { println!(`"$expected`"); }" | Set-Content -LiteralPath $sourcePath -Encoding utf8
            if ($mode -eq 'environment') {
                $env:CARGO_TARGET_DIR = Join-Path $fixtureRoot 'custom environment target'
            } else {
                $configDir = Join-Path $fixtureRoot '.cargo'
                $null = New-Item -ItemType Directory -Path $configDir
                '[build]', 'target-dir = "custom configuration target"' |
                    Set-Content -LiteralPath (Join-Path $configDir 'config.toml') -Encoding utf8
            }
            $metadataText = & cargo metadata --no-deps --format-version 1 --offline
            if ($LASTEXITCODE -ne 0) { throw 'Fixture metadata failed.' }
            $configuredTargetDir = ($metadataText | ConvertFrom-Json).target_directory
            if ($configuredTargetDir -eq $defaultTargetDir) { throw "$mode override was not active." }
            $parameters = @{}
            if ($MakeAppxPath) { $parameters.MakeAppxPath = $MakeAppxPath }
            & (Join-Path $fixturePackaging 'Build-Msix.ps1') @parameters
            [xml]$fixtureManifest = Get-Content -LiteralPath (Join-Path $fixturePackaging 'AppxManifest.xml') -Raw
            $packageVersion = $fixtureManifest.Package.Identity.Version
            $packagePath = Join-Path $defaultTargetDir "msix\locksmith_${packageVersion}_x64.msix"
            $unpacked = Join-Path $fixtureRoot 'unpacked'
            # MSIX is a ZIP; inspect the executable actually included in the package.
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $unpacked)
            $packagedBinary = Join-Path $unpacked 'locksmith.exe'
            $actual = & $packagedBinary --help
            if ($LASTEXITCODE -ne 0 -or $actual -ne $expected) {
                throw "$mode override packaged '$actual'; expected '$expected'."
            }
            $builtBinary = Join-Path $defaultTargetDir "$target\release\locksmith.exe"
            if ((Get-FileHash -LiteralPath $packagedBinary).Hash -ne
                (Get-FileHash -LiteralPath $builtBinary).Hash) {
                throw "$mode package does not match the fresh build."
            }
            Write-Output "PASS: $mode target-directory override packages the fresh executable."
        } finally {
            Pop-Location
        }
    }
    Write-Output "Test artifacts: $testRoot"
} finally {
    $env:CARGO_TARGET_DIR = $previousTargetDir
    $env:RUSTFLAGS = $previousRustFlags
    $env:CARGO_NET_OFFLINE = $previousOffline
}
