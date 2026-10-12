# Microsoft Store package

This directory packages CLI release 0.1.3 as a full-trust Windows desktop MSIX.
The identity matches the reserved **locksmith** product in Partner Center
(Store ID `9PF14DG43JH0`). The package registers the console execution alias
`locksmith.exe`; run it from PowerShell, Command Prompt, or Windows Terminal.
It has no graphical interface. Its visible Start menu entry shows command-line
instructions and waits for Enter before closing.

## Build

On Windows, install stable Rust, Visual Studio C++ build tools (including the
ARM64 tools for cross-compilation), and the Windows SDK including MakeAppx.
From the repo:

```powershell
rustup target add x86_64-pc-windows-msvc aarch64-pc-windows-msvc
.\packaging\msix\Build-Msix.ps1
.\packaging\msix\Build-Msix.ps1 -Architecture arm64
```

The script builds with `--locked` and a static CRT, checks `--help` when the host
can run the target executable, stages only the executable, license, manifest,
and icon assets, then runs MakeAppx validation with SHA-256 block hashes.
It prints the upload path and SHA-256.
The build explicitly uses the repo's `target` directory, overriding
`CARGO_TARGET_DIR` and Cargo's `build.target-dir` so staging uses the fresh build.
Output is under `target\msix`, which is ignored by Git. It does not sign, install,
upload, or submit anything. Microsoft signs Store-delivered MSIX packages;
sideloading requires a separately signed package or a development registration.

The manifest's package version is `1.1.3.0`. The CLI/Cargo version remains
`0.1.3`. Microsoft Store requires a nonzero first component and a zero fourth
component. For pre-1.0 CLI releases, use `1.<minor>.<patch>.0`; after that,
choose an increasing Store version independently of Cargo. Override explicitly
with `-PackageVersion 1.1.4.0` when creating a new package revision.

The packages target x64 and ARM64 Windows Desktop, Windows 10 build 19041 or
later. ARM64 cross-compilation does not establish runtime behavior on ARM hardware.
Regenerate icon sizes from the included imagegen artwork with
`.\packaging\msix\New-Assets.ps1`. `StoreIcon.png` is the 300x300 listing icon.

## Release validation

Run `.\packaging\msix\Test-Build-Msix.ps1` to verify both target-directory
overrides with offline Cargo fixtures and MakeAppx, including a stale executable.

Run existing tests against the same static-CRT release configuration:

```powershell
$env:RUSTFLAGS = '-C target-feature=+crt-static'
cargo test --release --locked --target x86_64-pc-windows-msvc
```

The live-process tests need normal Windows process-query access. A restricted
sandbox can deny `NtQuerySystemInformation`; that is distinct from a test run
with normal access. Before submission, validate installed package activation,
working directory, scanning, and cancellation through the execution alias, and
run the Windows App Certification Kit. MakeAppx validation and unpackaged CLI
tests alone do not establish certification or installed-package behavior.

For unsigned local testing, enable Windows Developer Mode and register the
manifest from the staging directory printed by MakeAppx:

```powershell
Add-AppxPackage -Register '.\target\msix\stage-<id>\AppxManifest.xml'
```

The registration points into that directory. Remove it before deleting the files:

```powershell
Get-AppxPackage -Name 55832277989FF.locksmith | Remove-AppxPackage
```

## Store submission

Prepare a free, public, English (United States) listing in all available markets.
Upload `target\msix\locksmith_1.1.3.0_x64.msix` and
`target\msix\locksmith_1.1.3.0_arm64.msix` to Packages. Explain that `runFullTrust`
is needed to inspect accessible process handles/modules and optionally terminate
processes with user confirmation. Include terminal usage and Start menu behavior
in certification notes. The root `PRIVACY.md` describes local data processing;
Partner Center accepts policy text directly. Supply a genuine terminal screenshot
and review the listing, age ratings, and legal agreements before submitting.

Microsoft references:

- [Package requirements and versioning](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/app-package-requirements)
- [Console execution aliases](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-uap5-appexecutionalias)
- [Manual desktop packaging](https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-manual-conversion)
