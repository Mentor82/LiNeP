<#
.SYNOPSIS
    Build LiNeP shared libraries for Windows and Linux targets.

.DESCRIPTION
    Builds liblinep for one or more targets:

      win-x64      linep.dll   native MSVC/MinGW on this machine
      win-arm64    linep.dll   MSVC ARM64 cross-tools (VS component required)
      linux-x64    liblinep.so via WSL/GCC (native x64)
      linux-arm64  liblinep.so via WSL/GCC (aarch64 cross-compile)
      all          every target above (default)

    macOS targets (macos-x64, macos-arm64, macos-universal) must be built on a
    Mac using scripts/build-targets.sh.

    Linux tools (cmake, ninja, g++) are installed automatically in WSL.
    win-arm64 requires VS component:
      "MSVC v14x - VS 2022 C++ ARM64 build tools (Latest)"

.PARAMETER Target
    Which target(s) to build.
    Accepted: win-x64, win-arm64, linux-x64, linux-arm64, all
    Default:  all

.PARAMETER BuildType
    CMake build type: Release (default), Debug, RelWithDebInfo

.PARAMETER Clean
    Wipe each build directory before configuring.

.EXAMPLE
    .\scripts\build-targets.ps1
    .\scripts\build-targets.ps1 -Target win-arm64
    .\scripts\build-targets.ps1 -Target linux-x64 -BuildType Debug
    .\scripts\build-targets.ps1 -Clean
#>
param(
    [ValidateSet("win-x64","win-arm64","linux-x64","linux-arm64","all")]
    [string]$Target = "all",

    [ValidateSet("Release","Debug","RelWithDebInfo")]
    [string]$BuildType = "Release",

    [switch]$Clean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Step([string]$msg) {
    Write-Host ""; Write-Host "==> $msg" -ForegroundColor Cyan
}

function Invoke-Wsl([string]$cmd) {
    wsl -e bash -c $cmd
    if ($LASTEXITCODE -ne 0) { throw "WSL command failed (exit $LASTEXITCODE): $cmd" }
}

function Show-Artifact([string]$path, [string]$label) {
    if (Test-Path $path) {
        $size = (Get-Item $path).Length
        Write-Host ("  [OK] {0,-20} {1,9:N0} bytes  {2}" -f $label, $size, $path) -ForegroundColor Green
    } else {
        Write-Host "  [??] $label - not found at $path" -ForegroundColor Yellow
    }
}

function Show-WinArtifact([string]$outDir, [string]$label) {
    $candidates = @(
        (Join-Path $outDir "linep.dll"),
        (Join-Path $outDir "liblinep.dll")
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) {
            Show-Artifact $p $label
            return
        }
    }
    Show-Artifact $candidates[0] $label
}

# ── Repo root ────────────────────────────────────────────────────────────────

$RepoRoot  = Split-Path $PSScriptRoot -Parent
$Toolchain = "$RepoRoot\cmake\toolchains"

Write-Host "Repo: $RepoRoot" -ForegroundColor Gray

$DoWinX64    = $Target -in @("win-x64",    "all")
$DoWinArm64  = $Target -in @("win-arm64",  "all")
$DoLinuxX64  = $Target -in @("linux-x64",  "all")
$DoLinuxArm64= $Target -in @("linux-arm64","all")

# ── win-x64: native build on this machine ───────────────────────────────────

if ($DoWinX64) {
    Write-Step "Building win-x64  ($BuildType)"
    $out = "$RepoRoot\build-win-x64"
    if ($Clean -and (Test-Path $out)) { Remove-Item -Recurse -Force $out }

    cmake -S $RepoRoot -B $out -G Ninja `
        "-DCMAKE_BUILD_TYPE=$BuildType" `
        -DLINEP_BUILD_TESTS=OFF `
        --log-level=WARNING
    cmake --build $out --parallel
    if ($LASTEXITCODE -ne 0) { throw "win-x64 build failed." }
    Show-WinArtifact $out "win-x64"
}

# ── win-arm64: MSVC ARM64 cross ──────────────────────────────────────────────

if ($DoWinArm64) {
    Write-Step "Building win-arm64  ($BuildType)"

    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vsWhere)) { throw "vswhere.exe not found - install Visual Studio 2022." }
    $vsPath = & $vsWhere -latest -property installationPath

    $msvcVer = Get-ChildItem "$vsPath\VC\Tools\MSVC" -Directory |
               Sort-Object Name | Select-Object -Last 1
    $arm64cl = Join-Path $msvcVer.FullName "bin\Hostx64\arm64\cl.exe"

    if (-not (Test-Path $arm64cl)) {
        Write-Host ""
        Write-Host "  ARM64 cross-tools not installed." -ForegroundColor Red
        Write-Host "  Add VS component:  MSVC v14x - VS 2022 C++ ARM64 build tools (Latest)" -ForegroundColor Yellow
        Write-Host "  Or via winget:" -ForegroundColor Yellow
        Write-Host "    winget install Microsoft.VisualStudio.2022.Community --override '--add Microsoft.VisualStudio.Component.VC.Tools.ARM64'" -ForegroundColor Yellow
        throw "win-arm64 skipped - toolset not installed."
    }
    Write-Host "  cl.exe: $arm64cl" -ForegroundColor Gray

    $out       = "$RepoRoot\build-win-arm64"
    $vsDevCmd  = "$vsPath\Common7\Tools\VsDevCmd.bat"
    if ($Clean -and (Test-Path $out)) { Remove-Item -Recurse -Force $out }

    $cmds = (
        "`"$vsDevCmd`" -arch=arm64 -host_arch=amd64",
        "cmake -S `"$RepoRoot`" -B `"$out`" -G Ninja " +
            "-DCMAKE_BUILD_TYPE=$BuildType " +
            "-DCMAKE_TOOLCHAIN_FILE=`"$Toolchain\windows-arm64.cmake`" " +
            "-DLINEP_BUILD_TESTS=OFF --log-level=WARNING",
        "cmake --build `"$out`" --parallel"
    ) -join " && "

    cmd /c $cmds
    if ($LASTEXITCODE -ne 0) { throw "win-arm64 build failed (exit $LASTEXITCODE)." }
    Show-WinArtifact $out "win-arm64"
}

# ── Linux targets via WSL ────────────────────────────────────────────────────

if ($DoLinuxX64 -or $DoLinuxArm64) {

    # Convert Windows path to WSL mount path
    $WslRoot = $RepoRoot -replace '^([A-Za-z]):\\', { "/mnt/$($_.Groups[1].Value.ToLower())/" }
    $WslRoot = $WslRoot  -replace '\\', '/'

    Write-Step "Checking WSL"
    wsl -e bash -c "echo ok" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "WSL unavailable. Install WSL2 with a Debian/Ubuntu distro." }
    Write-Host "  WSL OK" -ForegroundColor Green

    Write-Step "Ensuring WSL build tools (cmake, ninja-build, g++)"
    Invoke-Wsl "sudo apt-get update -qq && sudo apt-get install -y -qq cmake ninja-build g++ 2>&1 | tail -2"

    if ($DoLinuxArm64) {
        Write-Step "Ensuring ARM64 cross-compiler (g++-aarch64-linux-gnu)"
        Invoke-Wsl "sudo apt-get install -y -qq gcc-aarch64-linux-gnu g++-aarch64-linux-gnu 2>&1 | tail -2"
    }

    function Build-LinuxTarget([string]$label, [string]$toolchain, [string]$dirName) {
        Write-Step "Building $label  ($BuildType)"
        $wslBuild = "$WslRoot/$dirName"

        if ($Clean) {
            Write-Host "  Cleaning $dirName ..." -ForegroundColor Yellow
            Invoke-Wsl "rm -rf '$wslBuild'"
        }

        Invoke-Wsl (
            "cmake -S '$WslRoot' -B '$wslBuild'" +
            " -G Ninja -DCMAKE_BUILD_TYPE=$BuildType" +
            " -DCMAKE_TOOLCHAIN_FILE='$WslRoot/cmake/toolchains/$toolchain'" +
            " -DLINEP_BUILD_TESTS=OFF --log-level=WARNING"
        )
        Invoke-Wsl "cmake --build '$wslBuild' --parallel"

        $found = wsl -e bash -c "ls '$wslBuild'/liblinep.so* 2>/dev/null | head -1 || true"
        if ($found) {
            $winPath = $found -replace '^/mnt/([a-z])/', { "$($_.Groups[1].Value.ToUpper()):\" }
            $winPath = $winPath -replace '/', '\'
            Show-Artifact $winPath $label
        } else {
            Write-Host "  [??] No liblinep.so* in $dirName" -ForegroundColor Yellow
        }
    }

    if ($DoLinuxX64)   { Build-LinuxTarget "linux-x64"   "linux-x64.cmake"   "build-linux-x64"   }
    if ($DoLinuxArm64) { Build-LinuxTarget "linux-arm64" "linux-arm64.cmake" "build-linux-arm64" }
}

# ── Summary ──────────────────────────────────────────────────────────────────

Write-Host ""; Write-Host "Build complete." -ForegroundColor Green
if ($DoWinX64)    { Write-Host "  win-x64     -> $RepoRoot\build-win-x64\(linep.dll|liblinep.dll)" }
if ($DoWinArm64)  { Write-Host "  win-arm64   -> $RepoRoot\build-win-arm64\(linep.dll|liblinep.dll)" }
if ($DoLinuxX64)  { Write-Host "  linux-x64   -> $RepoRoot\build-linux-x64\liblinep.so" }
if ($DoLinuxArm64){ Write-Host "  linux-arm64 -> $RepoRoot\build-linux-arm64\liblinep.so" }
