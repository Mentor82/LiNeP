<#
.SYNOPSIS
    Build LiNeP macOS targets on a remote Mac via SSH + rsync.

.DESCRIPTION
    Syncs the repo source to the Mac via rsync, runs cmake + ninja there,
    and optionally copies the resulting .dylib back.

    Targets:
      arm64      liblinep.dylib  (Apple Silicon — default)
      x64        liblinep.dylib  (Intel)
      universal  liblinep.dylib  (fat: arm64 + x86_64)
      all        all three targets

    Prerequisites on the Mac:
      xcode-select --install   (or full Xcode)
      cmake + ninja are installed automatically via brew if missing.

    Prerequisites here (Windows):
      MSYS2  C:\msys64\usr\bin\rsync.exe + sshpass.exe
        Install once:  C:\msys64\usr\bin\bash.exe -lc "pacman -S --noconfirm rsync sshpass"
      OR key-based SSH (omit -Password):
        ssh-keygen; ssh-copy-id mirkowaldhauer@192.168.178.145

.PARAMETER MacHost
    Mac hostname or IP. Default: 192.168.178.145

.PARAMETER User
    SSH username on the Mac. Default: mirkowaldhauer

.PARAMETER Password
    SSH password. If omitted, key-based auth is used.

.PARAMETER Target
    Which macOS target(s) to build: arm64, x64, universal, all.  Default: all

.PARAMETER BuildType
    CMake build type: Release (default), Debug, RelWithDebInfo

.PARAMETER RemoteDir
    Working directory on the Mac. Default: ~/linep-build

.PARAMETER Fetch
    After building, copy .dylib back into build-macos-<target>\ locally.

.EXAMPLE
    .\scripts\build-mac.ps1 -Password m20m24m26 -Fetch
    .\scripts\build-mac.ps1 -Target arm64 -Password m20m24m26 -Fetch
    .\scripts\build-mac.ps1 -Target universal -BuildType Debug -Password m20m24m26
#>
param(
    [string]$MacHost   = "192.168.178.145",
    [string]$User      = "mirkowaldhauer",
    [string]$Password  = "",

    [ValidateSet("arm64","x64","universal","all")]
    [string]$Target    = "all",

    [ValidateSet("Release","Debug","RelWithDebInfo")]
    [string]$BuildType = "Release",

    [string]$RemoteDir = "~/linep-build",

    [switch]$Fetch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Prevent MSYS2 from converting POSIX paths (e.g. /opt/homebrew) to Windows paths
$env:MSYS_NO_PATHCONV     = "1"
$env:MSYS2_ARG_CONV_EXCL  = "*"

# ── Tool paths ───────────────────────────────────────────────────────────────

$Msys2Bin  = "C:\msys64\usr\bin"
$Rsync     = "$Msys2Bin\rsync.exe"
$Sshpass   = "$Msys2Bin\sshpass.exe"
$MsysBash  = "C:\msys64\usr\bin\bash.exe"

$UseSshpass = ($Password -ne "") -and (Test-Path $Sshpass)

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Step([string]$msg) { Write-Host ""; Write-Host "==> $msg" -ForegroundColor Cyan }

$SshOpts = "-o StrictHostKeyChecking=no -o ConnectTimeout=10"
$Remote  = "$User@$MacHost"

# Invoke-Ssh: writes the remote command to a temp bash script and pipes it via
# 'ssh bash -s' to avoid MSYS2 path-conversion issues with argument quoting.
function Invoke-Ssh([string]$cmd) {
    $id      = [System.Guid]::NewGuid().ToString('N').Substring(0,8)
    $winTmp  = "C:\msys64\tmp\_ssh_$id.sh"
    $content = "#!/bin/bash`nexport PATH=`"/opt/homebrew/bin:/usr/local/bin:`$PATH`"`n$cmd`n"
    # Write with LF line endings (no BOM)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    [System.IO.File]::WriteAllBytes($winTmp, $bytes)
    $posixTmp = "/tmp/_ssh_$id.sh"
    if ($UseSshpass) {
        & $MsysBash "-lc" "chmod +x $posixTmp; sshpass -p '$Password' ssh $SshOpts $Remote bash -s < $posixTmp"
    } else {
        & $MsysBash "-lc" "chmod +x $posixTmp; ssh $SshOpts $Remote bash -s < $posixTmp"
    }
    Remove-Item $winTmp -ErrorAction SilentlyContinue
    if ($LASTEXITCODE -ne 0) { throw "SSH failed (exit $LASTEXITCODE): $cmd" }
}

function Invoke-Rsync([string]$src, [string]$dst) {
    $id      = [System.Guid]::NewGuid().ToString('N').Substring(0,8)
    $winTmp  = "C:\msys64\tmp\_rsync_$id.sh"
    $sshCmd  = if ($UseSshpass) { "sshpass -p '$Password' ssh $SshOpts" } else { "ssh $SshOpts" }
    $content = "#!/bin/bash`nrsync -azL --delete --exclude='build*' --exclude='.git' --exclude='*.dll' --exclude='*.obj' --exclude='.venv' -e `"$sshCmd`" `"$src`" `"$dst`"`n"
    $rbytes  = [System.Text.Encoding]::UTF8.GetBytes($content)
    [System.IO.File]::WriteAllBytes($winTmp, $rbytes)
    $posixTmp = "/tmp/_rsync_$id.sh"
    & $MsysBash "-lc" "bash $posixTmp"
    Remove-Item $winTmp -ErrorAction SilentlyContinue
    if ($LASTEXITCODE -ne 0) { throw "rsync failed (exit $LASTEXITCODE)" }
}

# ── Repo root → POSIX path for MSYS2 rsync ───────────────────────────────────

$RepoRoot = Split-Path $PSScriptRoot -Parent
$RepoName = Split-Path $RepoRoot -Leaf
# Convert  C:\ai\LiNeP  →  /c/ai/LiNeP  (MSYS2 style, no scriptblock)
$drive     = $RepoRoot.Substring(0,1).ToLower()
$PosixRepo = "/$drive/" + ($RepoRoot.Substring(3) -replace '\\', '/')

Write-Host "Repo  : $RepoRoot" -ForegroundColor Gray
Write-Host "Remote: $Remote`:$RemoteDir/$RepoName" -ForegroundColor Gray
if (-not (Test-Path $Rsync))   { throw "rsync not found at $Rsync. Run: C:\msys64\usr\bin\bash.exe -lc `"pacman -S --noconfirm rsync sshpass`"" }
if ($UseSshpass) { Write-Host "  Auth  : sshpass" -ForegroundColor Gray }
else             { Write-Host "  Auth  : key-based SSH" -ForegroundColor Gray }

# ── Probe Mac ─────────────────────────────────────────────────────────────────

Write-Step "Probing Mac"
Invoke-Ssh "uname -m; sw_vers --productVersion; xcode-select -p"

# ── Ensure cmake + ninja on Mac (via brew) ────────────────────────────────────

Write-Step "Ensuring cmake + ninja on Mac"
Invoke-Ssh "command -v cmake >/dev/null 2>&1 && command -v ninja >/dev/null 2>&1 && echo 'cmake+ninja ok' || brew install cmake ninja"

# ── Sync source via rsync ─────────────────────────────────────────────────────

Write-Step "Syncing source to Mac"
Invoke-Ssh "mkdir -p $RemoteDir"
# Trailing slash on src = sync contents into RemoteDir/RepoName
Invoke-Rsync "$PosixRepo/" "$Remote`:$RemoteDir/$RepoName/"
Write-Host "  Sync done." -ForegroundColor Green

$RemoteSrc   = "$RemoteDir/$RepoName"

# ── Build function ────────────────────────────────────────────────────────────

function Build-MacTarget([string]$label, [string]$arch, [string]$remoteBuild, [string]$localOut) {
    Write-Step "Building macos-$label  ($BuildType)"

    Invoke-Ssh "cmake -S $RemoteSrc -B $remoteBuild -G Ninja --fresh -DCMAKE_BUILD_TYPE=$BuildType -DCMAKE_OSX_ARCHITECTURES='$arch' -DLINEP_BUILD_TESTS=OFF"
    Invoke-Ssh "cmake --build $remoteBuild --parallel"
    Invoke-Ssh "lipo -info $remoteBuild/liblinep.dylib"

    if ($Fetch) {
        $localDir = "$RepoRoot\$localOut"
        New-Item -ItemType Directory -Force -Path $localDir | Out-Null
        # rsync back
        Invoke-Rsync "$Remote`:$remoteBuild/liblinep.dylib" "$PosixRepo/$localOut/"
        $size = (Get-Item "$localDir\liblinep.dylib").Length
        Write-Host ("  [OK] macos-{0,-12} {1,9:N0} bytes  ->  {2}\liblinep.dylib" -f $label, $size, $localDir) -ForegroundColor Green
    } else {
        Write-Host "  [OK] $Remote`:$remoteBuild/liblinep.dylib  (use -Fetch to copy back)" -ForegroundColor Green
    }
}

# ── Run builds ────────────────────────────────────────────────────────────────

$DoArm64     = $Target -in @("arm64",    "all")
$DoX64       = $Target -in @("x64",      "all")
$DoUniversal = $Target -in @("universal","all")

if ($DoArm64)     { Build-MacTarget "arm64"     "arm64"         "$RemoteDir/build-macos-arm64"     "build-macos-arm64"     }
if ($DoX64)       { Build-MacTarget "x64"        "x86_64"        "$RemoteDir/build-macos-x64"       "build-macos-x64"       }
if ($DoUniversal) { Build-MacTarget "universal"  "arm64;x86_64"  "$RemoteDir/build-macos-universal" "build-macos-universal" }

# ── Summary ──────────────────────────────────────────────────────────────────

Write-Host ""; Write-Host "Mac builds complete." -ForegroundColor Green
if ($DoArm64)     { Write-Host "  macos-arm64     : $Remote`:$RemoteDir/build-macos-arm64/liblinep.dylib" }
if ($DoX64)       { Write-Host "  macos-x64       : $Remote`:$RemoteDir/build-macos-x64/liblinep.dylib" }
if ($DoUniversal) { Write-Host "  macos-universal : $Remote`:$RemoteDir/build-macos-universal/liblinep.dylib" }
if ($Fetch) {
    Write-Host "Fetched:" -ForegroundColor Green
    if ($DoArm64)     { Write-Host "  $RepoRoot\build-macos-arm64\liblinep.dylib" }
    if ($DoX64)       { Write-Host "  $RepoRoot\build-macos-x64\liblinep.dylib" }
    if ($DoUniversal) { Write-Host "  $RepoRoot\build-macos-universal\liblinep.dylib" }
}
