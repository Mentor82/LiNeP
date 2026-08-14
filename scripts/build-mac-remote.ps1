<#
.SYNOPSIS
    Build LiNeP macOS dylibs on a remote Mac via SSH.

.DESCRIPTION
    Rsyncs the repo sources to the Mac, runs the build script remotely,
    and copies liblinep.dylib back into build-macos-arm64/, build-macos-x64/
    and build-macos-universal/ under this repo root.

    Requires sshpass in WSL (installed automatically if missing).

.PARAMETER MacHost
    IP or hostname of the Mac. Default: 192.168.178.145

.PARAMETER MacUser
    SSH username. Default: mirkowaldhauer

.PARAMETER MacPassword
    SSH password (plain text). If omitted, SSH key auth is used.

.PARAMETER BuildType
    CMake build type: Release (default), Debug, RelWithDebInfo

.EXAMPLE
    .\scripts\build-mac-remote.ps1
    .\scripts\build-mac-remote.ps1 -MacHost 192.168.178.145 -MacUser mirkowaldhauer -MacPassword m20m24m26
    .\scripts\build-mac-remote.ps1 -BuildType Debug
#>
param(
    [string]$MacHost     = "192.168.178.145",
    [string]$MacUser     = "mirkowaldhauer",
    [string]$MacPassword = "m20m24m26",
    [ValidateSet("Release","Debug","RelWithDebInfo")]
    [string]$BuildType   = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path $PSScriptRoot -Parent
$WslRoot  = $RepoRoot -replace '^([A-Za-z]):\\', { "/mnt/$($_.Groups[1].Value.ToLower())/" }
$WslRoot  = $WslRoot  -replace '\\', '/'

$RemoteDir = "/Users/$MacUser/linep-build"

function Write-Step([string]$msg) { Write-Host ""; Write-Host "==> $msg" -ForegroundColor Cyan }
function Show-Artifact([string]$p, [string]$label) {
    if (Test-Path $p) {
        $sz = (Get-Item $p).Length
        Write-Host ("  [OK] {0,-24} {1,9:N0} bytes  {2}" -f $label, $sz, $p) -ForegroundColor Green
    } else {
        Write-Host "  [??] $label not found at $p" -ForegroundColor Yellow
    }
}

# ── ssh / sshpass helpers ────────────────────────────────────────────────────

$SshPrefix = if ($MacPassword) {
    "sshpass -p '$MacPassword' ssh -o StrictHostKeyChecking=no"
} else {
    "ssh -o StrictHostKeyChecking=no"
}

$RsyncPrefix = if ($MacPassword) {
    "sshpass -p '$MacPassword' rsync"
} else {
    "rsync"
}

function Invoke-WslCmd([string]$cmd) {
    wsl -e bash -c $cmd
    if ($LASTEXITCODE -ne 0) { throw "Command failed (exit $LASTEXITCODE): $cmd" }
}

function Invoke-MacSsh([string]$cmd) {
    Invoke-WslCmd "$SshPrefix $MacUser@$MacHost '$cmd'"
}

# ── Ensure sshpass in WSL ────────────────────────────────────────────────────

if ($MacPassword) {
    Write-Step "Ensuring sshpass in WSL"
    wsl -e bash -c "command -v sshpass >/dev/null || sudo apt-get install -y -qq sshpass 2>&1 | tail -1"
}

# ── Reachability check ───────────────────────────────────────────────────────

Write-Step "Checking Mac reachability ($MacHost)"
Invoke-WslCmd "$SshPrefix -o ConnectTimeout=8 $MacUser@$MacHost 'echo ok'"
Write-Host "  Mac reachable." -ForegroundColor Green

# ── Rsync sources ────────────────────────────────────────────────────────────

Write-Step "Syncing sources to $MacUser@$MacHost:$RemoteDir"
# Exclude build dirs, venv, __pycache__ to keep transfer small
Invoke-WslCmd (
    "$RsyncPrefix -az --delete " +
    "--exclude='.git/' " +
    "--exclude='build*/' " +
    "--exclude='__pycache__/' " +
    "--exclude='.venv/' " +
    "--exclude='*.pyc' " +
    "-e 'sshpass -p ''$MacPassword'' ssh -o StrictHostKeyChecking=no' " +
    "'$WslRoot/' '$MacUser@${MacHost}:$RemoteDir/'"
)
Write-Host "  Sync complete." -ForegroundColor Green

# ── Copy build script to Mac ─────────────────────────────────────────────────

Write-Step "Uploading build script"
Invoke-WslCmd (
    "$RsyncPrefix -az " +
    "-e 'sshpass -p ''$MacPassword'' ssh -o StrictHostKeyChecking=no' " +
    "'$WslRoot/scripts/_mac_build_remote.sh' '$MacUser@${MacHost}:$RemoteDir/scripts/'"
)
Invoke-MacSsh "chmod +x $RemoteDir/scripts/_mac_build_remote.sh"

# ── Run remote build ─────────────────────────────────────────────────────────

Write-Step "Running build on Mac (this may take a few minutes on first run)"
Invoke-WslCmd (
    "$SshPrefix -t $MacUser@$MacHost " +
    "'BUILD_TYPE=$BuildType REPO_DIR=$RemoteDir bash $RemoteDir/scripts/_mac_build_remote.sh 2>&1'"
)

# ── Fetch artifacts back ─────────────────────────────────────────────────────

Write-Step "Fetching artifacts"
foreach ($variant in @("arm64","x64","universal")) {
    $localDir = "$RepoRoot\build-macos-$variant"
    New-Item -ItemType Directory -Force $localDir | Out-Null

    Invoke-WslCmd (
        "$RsyncPrefix -az " +
        "-e 'sshpass -p ''$MacPassword'' ssh -o StrictHostKeyChecking=no' " +
        "'$MacUser@${MacHost}:$RemoteDir/build-macos-$variant/liblinep.dylib' " +
        "'$WslRoot/build-macos-$variant/'"
    )
    Show-Artifact "$localDir\liblinep.dylib" "macos-$variant"
}

Write-Host ""; Write-Host "macOS build complete." -ForegroundColor Green
