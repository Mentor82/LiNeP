#!/usr/bin/env bash
# build-targets.sh — build LiNeP for macOS and Linux targets.
#
# Targets:
#   macos-x64       liblinep.dylib  (Intel)
#   macos-arm64     liblinep.dylib  (Apple Silicon)
#   macos-universal liblinep.dylib  (fat: arm64 + x86_64)
#   linux-x64       liblinep.so     (native GCC, no cross)
#   linux-arm64     liblinep.so     (aarch64-linux-gnu cross-compile)
#   all             every target for the current OS (default)
#
# Usage:
#   ./scripts/build-targets.sh
#   ./scripts/build-targets.sh macos-arm64
#   ./scripts/build-targets.sh macos-universal Release
#   ./scripts/build-targets.sh all Debug
#
# Requirements:
#   macOS  : Xcode CLT  (xcode-select --install)  + cmake + ninja
#   Linux  : cmake ninja-build g++
#   arm64 cross (Linux only): g++-aarch64-linux-gnu

set -euo pipefail

# ── args ─────────────────────────────────────────────────────────────────────

TARGET="${1:-all}"
BUILD_TYPE="${2:-Release}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLCHAINS="$REPO_ROOT/cmake/toolchains"

# ── helpers ───────────────────────────────────────────────────────────────────

step()  { echo; echo "==> $*"; }
ok()    { echo "  [OK] $*"; }
fail()  { echo "  [!!] $*" >&2; exit 1; }

detect_os() {
    case "$(uname -s)" in
        Darwin) echo "macos"  ;;
        Linux)  echo "linux"  ;;
        *)      echo "unknown";;
    esac
}

OS="$(detect_os)"

# ── dependency checks ────────────────────────────────────────────────────────

step "Checking dependencies"

require() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 not found. $2"
}

require cmake "Install: brew install cmake  OR  sudo apt install cmake"
require ninja "Install: brew install ninja  OR  sudo apt install ninja-build"
require g++   "Install: brew install gcc    OR  sudo apt install g++"

if [[ "$OS" == "linux" ]] && [[ "$TARGET" =~ arm64|all ]]; then
    require aarch64-linux-gnu-g++ \
        "Install: sudo apt install g++-aarch64-linux-gnu"
fi

# ── build function ────────────────────────────────────────────────────────────

build_target() {
    local label="$1"
    local toolchain="$2"
    local out_dir="$REPO_ROOT/$3"

    step "Building $label  ($BUILD_TYPE)"

    cmake -S "$REPO_ROOT" -B "$out_dir" \
        -G Ninja \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAINS/$toolchain" \
        -DLINEP_BUILD_TESTS=OFF \
        --log-level=WARNING

    cmake --build "$out_dir" --parallel

    # Find .dylib or .so
    local artifact
    artifact="$(ls "$out_dir"/liblinep.dylib "$out_dir"/liblinep.so \
                   "$out_dir"/liblinep.so.* 2>/dev/null | head -1 || true)"
    if [[ -n "$artifact" ]]; then
        local size
        size="$(wc -c < "$artifact" | tr -d ' ')"
        ok "$artifact  (${size} bytes)"
    else
        echo "  [??] No artifact found in $out_dir" >&2
    fi
}

# ── target selection ─────────────────────────────────────────────────────────

DO_MACOS_X64=false
DO_MACOS_ARM64=false
DO_MACOS_UNIVERSAL=false
DO_LINUX_X64=false
DO_LINUX_ARM64=false

case "$TARGET" in
    macos-x64)       DO_MACOS_X64=true ;;
    macos-arm64)     DO_MACOS_ARM64=true ;;
    macos-universal) DO_MACOS_UNIVERSAL=true ;;
    linux-x64)       DO_LINUX_X64=true ;;
    linux-arm64)     DO_LINUX_ARM64=true ;;
    all)
        if [[ "$OS" == "macos" ]]; then
            DO_MACOS_X64=true
            DO_MACOS_ARM64=true
            DO_MACOS_UNIVERSAL=true
        elif [[ "$OS" == "linux" ]]; then
            DO_LINUX_X64=true
            DO_LINUX_ARM64=true
        else
            fail "Unsupported OS: $OS. Use macOS or Linux."
        fi
        ;;
    *) fail "Unknown target '$TARGET'. Use: macos-x64 | macos-arm64 | macos-universal | linux-x64 | linux-arm64 | all" ;;
esac

# Validate OS / target combos
if [[ "$OS" == "linux" ]] && { $DO_MACOS_X64 || $DO_MACOS_ARM64 || $DO_MACOS_UNIVERSAL; }; then
    fail "macOS targets cannot be built on Linux."
fi
if [[ "$OS" == "macos" ]] && { $DO_LINUX_X64 || $DO_LINUX_ARM64; }; then
    fail "Linux targets cannot be built on macOS. Use WSL or a Linux machine."
fi

# ── run ───────────────────────────────────────────────────────────────────────

$DO_MACOS_X64       && build_target "macos-x64"       "macos-x64.cmake"       "build-macos-x64"
$DO_MACOS_ARM64     && build_target "macos-arm64"      "macos-arm64.cmake"     "build-macos-arm64"
$DO_MACOS_UNIVERSAL && build_target "macos-universal"  "macos-universal.cmake" "build-macos-universal"
$DO_LINUX_X64       && build_target "linux-x64"        "linux-x64.cmake"       "build-linux-x64"
$DO_LINUX_ARM64     && build_target "linux-arm64"       "linux-arm64.cmake"     "build-linux-arm64"

# ── summary ───────────────────────────────────────────────────────────────────

echo
echo "Build complete."
$DO_MACOS_X64       && echo "  macos-x64       -> $REPO_ROOT/build-macos-x64/liblinep.dylib"
$DO_MACOS_ARM64     && echo "  macos-arm64     -> $REPO_ROOT/build-macos-arm64/liblinep.dylib"
$DO_MACOS_UNIVERSAL && echo "  macos-universal -> $REPO_ROOT/build-macos-universal/liblinep.dylib"
$DO_LINUX_X64       && echo "  linux-x64       -> $REPO_ROOT/build-linux-x64/liblinep.so"
$DO_LINUX_ARM64     && echo "  linux-arm64     -> $REPO_ROOT/build-linux-arm64/liblinep.so"
