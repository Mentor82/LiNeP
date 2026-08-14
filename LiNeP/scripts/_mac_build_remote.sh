#!/bin/bash
# Remotely executed on the Mac via SSH.
# Installs Homebrew + cmake + ninja (idempotent), then builds liblinep.dylib.
# Usage: pass BUILD_TYPE and REPO_DIR as env vars (set by caller).

set -euo pipefail

BUILD_TYPE="${BUILD_TYPE:-Release}"
REPO_DIR="${REPO_DIR:-$HOME/linep-build}"

echo "==> Mac setup + build  (arch: $(uname -m), os: $(sw_vers --productVersion))"
echo "    build_type : $BUILD_TYPE"
echo "    repo_dir   : $REPO_DIR"

# ── Homebrew ──────────────────────────────────────────────────────────────────

if ! command -v brew &>/dev/null; then
    echo "==> Installing Homebrew..."
    NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # Add to PATH for this session (Apple Silicon default path)
    eval "$(/opt/homebrew/bin/brew shellenv)" 2>/dev/null || true
fi
eval "$($(command -v brew) shellenv)" 2>/dev/null || true
echo "    brew: $(brew --version | head -1)"

# ── cmake + ninja ─────────────────────────────────────────────────────────────

for pkg in cmake ninja; do
    if ! command -v $pkg &>/dev/null; then
        echo "==> Installing $pkg..."
        brew install $pkg
    else
        echo "    $pkg: $(${pkg} --version 2>/dev/null | head -1)"
    fi
done

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> Configuring (arm64)..."
cmake -S "$REPO_DIR" -B "$REPO_DIR/build-macos-arm64" -G Ninja \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_TOOLCHAIN_FILE="$REPO_DIR/cmake/toolchains/macos-arm64.cmake" \
    -DLINEP_BUILD_TESTS=OFF \
    --log-level=WARNING

echo "==> Building..."
cmake --build "$REPO_DIR/build-macos-arm64" --parallel

echo "==> Configuring (x64)..."
cmake -S "$REPO_DIR" -B "$REPO_DIR/build-macos-x64" -G Ninja \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_TOOLCHAIN_FILE="$REPO_DIR/cmake/toolchains/macos-x64.cmake" \
    -DLINEP_BUILD_TESTS=OFF \
    --log-level=WARNING

echo "==> Building..."
cmake --build "$REPO_DIR/build-macos-x64" --parallel

echo "==> Creating universal binary..."
mkdir -p "$REPO_DIR/build-macos-universal"
lipo -create \
    "$REPO_DIR/build-macos-arm64/liblinep.dylib" \
    "$REPO_DIR/build-macos-x64/liblinep.dylib" \
    -output "$REPO_DIR/build-macos-universal/liblinep.dylib"

echo "==> Verifying architectures..."
lipo -info "$REPO_DIR/build-macos-universal/liblinep.dylib"

echo "==> Done."
echo "ARTIFACTS:"
ls -lh "$REPO_DIR"/build-macos-*/liblinep.dylib
