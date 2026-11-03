#!/bin/bash
# Recipe only: run on the LIARA OS packaging host after host dependencies exist.
# Bundle source is shared with the Debian arm64 output; no Hailo SDK is vendored.
set -euo pipefail
bundle=${1:?usage: build-lpkg.sh <bundle.tar.gz> <output> <sign-key>}
output=${2:?output directory required}
sign_key=${3:?explicit Ed25519 signing key required}
bundle=$(realpath "$bundle")
test -f "$bundle"
(cd "$(dirname "$bundle")" && sha256sum -c "$(basename "$bundle").sha256")
work=$(mktemp -d)
mkdir "$work/source"
python3 - "$bundle" "$work/source" <<'PY'
import pathlib, sys, tarfile
with tarfile.open(sys.argv[1], 'r:gz') as archive:
    for member in archive.getmembers():
        p = pathlib.PurePosixPath(member.name)
        if p.is_absolute() or '..' in p.parts or not (member.isfile() or member.isdir()):
            raise ValueError('unsafe source member')
    archive.extractall(sys.argv[2])
PY
bundle_dir=$(find "$work/source" -mindepth 1 -maxdepth 1 -type d)
test -f "$bundle_dir/PROVENANCE.json"
(cd "$bundle_dir" && sha256sum -c SHA256SUMS)
payload=$work/payload
mkdir -p "$payload/opt/linep/linep-vision" "$payload/usr/lib/systemd/system"
cp -a "$bundle_dir/." "$payload/opt/linep/linep-vision/"
cp "$bundle_dir/deploy/linep-vision.service" "$payload/usr/lib/systemd/system/"
cat > "$work/post-install" <<'HOOK'
#!/bin/sh
systemctl daemon-reload
# No automatic enable/start or tunnel provisioning from package hooks.
HOOK
chmod 755 "$work/post-install"
source_hash=$(sha256sum "$bundle" | cut -d' ' -f1)
lpm-build --name linep-vision --version 0.1.0 --arch aarch64 \
  --tier source-packaged --payload "$payload" --output "$output" \
  --description "LiNeP Hailo object detection runtime; host HailoRT/OpenCV required" \
  --license Apache-2.0 --ml --source-url https://github.com/Mentor82/LiNeP \
  --source-sha256 "$source_hash" --recipe "$0" --post-install "$work/post-install" --sign "$sign_key"
printf 'Packaging workspace retained for audit: %s\n' "$work"
