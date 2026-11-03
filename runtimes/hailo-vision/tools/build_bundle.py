"""Build a source-pinned arm64 host bundle, without Hailo/NumPy/OpenCV binaries."""

import argparse
import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default="HEAD", help="Committed source revision only")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    commit = git(root, "rev-parse", args.source + "^{commit}").decode().strip()
    files = {}
    mappings = [("LiNeP/python/linep/", "linep/"),
                ("runtimes/hailo-vision/src/linep_vision/", "linep_vision/"),
                ("runtimes/hailo-vision/deploy/", "deploy/"),
                ("runtimes/hailo-vision/tools/", "tools/")]
    for prefix, dest in mappings:
        for name in git(root, "ls-tree", "-r", "--name-only", commit, "--", prefix).decode().splitlines():
            if name.endswith((".py", ".txt", ".service", ".toml", ".sh", ".md")):
                files[dest + name[len(prefix):]] = git(root, "show", commit + ":" + name)
    for name in ("LICENSE", "NOTICE", "README.md", "VALIDATION.md"):
        files[name] = git(root, "show", commit + ":runtimes/hailo-vision/" + name)
    files["PROVENANCE.json"] = (json.dumps({
        "source": "https://github.com/Mentor82/LiNeP", "source_commit": commit,
        "runtime_tree": git(root, "rev-parse", commit + ":runtimes/hailo-vision/src/linep_vision").decode().strip(),
        "version": "0.1.0", "target": "arm64", "payload": "pure Python source",
        "host_dependencies": ["Python >=3.9", "HailoRT 4.23 + driver", "NumPy", "OpenCV", "COCO80 HEF"],
    }, indent=2) + "\n").encode()
    files["SHA256SUMS"] = "".join(hashlib.sha256(data).hexdigest() + "  " + name + "\n"
                                       for name, data in sorted(files.items())).encode()
    args.output.mkdir(parents=True, exist_ok=True)
    name = "linep-vision-0.1.0-" + commit[:12] + "-arm64"
    path = args.output / (name + ".tar.gz")
    with path.open("wb") as raw:
        import gzip
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for filename, data in sorted(files.items()):
                    info = tarfile.TarInfo(name + "/" + filename)
                    info.size = len(data)
                    info.mode = 0o755 if filename.endswith(".sh") else 0o644
                    archive.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    (args.output / (path.name + ".sha256")).write_text(digest + "  " + path.name + "\n", encoding="ascii")
    print(json.dumps({"bundle": str(path), "sha256": digest, "source_commit": commit}))


if __name__ == "__main__":
    main()
