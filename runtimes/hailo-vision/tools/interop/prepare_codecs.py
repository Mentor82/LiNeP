"""Snapshot only tracked reference codec files; never change the source repos."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--go-repo",type=Path,required=True)
    p.add_argument("--rust-repo",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    manifest={}
    here=Path(__file__).resolve().parent
    for language,repo,prefix in [("go",args.go_repo,"pkg/linep/v02/"),("rust",args.rust_repo,"src/liara-noded/src/")]:
        commit=git(repo,"rev-parse","HEAD").decode().strip()
        names=git(repo,"ls-tree","-r","--name-only",commit,"--",prefix).decode().splitlines()
        if language=="go":
            names=[n for n in names if n.endswith(".go") and not n.endswith("_test.go")]
        else:
            names=[prefix+"linep_v02.rs",prefix+"sl1.rs"]
        folder=args.output/language/"codec"
        folder.mkdir(parents=True)
        hashes={}
        for name in names:
            data=git(repo,"show",commit+":"+name)
            (folder/Path(name).name).write_bytes(data)
            hashes[name]=hashlib.sha256(data).hexdigest()
        manifest[language]={"source_commit":commit,"codec_sha256":hashes}
    (args.output/"go/main.go").write_bytes((here/"go_vision.go").read_bytes())
    (args.output/"go/go.mod").write_text("module visioninterop\n\ngo 1.24.0\n",encoding="ascii")
    (args.output/"rust/main.rs").write_bytes((here/"rust_roundtrip.rs").read_bytes())
    (args.output/"CODEC_SOURCES.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(manifest,indent=2))


if __name__=="__main__":
    main()
