#!/usr/bin/env python3
"""Fail when a LiNeP release wheel omits required legal material."""

from __future__ import annotations

import argparse
from pathlib import Path
from zipfile import ZipFile


THIRD_PARTY_FILES = {
    "GPL-3.0.txt",
    "GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt",
    "LIBWINPTHREAD.txt",
}


def require_wheel_legal_files(wheel: Path) -> None:
    with ZipFile(wheel) as archive:
        names = set(archive.namelist())

    license_names = {Path(name).name for name in names if ".dist-info/licenses/" in name}
    required_project = {"LICENSE", "NOTICE"}
    if wheel.name.startswith("linep-"):
        required_project.add("THIRD_PARTY_NOTICES.md")
    missing_project = required_project - license_names
    if missing_project:
        raise SystemExit(f"{wheel}: missing project legal files: {sorted(missing_project)}")

    if wheel.name.startswith("linep-"):
        packaged = {
            Path(name).name
            for name in names
            if name.startswith("linep/licenses/")
        }
        missing_third_party = THIRD_PARTY_FILES - packaged
        if missing_third_party:
            raise SystemExit(
                f"{wheel}: missing third-party license files: {sorted(missing_third_party)}"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel_dir", type=Path)
    args = parser.parse_args()

    wheels = sorted(args.wheel_dir.glob("*.whl"))
    if len(wheels) != 2:
        raise SystemExit(f"expected 2 wheels in {args.wheel_dir}, found {len(wheels)}")

    repository_root = Path(__file__).resolve().parent.parent
    canonical_notices = repository_root / "docs" / "legal" / "THIRD_PARTY_NOTICES.md"
    packaged_notices = repository_root / "LiNeP" / "python" / "THIRD_PARTY_NOTICES.md"
    if canonical_notices.read_bytes() != packaged_notices.read_bytes():
        raise SystemExit("Python THIRD_PARTY_NOTICES.md is out of sync with docs/legal")

    for wheel in wheels:
        require_wheel_legal_files(wheel)
        print(f"[PASS] legal payload: {wheel.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
