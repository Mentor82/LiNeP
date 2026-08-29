from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest


def _ensure_linep_lib_path() -> None:
    if os.environ.get("LINEP_LIB_PATH"):
        return
    repo_root = Path(__file__).resolve().parents[2]
    if sys.platform == "win32":
        names = ["build/liblinep.dll", "build/linep.dll"]
    elif sys.platform == "darwin":
        names = ["build/liblinep.dylib"]
    else:
        names = ["build_linux/liblinep.so", "build/liblinep.so"]
    for rel in names:
        candidate = repo_root / rel
        if candidate.exists():
            os.environ["LINEP_LIB_PATH"] = str(candidate)
            return


@pytest.fixture(scope="module")
def linep_module():
    _ensure_linep_lib_path()
    import linep
    linep.net_init()
    yield linep
    linep.net_cleanup()


def test_task_streaming_python(linep_module):
    # Verify that Python bindings can construct and validate streaming frames (FLAG_FRAGMENTED / FLAG_FINAL_FRAGMENT)
    h_frag = linep_module.Header.build(
        msg_type=linep_module.MsgType.RESULT,
        payload_len=64,
        sequence=1,
        correlation_id=505,
        worker_id=1,
        slot_id=0,
        flags=int(linep_module.HeaderFlags.FRAGMENTED),
    )
    assert h_frag.flags & int(linep_module.HeaderFlags.FRAGMENTED)

    h_final = linep_module.Header.build(
        msg_type=linep_module.MsgType.RESULT,
        payload_len=64,
        sequence=2,
        correlation_id=505,
        worker_id=1,
        slot_id=0,
        flags=int(linep_module.HeaderFlags.FRAGMENTED | linep_module.HeaderFlags.FINAL_FRAGMENT),
    )
    assert h_final.flags & int(linep_module.HeaderFlags.FRAGMENTED)
    assert h_final.flags & int(linep_module.HeaderFlags.FINAL_FRAGMENT)

    raw = h_final.to_bytes()
    h2 = linep_module.Header.from_bytes(raw)
    h2.validate()
    assert h2.correlation_id == 505
    assert h2.sequence == 2
