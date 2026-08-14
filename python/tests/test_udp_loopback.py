from __future__ import annotations

import importlib
import os
import socket
from pathlib import Path

import pytest


def _ensure_linep_lib_path() -> None:
    if os.environ.get("LINEP_LIB_PATH"):
        return
    repo_root = Path(__file__).resolve().parents[2]
    candidate = repo_root / "build" / "liblinep.dll"
    if candidate.exists():
        os.environ["LINEP_LIB_PATH"] = str(candidate)


@pytest.fixture(scope="module")
def linep_module():
    _ensure_linep_lib_path()

    lib_path = os.environ.get("LINEP_LIB_PATH")
    if not lib_path:
        pytest.skip("LINEP_LIB_PATH not set and build/liblinep.dll not found")
    if not Path(lib_path).exists():
        pytest.skip(f"Configured LINEP_LIB_PATH does not exist: {lib_path}")

    return importlib.import_module("linep")


def test_udp_heartbeat_loopback(linep_module):
    linep = linep_module

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        rx.bind(("127.0.0.1", 0))
        udp_port = int(rx.getsockname()[1])

        hb = linep.HeartbeatCompact.build(
            worker_id=21,
            slot_id=2,
            slot_flags=int(linep.SlotFlags.ALIVE | linep.SlotFlags.READY),
            load=17,
            queue_depth=3,
            sequence=11,
            worker_score=170,
        )

        tx.sendto(hb.to_bytes(), ("127.0.0.1", udp_port))
        raw, _addr = rx.recvfrom(64)

        parsed = linep.HeartbeatCompact.from_bytes(raw)
        parsed.validate()

        assert parsed.worker_id == 21
        assert parsed.slot_id == 2
        assert parsed.queue_depth == 3
        assert parsed.is_ready is True
    finally:
        tx.close()
        rx.close()
