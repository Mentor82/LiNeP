from __future__ import annotations

import importlib
import os
import sys
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


@pytest.fixture(scope="session")
def linep_module():
    _ensure_linep_lib_path()

    lib_path = os.environ.get("LINEP_LIB_PATH")
    if not lib_path:
        pytest.skip("LINEP_LIB_PATH not set and build/liblinep.dll not found")

    if not Path(lib_path).exists():
        pytest.skip(f"Configured LINEP_LIB_PATH does not exist: {lib_path}")

    return importlib.import_module("linep")


def test_import_and_version(linep_module):
    assert hasattr(linep_module, "__version__")
    assert linep_module.__version__ == "0.2.0"


def test_crc8_is_stable(linep_module):
    a = linep_module.crc8(b"hello")
    b = linep_module.crc8(b"hello")
    c = linep_module.crc8(b"hellO")

    assert isinstance(a, int)
    assert 0 <= a <= 255
    assert a == b
    assert a != c


def test_header_roundtrip_and_validate(linep_module):
    h = linep_module.Header.build(
        msg_type=linep_module.MsgType.TASK,
        payload_len=128,
        sequence=7,
        correlation_id=42,
        worker_id=3,
        slot_id=1,
    )

    raw = h.to_bytes()
    assert len(raw) == 24

    h2 = linep_module.Header.from_bytes(raw)
    h2.validate()

    assert h2.msg_type == linep_module.MsgType.TASK
    assert h2.payload_len == 128
    assert h2.sequence == 7
    assert h2.correlation_id == 42
    assert h2.worker_id == 3
    assert h2.slot_id == 1


def test_heartbeat_roundtrip_and_validate(linep_module):
    flags = linep_module.SlotFlags.ALIVE | linep_module.SlotFlags.READY
    hb = linep_module.HeartbeatCompact.build(
        worker_id=11,
        slot_id=2,
        slot_flags=int(flags),
        load=12,
        queue_depth=1,
        sequence=9,
        worker_score=120,
    )

    raw = hb.to_bytes()
    assert len(raw) == 19

    hb2 = linep_module.HeartbeatCompact.from_bytes(raw)
    hb2.validate()

    assert hb2.worker_id == 11
    assert hb2.slot_id == 2
    assert hb2.load == 12
    assert hb2.queue_depth == 1
    assert hb2.is_ready is True


def test_udp_control_frames_python(linep_module):
    # Invite frame
    inv = linep_module.UdpInviteFrame.build(
        invite_seq=5, worker_id=12, slot_id=0, lease_ttl_ms=1500, session_token=0x12345678
    )
    raw_inv = inv.to_bytes()
    assert len(raw_inv) == 14
    inv2 = linep_module.UdpInviteFrame.from_bytes(raw_inv)
    inv2.validate()
    assert inv2.invite_seq == 5
    assert inv2.session_token == 0x12345678

    # Invite ACK frame
    ack = linep_module.UdpInviteAckFrame.build(
        invite_seq=5, worker_id=12, slot_id=0, accepted=1, session_token=0x12345678
    )
    raw_ack = ack.to_bytes()
    assert len(raw_ack) == 11
    ack2 = linep_module.UdpInviteAckFrame.from_bytes(raw_ack)
    ack2.validate()
    assert ack2.accepted == 1

    # Heartbeat ACK frame
    hb_ack = linep_module.UdpHeartbeatAckFrame.build(
        heartbeat_seq=99, worker_id=12, slot_id=0, scheduler_time_sec=1714745395
    )
    raw_hb_ack = hb_ack.to_bytes()
    assert len(raw_hb_ack) == 10
    hb_ack2 = linep_module.UdpHeartbeatAckFrame.from_bytes(raw_hb_ack)
    hb_ack2.validate()
    assert hb_ack2.scheduler_time_sec == 1714745395

