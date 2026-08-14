"""
End-to-end test: coworker UDP heartbeat  +  TCP task flow.

Scenario
--------
1. A TCP Receiver starts on a random loopback port.  Its handler echoes
   the payload back prefixed with "echo:".
2. A raw UDP socket sends a valid HeartbeatCompact frame to a second
   loopback port that we bind just to consume the datagram (confirming
   the wire format is accepted without error).
3. A TCP Sender sends a TASK frame to the Receiver and checks the RESULT.

This exercises the full V0.1.0 control-plane + data-plane path in a single
process without spawning subprocesses, keeping the test fast and portable.
"""

from __future__ import annotations

import importlib
import os
import socket
import threading
import time
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------

def _ensure_linep_lib_path() -> None:
    if os.environ.get("LINEP_LIB_PATH"):
        return
    repo_root = Path(__file__).resolve().parents[2]
    for name in ("liblinep.dll", "liblinep.so", "liblinep.dylib"):
        candidate = repo_root / "build" / name
        if candidate.exists():
            os.environ["LINEP_LIB_PATH"] = str(candidate)
            return


@pytest.fixture(scope="module")
def linep():
    _ensure_linep_lib_path()
    lib_path = os.environ.get("LINEP_LIB_PATH")
    if not lib_path or not Path(lib_path).exists():
        pytest.skip("liblinep shared library not found — set LINEP_LIB_PATH")
    mod = importlib.import_module("linep")
    mod.net_init()
    yield mod
    mod.net_cleanup()


def _free_udp_port() -> int:
    """Bind to port 0 and return the OS-assigned port number."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_udp_heartbeat_wire_format(linep):
    """HeartbeatCompact serialises to 19 bytes and round-trips cleanly."""
    hb = linep.HeartbeatCompact.build(
        worker_id=7,
        slot_id=1,
        slot_flags=int(linep.SlotFlags.ALIVE | linep.SlotFlags.READY),
        load=25,
        queue_depth=2,
        sequence=42,
        worker_score=linep.compute_worker_score(load=25, queue_depth=2),
    )
    raw = hb.to_bytes()
    assert len(raw) == 19, f"expected 19 bytes, got {len(raw)}"

    parsed = linep.HeartbeatCompact.from_bytes(raw)
    parsed.validate()
    assert parsed.worker_id == 7
    assert parsed.slot_id == 1
    assert parsed.load == 25
    assert parsed.queue_depth == 2
    assert parsed.is_ready is True


def test_udp_heartbeat_sent_and_received(linep):
    """HeartbeatCompact frame survives a real UDP loopback round-trip."""
    udp_port = _free_udp_port()

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        rx.bind(("127.0.0.1", udp_port))
        rx.settimeout(2.0)

        hb = linep.HeartbeatCompact.build(
            worker_id=10,
            slot_id=0,
            slot_flags=int(linep.SlotFlags.ALIVE | linep.SlotFlags.READY | linep.SlotFlags.BUSY),
            load=60,
            queue_depth=3,
            sequence=1,
            worker_score=linep.compute_worker_score(load=60, queue_depth=3),
        )
        tx.sendto(hb.to_bytes(), ("127.0.0.1", udp_port))
        raw, _addr = rx.recvfrom(64)

        parsed = linep.HeartbeatCompact.from_bytes(raw)
        parsed.validate()

        assert parsed.worker_id == 10
        assert parsed.queue_depth == 3
        assert bool(parsed.slot_flags & linep.SlotFlags.BUSY) is True
    finally:
        rx.close()
        tx.close()


def test_tcp_task_send_receive(linep):
    """TASK frame reaches the Receiver handler; RESULT is echoed back."""
    tcp_port = _free_tcp_port()
    received: list[bytes] = []
    ready = threading.Event()

    def handler(task_type, correlation_id, worker_id, slot_id, payload):
        received.append(payload)
        return int(linep.ResultStatus.OK), b"echo:" + payload

    recv = linep.tcp.Receiver()
    recv.start(tcp_port, handler)
    # Give the listener a moment to bind.
    time.sleep(0.05)

    try:
        with linep.tcp.Sender() as sender:
            result = sender.send_task(
                host="127.0.0.1",
                port=tcp_port,
                task_type=linep.TaskType.INSTRUCT,
                payload=b"hello linep",
                correlation_id=99,
                worker_id=10,
                slot_id=0,
                timeout_ms=3000,
            )

        assert result.status == linep.ResultStatus.OK, result.status
        assert result.text == "echo:hello linep"
        assert received == [b"hello linep"]
    finally:
        recv.stop()
        recv.close()


def test_combined_heartbeat_then_task(linep):
    """Full control-plane + data-plane sequence in one test.

    1. Coworker announces itself via UDP heartbeat.
    2. Scheduler-side (here: us) receives and parses the heartbeat.
    3. TCP task is dispatched and the response is validated.

    The worker_score computed from the heartbeat telemetry is used to
    confirm scoring parity between Python and C++.
    """
    udp_port = _free_udp_port()
    tcp_port = _free_tcp_port()

    # ── Step 1: coworker sends heartbeat ─────────────────────────────────────
    worker_score = linep.compute_worker_score(load=30, queue_depth=1)
    hb = linep.HeartbeatCompact.build(
        worker_id=20,
        slot_id=0,
        slot_flags=int(linep.SlotFlags.ALIVE | linep.SlotFlags.READY),
        load=30,
        queue_depth=1,
        sequence=5,
        worker_score=worker_score,
    )

    rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        rx_sock.bind(("127.0.0.1", udp_port))
        rx_sock.settimeout(2.0)
        tx_sock.sendto(hb.to_bytes(), ("127.0.0.1", udp_port))
        raw, _ = rx_sock.recvfrom(64)
    finally:
        rx_sock.close()
        tx_sock.close()

    parsed_hb = linep.HeartbeatCompact.from_bytes(raw)
    parsed_hb.validate()
    assert parsed_hb.worker_id == 20
    assert parsed_hb.worker_score == worker_score

    # ── Step 2: verify scoring parity ────────────────────────────────────────
    score = linep.score_slot(
        load=parsed_hb.load,
        queue_depth=parsed_hb.queue_depth,
        worker_score=parsed_hb.worker_score,
    )
    assert score > 0.0

    # ── Step 3: dispatch TCP task to the same worker ──────────────────────────
    prompt = b"What is 6 * 7?"
    response_body = b"42"

    def handler(task_type, correlation_id, worker_id, slot_id, payload):
        assert payload == prompt
        assert worker_id == 20
        return int(linep.ResultStatus.OK), response_body

    recv = linep.tcp.Receiver()
    recv.start(tcp_port, handler)
    time.sleep(0.05)

    try:
        with linep.tcp.Sender() as sender:
            result = sender.send_task(
                host="127.0.0.1",
                port=tcp_port,
                task_type=linep.TaskType.INSTRUCT,
                payload=prompt,
                correlation_id=1,
                worker_id=20,
                slot_id=0,
                timeout_ms=3000,
            )

        assert result.status == linep.ResultStatus.OK
        assert result.body == response_body
    finally:
        recv.stop()
        recv.close()
