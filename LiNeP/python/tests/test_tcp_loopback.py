from __future__ import annotations

import importlib
import os
import sys
import socket
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


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def linep_module():
    _ensure_linep_lib_path()

    lib_path = os.environ.get("LINEP_LIB_PATH")
    if not lib_path:
        pytest.skip("LINEP_LIB_PATH not set and build/liblinep.dll not found")
    if not Path(lib_path).exists():
        pytest.skip(f"Configured LINEP_LIB_PATH does not exist: {lib_path}")

    mod = importlib.import_module("linep")
    mod.net_init()
    try:
        yield mod
    finally:
        mod.net_cleanup()


def test_tcp_roundtrip_ok(linep_module):
    linep = linep_module
    port = _free_tcp_port()

    def handler(task_type, correlation_id, worker_id, slot_id, payload):
        assert task_type == int(linep.TaskType.INSTRUCT)
        assert correlation_id == 1234
        assert worker_id == 7
        assert slot_id == 1
        return linep.ResultStatus.OK, b"echo:" + payload

    with linep.tcp.Receiver() as recv:
        recv.start(port=port, handler=handler)
        time.sleep(0.05)

        with linep.tcp.Sender() as sender:
            result = sender.send_task(
                host="127.0.0.1",
                port=port,
                task_type=linep.TaskType.INSTRUCT,
                payload=b"hello",
                correlation_id=1234,
                worker_id=7,
                slot_id=1,
                timeout_ms=2000,
            )

        assert result.status == linep.ResultStatus.OK
        assert result.body == b"echo:hello"


def test_tcp_roundtrip_rejected_status(linep_module):
    linep = linep_module
    port = _free_tcp_port()

    def handler(task_type, correlation_id, worker_id, slot_id, payload):
        return linep.ResultStatus.REJECTED, b"slot busy"

    with linep.tcp.Receiver() as recv:
        recv.start(port=port, handler=handler)
        time.sleep(0.05)

        with linep.tcp.Sender() as sender:
            result = sender.send_task(
                host="127.0.0.1",
                port=port,
                task_type=linep.TaskType.CODE,
                payload=b"print('x')",
                correlation_id=999,
                worker_id=1,
                slot_id=0,
                timeout_ms=2000,
            )

        assert result.status == linep.ResultStatus.REJECTED
        assert result.text == "slot busy"
