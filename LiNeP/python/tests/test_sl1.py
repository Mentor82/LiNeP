from __future__ import annotations

import importlib
import os
import socket
import time
from pathlib import Path

import pytest


def _ensure_linep_lib_path() -> None:
    if os.environ.get("LINEP_LIB_PATH"):
        return
    repo_root = Path(__file__).resolve().parents[2]
    candidate = repo_root / "build" / "liblinep.dll"
    if candidate.exists():
        os.environ["LINEP_LIB_PATH"] = str(candidate)


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


def test_sl1_authentication_flow(linep_module):
    linep = linep_module
    port = _free_tcp_port()
    secret = b"SL1_SECRET_KEY_12345"

    executed_count = 0

    def handler(task_type, correlation_id, worker_id, slot_id, payload):
        nonlocal executed_count
        executed_count += 1
        return linep.ResultStatus.OK, b"SL1_AUTH_OK:" + payload

    with linep.tcp.Receiver() as recv:
        recv.set_sl1_session(0x12345678, 1, secret, require_auth=True)
        recv.start(port=port, handler=handler)
        time.sleep(0.05)

        with linep.tcp.Sender() as sender:
            # 1. Valid SL1 task execution
            sender.set_sl1_session(0x12345678, 1, secret)
            res = sender.send_task(
                host="127.0.0.1",
                port=port,
                task_type=linep.TaskType.INSTRUCT,
                payload=b"test_payload",
                correlation_id=100,
                worker_id=1,
                slot_id=0,
            )
            assert res.status == linep.ResultStatus.OK
            assert res.body == b"SL1_AUTH_OK:test_payload"
            assert executed_count == 1

            # 2. Reject unauthenticated frame when auth required (fail closed / no downgrade)
            sender.clear_sl1_session()
            res2 = sender.send_task(
                host="127.0.0.1",
                port=port,
                task_type=linep.TaskType.INSTRUCT,
                payload=b"unauth_payload",
                correlation_id=101,
                worker_id=1,
                slot_id=0,
            )
            assert res2.status != linep.ResultStatus.OK
            assert executed_count == 1  # Callback MUST NOT be executed!

            # 3. Reject bad key (reject-before-execution)
            sender.set_sl1_session(0x12345678, 1, b"WRONG_KEY_00000000")
            res3 = sender.send_task(
                host="127.0.0.1",
                port=port,
                task_type=linep.TaskType.INSTRUCT,
                payload=b"bad_key_payload",
                correlation_id=102,
                worker_id=1,
                slot_id=0,
            )
            assert res3.status != linep.ResultStatus.OK
            assert executed_count == 1  # Callback MUST NOT be executed!
