from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import os
import socket
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


def _crc8(data: bytes) -> int:
    # CRC-8 poly=0x07, init=0x00, no reflection.
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            if (crc & 0x80) != 0:
                crc = ((crc << 1) ^ 0x07) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


def _build_heartbeat(worker_id: int = 65530, slot_id: int = 1, sequence: int = 1) -> bytes:
    # Layout: <HBBHBBBBBHBBBBB + crc8
    now = datetime.now(timezone.utc)
    prefix = struct.pack(
        "<HBBHBBBBBHBBBBB",
        0x4C4E,   # magic "LN"
        0x01,     # version
        0x01,     # HEARTBEAT
        worker_id & 0xFFFF,
        slot_id & 0xFF,
        0x03,     # SLOT_ALIVE | SLOT_READY
        10,       # load
        0,        # queue_depth
        sequence & 0xFF,
        100,      # worker_score
        now.month,
        now.day,
        now.hour,
        now.minute,
        now.second,
    )
    return prefix + bytes([_crc8(prefix)])


def _try_find_lib(explicit: str | None) -> str:
    if explicit:
        return explicit

    env = os.environ.get("LINEP_LIB_PATH")
    if env:
        return env

    cwd = Path.cwd()
    candidates = [
        cwd / "build" / "liblinep.dll",
        cwd / "build" / "linep.dll",
        cwd / "build" / "liblinep.so",
        cwd / "build" / "liblinep.so.1",
        cwd / "build" / "liblinep.dylib",
    ]
    for c in candidates:
        if c.exists():
            return str(c)

    if os.name == "nt":
        return "linep.dll"
    if sys.platform == "darwin":
        return "liblinep.dylib"
    return "liblinep.so.1"


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


def _check_dll(lib_path: str) -> CheckResult:
    try:
        ctypes.CDLL(lib_path)
        return CheckResult("shared-library", True, f"loaded: {lib_path}")
    except OSError as exc:
        return CheckResult("shared-library", False, f"failed to load {lib_path}: {exc}")


def _check_tcp(host: str, port: int, timeout: float) -> CheckResult:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return CheckResult("tcp-port", True, f"reachable at {host}:{port}")
    except OSError as exc:
        return CheckResult("tcp-port", False, f"cannot connect to {host}:{port}: {exc}")


def _check_udp(host: str, port: int, timeout: float) -> CheckResult:
    hb = _build_heartbeat()

    local_hosts = {"127.0.0.1", "localhost", "0.0.0.0"}
    if host in local_hosts:
        # Best case: bind directly to udp port and verify receive path.
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            rx.settimeout(timeout)
            rx.bind(("127.0.0.1", port))
            tx.sendto(hb, ("127.0.0.1", port))
            data, _ = rx.recvfrom(64)
            ok = len(data) == 19 and data[-1] == _crc8(data[:-1])
            if ok:
                return CheckResult("udp-heartbeat", True, f"loopback recv ok on 127.0.0.1:{port}")
            return CheckResult("udp-heartbeat", False, "received datagram but heartbeat CRC/layout invalid")
        except OSError:
            # Port may already be used by a running receiver. Fall back to send-only probe.
            pass
        finally:
            tx.close()
            rx.close()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx:
            sent = tx.sendto(hb, (host, port))
            if sent == len(hb):
                return CheckResult(
                    "udp-heartbeat",
                    True,
                    f"heartbeat datagram sent to {host}:{port} (no ACK in UDP)",
                )
            return CheckResult("udp-heartbeat", False, f"partial send: {sent}/{len(hb)} bytes")
    except OSError as exc:
        return CheckResult("udp-heartbeat", False, f"cannot send UDP heartbeat to {host}:{port}: {exc}")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="linep-doctor",
        description="LiNeP local connectivity checker (DLL + TCP + UDP)",
    )
    parser.add_argument("--lib", dest="lib_path", default=None, help="path to linep shared library")
    parser.add_argument("--host", default="127.0.0.1", help="target host for TCP/UDP checks")
    parser.add_argument("--tcp-port", type=int, default=9000, help="TCP TASK/RESULT port")
    parser.add_argument("--udp-port", type=int, default=9001, help="UDP HEARTBEAT port")
    parser.add_argument("--timeout-ms", type=int, default=1000, help="socket timeout in milliseconds")
    parser.add_argument("--skip-tcp", action="store_true", help="skip TCP reachability check")
    parser.add_argument("--skip-udp", action="store_true", help="skip UDP heartbeat check")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    ns = _parse_args(sys.argv[1:] if argv is None else argv)

    timeout = max(1, ns.timeout_ms) / 1000.0
    lib_path = _try_find_lib(ns.lib_path)

    results: list[CheckResult] = []
    results.append(_check_dll(lib_path))

    if not ns.skip_tcp:
        results.append(_check_tcp(ns.host, ns.tcp_port, timeout))
    if not ns.skip_udp:
        results.append(_check_udp(ns.host, ns.udp_port, timeout))

    for r in results:
        prefix = "[OK]" if r.ok else "[FAIL]"
        print(f"{prefix} {r.name}: {r.detail}")

    failed = [r for r in results if not r.ok]
    if failed:
        print(f"linep-doctor: {len(failed)} check(s) failed")
        return 1

    print("linep-doctor: all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
