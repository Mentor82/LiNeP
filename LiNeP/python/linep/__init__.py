"""
LiNeP — Liara Neural Protocol Python Package
=============================================

Sub-packages:
- `linep.v0_2` — Pure-Python LiNeP V0.2 Dual-Plane Protocol (TCP Data Plane & UDP Control Plane).
- `linep.v0_1` — Legacy LiNeP V0.1 CFFI bindings.

Top-level backward compatibility:
All V0.1 functions, classes, and sub-modules are loaded lazily on demand so importing
`linep` or `linep.v0_2` does not require native shared libraries.
"""

from __future__ import annotations

import importlib
from typing import Any

from linep import v0_2 as v0_2

__version__ = "0.2.0"

_LEGACY_MODULES = {
    "constants": "linep.constants",
    "exceptions": "linep.exceptions",
    "framing": "linep.framing",
    "ports": "linep.ports",
    "scoring": "linep.scoring",
    "tcp": "linep.tcp",
    "_cabi": "linep._cabi",
}

_LEGACY_SYMBOLS = {
    # Constants / Enums
    "MsgType": "linep.constants",
    "TaskType": "linep.constants",
    "ResultStatus": "linep.constants",
    "SlotFlags": "linep.constants",
    "HeaderFlags": "linep.constants",
    "ErrorCode": "linep.constants",
    # Exceptions
    "LiNePError": "linep.exceptions",
    # Framing
    "Header": "linep.framing",
    "BuildTimeExt": "linep.framing",
    "HeartbeatCompact": "linep.framing",
    "UdpInviteFrame": "linep.framing",
    "UdpInviteAckFrame": "linep.framing",
    "UdpHeartbeatAckFrame": "linep.framing",
    # Ports
    "PortPair": "linep.ports",
    # TCP
    "Sender": "linep.tcp",
    "Receiver": "linep.tcp",
    "TaskResult": "linep.tcp",
    # Scoring
    "score_slot": "linep.scoring",
    "compute_worker_score": "linep.scoring",
}

__all__ = [
    "v0_2",
    "v0_1",
    *list(_LEGACY_MODULES.keys()),
    *list(_LEGACY_SYMBOLS.keys()),
    "net_init",
    "net_cleanup",
    "abi_version",
    "crc8",
]


def net_init() -> None:
    """Initialise the network layer (WSAStartup on Windows, no-op on POSIX)."""
    from linep._cabi import lib
    if lib is None:
        raise OSError("LiNeP V0.1 C-ABI shared library (linep.dll/liblinep.so) is not loaded.")
    lib.linep_net_init()


def net_cleanup() -> None:
    """Release network resources allocated by net_init."""
    from linep._cabi import lib
    if lib is None:
        raise OSError("LiNeP V0.1 C-ABI shared library (linep.dll/liblinep.so) is not loaded.")
    lib.linep_net_cleanup()


def abi_version() -> tuple[int, int, int]:
    """Return the loaded C-ABI version as (major, minor, patch)."""
    from linep._cabi import lib
    if lib is None:
        raise OSError("LiNeP V0.1 C-ABI shared library (linep.dll/liblinep.so) is not loaded.")
    raw = int(lib.linep_get_abi_version())
    major = (raw >> 16) & 0xFF
    minor = (raw >> 8) & 0xFF
    patch = raw & 0xFF
    return major, minor, patch


def crc8(data: bytes | bytearray) -> int:
    """Compute CRC-8 using C-ABI if available, or fallback to pure Python implementation."""
    if not data:
        return 0
    try:
        from linep._cabi import ffi, lib
        if lib is not None:
            c_data = ffi.from_buffer(bytes(data))
            return int(lib.linep_crc8(c_data, len(data)))
    except Exception:
        pass
    # Pure Python CRC8 fallback (poly 0x07, init 0x00, no reflection)
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x07) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


def __getattr__(name: str) -> Any:
    if name == "v0_1":
        mod = importlib.import_module("linep.v0_1")
        globals()["v0_1"] = mod
        return mod
    if name in _LEGACY_MODULES:
        mod = importlib.import_module(_LEGACY_MODULES[name])
        globals()[name] = mod
        return mod
    if name in _LEGACY_SYMBOLS:
        mod = importlib.import_module(_LEGACY_SYMBOLS[name])
        attr = getattr(mod, name)
        globals()[name] = attr
        return attr
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + __all__)
