"""
LiNeP — Liara Neural Protocol Python bindings
==============================================

This package exposes a Pythonic interface to the LiNeP binary protocol
library via cffi.  The shared library (``linep.dll`` / ``liblinep.so``) must
be either installed system-wide or placed next to this package directory.

Quick start
-----------

Send an inference task to a worker::

    import linep
    from linep.constants import TaskType, ResultStatus

    linep.net_init()

    with linep.tcp.Sender() as sender:
        result = sender.send_task(
            host="127.0.0.1",
            port=9000,
            task_type=TaskType.INSTRUCT,
            payload=b"Summarise the following text: ...",
            correlation_id=1,
        )
        if result.status == ResultStatus.OK:
            print(result.text)

    linep.net_cleanup()

Build and validate a heartbeat frame::

    from linep.framing import HeartbeatCompact
    from linep.constants import SlotFlags

    hb = HeartbeatCompact.build(
        worker_id=1, slot_id=0,
        slot_flags=SlotFlags.ALIVE | SlotFlags.READY,
        load=10, queue_depth=0, sequence=1,
        worker_score=100,
    )
    hb.validate()
    raw: bytes = hb.to_bytes()   # 19 bytes, ready for UDP broadcast

Sub-modules
-----------
- :mod:`linep.constants`   — IntEnum / IntFlag types and named constants.
- :mod:`linep.framing`     — Header and HeartbeatCompact builders/validators.
- :mod:`linep.tcp`         — Sender (client) and Receiver (server) classes.
- :mod:`linep.exceptions`  — Exception hierarchy.
"""

from __future__ import annotations

from linep._cabi import ffi as ffi, lib as lib  # noqa: F401
from linep import constants as constants, exceptions as exceptions, framing as framing, tcp as tcp, scoring as scoring
from linep.constants import (
    ErrorCode as ErrorCode,
    HeaderFlags as HeaderFlags,
    MsgType as MsgType,
    ResultStatus as ResultStatus,
    SlotFlags as SlotFlags,
    TaskType as TaskType,
)
from linep.exceptions import LiNePError as LiNePError
from linep.framing import (
    BuildTimeExt as BuildTimeExt,
    Header as Header,
    HeartbeatCompact as HeartbeatCompact,
    UdpHeartbeatAckFrame as UdpHeartbeatAckFrame,
    UdpInviteAckFrame as UdpInviteAckFrame,
    UdpInviteFrame as UdpInviteFrame,
)
from linep.ports import PortPair as PortPair
from linep.tcp import Receiver as Receiver, Sender as Sender, TaskResult as TaskResult
from linep.scoring import score_slot as score_slot, compute_worker_score as compute_worker_score

__all__ = [
    # Sub-modules
    "constants",
    "exceptions",
    "framing",
    "scoring",
    "tcp",
    # Enums / flags (re-exported for convenience)
    "MsgType",
    "TaskType",
    "ResultStatus",
    "SlotFlags",
    "HeaderFlags",
    "ErrorCode",
    # Classes
    "Header",
    "BuildTimeExt",
    "HeartbeatCompact",
    "UdpInviteFrame",
    "UdpInviteAckFrame",
    "UdpHeartbeatAckFrame",
    "PortPair",
    "Sender",
    "Receiver",
    "TaskResult",
    # Scoring helpers
    "score_slot",
    "compute_worker_score",
    # Base exception
    "LiNePError",
    # Lifecycle
    "net_init",
    "net_cleanup",
    "abi_version",
    "crc8",
]

__version__ = "0.1.0"


def net_init() -> None:
    """Initialise the network layer (WSAStartup on Windows, no-op on POSIX).

    Must be called once before any TCP or UDP operation.  Calling it multiple
    times is safe — the underlying implementation is reference-counted.
    """
    lib.linep_net_init()


def net_cleanup() -> None:
    """Release network resources allocated by :func:`net_init`.

    Should be called once at process shutdown.  After this call, no further
    TCP or UDP operations may be performed without calling :func:`net_init`
    again.
    """
    lib.linep_net_cleanup()


def abi_version() -> tuple[int, int, int]:
    """Return the loaded C-ABI version as ``(major, minor, patch)``.

    The raw encoding from the shared library is ``MAJOR<<16 | MINOR<<8 | PATCH``.
    """
    raw = int(lib.linep_get_abi_version())
    major = (raw >> 16) & 0xFF
    minor = (raw >> 8) & 0xFF
    patch = raw & 0xFF
    return major, minor, patch


def crc8(data: bytes | bytearray) -> int:
    """Compute CRC-8 (poly ``0x07``, init ``0x00``, no reflection).

    This is the same CRC used to protect LiNeP header and heartbeat frames.
    Exposed here for testing and manual frame construction.

    Args:
        data: Input bytes.

    Returns:
        CRC-8 value in the range 0–255.

    Example::

        import linep
        print(hex(linep.crc8(b"hello")))  # e.g. 0x92
    """
    if not data:
        return 0
    c_data = ffi.from_buffer(bytes(data))
    return lib.linep_crc8(c_data, len(data))
