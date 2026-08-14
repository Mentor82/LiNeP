"""
linep.constants
---------------
Python enumerations that mirror the C constants in ``include/linep/cabi.h``.

Using :class:`enum.IntEnum` / :class:`enum.IntFlag` means values are
interchangeable with plain ``int`` — you can pass them directly to cffi
function calls without casting.

Example::

    from linep.constants import MsgType, TaskType, ResultStatus

    print(MsgType.TASK)          # MsgType.TASK
    print(int(MsgType.TASK))     # 16
    assert TaskType.CODE == 0x02
"""

from __future__ import annotations

from enum import IntEnum, IntFlag

__all__ = [
    "MsgType",
    "TaskType",
    "ResultStatus",
    "SlotFlags",
    "HeaderFlags",
    "ErrorCode",
    "LOAD_IDLE",
    "LOAD_UNKNOWN",
    "LOAD_OFFLINE",
]


class MsgType(IntEnum):
    """Wire message-type byte (``Header.msg_type`` field).

    Every LiNeP frame carries one of these values in the header to identify
    the frame kind and expected payload schema.
    """

    # Presence
    HEARTBEAT         = 0x01
    REGISTER          = 0x02
    REGISTER_ACK      = 0x03
    BYE               = 0x04
    INVITE            = 0x05
    INVITE_ACK        = 0x06
    HEARTBEAT_ACK     = 0x07

    # Inference
    TASK              = 0x10
    TASK_ACK          = 0x11
    RESULT            = 0x12
    MSG_ERROR         = 0x13
    TASK_CANCEL       = 0x14

    # Status
    STATUS_REQUEST    = 0x20
    STATUS_RESPONSE   = 0x21

    # Embedding
    EMBED_REQUEST        = 0x30
    EMBED_RESPONSE       = 0x31
    SIMILARITY_REQUEST   = 0x32
    SIMILARITY_RESPONSE  = 0x33

    # Consensus
    CONSENSUS_REQUEST  = 0x40
    CONSENSUS_RESPONSE = 0x41

    # Diagnostics
    PING = 0xF0
    PONG = 0xF1


class TaskType(IntEnum):
    """Inference mode requested in a TASK frame payload.

    The ``task_type`` byte in a TASK header selects the inference pipeline
    the receiving worker should execute.
    """

    INSTRUCT       = 0x01
    """Instruction-following / chat completion."""

    CODE           = 0x02
    """Code generation or completion."""

    SUMMARIZE      = 0x03
    """Text summarisation."""

    CLASSIFY       = 0x04
    """Classification / labelling."""

    VALIDATE       = 0x05
    """Output validation / scoring."""

    EDGE_TEXT_EVAL = 0x06
    """Lightweight on-device text evaluation."""


class ResultStatus(IntEnum):
    """Outcome byte at the start of every RESULT frame payload.

    The first byte of the RESULT payload is always a :class:`ResultStatus`
    value; the remaining bytes carry the UTF-8 response body.
    """

    OK            = 0x00
    """Inference succeeded; response body follows."""

    REJECTED      = 0x01
    """Worker refused the task (slot not ready, wrong type, etc.)."""

    TIMEOUT       = 0x02
    """Worker did not respond within the negotiated deadline."""

    MODEL_ERROR   = 0x03
    """Inference-engine error (OOM, numerical instability, …)."""

    INVALID_INPUT = 0x04
    """Payload failed schema / sanity checks on the worker side."""

    DEGRADED      = 0x05
    """Result produced under degraded conditions (partial output)."""


class SlotFlags(IntFlag):
    """Bitmask in :attr:`~linep.framing.HeartbeatCompact.slot_flags`.

    Multiple flags can be combined::

        flags = SlotFlags.ALIVE | SlotFlags.READY
        if flags & SlotFlags.BUSY:
            ...
    """

    ALIVE         = 0x01
    """Slot process is running."""

    READY         = 0x02
    """Slot is idle and accepting tasks."""

    BUSY          = 0x04
    """A task is currently in flight."""

    DEGRADED      = 0x08
    """Model is operating in reduced-precision / fallback mode."""

    ERROR         = 0x10
    """Last task ended in a model error; slot may need restart."""

    THERMAL_LIMIT = 0x20
    """Device has throttled due to thermal constraints."""

    MODEL_LOADING = 0x40
    """Model weights are still loading; slot not yet usable."""


class HeaderFlags(IntFlag):
    """Bitmask in the ``flags`` field of every LiNeP :class:`~linep.framing.Header`."""

    BUILD_TIME     = 0x0001
    """v1.1: HeaderBuildTimeExt follows Header."""

    ACK_REQUIRED   = 0x0002
    """Request an acknowledgement frame."""

    ENCRYPTED      = 0x0004
    """Payload is encrypted."""

    AUTHENTICATED  = 0x0008
    """SL1: HeaderAuthExt follows Header."""

    COMPRESSED     = 0x0010
    """Payload is compressed."""

    FRAGMENTED     = 0x0020
    """Part of a multi-fragment message."""

    FINAL_FRAGMENT = 0x0040
    """Last fragment of a fragmented message."""

    PRIORITY       = 0x0080
    """High-priority task; scheduler may jump the queue."""

    DEGRADED       = 0x0100
    """Sender is operating in degraded mode."""

    RETRY          = 0x0200
    """This frame is a retry of a previously timed-out request."""

    ERROR          = 0x0400
    """Frame carries an error payload."""


class ErrorCode(IntEnum):
    """Protocol error codes carried in MSG_ERROR frames.

    Codes are grouped by origin:

    * ``1000`` — ``1099``: Protocol-level errors.
    * ``2000`` — ``2099``: Model / inference errors.
    * ``3000`` — ``3099``: Infrastructure / scheduler errors.
    """

    # Protocol
    PROTOCOL_ERROR      = 1000
    CRC_ERROR           = 1001
    UNSUPPORTED_VERSION = 1002
    UNKNOWN_MSG_TYPE    = 1003
    INVALID_PAYLOAD     = 1004

    # Model
    MODEL_NOT_READY    = 2000
    MODEL_LOAD_FAILED  = 2001
    INFERENCE_FAILED   = 2002
    TOKENIZER_FAILED   = 2003
    DEVICE_UNAVAILABLE = 2004

    # Infrastructure
    TIMEOUT           = 3000
    NO_SLOT_AVAILABLE = 3001
    CONSENSUS_FAILED  = 3002


# Special ``load`` byte values in HeartbeatCompact.
LOAD_IDLE    = 0
"""Load byte value: slot is completely idle (0 %)."""

LOAD_UNKNOWN = 200
"""Load byte value: load cannot be determined."""

LOAD_OFFLINE = 250
"""Load byte value: slot is offline."""
