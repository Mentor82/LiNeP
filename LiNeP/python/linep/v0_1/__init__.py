"""
LiNeP V0.1 Legacy CFFI Bindings Sub-package.
"""

from __future__ import annotations

from linep import constants, exceptions, framing, ports, scoring, tcp
from linep import net_init, net_cleanup, abi_version, crc8
from linep.constants import (
    ErrorCode,
    HeaderFlags,
    MsgType,
    ResultStatus,
    SlotFlags,
    TaskType,
)
from linep.exceptions import LiNePError
from linep.framing import (
    BuildTimeExt,
    Header,
    HeartbeatCompact,
    UdpHeartbeatAckFrame,
    UdpInviteAckFrame,
    UdpInviteFrame,
)
from linep.ports import PortPair
from linep.scoring import compute_worker_score, score_slot
from linep.tcp import Receiver, Sender, TaskResult

__all__ = [
    "constants",
    "exceptions",
    "framing",
    "ports",
    "scoring",
    "tcp",
    "ErrorCode",
    "HeaderFlags",
    "MsgType",
    "ResultStatus",
    "SlotFlags",
    "TaskType",
    "LiNePError",
    "BuildTimeExt",
    "Header",
    "HeartbeatCompact",
    "UdpHeartbeatAckFrame",
    "UdpInviteAckFrame",
    "UdpInviteFrame",
    "PortPair",
    "Receiver",
    "Sender",
    "TaskResult",
    "compute_worker_score",
    "score_slot",
    "net_init",
    "net_cleanup",
    "abi_version",
    "crc8",
]
