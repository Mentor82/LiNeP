"""
Type stubs for the ``linep`` package top-level namespace.

Pylance / mypy use this file instead of introspecting ``__init__.py``
(which imports cffi objects that are opaque to static analysers).
"""

from typing import Any

from linep import constants as constants
from linep import exceptions as exceptions
from linep import framing as framing
from linep import scoring as scoring
from linep import tcp as tcp
from linep.constants import ErrorCode as ErrorCode
from linep.constants import HeaderFlags as HeaderFlags
from linep.constants import MsgType as MsgType
from linep.constants import ResultStatus as ResultStatus
from linep.constants import SlotFlags as SlotFlags
from linep.constants import TaskType as TaskType
from linep.exceptions import LiNePError as LiNePError
from linep.framing import BuildTimeExt as BuildTimeExt
from linep.framing import Header as Header
from linep.framing import HeartbeatCompact as HeartbeatCompact
from linep.ports import PortPair as PortPair
from linep.scoring import compute_worker_score as compute_worker_score
from linep.scoring import score_slot as score_slot
from linep.tcp import Receiver as Receiver
from linep.tcp import Sender as Sender
from linep.tcp import TaskResult as TaskResult

# cffi objects — opaque to static analysis, typed as Any
ffi: Any
lib: Any

__version__: str

def net_init() -> None: ...
def net_cleanup() -> None: ...
def abi_version() -> tuple[int, int, int]: ...
def crc8(data: bytes | bytearray) -> int: ...
