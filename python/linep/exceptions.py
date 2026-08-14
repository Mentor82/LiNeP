"""
linep.exceptions
----------------
Exception hierarchy for the LiNeP Python bindings.

All exceptions raised by this library are subclasses of :exc:`LiNePError` so
callers can catch everything with a single ``except LiNePError`` clause while
still being able to handle specific failure modes individually.

Example::

    from linep.exceptions import LiNePError, TimeoutError, BadFrameError

    try:
        result = sender.send_task(...)
    except linep.exceptions.TimeoutError:
        print("no response within deadline")
    except LiNePError as exc:
        print(f"protocol error: {exc}")
"""

from __future__ import annotations

__all__ = [
    "LiNePError",
    "ArgumentError",
    "TimeoutError",
    "ConnectError",
    "SendError",
    "RecvError",
    "BadFrameError",
    "PortError",
    "InternalError",
    "BufferTooSmallError",
]

# Map C error codes to exception classes (populated at the bottom of this module).
_CODE_TO_EXC: dict[int, type["LiNePError"]] = {}


class LiNePError(RuntimeError):
    """Base class for all LiNeP errors.

    Attributes:
        code: The raw ``LINEP_C_ERR_*`` integer returned by the C layer,
              or ``None`` if the error originates in Python.
    """

    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code

    def __repr__(self) -> str:
        return f"{type(self).__name__}({str(self)!r}, code={self.code})"


class ArgumentError(LiNePError):
    """A required argument was ``None`` or contained an illegal value.

    Maps to ``LINEP_C_ERR_ARG`` (``-1``).
    """


class TimeoutError(LiNePError):
    """The remote worker did not respond within the configured deadline.

    Maps to ``LINEP_C_ERR_TIMEOUT`` (``-2``).
    """


class ConnectError(LiNePError):
    """TCP connection to the worker was refused or the host is unreachable.

    Maps to ``LINEP_C_ERR_CONNECT`` (``-3``).
    """


class SendError(LiNePError):
    """The TASK frame could not be sent over the established TCP connection.

    Maps to ``LINEP_C_ERR_SEND`` (``-4``).
    """


class RecvError(LiNePError):
    """Receiving the RESULT frame failed or the connection was closed early.

    Maps to ``LINEP_C_ERR_RECV`` (``-5``).
    """


class BadFrameError(LiNePError):
    """A frame failed CRC-8 validation or carried an invalid magic/version.

    Maps to ``LINEP_C_ERR_BAD_FRAME`` (``-6``).
    """


class PortError(LiNePError):
    """The requested TCP port is already in use and cannot be bound.

    Maps to ``LINEP_C_ERR_PORT`` (``-7``).
    """


class InternalError(LiNePError):
    """An unexpected internal error occurred inside the C library.

    Maps to ``LINEP_C_ERR_INTERNAL`` (``-8``).
    """


class BufferTooSmallError(LiNePError):
    """The caller-supplied result buffer is too small for the response.

    Maps to ``LINEP_C_ERR_BUF_SMALL`` (``-9``).
    """


# ---------------------------------------------------------------------------
# Helper used by higher-level modules
# ---------------------------------------------------------------------------

_CODE_TO_EXC = {
    -1: ArgumentError,
    -2: TimeoutError,
    -3: ConnectError,
    -4: SendError,
    -5: RecvError,
    -6: BadFrameError,
    -7: PortError,
    -8: InternalError,
    -9: BufferTooSmallError,
}


def raise_for_code(rc: int, context: str = "") -> None:
    """Raise the appropriate :exc:`LiNePError` subclass for a C return code.

    Args:
        rc: Return value from a ``lib.linep_*`` call.
        context: Optional human-readable description of the failing operation,
                 prepended to the error message.

    Raises:
        LiNePError: Appropriate subclass when ``rc < 0``.
    """
    if rc >= 0:
        return
    exc_cls = _CODE_TO_EXC.get(rc, LiNePError)
    prefix = f"{context}: " if context else ""
    raise exc_cls(f"{prefix}C library returned error code {rc}", code=rc)
