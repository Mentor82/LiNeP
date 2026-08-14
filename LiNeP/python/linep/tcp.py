"""
linep.tcp
---------
High-level Python wrappers for the LiNeP TCP task channel.

:class:`Sender`
    Client-side.  Opens a fresh TCP connection for each call, sends a TASK
    frame, and returns the worker's RESULT.  Thread-safe (each call is
    independent).

:class:`Receiver`
    Server-side.  Binds a TCP port, spawns one handler thread per accepted
    connection, calls a Python callback for each TASK frame, and sends the
    RESULT back automatically.

Both classes support the context-manager protocol::

    with linep.tcp.Sender() as sender:
        result = sender.send_task("127.0.0.1", 9000, task_type=TaskType.CODE,
                                   payload=b'print("hello")')

    with linep.tcp.Receiver() as recv:
        recv.start(9000, my_handler)
        time.sleep(60)

Note:
    :func:`linep_net_init` is called automatically on first import of this
    module.  Call :func:`linep.net_cleanup` (or let the process exit) when
    you are done.
"""

from __future__ import annotations

import threading
from typing import Callable

from linep._cabi import ffi, lib
from linep.constants import ResultStatus, TaskType
from linep.exceptions import ArgumentError, raise_for_code

__all__ = [
    "TaskResult",
    "Sender",
    "Receiver",
    "TaskHandler",
]

# Type alias for the Python-level task handler callback.
# See :class:`Receiver` for the full signature description.
TaskHandler = Callable[
    [int, int, int, int, bytes],   # task_type, correlation_id, worker_id, slot_id, payload
    tuple[ResultStatus | int, bytes],   # (status, result_body)
]

# ── Default buffer size for RESULT payloads (can be overridden per-call). ────
_DEFAULT_RESULT_BUF = 4 * 1024 * 1024  # 4 MiB


# ---------------------------------------------------------------------------
# TaskResult
# ---------------------------------------------------------------------------


class TaskResult:
    """Holds the outcome of a :meth:`Sender.send_task` call.

    Attributes:
        status: The :class:`~linep.constants.ResultStatus` byte returned by
                the worker.
        body: The raw response body bytes (everything after the status byte).
    """

    __slots__ = ("status", "body")

    def __init__(self, status: ResultStatus | int, body: bytes) -> None:
        self.status = ResultStatus(status)
        self.body = body

    def __repr__(self) -> str:
        return f"TaskResult(status={self.status.name}, body_len={len(self.body)})"

    @property
    def text(self) -> str:
        """Decode ``body`` as UTF-8 (errors replaced).

        Returns:
            The response body decoded as a UTF-8 string.
        """
        return self.body.decode("utf-8", errors="replace")

    def raise_on_error(self) -> None:
        """Raise :exc:`~linep.exceptions.LiNePError` if ``status`` is not OK.

        Raises:
            :exc:`~linep.exceptions.LiNePError`: When
                :attr:`status` is not :attr:`~linep.constants.ResultStatus.OK`.
        """
        if self.status != ResultStatus.OK:
            from linep.exceptions import LiNePError
            raise LiNePError(
                f"Worker returned {self.status.name}: {self.text[:200]}",
                code=int(self.status),
            )


# ---------------------------------------------------------------------------
# Sender
# ---------------------------------------------------------------------------


class Sender:
    """Client-side TCP task sender.

    Opens a fresh TCP connection for each :meth:`send_task` call, which makes
    the object itself stateless and safe to share across threads.

    Example::

        sender = linep.tcp.Sender()
        result = sender.send_task(
            host="worker-01.local",
            port=9000,
            task_type=TaskType.INSTRUCT,
            correlation_id=1,
            worker_id=1,
            slot_id=0,
            payload=b"Translate to German: hello",
        )
        print(result.text)
        sender.close()
    """

    def __init__(self) -> None:
        self._handle = lib.linep_sender_create()
        if self._handle == ffi.NULL:
            raise MemoryError("linep_sender_create() returned NULL")

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "Sender":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_task(
        self,
        host: str,
        port: int,
        task_type: TaskType | int,
        payload: bytes | bytearray,
        *,
        correlation_id: int = 0,
        worker_id: int = 0,
        slot_id: int = 0,
        timeout_ms: int = 5000,
        result_buf_size: int = _DEFAULT_RESULT_BUF,
    ) -> TaskResult:
        """Connect to ``host:port``, send a TASK frame, and receive a RESULT.

        A fresh TCP connection is opened and closed per call.  The call
        blocks until the worker responds or ``timeout_ms`` elapses.

        Args:
            host: Worker hostname or IPv4/IPv6 address.
            port: Worker TCP port.
            task_type: One of :class:`~linep.constants.TaskType`.
            payload: Raw task body bytes (e.g. UTF-8 prompt text).
            correlation_id: Request identifier echoed in the RESULT header.
                Useful for matching asynchronous results.
            worker_id: Worker identifier embedded in the TASK header.
            slot_id: Target inference slot on the worker.
            timeout_ms: Per-call deadline in milliseconds.
            result_buf_size: Size of the receive buffer in bytes.
                Must be >= the expected response size.

        Returns:
            A :class:`TaskResult` with ``status`` and ``body``.

        Raises:
            :exc:`~linep.exceptions.TimeoutError`: No response within the deadline.
            :exc:`~linep.exceptions.ConnectError`: TCP connection failed.
            :exc:`~linep.exceptions.SendError`: Frame could not be sent.
            :exc:`~linep.exceptions.RecvError`: Response could not be received.
            :exc:`~linep.exceptions.BadFrameError`: Response failed CRC check.
            :exc:`~linep.exceptions.ArgumentError`: Invalid argument.
        """
        if not host:
            raise ArgumentError("host must not be empty")
        if not (0 < port < 65536):
            raise ArgumentError(f"port must be 1–65535, got {port}")
        if not payload:
            payload = b""

        result_buf = ffi.new(f"uint8_t[{result_buf_size}]")
        result_len = ffi.new("uint32_t *", result_buf_size)

        c_payload = ffi.from_buffer(bytes(payload))

        rc = lib.linep_sender_send_task(
            self._handle,
            host.encode(),
            port,
            int(task_type),
            correlation_id,
            worker_id,
            slot_id,
            c_payload,
            len(payload),
            result_buf,
            result_len,
            timeout_ms,
        )
        raise_for_code(rc, f"Sender.send_task({host}:{port})")

        # result_buf[0] carries the ResultStatus; the body follows.
        total = int(result_len[0])
        if total == 0:
            return TaskResult(ResultStatus.OK, b"")

        status = result_buf[0]
        body = bytes(ffi.buffer(result_buf, total))[1:]
        return TaskResult(status, body)

    def close(self) -> None:
        """Release the underlying C handle.

        Safe to call multiple times.
        """
        if self._handle != ffi.NULL:
            lib.linep_sender_destroy(self._handle)
            self._handle = ffi.NULL


# ---------------------------------------------------------------------------
# Receiver
# ---------------------------------------------------------------------------


class Receiver:
    """Server-side TCP task receiver.

    Listens on a TCP port and dispatches incoming TASK frames to a Python
    callback.  One background thread is spawned per accepted connection.

    The callback signature must be::

        def handler(
            task_type: int,
            correlation_id: int,
            worker_id: int,
            slot_id: int,
            payload: bytes,
        ) -> tuple[int, bytes]:
            ...
            return ResultStatus.OK, b"response body"

    The returned ``(status, body)`` tuple is packed into a RESULT frame and
    sent back to the client automatically.

    Example::

        def my_handler(task_type, correlation_id, worker_id, slot_id, payload):
            text = payload.decode()
            response = run_model(text)
            return ResultStatus.OK, response.encode()

        with linep.tcp.Receiver() as recv:
            recv.start(9000, my_handler)
            time.sleep(3600)   # serve for one hour
    """

    def __init__(self) -> None:
        self._handle = lib.linep_receiver_create()
        if self._handle == ffi.NULL:
            raise MemoryError("linep_receiver_create() returned NULL")
        self._running = False
        self._lock = threading.Lock()
        # Keep a reference to the cffi callback to prevent GC.
        self._c_callback: object = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "Receiver":
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()
        self.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, port: int, handler: TaskHandler, user_data: object = None) -> None:
        """Bind ``port`` and begin accepting TASK frames.

        Args:
            port: TCP port to listen on (1–65535).
            handler: Python callable invoked once per TASK frame.
                Must return ``(status: int, body: bytes)``.
            user_data: Arbitrary Python object passed through to ``handler``
                via a closure.  Not passed to the C layer directly.

        Raises:
            :exc:`~linep.exceptions.PortError`: Port already in use.
            :exc:`~linep.exceptions.ArgumentError`: Invalid port or no handler.
            :exc:`RuntimeError`: Receiver already running.
        """
        with self._lock:
            if self._running:
                raise RuntimeError("Receiver is already running")
            if not callable(handler):
                raise ArgumentError("handler must be callable")
            if not (0 < port < 65536):
                raise ArgumentError(f"port must be 1–65535, got {port}")

            # Wrap the Python handler in a C-compatible callback.
            # cffi requires us to keep the cdata object alive for the
            # lifetime of the callback, so we store it on self.
            def _c_impl(
                task_type_c: int,
                correlation_id_c: int,
                worker_id_c: int,
                slot_id_c: int,
                payload_ptr: object,
                payload_len_c: int,
                result_buf: object,
                result_cap: int,
                result_len_ptr: object,
                _user_data: object,
            ) -> int:
                try:
                    raw = bytes(ffi.buffer(payload_ptr, payload_len_c))
                    status, body = handler(
                        task_type_c, correlation_id_c, worker_id_c, slot_id_c, raw
                    )
                    if body:
                        n = min(len(body), result_cap)
                        ffi.memmove(result_buf, body, n)
                        result_len_ptr[0] = n
                    else:
                        result_len_ptr[0] = 0
                    return int(status)
                except Exception:  # noqa: BLE001
                    result_len_ptr[0] = 0
                    return int(ResultStatus.MODEL_ERROR)

            self._c_callback = ffi.callback(
                "uint8_t(uint8_t, uint32_t, uint16_t, uint8_t,"
                " const uint8_t *, uint32_t,"
                " uint8_t *, uint32_t, uint32_t *, void *)",
                _c_impl,
            )

            rc = lib.linep_receiver_start(self._handle, port, self._c_callback, ffi.NULL)
            raise_for_code(rc, f"Receiver.start(port={port})")
            self._running = True

    def stop(self) -> None:
        """Stop accepting connections and wait for active handlers to finish.

        Safe to call multiple times or from any thread.
        """
        with self._lock:
            if self._running:
                lib.linep_receiver_stop(self._handle)
                self._running = False
                self._c_callback = None

    def close(self) -> None:
        """Release the underlying C handle.

        Calls :meth:`stop` first if the receiver is still running.
        Safe to call multiple times.
        """
        self.stop()
        if self._handle != ffi.NULL:
            lib.linep_receiver_destroy(self._handle)
            self._handle = ffi.NULL

    @property
    def is_running(self) -> bool:
        """``True`` between :meth:`start` and :meth:`stop`."""
        return self._running
