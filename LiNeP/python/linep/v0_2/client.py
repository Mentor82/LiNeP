"""LiNeP V0.2 High-Level Streaming TCP Client."""

from __future__ import annotations

import socket
import struct
import time
from typing import Iterator, List, Optional

from linep.v0_2.constants import (
    LINEP_V02_HEADER_SIZE,
    RuntimeProfile,
    EnvelopeType,
    EventType,
    ControlType,
    TerminalOutcome,
)
from linep.v0_2.envelopes import (
    StreamIdentity,
    WireEnvelopeHeader,
    RequestEnvelope,
    EventEnvelope,
    ControlEnvelope,
    CapabilitiesEnvelope,
    encode_request,
    decode_event,
    encode_control,
    decode_capabilities,
    encode_capabilities,
    decode_header,
)


class LiNePClient:
    """Pythonic synchronous TCP client for LiNeP V0.2 Dual-Plane runtime."""

    def __init__(self, host: str = "127.0.0.1", port: int = 11435, timeout: float = 10.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._request_counter = 1000

    def connect(self) -> LiNePClient:
        if self._sock is None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self.timeout)
            self._sock.connect((self.host, self.port))
        return self

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self._sock.close()
            self._sock = None

    def __enter__(self) -> LiNePClient:
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def is_connected(self) -> bool:
        return self._sock is not None

    def _send_all(self, data: bytes) -> None:
        if self._sock is None:
            raise ConnectionError("Not connected to LiNeP endpoint")
        self._sock.sendall(data)

    def _recv_exact(self, n: int) -> bytes:
        if self._sock is None:
            raise ConnectionError("Not connected to LiNeP endpoint")
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionResetError("Remote server closed connection")
            buf.extend(chunk)
        return bytes(buf)

    def _recv_envelope(self) -> bytes:
        hdr_bytes = self._recv_exact(LINEP_V02_HEADER_SIZE)
        hdr = decode_header(hdr_bytes)
        if hdr is None:
            raise ValueError("Invalid header received")
        if hdr.payload_len > 0:
            payload_bytes = self._recv_exact(hdr.payload_len)
            return hdr_bytes + payload_bytes
        return hdr_bytes

    def query_capabilities(self) -> Optional[CapabilitiesEnvelope]:
        if not self.is_connected():
            self.connect()
        query = CapabilitiesEnvelope()
        raw = encode_capabilities(query)
        self._send_all(raw)
        resp_raw = self._recv_envelope()
        return decode_capabilities(resp_raw)

    def send_control(self, ctrl: ControlEnvelope) -> None:
        raw = encode_control(ctrl)
        self._send_all(raw)

    def cancel_stream(self, stream: StreamIdentity, reason: str = "Client requested cancellation") -> None:
        ctrl = ControlEnvelope(stream=stream, control_type=ControlType.CANCEL, reason=reason)
        self.send_control(ctrl)

    def execute_stream(
        self, req: RequestEnvelope, auto_ack_window: bool = True
    ) -> Iterator[EventEnvelope]:
        if not self.is_connected():
            self.connect()

        self._send_all(encode_request(req))
        cumulative_bytes = 0

        while True:
            raw_env = self._recv_envelope()
            evt = decode_event(raw_env)
            if evt is None:
                raise ValueError("Received invalid event frame")

            if evt.stream.request_id != req.stream.request_id or evt.stream.execution_id != req.stream.execution_id:
                raise ValueError("Stream identity mismatch in received event")

            if auto_ack_window and evt.event_type in (EventType.CONTENT_DELTA, EventType.REASONING_DELTA):
                cumulative_bytes += len(evt.payload.encode("utf-8"))
                ctrl = ControlEnvelope(
                    stream=evt.stream,
                    control_type=ControlType.WINDOW_UPDATE,
                    reason="ACK",
                    ack_offset_bytes=cumulative_bytes,
                )
                self.send_control(ctrl)

            yield evt

            if evt.event_type in (EventType.COMPLETED, EventType.FAILED, EventType.CANCELLED):
                break

    def stream_chat(
        self, model: str, prompt: str, max_tokens: int = 512, temperature: float = 0.7
    ) -> Iterator[EventEnvelope]:
        self._request_counter += 1
        stream = StreamIdentity(request_id=self._request_counter, execution_id=self._request_counter * 10, output_id=0)
        req = RequestEnvelope(
            stream=stream,
            profile=RuntimeProfile.CHAT,
            model_id=model,
            payload=prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            stream_requested=True,
        )
        yield from self.execute_stream(req)

    def embed(self, model: str, text: str) -> List[float]:
        self._request_counter += 1
        stream = StreamIdentity(request_id=self._request_counter, execution_id=self._request_counter * 10, output_id=0)
        req = RequestEnvelope(
            stream=stream,
            profile=RuntimeProfile.EMBED,
            model_id=model,
            payload=text,
            max_tokens=0,
            temperature=0.0,
            stream_requested=False,
        )
        for evt in self.execute_stream(req, auto_ack_window=False):
            if evt.event_type == EventType.EMBEDDING_RESULT:
                return list(evt.embedding.vector)
        raise RuntimeError("No embedding result received from runtime")
