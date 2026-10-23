"""LiNeP V0.2 trunk session: the client side of a linepd trunk.

A linepd trunk (liara-noded) only serves bound connections:

1. Lease on the UDP control plane: NODE_HELLO -> INVITE (carries the lease token)
   -> LEASE_ACK. The lease expires after the node's idle timeout (300 s in
   liara-noded) unless HEARTBEAT datagrams keep it alive.
2. SESSION_BIND on the TCP trunk with identity, epoch and lease token.
3. With ``auth = "required"`` every frame in both directions carries an SL1
   wire_auth_extension (truncated HMAC-SHA256 over header, auth prefix, binding,
   direction and payload). linepd confirms a signed bind with its own signed
   bind (auth_seq 1); afterwards each side counts auth_seq up by one per frame.

`TrunkSession` does all three and then offers the same request API as
`LiNePClient` (`execute_stream`, `stream_chat`, `embed`). Only the standard
library is used (no native linep library).
"""

from __future__ import annotations

import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional, Union

from linep.v0_2.constants import (
    LINEP_V02_AUTH_EXTENSION_SIZE,
    LINEP_V02_FLAG_AUTHENTICATED,
    LINEP_V02_HEADER_SIZE,
    ControlMessageType,
    ControlType,
    EnvelopeType,
    EventType,
    MessageDirection,
    NodeAvailability,
    NodeHealth,
    RuntimeProfile,
)
from linep.v0_2.control_plane import (
    NodeEndpointIdentity,
    UdpControlDatagram,
    decode_control_datagram,
    encode_control_datagram,
)
from linep.v0_2.envelopes import (
    ControlEnvelope,
    EventEnvelope,
    GenerationOptions,
    RequestEnvelope,
    SessionBindEnvelope,
    StreamIdentity,
    decode_event,
    decode_header,
    encode_control,
    encode_request,
    encode_session_bind,
    sign_envelope,
    verify_envelope,
)

DEFAULT_TRUNK_PORT = 9000
DEFAULT_CONTROL_PORT = 9001
# runtime_id/endpoint_id a client announces for itself (as liara-noded's own tests do)
CLIENT_RUNTIME_ID = 3
CLIENT_ENDPOINT_ID = 1
# well below liara-noded's LEASE_IDLE_TIMEOUT of 300 s
DEFAULT_HEARTBEAT_INTERVAL = 60.0
# trunk_ready flag of the control datagram; tcp_port is informational for a client
_FLAG_TRUNK_READY = 0x01
_CLIENT_TCP_PORT = 40000


class TrunkError(Exception):
    """Lease, bind, authentication or request failure reported by the trunk."""

    def __init__(self, message: str, code: int = 0) -> None:
        super().__init__(f"{message} (code {code})" if code else message)
        self.code = code
        self.reason = message


@dataclass(frozen=True)
class Sl1Credentials:
    """SL1 client key: ``key_id`` and the shared secret.

    Key files use liara-noded's format, one ``name = value`` per line::

        key_id = 2001
        key = <hex>
    """

    key_id: int
    key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not 0 < self.key_id <= 0xFFFF:
            raise ValueError("SL1 key_id must be in 1..65535")
        if len(self.key) < 16:
            raise ValueError("SL1 key must be at least 16 bytes")

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "Sl1Credentials":
        key_id: Optional[int] = None
        key: Optional[bytes] = None
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            name, sep, value = line.partition("=")
            if not sep or name.strip().startswith("#"):
                continue
            if name.strip() == "key_id":
                key_id = int(value.strip())
            elif name.strip() == "key":
                key = bytes.fromhex(value.strip())
        if key_id is None or key is None:
            raise ValueError(f"{path}: key_id and key are required")
        return cls(key_id=key_id, key=key)


class TrunkSession:
    """Synchronous, leased (and optionally SL1-signed) session on a linepd trunk.

    One request runs at a time; a background thread sends lease heartbeats.
    """

    def __init__(
        self,
        host: str,
        trunk_port: int = DEFAULT_TRUNK_PORT,
        control_port: int = DEFAULT_CONTROL_PORT,
        credentials: Optional[Sl1Credentials] = None,
        timeout: float = 30.0,
        heartbeat_interval: float = DEFAULT_HEARTBEAT_INTERVAL,
    ) -> None:
        self.host = host
        self.trunk_port = trunk_port
        self.control_port = control_port
        self.credentials = credentials
        self.timeout = timeout
        self.heartbeat_interval = heartbeat_interval
        self._tcp: Optional[socket.socket] = None
        self._udp: Optional[socket.socket] = None
        self._binding: Optional[SessionBindEnvelope] = None
        self._control_seq = 0
        self._out_seq = 0
        self._in_seq = 0
        self._request_counter = 1000
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._heartbeat: Optional[threading.Thread] = None

    # -- lifecycle -----------------------------------------------------------
    def __enter__(self) -> "TrunkSession":
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def is_connected(self) -> bool:
        return self._tcp is not None and self._binding is not None

    def connect(self) -> "TrunkSession":
        if self.is_connected():
            return self
        identity = NodeEndpointIdentity(
            node_id=secrets.randbits(62) | 1, runtime_id=CLIENT_RUNTIME_ID, endpoint_id=CLIENT_ENDPOINT_ID
        )
        epoch = secrets.randbits(31) + 1
        try:
            self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp.settimeout(min(self.timeout, 5.0))
            lease = self._lease(identity, epoch)
            self._binding = SessionBindEnvelope(identity=identity, control_epoch=epoch, lease_token=lease)
            self._tcp = socket.create_connection((self.host, self.trunk_port), timeout=self.timeout)
            self._tcp.settimeout(self.timeout)
            self._bind()
        except Exception:
            self.close()
            raise
        self._stop.clear()
        self._heartbeat = threading.Thread(target=self._heartbeat_loop, name="linep-trunk-heartbeat", daemon=True)
        self._heartbeat.start()
        return self

    def close(self) -> None:
        self._stop.set()
        if self._heartbeat is not None and self._heartbeat is not threading.current_thread():
            self._heartbeat.join(timeout=1.0)
        self._heartbeat = None
        for sock in (self._tcp, self._udp):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._tcp = self._udp = None
        self._binding = None

    # -- control plane -------------------------------------------------------
    def _datagram(self, message_type: ControlMessageType, lease_token: int = 0) -> bytes:
        self._control_seq += 1
        return encode_control_datagram(
            UdpControlDatagram(
                message_type=int(message_type),
                flags=_FLAG_TRUNK_READY,
                node_id=self._identity.node_id,
                runtime_id=self._identity.runtime_id,
                endpoint_id=self._identity.endpoint_id,
                control_seq=self._control_seq,
                control_epoch=self._epoch,
                availability=int(NodeAvailability.AVAILABLE),
                health=int(NodeHealth.HEALTHY),
                tcp_port=_CLIENT_TCP_PORT,
                lease_token=lease_token,
            )
        )

    def _lease(self, identity: NodeEndpointIdentity, epoch: int) -> int:
        assert self._udp is not None
        self._identity, self._epoch, self._control_seq = identity, epoch, 0
        target = (self.host, self.control_port)
        self._udp.sendto(self._datagram(ControlMessageType.NODE_HELLO), target)
        deadline = time.monotonic() + self._udp.gettimeout()
        while True:
            try:
                data, _ = self._udp.recvfrom(256)
            except socket.timeout:
                raise TrunkError("no INVITE from the control plane (host not allowed or linepd down)") from None
            invite = decode_control_datagram(data)
            if (
                invite is not None
                and invite.message_type == int(ControlMessageType.INVITE)
                and (invite.node_id, invite.runtime_id, invite.endpoint_id)
                == (identity.node_id, identity.runtime_id, identity.endpoint_id)
                and invite.control_epoch == epoch
                and invite.lease_token
            ):
                break
            if time.monotonic() > deadline:
                raise TrunkError("no matching INVITE from the control plane")
        self._udp.sendto(self._datagram(ControlMessageType.LEASE_ACK, invite.lease_token), target)
        # the LEASE_ACK (UDP) has to reach linepd before the SESSION_BIND (TCP)
        time.sleep(0.2)
        return invite.lease_token

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self.heartbeat_interval):
            udp, binding = self._udp, self._binding
            if udp is None or binding is None:
                return
            try:
                udp.sendto(
                    self._datagram(ControlMessageType.HEARTBEAT, binding.lease_token), (self.host, self.control_port)
                )
            except OSError:
                return

    # -- framing -------------------------------------------------------------
    def _recv_exact(self, n: int) -> bytes:
        assert self._tcp is not None
        buf = bytearray()
        while len(buf) < n:
            chunk = self._tcp.recv(n - len(buf))
            if not chunk:
                raise ConnectionResetError("trunk closed the connection")
            buf.extend(chunk)
        return bytes(buf)

    def _recv_raw(self) -> bytes:
        hdr_bytes = self._recv_exact(LINEP_V02_HEADER_SIZE)
        hdr = decode_header(hdr_bytes)
        if hdr is None:
            raise TrunkError("invalid frame header from the trunk")
        ext = LINEP_V02_AUTH_EXTENSION_SIZE if hdr.flags & LINEP_V02_FLAG_AUTHENTICATED else 0
        rest = self._recv_exact(ext + hdr.payload_len) if ext + hdr.payload_len else b""
        return hdr_bytes + rest

    def _send_frame(self, plain: bytes) -> None:
        assert self._tcp is not None and self._binding is not None
        if self.credentials is not None:
            self._out_seq += 1
            plain = sign_envelope(
                plain,
                self._binding,
                MessageDirection.INITIATOR_TO_RESPONDER,
                self._out_seq,
                self.credentials.key_id,
                self.credentials.key,
            )
        self._tcp.sendall(plain)

    def _recv_frame(self) -> bytes:
        """Next frame as a plain (unsigned) frame; verifies SL1 and auth_seq order."""
        raw = self._recv_raw()
        if not raw[7] & LINEP_V02_FLAG_AUTHENTICATED:
            if self.credentials is not None:
                # linepd answers auth failures it cannot sign (wrong key) unsigned
                raise self._error_from(raw, "unsigned frame on an SL1 session")
            return raw
        if self.credentials is None or self._binding is None:
            raise TrunkError("signed frame on a session without SL1 credentials")
        ok, auth_ext, payload, reason = verify_envelope(
            raw, self._binding, MessageDirection.RESPONDER_TO_INITIATOR, self.credentials.key
        )
        if not ok or auth_ext is None or payload is None:
            raise TrunkError(f"SL1 verification of a trunk frame failed: {reason}")
        if auth_ext.auth_seq <= self._in_seq:
            raise TrunkError(f"SL1 replay: auth_seq {auth_ext.auth_seq} after {self._in_seq}")
        self._in_seq = auth_ext.auth_seq
        return bytes([*raw[:7], raw[7] & ~LINEP_V02_FLAG_AUTHENTICATED]) + raw[8:LINEP_V02_HEADER_SIZE] + payload

    @staticmethod
    def _error_from(plain: bytes, fallback: str) -> TrunkError:
        evt = decode_event(plain)
        if evt is not None and evt.event_type == EventType.FAILED:
            return TrunkError(evt.error.message or fallback, evt.error.code)
        return TrunkError(fallback)

    def _bind(self) -> None:
        assert self._binding is not None
        self._out_seq = self._in_seq = 0
        self._send_frame(encode_session_bind(self._binding))
        if self.credentials is None:
            return  # unsigned trunks answer a valid bind silently
        confirmation = self._recv_frame()
        hdr = decode_header(confirmation)
        if hdr is None or hdr.envelope_type != int(EnvelopeType.SESSION_BIND):
            raise self._error_from(confirmation, "SESSION_BIND not confirmed")

    # -- requests ------------------------------------------------------------
    def _next_stream(self) -> StreamIdentity:
        self._request_counter += 1
        return StreamIdentity(request_id=self._request_counter, execution_id=self._request_counter * 10, output_id=0)

    def execute_stream(self, req: RequestEnvelope, auto_ack_window: bool = True) -> Iterator[EventEnvelope]:
        with self._lock:
            self.connect()
            try:
                self._send_frame(encode_request(req))
            except OSError:
                # the trunk dropped an idle session (restart, expired lease): bind anew once
                self.close()
                self.connect()
                self._send_frame(encode_request(req))
            cumulative_bytes = 0
            while True:
                evt = decode_event(self._recv_frame())
                if evt is None:
                    raise TrunkError("invalid event frame from the trunk")
                if evt.stream.is_connection_level():
                    # connection-level failure (lease, auth, routing): the trunk closes
                    self.close()
                    raise TrunkError(evt.error.message or "connection-level error", evt.error.code)
                if evt.stream.request_id != req.stream.request_id or evt.stream.execution_id != req.stream.execution_id:
                    raise TrunkError("stream identity mismatch in a trunk event")
                if auto_ack_window and evt.event_type in (EventType.CONTENT_DELTA, EventType.REASONING_DELTA):
                    cumulative_bytes += len(evt.payload.encode("utf-8"))
                    self._send_frame(
                        encode_control(
                            ControlEnvelope(
                                stream=evt.stream,
                                control_type=ControlType.WINDOW_UPDATE,
                                reason="ACK",
                                ack_offset_bytes=cumulative_bytes,
                            )
                        )
                    )
                yield evt
                if evt.event_type in (EventType.COMPLETED, EventType.FAILED, EventType.CANCELLED):
                    break

    def stream_chat(
        self,
        model: str,
        prompt: str,
        max_tokens: int = 512,
        temperature: float = 0.7,
        options: Optional[GenerationOptions] = None,
    ) -> Iterator[EventEnvelope]:
        req = RequestEnvelope(
            stream=self._next_stream(),
            profile=RuntimeProfile.CHAT,
            model_id=model,
            payload=prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            stream_requested=True,
            has_options=options is not None,
            options=options or GenerationOptions(),
        )
        yield from self.execute_stream(req)

    def embed(self, model: str, text: str) -> List[float]:
        """Embedding vector for ``text`` (e.g. ``model="task:embed-bge"``)."""
        req = RequestEnvelope(
            stream=self._next_stream(),
            profile=RuntimeProfile.EMBED,
            model_id=model,
            payload=text,
            max_tokens=0,
            temperature=0.0,
            stream_requested=False,
        )
        vector: Optional[List[float]] = None
        for evt in self.execute_stream(req, auto_ack_window=False):
            if evt.event_type == EventType.EMBEDDING_RESULT:
                vector = list(evt.embedding.vector)
            elif evt.event_type == EventType.FAILED:
                raise TrunkError(evt.error.message or "embedding failed", evt.error.code)
        if vector is None:
            raise TrunkError("no embedding result from the trunk")
        return vector


__all__ = ["TrunkSession", "Sl1Credentials", "TrunkError", "DEFAULT_TRUNK_PORT", "DEFAULT_CONTROL_PORT"]
