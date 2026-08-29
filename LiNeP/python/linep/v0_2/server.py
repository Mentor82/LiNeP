"""LiNeP V0.2 Deterministic Python Mock Runtime Server (TCP & UDP)."""

from __future__ import annotations

import math
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from linep.v0_2.constants import (
    LINEP_V02_MAGIC,
    LINEP_V02_HEADER_SIZE,
    LINEP_V02_UDP_DATAGRAM_SIZE,
    RuntimeProfile,
    EnvelopeType,
    EventType,
    ControlType,
    TerminalOutcome,
    ErrorCategory,
    EmbeddingNormalization,
    EmbeddingDistanceMetric,
    ControlMessageType,
)
from linep.v0_2.envelopes import (
    StreamIdentity,
    WireEnvelopeHeader,
    RequestEnvelope,
    EventEnvelope,
    ControlEnvelope,
    CapabilitiesEnvelope,
    CapabilitiesDescriptor,
    EmbeddingSpaceDescriptor,
    EmbeddingPayload,
    RuntimeErrorPayload,
    encode_event,
    decode_request,
    decode_control,
    encode_capabilities,
    decode_header,
)
from linep.v0_2.control_plane import (
    UdpControlDatagram,
    ControlPlaneRouter,
    NodeEndpointIdentity,
    encode_control_datagram,
    decode_control_datagram,
)


@dataclass
class MockServerConfig:
    model_id: str = "linep-python-mock-v02"
    delay_per_event_s: float = 0.002
    tokens_per_stream: int = 10
    enable_reasoning: bool = True
    snapshot_mode: bool = False
    multi_output_count: int = 1
    fail_after_n: int = -1
    duplicate_event: bool = False
    cancel_after_accept: bool = False
    embedding_space_id: str = "nomic-embed-v1.5"
    embedding_dimensions: int = 768


class LiNePMockServer:
    def __init__(self, config: Optional[MockServerConfig] = None) -> None:
        self.config = config or MockServerConfig()
        self.tcp_port = 0
        self.udp_port = 0
        self._tcp_sock: Optional[socket.socket] = None
        self._udp_sock: Optional[socket.socket] = None
        self._running = False
        self._tcp_thread: Optional[threading.Thread] = None
        self._udp_thread: Optional[threading.Thread] = None
        self._cancelled_streams: Set[StreamIdentity] = set()
        self._lock = threading.Lock()

    def start(self, tcp_port: int = 0, udp_port: int = 0) -> None:
        self.stop()
        self._running = True

        # 1. Start TCP Data Plane Server
        self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_sock.bind(("127.0.0.1", tcp_port))
        self._tcp_sock.listen(10)
        self.tcp_port = self._tcp_sock.getsockname()[1]

        self._tcp_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._tcp_thread.start()

        # 2. Start UDP Control Plane Responder if requested
        if udp_port > 0 or udp_port == 0:
            try:
                self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._udp_sock.bind(("127.0.0.1", udp_port))
                self.udp_port = self._udp_sock.getsockname()[1]
                self._udp_thread = threading.Thread(target=self._udp_loop, daemon=True)
                self._udp_thread.start()
            except Exception:
                pass

    def stop(self) -> None:
        self._running = False
        if self._tcp_sock is not None:
            try:
                # Connect to unblock accept()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                try:
                    s.connect(("127.0.0.1", self.tcp_port))
                    s.close()
                except Exception:
                    pass
                self._tcp_sock.close()
            except Exception:
                pass
            self._tcp_sock = None

        if self._udp_sock is not None:
            try:
                self._udp_sock.close()
            except Exception:
                pass
            self._udp_sock = None

        if self._tcp_thread is not None:
            self._tcp_thread.join(timeout=1.0)
            self._tcp_thread = None
        if self._udp_thread is not None:
            self._udp_thread.join(timeout=1.0)
            self._udp_thread = None

    def _accept_loop(self) -> None:
        while self._running and self._tcp_sock is not None:
            try:
                conn, _ = self._tcp_sock.accept()
                if not self._running:
                    conn.close()
                    break
                t = threading.Thread(target=self._client_handler, args=(conn,), daemon=True)
                t.start()
            except Exception:
                break

    def _client_handler(self, conn: socket.socket) -> None:
        conn.settimeout(None)
        try:
            while self._running:
                hdr_bytes = bytearray()
                while len(hdr_bytes) < LINEP_V02_HEADER_SIZE:
                    chunk = conn.recv(LINEP_V02_HEADER_SIZE - len(hdr_bytes))
                    if not chunk:
                        return
                    hdr_bytes.extend(chunk)

                hdr = decode_header(bytes(hdr_bytes))
                if (
                    hdr is None
                    or hdr.magic != LINEP_V02_MAGIC
                    or hdr.version_major != 0
                    or hdr.version_minor != 2
                ):
                    return  # Instantly disconnect upon protocol violation!

                payload_bytes = bytearray()
                while len(payload_bytes) < hdr.payload_len:
                    chunk = conn.recv(hdr.payload_len - len(payload_bytes))
                    if not chunk:
                        return
                    payload_bytes.extend(chunk)

                full_frame = bytes(hdr_bytes) + bytes(payload_bytes)

                if hdr.envelope_type == int(EnvelopeType.REQUEST):
                    req = decode_request(full_frame)
                    if req is not None:
                        t = threading.Thread(target=self._execute_stream, args=(conn, req), daemon=True)
                        t.start()
                    else:
                        return
                elif hdr.envelope_type == int(EnvelopeType.CONTROL):
                    ctrl = decode_control(full_frame)
                    if ctrl is not None and ctrl.control_type == ControlType.CANCEL:
                        with self._lock:
                            self._cancelled_streams.add(ctrl.stream)
                elif hdr.envelope_type == int(EnvelopeType.CAPABILITIES):
                    caps = CapabilitiesEnvelope(
                        descriptor=CapabilitiesDescriptor(
                            supported_profiles=[RuntimeProfile.GENERATE, RuntimeProfile.CHAT, RuntimeProfile.EMBED],
                            max_context_tokens=8192,
                            max_output_tokens=4096,
                            supports_streaming=True,
                            supports_cancellation=True,
                            supports_tool_calling=True,
                            supports_reasoning_deltas=self.config.enable_reasoning,
                            supported_models=[self.config.model_id],
                            supported_embedding_spaces=[
                                EmbeddingSpaceDescriptor(
                                    embedding_space_id=self.config.embedding_space_id,
                                    model_id=self.config.model_id,
                                    model_revision="v1.5",
                                    dimensions=self.config.embedding_dimensions,
                                    normalization=EmbeddingNormalization.L2,
                                    distance_metric=EmbeddingDistanceMetric.COSINE,
                                )
                            ],
                        )
                    )
                    conn.sendall(encode_capabilities(caps))
                else:
                    return  # Unknown envelope type
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass
        except Exception as e:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _execute_stream(self, conn: socket.socket, req: RequestEnvelope) -> None:
        outputs = max(1, self.config.multi_output_count)
        for out_idx in range(outputs):
            stream_id = StreamIdentity(req.stream.request_id, req.stream.execution_id, out_idx)
            self._execute_single_output(conn, req, stream_id)

    def _execute_single_output(
        self, conn: socket.socket, req: RequestEnvelope, stream_id: StreamIdentity
    ) -> None:
        seq = 1
        emitted_events = 0

        def check_cancel() -> bool:
            with self._lock:
                return stream_id in self._cancelled_streams

        def safe_send(evt: EventEnvelope) -> bool:
            try:
                conn.sendall(encode_event(evt))
                return True
            except Exception:
                return False

        if self.config.cancel_after_accept or check_cancel():
            cancel_evt = EventEnvelope(
                stream=stream_id,
                event_seq=seq,
                event_type=EventType.CANCELLED,
                payload="Cancelled by client",
                outcome=TerminalOutcome.CANCELLED,
                error=RuntimeErrorPayload(code=499, message="Client cancelled stream"),
            )
            safe_send(cancel_evt)
            return

        if req.profile == RuntimeProfile.EMBED:
            # Generate unit normalized embedding vector
            dims = self.config.embedding_dimensions
            vec = [math.sin(float(i + 1)) for i in range(dims)]
            norm = math.sqrt(sum(v * v for v in vec))
            vec = [v / norm for v in vec]

            emb_evt = EventEnvelope(
                stream=stream_id,
                event_seq=seq,
                event_type=EventType.EMBEDDING_RESULT,
                embedding=EmbeddingPayload(
                    space=EmbeddingSpaceDescriptor(
                        embedding_space_id=self.config.embedding_space_id,
                        model_id=self.config.model_id,
                        model_revision="v1.5",
                        dimensions=dims,
                        normalization=EmbeddingNormalization.L2,
                        distance_metric=EmbeddingDistanceMetric.COSINE,
                    ),
                    vector=vec,
                ),
            )
            if not safe_send(emb_evt):
                return
            seq += 1

            term_evt = EventEnvelope(
                stream=stream_id,
                event_seq=seq,
                event_type=EventType.COMPLETED,
                payload="Embedding completed",
                outcome=TerminalOutcome.COMPLETED,
                error=RuntimeErrorPayload(code=200),
            )
            safe_send(term_evt)
            return

        # Chat / Generate:
        if self.config.enable_reasoning:
            for r_chunk in ["Analyzing request...", "Formulating LiNeP response..."]:
                if check_cancel():
                    cancel_evt = EventEnvelope(
                        stream=stream_id,
                        event_seq=seq,
                        event_type=EventType.CANCELLED,
                        payload="Cancelled by client",
                        outcome=TerminalOutcome.CANCELLED,
                        error=RuntimeErrorPayload(code=499),
                    )
                    safe_send(cancel_evt)
                    return

                r_evt = EventEnvelope(
                    stream=stream_id,
                    event_seq=seq,
                    event_type=EventType.REASONING_DELTA,
                    payload=r_chunk,
                )
                if not safe_send(r_evt):
                    return
                seq += 1
                time.sleep(self.config.delay_per_event_s)

        accumulated = ""
        for i in range(1, self.config.tokens_per_stream + 1):
            if check_cancel():
                cancel_evt = EventEnvelope(
                    stream=stream_id,
                    event_seq=seq,
                    event_type=EventType.CANCELLED,
                    payload="Cancelled by client",
                    outcome=TerminalOutcome.CANCELLED,
                    error=RuntimeErrorPayload(code=499),
                )
                safe_send(cancel_evt)
                return

            delta = f"Token_{i} "
            accumulated += delta
            ev_type = EventType.CONTENT_SNAPSHOT if self.config.snapshot_mode else EventType.CONTENT_DELTA
            payload_to_send = accumulated if self.config.snapshot_mode else delta

            c_evt = EventEnvelope(
                stream=stream_id,
                event_seq=seq,
                event_type=ev_type,
                payload=payload_to_send,
            )
            if not safe_send(c_evt):
                return
            seq += 1
            emitted_events += 1

            if self.config.fail_after_n >= 0 and emitted_events >= self.config.fail_after_n:
                fail_evt = EventEnvelope(
                    stream=stream_id,
                    event_seq=seq,
                    event_type=EventType.FAILED,
                    payload="Forced mock failure",
                    outcome=TerminalOutcome.FAILED,
                    error=RuntimeErrorPayload(code=500, message="Mock error injected"),
                )
                safe_send(fail_evt)
                return

            time.sleep(self.config.delay_per_event_s)

        term_evt = EventEnvelope(
            stream=stream_id,
            event_seq=seq,
            event_type=EventType.COMPLETED,
            payload="Generation completed",
            outcome=TerminalOutcome.COMPLETED,
            error=RuntimeErrorPayload(code=200),
        )
        safe_send(term_evt)

    def _udp_loop(self) -> None:
        router = ControlPlaneRouter()
        lease_counter = 0x500060007000

        while self._running and self._udp_sock is not None:
            try:
                data, addr = self._udp_sock.recvfrom(LINEP_V02_UDP_DATAGRAM_SIZE)
                dgram = decode_control_datagram(data)
                if dgram is None:
                    continue

                now_us = int(time.time() * 1_000_000)
                router.ingest_datagram(dgram, now_us)

                if dgram.message_type == int(ControlMessageType.NODE_HELLO):
                    lease_counter += 1
                    id = NodeEndpointIdentity(dgram.node_id, dgram.runtime_id, dgram.endpoint_id)
                    inv = router.issue_invite(id, lease_counter)
                    if inv is not None:
                        self._udp_sock.sendto(encode_control_datagram(inv), addr)
            except Exception:
                break
