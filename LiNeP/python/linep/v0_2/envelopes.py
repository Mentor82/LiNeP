"""LiNeP V0.2 Canonical TCP Data Plane Envelopes and Encoders/Decoders."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional

from linep.v0_2.constants import (
    LINEP_V02_MAGIC,
    LINEP_V02_VERSION_MAJOR,
    LINEP_V02_VERSION_MINOR,
    LINEP_V02_HEADER_SIZE,
    LINEP_V02_MAX_EMBEDDING_DIMS,
    RuntimeProfile,
    EnvelopeType,
    EventType,
    ControlType,
    TerminalOutcome,
    ErrorCategory,
    EmbeddingNormalization,
    EmbeddingDistanceMetric,
)


class BufferWriter:
    def __init__(self) -> None:
        self._buf = bytearray()

    def write_u8(self, val: int) -> None:
        self._buf.append(val & 0xFF)

    def write_u16(self, val: int) -> None:
        self._buf.extend(struct.pack("<H", val & 0xFFFF))

    def write_u32(self, val: int) -> None:
        self._buf.extend(struct.pack("<I", val & 0xFFFFFFFF))

    def write_u64(self, val: int) -> None:
        self._buf.extend(struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF))

    def write_float(self, val: float) -> None:
        self._buf.extend(struct.pack("<f", float(val)))

    def write_string_u16(self, s: str) -> None:
        raw = s.encode("utf-8")
        if len(raw) > 0xFFFF:
            raise ValueError("String exceeds 64KB uint16 limit")
        self.write_u16(len(raw))
        self._buf.extend(raw)

    def write_string_u32(self, s: str) -> None:
        raw = s.encode("utf-8")
        if len(raw) > 0xFFFFFFFF:
            raise ValueError("String exceeds uint32 limit")
        self.write_u32(len(raw))
        self._buf.extend(raw)

    def to_bytes(self) -> bytes:
        return bytes(self._buf)


class BufferReader:
    def __init__(self, data: bytes) -> None:
        self._data = memoryview(data)
        self._offset = 0

    def remaining(self) -> int:
        return len(self._data) - self._offset

    def has_remaining(self, n: int) -> bool:
        return (self._offset + n) <= len(self._data)

    def read_u8(self) -> int:
        if not self.has_remaining(1):
            raise ValueError("Buffer underflow reading uint8")
        val = self._data[self._offset]
        self._offset += 1
        return val

    def read_u16(self) -> int:
        if not self.has_remaining(2):
            raise ValueError("Buffer underflow reading uint16")
        val = struct.unpack_from("<H", self._data, self._offset)[0]
        self._offset += 2
        return val

    def read_u32(self) -> int:
        if not self.has_remaining(4):
            raise ValueError("Buffer underflow reading uint32")
        val = struct.unpack_from("<I", self._data, self._offset)[0]
        self._offset += 4
        return val

    def read_u64(self) -> int:
        if not self.has_remaining(8):
            raise ValueError("Buffer underflow reading uint64")
        val = struct.unpack_from("<Q", self._data, self._offset)[0]
        self._offset += 8
        return val

    def read_float(self) -> float:
        if not self.has_remaining(4):
            raise ValueError("Buffer underflow reading float")
        val = struct.unpack_from("<f", self._data, self._offset)[0]
        self._offset += 4
        return val

    def read_string_u16(self) -> str:
        length = self.read_u16()
        if not self.has_remaining(length):
            raise ValueError(f"Buffer underflow reading string of length {length}")
        raw = bytes(self._data[self._offset : self._offset + length])
        self._offset += length
        return raw.decode("utf-8", errors="replace")

    def read_string_u32(self) -> str:
        length = self.read_u32()
        if not self.has_remaining(length):
            raise ValueError(f"Buffer underflow reading string of length {length}")
        raw = bytes(self._data[self._offset : self._offset + length])
        self._offset += length
        return raw.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class StreamIdentity:
    request_id: int = 0
    execution_id: int = 0
    output_id: int = 0

    def is_valid(self) -> bool:
        return self.request_id > 0 and self.execution_id > 0


@dataclass
class WireEnvelopeHeader:
    magic: int = LINEP_V02_MAGIC
    version_major: int = LINEP_V02_VERSION_MAJOR
    version_minor: int = LINEP_V02_VERSION_MINOR
    envelope_type: int = 0
    flags: int = 0
    request_id: int = 0
    execution_id: int = 0
    output_id: int = 0
    payload_len: int = 0


@dataclass
class RequestEnvelope:
    stream: StreamIdentity = field(default_factory=StreamIdentity)
    profile: RuntimeProfile = RuntimeProfile.CHAT
    model_id: str = ""
    payload: str = ""
    max_tokens: int = 512
    temperature: float = 0.7
    stream_requested: bool = True

    def is_valid(self) -> bool:
        return self.stream.is_valid() and bool(self.model_id) and self.profile != RuntimeProfile.UNSPECIFIED


@dataclass
class RuntimeErrorPayload:
    category: ErrorCategory = ErrorCategory.NONE
    code: int = 0
    message: str = ""
    backend_diagnostic: str = ""


@dataclass
class EmbeddingSpaceDescriptor:
    embedding_space_id: str = ""
    model_id: str = ""
    model_revision: str = ""
    dimensions: int = 0
    normalization: EmbeddingNormalization = EmbeddingNormalization.NONE
    distance_metric: EmbeddingDistanceMetric = EmbeddingDistanceMetric.UNSPECIFIED


@dataclass
class EmbeddingPayload:
    space: EmbeddingSpaceDescriptor = field(default_factory=EmbeddingSpaceDescriptor)
    vector: List[float] = field(default_factory=list)


@dataclass
class EventEnvelope:
    stream: StreamIdentity = field(default_factory=StreamIdentity)
    event_seq: int = 1
    event_type: EventType = EventType.CONTENT_DELTA
    payload: str = ""
    outcome: TerminalOutcome = TerminalOutcome.UNSPECIFIED
    error: RuntimeErrorPayload = field(default_factory=RuntimeErrorPayload)
    embedding: EmbeddingPayload = field(default_factory=EmbeddingPayload)
    timestamp_us: int = 0

    def is_valid(self) -> bool:
        if not self.stream.is_valid() or self.event_seq == 0:
            return False
        if self.event_type == EventType.EMBEDDING_RESULT:
            if not self.embedding.space.embedding_space_id or self.embedding.space.dimensions == 0:
                return False
            if len(self.embedding.vector) != self.embedding.space.dimensions:
                return False
        return True


@dataclass
class ControlEnvelope:
    stream: StreamIdentity = field(default_factory=StreamIdentity)
    control_type: ControlType = ControlType.CANCEL
    reason: str = ""
    ack_offset_bytes: int = 0

    def is_valid(self) -> bool:
        return self.stream.is_valid()


@dataclass
class CapabilitiesDescriptor:
    supported_profiles: List[RuntimeProfile] = field(default_factory=list)
    max_context_tokens: int = 8192
    max_output_tokens: int = 4096
    supports_streaming: bool = True
    supports_cancellation: bool = True
    supports_tool_calling: bool = True
    supports_reasoning_deltas: bool = True
    supported_models: List[str] = field(default_factory=list)
    supported_embedding_spaces: List[EmbeddingSpaceDescriptor] = field(default_factory=list)


@dataclass
class CapabilitiesEnvelope:
    descriptor: CapabilitiesDescriptor = field(default_factory=CapabilitiesDescriptor)


def encode_header(hdr: WireEnvelopeHeader) -> bytes:
    w = BufferWriter()
    w.write_u32(hdr.magic)
    w.write_u8(hdr.version_major)
    w.write_u8(hdr.version_minor)
    w.write_u8(hdr.envelope_type)
    w.write_u8(hdr.flags)
    w.write_u64(hdr.request_id)
    w.write_u64(hdr.execution_id)
    w.write_u32(hdr.output_id)
    w.write_u32(hdr.payload_len)
    return w.to_bytes()


def decode_header(data: bytes) -> Optional[WireEnvelopeHeader]:
    if len(data) < LINEP_V02_HEADER_SIZE:
        return None
    r = BufferReader(data[:LINEP_V02_HEADER_SIZE])
    try:
        magic = r.read_u32()
        v_maj = r.read_u8()
        v_min = r.read_u8()
        env_type = r.read_u8()
        flags = r.read_u8()
        req_id = r.read_u64()
        exec_id = r.read_u64()
        out_id = r.read_u32()
        pay_len = r.read_u32()
        return WireEnvelopeHeader(
            magic=magic,
            version_major=v_maj,
            version_minor=v_min,
            envelope_type=env_type,
            flags=flags,
            request_id=req_id,
            execution_id=exec_id,
            output_id=out_id,
            payload_len=pay_len,
        )
    except Exception:
        return None


def peek_envelope_type(data: bytes) -> EnvelopeType:
    hdr = decode_header(data)
    if hdr is None or hdr.magic != LINEP_V02_MAGIC or hdr.version_major != LINEP_V02_VERSION_MAJOR:
        return EnvelopeType(0)
    try:
        return EnvelopeType(hdr.envelope_type)
    except ValueError:
        return EnvelopeType(0)


def encode_request(req: RequestEnvelope) -> bytes:
    if not req.is_valid():
        raise ValueError("Invalid RequestEnvelope")
    pw = BufferWriter()
    pw.write_u8(int(req.profile))
    pw.write_string_u16(req.model_id)
    pw.write_string_u32(req.payload)
    pw.write_u32(req.max_tokens)
    pw.write_float(req.temperature)
    pw.write_u8(1 if req.stream_requested else 0)
    payload = pw.to_bytes()

    hdr = WireEnvelopeHeader(
        magic=LINEP_V02_MAGIC,
        version_major=LINEP_V02_VERSION_MAJOR,
        version_minor=LINEP_V02_VERSION_MINOR,
        envelope_type=int(EnvelopeType.REQUEST),
        flags=0,
        request_id=req.stream.request_id,
        execution_id=req.stream.execution_id,
        output_id=req.stream.output_id,
        payload_len=len(payload),
    )
    return encode_header(hdr) + payload


def decode_request(data: bytes) -> Optional[RequestEnvelope]:
    hdr = decode_header(data)
    if (
        hdr is None
        or hdr.magic != LINEP_V02_MAGIC
        or hdr.version_major != LINEP_V02_VERSION_MAJOR
        or hdr.envelope_type != int(EnvelopeType.REQUEST)
    ):
        return None
    if len(data) < (LINEP_V02_HEADER_SIZE + hdr.payload_len):
        return None

    r = BufferReader(data[LINEP_V02_HEADER_SIZE : LINEP_V02_HEADER_SIZE + hdr.payload_len])
    try:
        prof = RuntimeProfile(r.read_u8())
        model_id = r.read_string_u16()
        payload = r.read_string_u32()
        max_tokens = r.read_u32()
        temp = r.read_float()
        stream_req = bool(r.read_u8())
        if r.remaining() != 0:
            return None  # Reject trailing garbage
        req = RequestEnvelope(
            stream=StreamIdentity(hdr.request_id, hdr.execution_id, hdr.output_id),
            profile=prof,
            model_id=model_id,
            payload=payload,
            max_tokens=max_tokens,
            temperature=temp,
            stream_requested=stream_req,
        )
        return req if req.is_valid() else None
    except Exception:
        return None


def encode_event(evt: EventEnvelope) -> bytes:
    if not evt.is_valid():
        raise ValueError("Invalid EventEnvelope")
    pw = BufferWriter()
    pw.write_u64(evt.event_seq)
    pw.write_u8(int(evt.event_type))
    pw.write_u8(int(evt.outcome))
    pw.write_u8(int(evt.error.category))
    pw.write_u32(evt.error.code)
    pw.write_string_u16(evt.error.message)
    pw.write_string_u16(evt.error.backend_diagnostic)
    pw.write_string_u32(evt.payload)
    pw.write_u64(evt.timestamp_us)

    if evt.event_type == EventType.EMBEDDING_RESULT:
        sp = evt.embedding.space
        pw.write_string_u16(sp.embedding_space_id)
        pw.write_string_u16(sp.model_id)
        pw.write_string_u16(sp.model_revision)
        pw.write_u32(sp.dimensions)
        pw.write_u8(int(sp.normalization))
        pw.write_u8(int(sp.distance_metric))
        pw.write_u32(len(evt.embedding.vector))
        for v in evt.embedding.vector:
            pw.write_float(v)

    payload = pw.to_bytes()
    hdr = WireEnvelopeHeader(
        magic=LINEP_V02_MAGIC,
        version_major=LINEP_V02_VERSION_MAJOR,
        version_minor=LINEP_V02_VERSION_MINOR,
        envelope_type=int(EnvelopeType.EVENT),
        flags=0,
        request_id=evt.stream.request_id,
        execution_id=evt.stream.execution_id,
        output_id=evt.stream.output_id,
        payload_len=len(payload),
    )
    return encode_header(hdr) + payload


def decode_event(data: bytes) -> Optional[EventEnvelope]:
    hdr = decode_header(data)
    if (
        hdr is None
        or hdr.magic != LINEP_V02_MAGIC
        or hdr.version_major != LINEP_V02_VERSION_MAJOR
        or hdr.envelope_type != int(EnvelopeType.EVENT)
    ):
        return None
    if len(data) < (LINEP_V02_HEADER_SIZE + hdr.payload_len):
        return None

    r = BufferReader(data[LINEP_V02_HEADER_SIZE : LINEP_V02_HEADER_SIZE + hdr.payload_len])
    try:
        seq = r.read_u64()
        ev_type = EventType(r.read_u8())
        outcome = TerminalOutcome(r.read_u8())
        err_cat = ErrorCategory(r.read_u8())
        err_code = r.read_u32()
        err_msg = r.read_string_u16()
        err_diag = r.read_string_u16()
        payload = r.read_string_u32()
        ts = r.read_u64()

        embedding = EmbeddingPayload()
        if ev_type == EventType.EMBEDDING_RESULT:
            space_id = r.read_string_u16()
            model_id = r.read_string_u16()
            model_rev = r.read_string_u16()
            dims = r.read_u32()
            norm = EmbeddingNormalization(r.read_u8())
            dist = EmbeddingDistanceMetric(r.read_u8())
            vec_count = r.read_u32()

            if vec_count > LINEP_V02_MAX_EMBEDDING_DIMS or vec_count != dims:
                return None
            if vec_count > (r.remaining() // 4):
                return None

            vector = [r.read_float() for _ in range(vec_count)]
            embedding = EmbeddingPayload(
                space=EmbeddingSpaceDescriptor(
                    embedding_space_id=space_id,
                    model_id=model_id,
                    model_revision=model_rev,
                    dimensions=dims,
                    normalization=norm,
                    distance_metric=dist,
                ),
                vector=vector,
            )

        if r.remaining() != 0:
            return None  # Reject trailing garbage

        evt = EventEnvelope(
            stream=StreamIdentity(hdr.request_id, hdr.execution_id, hdr.output_id),
            event_seq=seq,
            event_type=ev_type,
            payload=payload,
            outcome=outcome,
            error=RuntimeErrorPayload(
                category=err_cat,
                code=err_code,
                message=err_msg,
                backend_diagnostic=err_diag,
            ),
            embedding=embedding,
            timestamp_us=ts,
        )
        return evt if evt.is_valid() else None
    except Exception:
        return None


def encode_control(ctrl: ControlEnvelope) -> bytes:
    if not ctrl.is_valid():
        raise ValueError("Invalid ControlEnvelope")
    pw = BufferWriter()
    pw.write_u8(int(ctrl.control_type))
    pw.write_string_u16(ctrl.reason)
    pw.write_u64(ctrl.ack_offset_bytes)
    payload = pw.to_bytes()

    hdr = WireEnvelopeHeader(
        magic=LINEP_V02_MAGIC,
        version_major=LINEP_V02_VERSION_MAJOR,
        version_minor=LINEP_V02_VERSION_MINOR,
        envelope_type=int(EnvelopeType.CONTROL),
        flags=0,
        request_id=ctrl.stream.request_id,
        execution_id=ctrl.stream.execution_id,
        output_id=ctrl.stream.output_id,
        payload_len=len(payload),
    )
    return encode_header(hdr) + payload


def decode_control(data: bytes) -> Optional[ControlEnvelope]:
    hdr = decode_header(data)
    if (
        hdr is None
        or hdr.magic != LINEP_V02_MAGIC
        or hdr.version_major != LINEP_V02_VERSION_MAJOR
        or hdr.envelope_type != int(EnvelopeType.CONTROL)
    ):
        return None
    if len(data) < (LINEP_V02_HEADER_SIZE + hdr.payload_len):
        return None

    r = BufferReader(data[LINEP_V02_HEADER_SIZE : LINEP_V02_HEADER_SIZE + hdr.payload_len])
    try:
        ctrl_type = ControlType(r.read_u8())
        reason = r.read_string_u16()
        ack_offset = r.read_u64()
        if r.remaining() != 0:
            return None
        ctrl = ControlEnvelope(
            stream=StreamIdentity(hdr.request_id, hdr.execution_id, hdr.output_id),
            control_type=ctrl_type,
            reason=reason,
            ack_offset_bytes=ack_offset,
        )
        return ctrl if ctrl.is_valid() else None
    except Exception:
        return None


def encode_capabilities(caps: CapabilitiesEnvelope) -> bytes:
    pw = BufferWriter()
    desc = caps.descriptor
    pw.write_u16(len(desc.supported_profiles))
    for p in desc.supported_profiles:
        pw.write_u8(int(p))

    pw.write_u32(desc.max_context_tokens)
    pw.write_u32(desc.max_output_tokens)
    pw.write_u8(1 if desc.supports_streaming else 0)
    pw.write_u8(1 if desc.supports_cancellation else 0)
    pw.write_u8(1 if desc.supports_tool_calling else 0)
    pw.write_u8(1 if desc.supports_reasoning_deltas else 0)

    pw.write_u16(len(desc.supported_models))
    for m in desc.supported_models:
        pw.write_string_u16(m)

    pw.write_u16(len(desc.supported_embedding_spaces))
    for sp in desc.supported_embedding_spaces:
        pw.write_string_u16(sp.embedding_space_id)
        pw.write_string_u16(sp.model_id)
        pw.write_string_u16(sp.model_revision)
        pw.write_u32(sp.dimensions)
        pw.write_u8(int(sp.normalization))
        pw.write_u8(int(sp.distance_metric))

    payload = pw.to_bytes()
    hdr = WireEnvelopeHeader(
        magic=LINEP_V02_MAGIC,
        version_major=LINEP_V02_VERSION_MAJOR,
        version_minor=LINEP_V02_VERSION_MINOR,
        envelope_type=int(EnvelopeType.CAPABILITIES),
        flags=0,
        request_id=0,
        execution_id=0,
        output_id=0,
        payload_len=len(payload),
    )
    return encode_header(hdr) + payload


def decode_capabilities(data: bytes) -> Optional[CapabilitiesEnvelope]:
    hdr = decode_header(data)
    if (
        hdr is None
        or hdr.magic != LINEP_V02_MAGIC
        or hdr.version_major != LINEP_V02_VERSION_MAJOR
        or hdr.envelope_type != int(EnvelopeType.CAPABILITIES)
    ):
        return None
    if len(data) < (LINEP_V02_HEADER_SIZE + hdr.payload_len):
        return None

    r = BufferReader(data[LINEP_V02_HEADER_SIZE : LINEP_V02_HEADER_SIZE + hdr.payload_len])
    try:
        prof_count = r.read_u16()
        profiles = [RuntimeProfile(r.read_u8()) for _ in range(prof_count)]
        max_ctx = r.read_u32()
        max_out = r.read_u32()
        s_stream = bool(r.read_u8())
        s_cancel = bool(r.read_u8())
        s_tool = bool(r.read_u8())
        s_reason = bool(r.read_u8())

        mod_count = r.read_u16()
        models = [r.read_string_u16() for _ in range(mod_count)]

        sp_count = r.read_u16()
        spaces = []
        for _ in range(sp_count):
            spaces.append(
                EmbeddingSpaceDescriptor(
                    embedding_space_id=r.read_string_u16(),
                    model_id=r.read_string_u16(),
                    model_revision=r.read_string_u16(),
                    dimensions=r.read_u32(),
                    normalization=EmbeddingNormalization(r.read_u8()),
                    distance_metric=EmbeddingDistanceMetric(r.read_u8()),
                )
            )

        if r.remaining() != 0:
            return None

        desc = CapabilitiesDescriptor(
            supported_profiles=profiles,
            max_context_tokens=max_ctx,
            max_output_tokens=max_out,
            supports_streaming=s_stream,
            supports_cancellation=s_cancel,
            supports_tool_calling=s_tool,
            supports_reasoning_deltas=s_reason,
            supported_models=models,
            supported_embedding_spaces=spaces,
        )
        return CapabilitiesEnvelope(descriptor=desc)
    except Exception:
        return None
