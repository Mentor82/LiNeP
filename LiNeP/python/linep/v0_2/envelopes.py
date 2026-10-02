"""LiNeP V0.2 Canonical TCP Data Plane Envelopes and Encoders/Decoders."""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from linep.v0_2.constants import (
    LINEP_V02_MAGIC,
    LINEP_V02_VERSION_MAJOR,
    LINEP_V02_VERSION_MINOR,
    LINEP_V02_HEADER_SIZE,
    LINEP_V02_SESSION_BIND_PAYLOAD_SIZE,
    LINEP_V02_FLAG_AUTHENTICATED,
    LINEP_V02_AUTH_EXTENSION_SIZE,
    LINEP_V02_MAX_EMBEDDING_DIMS,
    LINEP_V02_MAX_REGISTRATION_BYTES,
    LINEP_V02_MAX_VISION_IMAGE_BYTES,
    LINEP_V02_MAX_VISION_DETECTIONS,
    MessageDirection,
    RuntimeProfile,
    EnvelopeType,
    RegistrationOperation,
    EventType,
    VisionTask,
    ControlType,
    TerminalOutcome,
    ErrorCategory,
    EmbeddingNormalization,
    EmbeddingDistanceMetric,
)
from linep.v0_2.control_plane import NodeEndpointIdentity
from linep.v0_2.vision import (
    VisionBox2D,
    VisionDetection,
    VisionDetectResult,
    VisionResultPayload,
    VisionModelDescriptor,
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

    def write_i32(self, val: int) -> None:
        self._buf.extend(struct.pack("<i", int(val)))

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

    def read_i32(self) -> int:
        if not self.has_remaining(4):
            raise ValueError("Buffer underflow reading int32")
        val = struct.unpack_from("<i", self._data, self._offset)[0]
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

    def is_connection_level(self) -> bool:
        return self.request_id == 0 and self.execution_id == 0 and self.output_id == 0


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
class GenerationOptions:
    top_p: float = 0.9
    top_k: int = 40
    repeat_penalty: float = 1.0
    repeat_last_n: int = 64
    seed: int = 0
    presence_penalty: float = 0.0
    frequency_penalty: float = 0.0
    stop_sequences: List[str] = field(default_factory=list)
    extra_options: List[Tuple[str, str]] = field(default_factory=list)

    def is_default(self) -> bool:
        return (
            self.top_p == 0.9 and
            self.top_k == 40 and
            self.repeat_penalty == 1.0 and
            self.repeat_last_n == 64 and
            self.seed == 0 and
            self.presence_penalty == 0.0 and
            self.frequency_penalty == 0.0 and
            not self.stop_sequences and
            not self.extra_options
        )


@dataclass
class ChatMessage:
    role: str = ""  # "system", "user", "assistant"
    content: str = ""


@dataclass
class StructuredChatPayload:
    messages: List[ChatMessage] = field(default_factory=list)


@dataclass
class RequestEnvelope:
    stream: StreamIdentity = field(default_factory=StreamIdentity)
    profile: RuntimeProfile = RuntimeProfile.CHAT
    model_id: str = ""
    payload: str = ""
    max_tokens: int = 512
    temperature: float = 0.7
    stream_requested: bool = True
    has_options: bool = False
    options: GenerationOptions = field(default_factory=GenerationOptions)

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
    vision: VisionResultPayload = field(default_factory=VisionResultPayload)
    timestamp_us: int = 0

    def is_valid(self) -> bool:
        if not (self.stream.is_valid() or self.stream.is_connection_level()):
            return False
        if not self.stream.is_connection_level() and self.event_seq == 0:
            return False
        if self.event_type == EventType.EMBEDDING_RESULT:
            if not self.embedding.space.embedding_space_id or self.embedding.space.dimensions == 0:
                return False
            if len(self.embedding.vector) != self.embedding.space.dimensions:
                return False
        if self.event_type == EventType.VISION_RESULT:
            if not self.vision.is_valid():
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
class AuthExtension:
    auth_seq: int = 0
    key_id: int = 0
    reserved: int = 0
    mac: bytes = field(default_factory=lambda: bytes(16))

    def encode(self) -> bytes:
        return struct.pack("<IHH16s", self.auth_seq, self.key_id, self.reserved, self.mac)

    @classmethod
    def decode(cls, data: bytes) -> Optional["AuthExtension"]:
        if len(data) < LINEP_V02_AUTH_EXTENSION_SIZE:
            return None
        auth_seq, key_id, reserved, mac = struct.unpack_from("<IHH16s", data, 0)
        if reserved != 0:
            return None
        return cls(auth_seq=auth_seq, key_id=key_id, reserved=reserved, mac=mac)


@dataclass
class SessionBindEnvelope:
    identity: NodeEndpointIdentity = field(default_factory=NodeEndpointIdentity)
    control_epoch: int = 0
    lease_token: int = 0
    sl1_requested: bool = False
    key_id: int = 0
    auth_ext: Optional[AuthExtension] = None

    def is_valid(self) -> bool:
        return self.identity.is_valid() and self.lease_token != 0


@dataclass
class CapabilitiesDescriptor:
    supported_profiles: List[RuntimeProfile] = field(default_factory=list)
    max_context_tokens: int = 0
    max_output_tokens: int = 0
    supports_streaming: bool = True
    supports_cancellation: bool = True
    supports_tool_calling: bool = False
    supports_reasoning_deltas: bool = False
    supports_structured_messages: bool = False
    supported_models: List[str] = field(default_factory=list)
    supported_embedding_spaces: List[EmbeddingSpaceDescriptor] = field(default_factory=list)
    supported_vision_models: List[VisionModelDescriptor] = field(default_factory=list)

    def supports_profile(self, profile: RuntimeProfile) -> bool:
        return profile in self.supported_profiles

    def supports_vision_model(self, model_id: str, task: VisionTask = VisionTask.DETECT) -> bool:
        for vm in self.supported_vision_models:
            if vm.model_id == model_id and (task == VisionTask.UNSPECIFIED or vm.task == task):
                return True
        return False


@dataclass
class CapabilitiesEnvelope:
    descriptor: CapabilitiesDescriptor = field(default_factory=CapabilitiesDescriptor)


@dataclass
class RegistrationExtension:
    tag: int = 0  # >= 0x8000: optional, preserved; unknown mandatory tags fail
    value: bytes = field(default_factory=bytes)


@dataclass
class RuntimeRegistrationEnvelope:
    operation: RegistrationOperation = RegistrationOperation.REGISTER_RUNTIME
    concurrent_slots: int = 0
    status_code: int = 0  # result: 200 accepted or 4xx/5xx rejected
    reason: str = ""
    capabilities: CapabilitiesEnvelope = field(default_factory=CapabilitiesEnvelope)
    extensions: List[RegistrationExtension] = field(default_factory=list)


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

    if req.has_options:
        flags = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40
        pw.write_u32(flags)
        pw.write_float(req.options.top_p)
        pw.write_i32(req.options.top_k)
        pw.write_float(req.options.repeat_penalty)
        pw.write_i32(req.options.repeat_last_n)
        pw.write_u64(req.options.seed)
        pw.write_float(req.options.presence_penalty)
        pw.write_float(req.options.frequency_penalty)

        if len(req.options.stop_sequences) > 0xFFFF:
            raise ValueError("stop_sequences exceeds uint16 limit")
        pw.write_u16(len(req.options.stop_sequences))
        for stop in req.options.stop_sequences:
            pw.write_string_u16(stop)

        if len(req.options.extra_options) > 0xFFFF:
            raise ValueError("extra_options exceeds uint16 limit")
        sorted_extras = sorted(req.options.extra_options, key=lambda x: x[0])
        for i in range(1, len(sorted_extras)):
            if sorted_extras[i][0] == sorted_extras[i - 1][0]:
                raise ValueError(f"Duplicate extra_options key: {sorted_extras[i][0]}")
        pw.write_u16(len(sorted_extras))
        for k, v in sorted_extras:
            pw.write_string_u16(k)
            pw.write_string_u16(v)

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

        if r.remaining() == 0:
            # Baseline V0.2 request without options
            req = RequestEnvelope(
                stream=StreamIdentity(hdr.request_id, hdr.execution_id, hdr.output_id),
                profile=prof,
                model_id=model_id,
                payload=payload,
                max_tokens=max_tokens,
                temperature=temp,
                stream_requested=stream_req,
                has_options=False,
                options=GenerationOptions(),
            )
            return req if req.is_valid() else None

        # Decode generation options
        flags = r.read_u32()
        top_p = r.read_float()
        top_k = r.read_i32()
        repeat_penalty = r.read_float()
        repeat_last_n = r.read_i32()
        seed = r.read_u64()
        presence_penalty = r.read_float()
        frequency_penalty = r.read_float()

        stop_count = r.read_u16()
        stop_sequences = [r.read_string_u16() for _ in range(stop_count)]

        extra_count = r.read_u16()
        extra_options: List[Tuple[str, str]] = []
        prev_key = ""
        for i in range(extra_count):
            k = r.read_string_u16()
            v = r.read_string_u16()
            if i > 0 and k <= prev_key:
                return None  # Non-canonical / unsorted / duplicate keys rejected!
            prev_key = k
            extra_options.append((k, v))

        if r.remaining() != 0:
            return None  # Strict canonical framing: reject trailing garbage

        opts = GenerationOptions(
            top_p=top_p,
            top_k=top_k,
            repeat_penalty=repeat_penalty,
            repeat_last_n=repeat_last_n,
            seed=seed,
            presence_penalty=presence_penalty,
            frequency_penalty=frequency_penalty,
            stop_sequences=stop_sequences,
            extra_options=extra_options,
        )
        req = RequestEnvelope(
            stream=StreamIdentity(hdr.request_id, hdr.execution_id, hdr.output_id),
            profile=prof,
            model_id=model_id,
            payload=payload,
            max_tokens=max_tokens,
            temperature=temp,
            stream_requested=stream_req,
            has_options=True,
            options=opts,
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

    elif evt.event_type == EventType.VISION_RESULT:
        v = evt.vision
        pw.write_u8(int(v.task))
        pw.write_string_u16(v.model_id)
        pw.write_string_u16(v.model_revision)
        if v.task == VisionTask.DETECT:
            pw.write_string_u16(v.detect.label_set_id)
            pw.write_u32(v.detect.original_width)
            pw.write_u32(v.detect.original_height)
            pw.write_u32(len(v.detect.detections))
            for d in v.detect.detections:
                pw.write_u32(d.class_id)
                pw.write_float(d.score)
                pw.write_float(d.box.x_min)
                pw.write_float(d.box.y_min)
                pw.write_float(d.box.x_max)
                pw.write_float(d.box.y_max)
                pw.write_string_u16(d.label)

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
        vision = VisionResultPayload()
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
        elif ev_type == EventType.VISION_RESULT:
            v_task = VisionTask(r.read_u8())
            v_model_id = r.read_string_u16()
            v_model_rev = r.read_string_u16()
            if v_task == VisionTask.DETECT:
                v_label_set = r.read_string_u16()
                v_w = r.read_u32()
                v_h = r.read_u32()
                det_count = r.read_u32()
                if det_count > LINEP_V02_MAX_VISION_DETECTIONS:
                    return None
                if det_count > (r.remaining() // 26):
                    return None
                dets = []
                for _ in range(det_count):
                    cid = r.read_u32()
                    score = r.read_float()
                    x_min = r.read_float()
                    y_min = r.read_float()
                    x_max = r.read_float()
                    y_max = r.read_float()
                    lbl = r.read_string_u16()
                    dets.append(VisionDetection(
                        class_id=cid,
                        label=lbl,
                        score=score,
                        box=VisionBox2D(x_min=x_min, y_min=y_min, x_max=x_max, y_max=y_max),
                    ))
                vision = VisionResultPayload(
                    task=v_task,
                    model_id=v_model_id,
                    model_revision=v_model_rev,
                    detect=VisionDetectResult(
                        label_set_id=v_label_set,
                        original_width=v_w,
                        original_height=v_h,
                        detections=dets,
                    ),
                )
            else:
                return None

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
            vision=vision,
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
    pw.write_u8(1 if desc.supports_structured_messages else 0)

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

    if desc.supported_vision_models:
        pw.write_u16(len(desc.supported_vision_models))
        for vm in desc.supported_vision_models:
            pw.write_string_u16(vm.model_id)
            pw.write_string_u16(vm.model_revision)
            pw.write_string_u16(vm.label_set_id)
            pw.write_u8(int(vm.task))
            pw.write_u32(vm.max_detections)
            pw.write_u16(len(vm.custom_labels))
            for lbl in vm.custom_labels:
                pw.write_string_u16(lbl)

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


def _decode_capabilities_payload(payload: bytes, five_bools: bool) -> Optional[CapabilitiesEnvelope]:
    try:
        r = BufferReader(payload)
        prof_count = r.read_u16()
        profiles = [RuntimeProfile(r.read_u8()) for _ in range(prof_count)]
        max_ctx = r.read_u32()
        max_out = r.read_u32()
        s_stream = bool(r.read_u8())
        s_cancel = bool(r.read_u8())
        s_tool = bool(r.read_u8())
        s_reason = bool(r.read_u8())
        if five_bools:
            s_struct_msg = bool(r.read_u8())
        else:
            s_struct_msg = False

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

        vision_models = []
        if r.remaining() > 0:
            vm_count = r.read_u16()
            for _ in range(vm_count):
                vm_id = r.read_string_u16()
                vm_rev = r.read_string_u16()
                v_lbl = r.read_string_u16()
                v_task = VisionTask(r.read_u8())
                v_max = r.read_u32()
                cl_count = r.read_u16()
                cl_labels = [r.read_string_u16() for _ in range(cl_count)]
                vision_models.append(
                    VisionModelDescriptor(
                        model_id=vm_id,
                        model_revision=vm_rev,
                        label_set_id=v_lbl,
                        task=v_task,
                        max_detections=v_max,
                        custom_labels=cl_labels,
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
            supports_structured_messages=s_struct_msg,
            supported_models=models,
            supported_embedding_spaces=spaces,
            supported_vision_models=vision_models,
        )
        return CapabilitiesEnvelope(descriptor=desc)
    except Exception:
        return None


def decode_capabilities(data: bytes) -> Optional[CapabilitiesEnvelope]:
    hdr = decode_header(data)
    if (
        hdr is None
        or hdr.magic != LINEP_V02_MAGIC
        or hdr.version_major != LINEP_V02_VERSION_MAJOR
        or hdr.envelope_type != int(EnvelopeType.CAPABILITIES)
    ):
        return None

    is_auth = (hdr.flags & LINEP_V02_FLAG_AUTHENTICATED) != 0
    auth_ext_len = LINEP_V02_AUTH_EXTENSION_SIZE if is_auth else 0

    if len(data) < (LINEP_V02_HEADER_SIZE + auth_ext_len + hdr.payload_len):
        return None

    payload = data[LINEP_V02_HEADER_SIZE + auth_ext_len : LINEP_V02_HEADER_SIZE + auth_ext_len + hdr.payload_len]

    # Issue #29: Dual layout decoding for backward compatibility.
    # Try post-#28 layout first (5 boolean flags: streaming, cancellation, tool_calling,
    # reasoning_deltas, structured_messages).
    caps = _decode_capabilities_payload(payload, five_bools=True)
    if caps is not None:
        return caps

    # Fall back to legacy pre-#28 layout (4 boolean flags, structured_messages defaults to False).
    return _decode_capabilities_payload(payload, five_bools=False)


def encode_session_bind(bind: SessionBindEnvelope) -> bytes:
    """Encode SessionBindEnvelope into canonical little-endian wire frame."""
    if not bind.is_valid():
        raise ValueError("Invalid session_bind envelope: missing identity or zero lease token")

    pw = BufferWriter()
    pw.write_u64(bind.identity.node_id)
    pw.write_u64(bind.identity.runtime_id)
    pw.write_u32(bind.identity.endpoint_id)
    pw.write_u64(bind.control_epoch)
    pw.write_u64(bind.lease_token)
    payload = pw.to_bytes()

    if len(payload) != LINEP_V02_SESSION_BIND_PAYLOAD_SIZE:
        raise ValueError("Invalid session_bind payload length")

    hdr = WireEnvelopeHeader(
        magic=LINEP_V02_MAGIC,
        version_major=LINEP_V02_VERSION_MAJOR,
        version_minor=LINEP_V02_VERSION_MINOR,
        envelope_type=int(EnvelopeType.SESSION_BIND),
        flags=LINEP_V02_FLAG_AUTHENTICATED if bind.sl1_requested else 0,
        request_id=0,
        execution_id=0,
        output_id=0,
        payload_len=len(payload),
    )
    hdr_bytes = encode_header(hdr)
    if bind.sl1_requested:
        ext = bind.auth_ext if bind.auth_ext is not None else AuthExtension(auth_seq=1, key_id=bind.key_id)
        return hdr_bytes + ext.encode() + payload
    return hdr_bytes + payload


def decode_session_bind(data: bytes) -> Optional[SessionBindEnvelope]:
    """Decode SessionBindEnvelope from canonical little-endian wire frame."""
    hdr = decode_header(data)
    if (
        hdr is None
        or hdr.magic != LINEP_V02_MAGIC
        or hdr.version_major != LINEP_V02_VERSION_MAJOR
        or hdr.envelope_type != int(EnvelopeType.SESSION_BIND)
        or (hdr.flags & ~LINEP_V02_FLAG_AUTHENTICATED) != 0
        or hdr.request_id != 0
        or hdr.execution_id != 0
        or hdr.output_id != 0
        or hdr.payload_len != LINEP_V02_SESSION_BIND_PAYLOAD_SIZE
    ):
        return None

    has_auth = (hdr.flags & LINEP_V02_FLAG_AUTHENTICATED) != 0
    expected_size = LINEP_V02_HEADER_SIZE + (LINEP_V02_AUTH_EXTENSION_SIZE if has_auth else 0) + hdr.payload_len
    if len(data) != expected_size:
        return None

    auth_ext = None
    if has_auth:
        auth_ext = AuthExtension.decode(data[LINEP_V02_HEADER_SIZE : LINEP_V02_HEADER_SIZE + LINEP_V02_AUTH_EXTENSION_SIZE])
        if auth_ext is None:
            return None
        payload_offset = LINEP_V02_HEADER_SIZE + LINEP_V02_AUTH_EXTENSION_SIZE
    else:
        payload_offset = LINEP_V02_HEADER_SIZE

    try:
        r = BufferReader(data[payload_offset : payload_offset + hdr.payload_len])
        node_id = r.read_u64()
        runtime_id = r.read_u64()
        endpoint_id = r.read_u32()
        control_epoch = r.read_u64()
        lease_token = r.read_u64()
        if r.remaining() != 0:
            return None

        bind = SessionBindEnvelope(
            identity=NodeEndpointIdentity(node_id=node_id, runtime_id=runtime_id, endpoint_id=endpoint_id),
            control_epoch=control_epoch,
            lease_token=lease_token,
            sl1_requested=has_auth,
            key_id=auth_ext.key_id if auth_ext else 0,
            auth_ext=auth_ext,
        )
        if not bind.is_valid():
            return None
        return bind
    except Exception:
        return None


def compute_sl1_mac(
    secret_key: bytes,
    header: WireEnvelopeHeader,
    auth_ext: AuthExtension,
    binding: SessionBindEnvelope,
    direction: MessageDirection,
    payload: bytes = b"",
) -> bytes:
    """Compute 16-byte SL1 truncated HMAC-SHA256 over canonical 80-byte prefix and payload."""
    if not secret_key:
        return bytes(16)
    hdr_bytes = encode_header(header)
    auth_prefix = struct.pack("<IHH", auth_ext.auth_seq, auth_ext.key_id, auth_ext.reserved)
    bind_bytes = struct.pack(
        "<QQIQQ",
        binding.identity.node_id,
        binding.identity.runtime_id,
        binding.identity.endpoint_id,
        binding.control_epoch,
        binding.lease_token,
    )
    direction_bytes = struct.pack("<BBBB", int(direction), 0, 0, 0)
    mac_input = hdr_bytes + auth_prefix + bind_bytes + direction_bytes + payload
    full_digest = hmac.new(secret_key, mac_input, hashlib.sha256).digest()
    return full_digest[:16]


def sign_envelope(
    raw_frame: bytes,
    binding: SessionBindEnvelope,
    direction: MessageDirection,
    auth_seq: int,
    key_id: int,
    secret_key: bytes,
) -> bytes:
    """Sign an existing serialized envelope buffer with an SL1 wire_auth_extension."""
    if len(raw_frame) < LINEP_V02_HEADER_SIZE or not secret_key or auth_seq == 0:
        raise ValueError("Invalid parameters for envelope signing")
    hdr = decode_header(raw_frame)
    if hdr is None or len(raw_frame) != (LINEP_V02_HEADER_SIZE + hdr.payload_len):
        raise ValueError("Invalid frame buffer for envelope signing")

    hdr.flags |= LINEP_V02_FLAG_AUTHENTICATED
    auth_ext = AuthExtension(auth_seq=auth_seq, key_id=key_id, reserved=0)
    payload = raw_frame[LINEP_V02_HEADER_SIZE:]
    auth_ext.mac = compute_sl1_mac(secret_key, hdr, auth_ext, binding, direction, payload)

    new_hdr_bytes = encode_header(hdr)
    return new_hdr_bytes + auth_ext.encode() + payload


def verify_envelope(
    raw_frame: bytes,
    binding: SessionBindEnvelope,
    direction: MessageDirection,
    secret_key: bytes,
) -> Tuple[bool, Optional[AuthExtension], Optional[bytes], str]:
    """Verify an SL1 signed envelope buffer."""
    if len(raw_frame) < (LINEP_V02_HEADER_SIZE + LINEP_V02_AUTH_EXTENSION_SIZE):
        return False, None, None, "buffer too small for authenticated envelope"
    hdr = decode_header(raw_frame)
    if hdr is None:
        return False, None, None, "header decode failed"
    if (hdr.flags & LINEP_V02_FLAG_AUTHENTICATED) == 0:
        return False, None, None, "auth_required: missing authentication flag"
    if len(raw_frame) != (LINEP_V02_HEADER_SIZE + LINEP_V02_AUTH_EXTENSION_SIZE + hdr.payload_len):
        return False, None, None, "envelope size mismatch"

    auth_ext = AuthExtension.decode(raw_frame[LINEP_V02_HEADER_SIZE : LINEP_V02_HEADER_SIZE + LINEP_V02_AUTH_EXTENSION_SIZE])
    if auth_ext is None:
        return False, None, None, "auth extension decode failed"

    payload = raw_frame[LINEP_V02_HEADER_SIZE + LINEP_V02_AUTH_EXTENSION_SIZE :]
    expected_mac = compute_sl1_mac(secret_key, hdr, auth_ext, binding, direction, payload)
    if not hmac.compare_digest(auth_ext.mac, expected_mac):
        return False, auth_ext, payload, "auth_invalid: MAC verification failed"
    return True, auth_ext, payload, ""


def _is_valid_runtime_registration(e: RuntimeRegistrationEnvelope) -> bool:
    try:
        op = int(e.operation)
    except (TypeError, ValueError):
        return False
    if op < 1 or op > 6:
        return False

    reason_bytes = e.reason.encode("utf-8") if isinstance(e.reason, str) else bytes(e.reason)
    if len(reason_bytes) > 8192:
        return False

    d = e.capabilities.descriptor if (e.capabilities is not None and e.capabilities.descriptor is not None) else None
    if d is None:
        return False

    empty_capabilities = (
        len(d.supported_models) == 0
        and len(d.supported_profiles) == 0
        and len(d.supported_embedding_spaces) == 0
        and d.max_context_tokens == 0
        and d.max_output_tokens == 0
        and d.supports_streaming is True
        and d.supports_cancellation is True
        and not d.supports_tool_calling
        and not d.supports_reasoning_deltas
        and not d.supports_structured_messages
    )

    if e.operation == RegistrationOperation.RESULT:
        return (
            (e.status_code == 200 or (400 <= e.status_code <= 599))
            and e.concurrent_slots == 0
            and empty_capabilities
        )

    if e.status_code != 0 or len(reason_bytes) != 0:
        return False

    if e.operation != RegistrationOperation.REGISTER_RUNTIME:
        return empty_capabilities and (
            e.operation == RegistrationOperation.CAPACITY_UPDATE or e.concurrent_slots == 0
        )

    if e.concurrent_slots == 0 or len(d.supported_models) == 0 or len(d.supported_profiles) == 0:
        return False
    if len(d.supported_models) > 2048 or len(d.supported_embedding_spaces) > 2048:
        return False

    total_bytes = 64
    for m in d.supported_models:
        total_bytes += len(m.encode("utf-8")) + 2
    for sp in d.supported_embedding_spaces:
        sp_id_bytes = sp.embedding_space_id.encode("utf-8")
        sp_mod_bytes = sp.model_id.encode("utf-8")
        sp_rev_bytes = sp.model_revision.encode("utf-8")
        if (
            not sp.embedding_space_id
            or not sp.model_id
            or sp.dimensions == 0
            or sp.dimensions > LINEP_V02_MAX_EMBEDDING_DIMS
            or int(sp.normalization) > 1
            or int(sp.distance_metric) < 1
            or int(sp.distance_metric) > 3
            or sp.model_id not in d.supported_models
            or len(sp_id_bytes) > 8192
            or len(sp_mod_bytes) > 8192
            or len(sp_rev_bytes) > 8192
        ):
            return False
        total_bytes += len(sp_id_bytes) + len(sp_mod_bytes) + len(sp_rev_bytes) + 12

    if total_bytes > LINEP_V02_MAX_REGISTRATION_BYTES - 64:
        return False

    seen_models = set()
    for m in d.supported_models:
        m_bytes = m.encode("utf-8")
        if not m or len(m_bytes) > 8192 or m in seen_models:
            return False
        seen_models.add(m)

    seen_profiles = set()
    for p in d.supported_profiles:
        v = int(p)
        if v < 1 or v > 3 or v in seen_profiles:
            return False
        seen_profiles.add(v)

    return True


def encode_runtime_registration(e: RuntimeRegistrationEnvelope) -> bytes:
    """Encode RuntimeRegistrationEnvelope into canonical little-endian wire frame."""
    if not _is_valid_runtime_registration(e):
        raise ValueError("Invalid RuntimeRegistrationEnvelope")

    b = bytearray([1, 0, int(e.operation), 0])

    def put_field(tag: int, val: bytes):
        b.extend(struct.pack("<HI", tag, len(val)))
        b.extend(val)

    if e.operation in (RegistrationOperation.REGISTER_RUNTIME, RegistrationOperation.CAPACITY_UPDATE):
        put_field(1, struct.pack("<I", e.concurrent_slots))

    if e.operation == RegistrationOperation.RESULT:
        put_field(2, struct.pack("<I", e.status_code))
        put_field(3, e.reason.encode("utf-8"))

    if e.operation == RegistrationOperation.REGISTER_RUNTIME:
        caps_bytes = encode_capabilities(e.capabilities)
        put_field(4, caps_bytes)

    previous = 0x7FFF
    for x in e.extensions:
        if x.tag <= previous or len(x.value) > LINEP_V02_MAX_REGISTRATION_BYTES:
            raise ValueError(f"Invalid extension tag {x.tag} or length {len(x.value)}")
        previous = x.tag
        put_field(x.tag, x.value)
        if len(b) > LINEP_V02_MAX_REGISTRATION_BYTES:
            raise ValueError("Registration payload exceeds max allowed bytes")

    if len(b) > LINEP_V02_MAX_REGISTRATION_BYTES:
        raise ValueError("Registration payload exceeds max allowed bytes")

    hdr = WireEnvelopeHeader(
        magic=LINEP_V02_MAGIC,
        version_major=LINEP_V02_VERSION_MAJOR,
        version_minor=LINEP_V02_VERSION_MINOR,
        envelope_type=int(EnvelopeType.RUNTIME_REGISTER),
        flags=0,
        request_id=0,
        execution_id=0,
        output_id=0,
        payload_len=len(b),
    )
    return encode_header(hdr) + bytes(b)


def decode_runtime_registration(data: bytes) -> Optional[RuntimeRegistrationEnvelope]:
    """Decode RuntimeRegistrationEnvelope from canonical wire frame (structural decode only)."""
    if len(data) < LINEP_V02_HEADER_SIZE:
        return None
    hdr = decode_header(data)
    if (
        hdr is None
        or hdr.magic != LINEP_V02_MAGIC
        or hdr.version_major != LINEP_V02_VERSION_MAJOR
        or hdr.version_minor != LINEP_V02_VERSION_MINOR
        or (hdr.flags & ~LINEP_V02_FLAG_AUTHENTICATED) != 0
        or hdr.envelope_type != int(EnvelopeType.RUNTIME_REGISTER)
        or hdr.request_id != 0
        or hdr.execution_id != 0
        or hdr.output_id != 0
        or hdr.payload_len < 4
        or hdr.payload_len > LINEP_V02_MAX_REGISTRATION_BYTES
    ):
        return None

    is_auth = (hdr.flags & LINEP_V02_FLAG_AUTHENTICATED) != 0
    offset = LINEP_V02_HEADER_SIZE + (LINEP_V02_AUTH_EXTENSION_SIZE if is_auth else 0)
    if len(data) != offset + hdr.payload_len:
        return None

    if data[offset] != 1 or data[offset + 1] != 0 or data[offset + 3] != 0:
        return None

    try:
        op = RegistrationOperation(data[offset + 2])
    except ValueError:
        return None

    e = RuntimeRegistrationEnvelope(operation=op)
    pos = offset + 4
    end = len(data)
    previous = 0
    seen = 0

    while pos < end:
        if end - pos < 6:
            return None
        tag, tlen = struct.unpack_from("<HI", data, pos)
        pos += 6
        if tag <= previous or tlen > end - pos:
            return None
        previous = tag

        val_bytes = data[pos : pos + tlen]
        if tag == 1:
            if tlen != 4:
                return None
            e.concurrent_slots = struct.unpack_from("<I", val_bytes, 0)[0]
        elif tag == 2:
            if tlen != 4:
                return None
            e.status_code = struct.unpack_from("<I", val_bytes, 0)[0]
        elif tag == 3:
            if tlen > 8192:
                return None
            e.reason = val_bytes.decode("utf-8", errors="replace")
        elif tag == 4:
            ch = decode_header(val_bytes)
            if (
                ch is None
                or ch.magic != LINEP_V02_MAGIC
                or ch.version_major != LINEP_V02_VERSION_MAJOR
                or ch.version_minor != LINEP_V02_VERSION_MINOR
                or ch.flags != 0
                or ch.request_id != 0
                or ch.execution_id != 0
                or ch.output_id != 0
                or ch.envelope_type != int(EnvelopeType.CAPABILITIES)
                or tlen != LINEP_V02_HEADER_SIZE + ch.payload_len
            ):
                return None
            caps = decode_capabilities(val_bytes)
            if caps is None:
                return None
            # Canonical re-encoding check (reject non-canonical or trailing nested data)
            canonical = encode_capabilities(caps)
            if canonical != val_bytes:
                return None
            e.capabilities = caps
        elif tag < 0x8000:
            return None
        else:
            e.extensions.append(RegistrationExtension(tag=tag, value=bytes(val_bytes)))

        if tag <= 4:
            seen |= (1 << tag)
        pos += tlen

    expected = (
        18 if e.operation == RegistrationOperation.REGISTER_RUNTIME
        else (12 if e.operation == RegistrationOperation.RESULT
        else (2 if e.operation == RegistrationOperation.CAPACITY_UPDATE
        else 0))
    )
    if seen != expected or not _is_valid_runtime_registration(e):
        return None

    return e

