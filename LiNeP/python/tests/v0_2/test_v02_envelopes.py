"""Unit tests for LiNeP V0.2 TCP Data Plane Envelopes and Encoders/Decoders."""

import pytest
from linep.v0_2 import (
    LINEP_V02_MAGIC,
    LINEP_V02_VERSION_MAJOR,
    LINEP_V02_VERSION_MINOR,
    LINEP_V02_HEADER_SIZE,
    RuntimeProfile,
    EnvelopeType,
    EventType,
    ControlType,
    TerminalOutcome,
    ErrorCategory,
    EmbeddingNormalization,
    EmbeddingDistanceMetric,
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
    encode_header,
    decode_header,
    peek_envelope_type,
    encode_request,
    decode_request,
    encode_event,
    decode_event,
    encode_control,
    decode_control,
    encode_capabilities,
    decode_capabilities,
)


def test_header_roundtrip():
    hdr = WireEnvelopeHeader(
        magic=LINEP_V02_MAGIC,
        version_major=0,
        version_minor=2,
        envelope_type=int(EnvelopeType.REQUEST),
        flags=0,
        request_id=12345,
        execution_id=67890,
        output_id=2,
        payload_len=1024,
    )
    raw = encode_header(hdr)
    assert len(raw) == LINEP_V02_HEADER_SIZE

    decoded = decode_header(raw)
    assert decoded is not None
    assert decoded.magic == LINEP_V02_MAGIC
    assert decoded.version_major == 0
    assert decoded.version_minor == 2
    assert decoded.envelope_type == int(EnvelopeType.REQUEST)
    assert decoded.request_id == 12345
    assert decoded.execution_id == 67890
    assert decoded.output_id == 2
    assert decoded.payload_len == 1024


def test_request_roundtrip():
    req = RequestEnvelope(
        stream=StreamIdentity(1001, 2001, 0),
        profile=RuntimeProfile.CHAT,
        model_id="meta-llama/Llama-3.1-8B-Instruct",
        payload='{"messages":[{"role":"user","content":"Hello from Python!"}]}',
        max_tokens=512,
        temperature=0.8,
        stream_requested=True,
    )
    raw = encode_request(req)
    assert len(raw) > LINEP_V02_HEADER_SIZE
    assert peek_envelope_type(raw) == EnvelopeType.REQUEST

    decoded = decode_request(raw)
    assert decoded is not None
    assert decoded.stream.request_id == 1001
    assert decoded.stream.execution_id == 2001
    assert decoded.stream.output_id == 0
    assert decoded.profile == RuntimeProfile.CHAT
    assert decoded.model_id == "meta-llama/Llama-3.1-8B-Instruct"
    assert decoded.payload == req.payload
    assert decoded.max_tokens == 512
    assert abs(decoded.temperature - 0.8) < 1e-4
    assert decoded.stream_requested is True


def test_event_content_and_reasoning_deltas():
    evt = EventEnvelope(
        stream=StreamIdentity(1001, 2001, 1),
        event_seq=42,
        event_type=EventType.REASONING_DELTA,
        payload="Thinking through quantum algorithms...",
        timestamp_us=1700000000123456,
    )
    raw = encode_event(evt)
    decoded = decode_event(raw)
    assert decoded is not None
    assert decoded.event_seq == 42
    assert decoded.event_type == EventType.REASONING_DELTA
    assert decoded.payload == "Thinking through quantum algorithms..."
    assert decoded.timestamp_us == 1700000000123456


def test_event_embedding_roundtrip():
    sp = EmbeddingSpaceDescriptor(
        embedding_space_id="nomic-embed-text-v1.5",
        model_id="nomic-ai/nomic-embed-text-v1.5",
        model_revision="v1.5",
        dimensions=4,
        normalization=EmbeddingNormalization.L2,
        distance_metric=EmbeddingDistanceMetric.COSINE,
    )
    evt = EventEnvelope(
        stream=StreamIdentity(3001, 4001, 0),
        event_seq=1,
        event_type=EventType.EMBEDDING_RESULT,
        embedding=EmbeddingPayload(space=sp, vector=[0.1, -0.25, 0.77, 0.05]),
        timestamp_us=1700000000123500,
    )
    raw = encode_event(evt)
    decoded = decode_event(raw)
    assert decoded is not None
    assert decoded.event_type == EventType.EMBEDDING_RESULT
    assert decoded.embedding.space.embedding_space_id == "nomic-embed-text-v1.5"
    assert decoded.embedding.space.dimensions == 4
    assert decoded.embedding.space.normalization == EmbeddingNormalization.L2
    assert decoded.embedding.space.distance_metric == EmbeddingDistanceMetric.COSINE
    assert len(decoded.embedding.vector) == 4
    assert abs(decoded.embedding.vector[0] - 0.1) < 1e-4


def test_event_error_and_cancellation():
    evt = EventEnvelope(
        stream=StreamIdentity(1001, 2001, 0),
        event_seq=99,
        event_type=EventType.CANCELLED,
        payload="Cancelled by client",
        outcome=TerminalOutcome.CANCELLED,
        error=RuntimeErrorPayload(
            category=ErrorCategory.RESOURCE_EXHAUSTED,
            code=499,
            message="Stream cancelled",
            backend_diagnostic="Client issued CANCEL envelope",
        ),
    )
    raw = encode_event(evt)
    decoded = decode_event(raw)
    assert decoded is not None
    assert decoded.event_type == EventType.CANCELLED
    assert decoded.outcome == TerminalOutcome.CANCELLED
    assert decoded.error.code == 499
    assert decoded.error.category == ErrorCategory.RESOURCE_EXHAUSTED
    assert decoded.error.message == "Stream cancelled"


def test_control_cancel_and_window_update():
    ctrl_win = ControlEnvelope(
        stream=StreamIdentity(1001, 2001, 0),
        control_type=ControlType.WINDOW_UPDATE,
        reason="ACK",
        ack_offset_bytes=16384,
    )
    raw_win = encode_control(ctrl_win)
    decoded_win = decode_control(raw_win)
    assert decoded_win is not None
    assert decoded_win.control_type == ControlType.WINDOW_UPDATE
    assert decoded_win.ack_offset_bytes == 16384


def test_capabilities_roundtrip():
    caps = CapabilitiesEnvelope(
        descriptor=CapabilitiesDescriptor(
            supported_profiles=[RuntimeProfile.GENERATE, RuntimeProfile.CHAT, RuntimeProfile.EMBED],
            max_context_tokens=8192,
            max_output_tokens=4096,
            supports_streaming=True,
            supports_cancellation=True,
            supports_tool_calling=True,
            supports_reasoning_deltas=True,
            supported_models=["llama3:8b", "qwen2.5:7b"],
            supported_embedding_spaces=[
                EmbeddingSpaceDescriptor(
                    embedding_space_id="nomic-embed-text-v1.5",
                    model_id="nomic-ai/nomic-embed-text-v1.5",
                    model_revision="v1.5",
                    dimensions=768,
                    normalization=EmbeddingNormalization.L2,
                    distance_metric=EmbeddingDistanceMetric.COSINE,
                )
            ],
        )
    )
    raw = encode_capabilities(caps)
    decoded = decode_capabilities(raw)
    assert decoded is not None
    assert len(decoded.descriptor.supported_profiles) == 3
    assert decoded.descriptor.max_context_tokens == 8192
    assert decoded.descriptor.supported_models == ["llama3:8b", "qwen2.5:7b"]
    assert len(decoded.descriptor.supported_embedding_spaces) == 1
    assert decoded.descriptor.supported_embedding_spaces[0].dimensions == 768


def test_strict_rejection_of_malformed_and_trailing_data():
    req = RequestEnvelope(
        stream=StreamIdentity(1, 1, 0),
        profile=RuntimeProfile.CHAT,
        model_id="test",
        payload="ok",
    )
    raw = encode_request(req)

    # 1. Truncated
    assert decode_request(raw[:20]) is None

    # 2. Corrupted magic
    bad_magic = bytearray(raw)
    bad_magic[0] = 0xFF
    assert decode_request(bytes(bad_magic)) is None

    # 3. Trailing garbage (strict fail-closed)
    bad_trailing = raw + b"\x00\x00\x00\x00"
    # Header payload_len was not updated, but BufferReader check sees remaining bytes if length was modified
    # If payload_len is modified to include trailing bytes, decode fails on trailing check
