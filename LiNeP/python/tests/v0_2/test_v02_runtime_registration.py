"""Unit tests for LiNeP V0.2 Runtime Registration Envelope (Issue #31).

Ensures complete wire-compatibility and parity with C++ reference implementation
(test_v02_runtime_registration.cpp / linep::v0_2::runtime_registration_envelope).
"""

import struct
import pytest

from linep.v0_2 import (
    LINEP_V02_MAGIC,
    LINEP_V02_VERSION_MAJOR,
    LINEP_V02_VERSION_MINOR,
    LINEP_V02_HEADER_SIZE,
    LINEP_V02_FLAG_AUTHENTICATED,
    LINEP_V02_MAX_REGISTRATION_BYTES,
    EnvelopeType,
    RegistrationOperation,
    RuntimeProfile,
    EmbeddingNormalization,
    EmbeddingDistanceMetric,
    StreamIdentity,
    CapabilitiesEnvelope,
    CapabilitiesDescriptor,
    EmbeddingSpaceDescriptor,
    RegistrationExtension,
    RuntimeRegistrationEnvelope,
    SessionBindEnvelope,
    NodeEndpointIdentity,
    MessageDirection,
    encode_runtime_registration,
    decode_runtime_registration,
    encode_header,
    WireEnvelopeHeader,
    sign_envelope,
    verify_envelope,
)


def _make_valid_registration(slots: int = 1) -> RuntimeRegistrationEnvelope:
    return RuntimeRegistrationEnvelope(
        operation=RegistrationOperation.REGISTER_RUNTIME,
        concurrent_slots=slots,
        capabilities=CapabilitiesEnvelope(
            descriptor=CapabilitiesDescriptor(
                supported_models=["test-model"],
                supported_profiles=[RuntimeProfile.GENERATE],
            )
        ),
    )


def test_golden_vector_capacity_update():
    """Verify exact bit-for-bit parity with C++ wire golden frame for capacity_update."""
    e = RuntimeRegistrationEnvelope(
        operation=RegistrationOperation.CAPACITY_UPDATE,
        concurrent_slots=2,
    )
    golden = bytes([
        0x32, 0x4C, 0x4E, 0x50, 0, 2, 6, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0,
        1, 0, 5, 0, 1, 0, 4, 0, 0, 0, 2, 0, 0, 0,
    ])
    encoded = encode_runtime_registration(e)
    assert encoded == golden

    decoded = decode_runtime_registration(golden)
    assert decoded is not None
    assert decoded.operation == RegistrationOperation.CAPACITY_UPDATE
    assert decoded.concurrent_slots == 2
    assert decoded.status_code == 0
    assert decoded.reason == ""
    assert len(decoded.extensions) == 0


def test_register_runtime_roundtrip():
    """Test roundtrip encoding/decoding of a standard REGISTER_RUNTIME envelope."""
    reg = _make_valid_registration(slots=4)
    reg.capabilities.descriptor.supported_models = ["llama3:8b", "qwen2.5:7b"]
    reg.capabilities.descriptor.supported_profiles = [RuntimeProfile.GENERATE, RuntimeProfile.CHAT]
    reg.capabilities.descriptor.max_context_tokens = 8192
    reg.capabilities.descriptor.max_output_tokens = 4096

    raw = encode_runtime_registration(reg)
    decoded = decode_runtime_registration(raw)
    assert decoded is not None
    assert decoded.operation == RegistrationOperation.REGISTER_RUNTIME
    assert decoded.concurrent_slots == 4
    desc = decoded.capabilities.descriptor
    assert desc.supported_models == ["llama3:8b", "qwen2.5:7b"]
    assert desc.supported_profiles == [RuntimeProfile.GENERATE, RuntimeProfile.CHAT]
    assert desc.max_context_tokens == 8192
    assert desc.max_output_tokens == 4096


def test_result_roundtrip():
    """Test roundtrip of registration RESULT envelopes (accepted and rejected)."""
    # 200 Accepted
    res_ok = RuntimeRegistrationEnvelope(
        operation=RegistrationOperation.RESULT,
        status_code=200,
        reason="",
    )
    raw_ok = encode_runtime_registration(res_ok)
    dec_ok = decode_runtime_registration(raw_ok)
    assert dec_ok is not None
    assert dec_ok.operation == RegistrationOperation.RESULT
    assert dec_ok.status_code == 200
    assert dec_ok.reason == ""

    # 403 Forbidden
    res_rej = RuntimeRegistrationEnvelope(
        operation=RegistrationOperation.RESULT,
        status_code=403,
        reason="runtime_not_authorized",
    )
    raw_rej = encode_runtime_registration(res_rej)
    dec_rej = decode_runtime_registration(raw_rej)
    assert dec_rej is not None
    assert dec_rej.operation == RegistrationOperation.RESULT
    assert dec_rej.status_code == 403
    assert dec_rej.reason == "runtime_not_authorized"


def test_lifecycle_operations_roundtrip():
    """Test roundtrip of parameter-less lifecycle operations: DRAINING, DEREGISTER, CAPABILITIES_QUERY."""
    for op in (
        RegistrationOperation.DRAINING,
        RegistrationOperation.DEREGISTER,
        RegistrationOperation.CAPABILITIES_QUERY,
    ):
        e = RuntimeRegistrationEnvelope(operation=op)
        raw = encode_runtime_registration(e)
        dec = decode_runtime_registration(raw)
        assert dec is not None
        assert dec.operation == op
        assert dec.concurrent_slots == 0
        assert dec.status_code == 0
        assert dec.reason == ""


def test_optional_extensions_preserved():
    """Verify optional extensions (tag >= 0x8000) are strictly ordered and preserved through roundtrip."""
    reg = _make_valid_registration(slots=1)
    reg.extensions = [
        RegistrationExtension(tag=0x8000, value=b"\x01\x02\x03"),
        RegistrationExtension(tag=0x80FF, value=b"vendor_metadata_blob"),
    ]
    raw = encode_runtime_registration(reg)
    dec = decode_runtime_registration(raw)
    assert dec is not None
    assert len(dec.extensions) == 2
    assert dec.extensions[0].tag == 0x8000
    assert dec.extensions[0].value == b"\x01\x02\x03"
    assert dec.extensions[1].tag == 0x80FF
    assert dec.extensions[1].value == b"vendor_metadata_blob"
    assert encode_runtime_registration(dec) == raw


def test_unknown_mandatory_tag_fails_closed():
    """Verify unknown tags < 0x8000 fail closed on decode."""
    reg = _make_valid_registration(slots=1)
    reg.extensions = [RegistrationExtension(tag=0x8000, value=b"\x01\x02\x03")]
    raw = bytearray(encode_runtime_registration(reg))

    # Mutate tag 0x8000 to 0x0005 (unknown mandatory tag < 0x8000)
    # The last TLV is at raw[-9:] : tag(2), len(4), val(3)
    struct.pack_into("<H", raw, len(raw) - 9, 5)
    assert decode_runtime_registration(bytes(raw)) is None


def test_duplicate_or_unordered_extensions_rejected():
    """Ensure duplicate or decreasing extension tags are rejected on encode and decode."""
    reg = _make_valid_registration(slots=1)
    reg.extensions = [
        RegistrationExtension(tag=0x8001, value=b"first"),
        RegistrationExtension(tag=0x8000, value=b"second_out_of_order"),
    ]
    with pytest.raises(ValueError):
        encode_runtime_registration(reg)

    reg.extensions = [
        RegistrationExtension(tag=0x8000, value=b"a"),
        RegistrationExtension(tag=0x8000, value=b"b"),
    ]
    with pytest.raises(ValueError):
        encode_runtime_registration(reg)


def test_truncation_detection():
    """Every truncated prefix of a valid registration frame must fail decode."""
    reg = _make_valid_registration(slots=1)
    raw = encode_runtime_registration(reg)
    for n in range(len(raw)):
        assert decode_runtime_registration(raw[:n]) is None


def test_trailing_garbage_rejected():
    """Trailing bytes appended to a valid registration frame must cause decode failure."""
    reg = _make_valid_registration(slots=1)
    raw = encode_runtime_registration(reg)
    assert decode_runtime_registration(raw + b"\x00") is None


def test_invalid_schema_or_reserved_bytes():
    """Schema version != 1.0 or nonzero reserved byte must fail decode."""
    reg = _make_valid_registration(slots=1)
    raw = bytearray(encode_runtime_registration(reg))

    # Offset 32 is schema_major
    raw[32] = 2
    assert decode_runtime_registration(bytes(raw)) is None

    # Reset and mutate schema_minor (offset 33)
    raw[32] = 1
    raw[33] = 1
    assert decode_runtime_registration(bytes(raw)) is None

    # Reset and mutate reserved byte (offset 35)
    raw[33] = 0
    raw[35] = 1
    assert decode_runtime_registration(bytes(raw)) is None


def test_connection_level_stream_identity_enforced():
    """Nonzero request_id, execution_id, or output_id must cause decode failure."""
    reg = _make_valid_registration(slots=1)
    raw = bytearray(encode_runtime_registration(reg))

    # request_id at offset 8 (uint64)
    struct.pack_into("<Q", raw, 8, 1)
    assert decode_runtime_registration(bytes(raw)) is None
    struct.pack_into("<Q", raw, 8, 0)

    # execution_id at offset 16 (uint64)
    struct.pack_into("<Q", raw, 16, 1)
    assert decode_runtime_registration(bytes(raw)) is None
    struct.pack_into("<Q", raw, 16, 0)

    # output_id at offset 24 (uint32)
    struct.pack_into("<I", raw, 24, 1)
    assert decode_runtime_registration(bytes(raw)) is None


def test_validation_edge_cases():
    """Test validation constraints on slots, models, profiles, reason strings."""
    # Zero slots on register_runtime
    with pytest.raises(ValueError):
        encode_runtime_registration(RuntimeRegistrationEnvelope(
            operation=RegistrationOperation.REGISTER_RUNTIME,
            concurrent_slots=0,
            capabilities=CapabilitiesEnvelope(
                descriptor=CapabilitiesDescriptor(
                    supported_models=["m1"],
                    supported_profiles=[RuntimeProfile.GENERATE],
                )
            ),
        ))

    # Nonzero slots on draining
    with pytest.raises(ValueError):
        encode_runtime_registration(RuntimeRegistrationEnvelope(
            operation=RegistrationOperation.DRAINING,
            concurrent_slots=1,
        ))

    # Capabilities supplied on draining (must not silently drop)
    with pytest.raises(ValueError):
        encode_runtime_registration(RuntimeRegistrationEnvelope(
            operation=RegistrationOperation.DRAINING,
            capabilities=CapabilitiesEnvelope(
                descriptor=CapabilitiesDescriptor(
                    supported_models=["m1"],
                    supported_profiles=[RuntimeProfile.GENERATE],
                )
            ),
        ))

    # Duplicate models
    with pytest.raises(ValueError):
        encode_runtime_registration(RuntimeRegistrationEnvelope(
            operation=RegistrationOperation.REGISTER_RUNTIME,
            concurrent_slots=1,
            capabilities=CapabilitiesEnvelope(
                descriptor=CapabilitiesDescriptor(
                    supported_models=["m1", "m1"],
                    supported_profiles=[RuntimeProfile.GENERATE],
                )
            ),
        ))

    # Duplicate profiles
    with pytest.raises(ValueError):
        encode_runtime_registration(RuntimeRegistrationEnvelope(
            operation=RegistrationOperation.REGISTER_RUNTIME,
            concurrent_slots=1,
            capabilities=CapabilitiesEnvelope(
                descriptor=CapabilitiesDescriptor(
                    supported_models=["m1"],
                    supported_profiles=[RuntimeProfile.GENERATE, RuntimeProfile.GENERATE],
                )
            ),
        ))

    # Invalid status code on RESULT
    with pytest.raises(ValueError):
        encode_runtime_registration(RuntimeRegistrationEnvelope(
            operation=RegistrationOperation.RESULT,
            status_code=300,  # Only 200 or 400..599 allowed
        ))


def test_sl1_authentication_on_runtime_registration():
    """Verify SL1 signing and MAC verification on runtime_register envelopes."""
    key = bytes(range(1, 33))
    binding = SessionBindEnvelope(
        identity=NodeEndpointIdentity(node_id=1, runtime_id=2, endpoint_id=3),
        lease_token=4,
        sl1_requested=True,
        key_id=1,
    )
    reg = _make_valid_registration(slots=2)
    raw = encode_runtime_registration(reg)

    # Sign envelope (worker -> router: INITIATOR_TO_RESPONDER)
    signed = sign_envelope(
        raw_frame=raw,
        binding=binding,
        direction=MessageDirection.INITIATOR_TO_RESPONDER,
        auth_seq=2,
        key_id=1,
        secret_key=key,
    )

    # Verify signature
    ok, auth_ext, payload, err = verify_envelope(
        raw_frame=signed,
        binding=binding,
        direction=MessageDirection.INITIATOR_TO_RESPONDER,
        secret_key=key,
    )
    assert ok is True, f"Verification failed: {err}"
    assert auth_ext.auth_seq == 2
    assert auth_ext.key_id == 1

    # Decode payload from authenticated frame
    dec = decode_runtime_registration(signed)
    assert dec is not None
    assert dec.operation == RegistrationOperation.REGISTER_RUNTIME
    assert dec.concurrent_slots == 2

    # Wrong direction must fail verification
    ok_wrong, _, _, _ = verify_envelope(
        raw_frame=signed,
        binding=binding,
        direction=MessageDirection.RESPONDER_TO_INITIATOR,
        secret_key=key,
    )
    assert ok_wrong is False

    # Tampered payload must fail verification
    tampered = bytearray(signed)
    tampered[-1] ^= 0xFF
    ok_tamper, _, _, _ = verify_envelope(
        raw_frame=bytes(tampered),
        binding=binding,
        direction=MessageDirection.INITIATOR_TO_RESPONDER,
        secret_key=key,
    )
    assert ok_tamper is False
