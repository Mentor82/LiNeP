"""Unit tests for LiNeP V0.2 Runtime Registration Envelope (Issue #31).

Ensures complete wire-compatibility and parity with C++ reference implementation
(test_v02_runtime_registration.cpp / linep::v0_2::runtime_registration_envelope).
"""

import struct
import copy
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
    DecisionModelDescriptor,
    VisionModelDescriptor,
    VisionTask,
    encode_capabilities,
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


DECISION_REGISTRATION_GOLDEN = bytes.fromhex(
    "324c4e500002060000000000000000000000000000000000000000005e000000"
    "010001000100040000000100000004004a000000324c4e500002040000000000"
    "000000000000000000000000000000002a0000000100050000000000000000"
    "0101000000010001006400000000010001006402007631060063686f696365"
)


def _profile_registration(profile):
    reg = _make_valid_registration()
    d = reg.capabilities.descriptor
    d.supported_profiles = [profile]
    if profile == RuntimeProfile.DECISION:
        d.supported_decision_models = [DecisionModelDescriptor("test-model", "v1", "choice")]
    else:
        d.supported_vision_models = [VisionModelDescriptor(model_id="test-model", label_set_id="coco80:v1")]
    return reg


def _unchecked_registration(reg):
    # Build a valid TLV envelope around inconsistent capabilities, bypassing the
    # production registration validator so the receiver is tested independently.
    caps = encode_capabilities(reg.capabilities)
    payload = (b"\x01\x00\x01\x00" + struct.pack("<HII", 1, 4, reg.concurrent_slots)
               + struct.pack("<HI", 4, len(caps)) + caps)
    return encode_header(WireEnvelopeHeader(envelope_type=int(EnvelopeType.RUNTIME_REGISTER), payload_len=len(payload))) + payload


def test_decision_registration_shared_cpp_golden():
    reg = decode_runtime_registration(DECISION_REGISTRATION_GOLDEN)
    assert reg is not None
    assert reg.capabilities.descriptor.supported_profiles == [RuntimeProfile.DECISION]
    assert reg.capabilities.descriptor.supported_decision_models == [DecisionModelDescriptor("d", "v1", "choice")]
    assert encode_runtime_registration(reg) == DECISION_REGISTRATION_GOLDEN


@pytest.mark.parametrize("profile", [RuntimeProfile.VISION, RuntimeProfile.DECISION])
def test_profile_registration_roundtrip_and_negative_relations(profile):
    reg = _profile_registration(profile)
    raw = encode_runtime_registration(reg)
    assert encode_runtime_registration(decode_runtime_registration(raw)) == raw
    for change in ("missing_profile", "missing_descriptor", "unadvertised", "duplicate", "long_revision"):
        bad = copy.deepcopy(reg)
        d = bad.capabilities.descriptor
        descriptors = d.supported_decision_models if profile == RuntimeProfile.DECISION else d.supported_vision_models
        if change == "missing_profile":
            d.supported_profiles = [RuntimeProfile.CHAT]
        elif change == "missing_descriptor":
            descriptors.clear()
        elif change == "unadvertised":
            descriptors[0].model_id = "other"
        elif change == "duplicate":
            descriptors.append(copy.deepcopy(descriptors[0]))
        else:
            descriptors[0].model_revision = "x" * 257
        with pytest.raises(ValueError):
            encode_runtime_registration(bad)
        assert decode_runtime_registration(_unchecked_registration(bad)) is None


@pytest.mark.parametrize("profile", [RuntimeProfile.VISION, RuntimeProfile.DECISION])
@pytest.mark.parametrize("operation", [RegistrationOperation.RESULT, RegistrationOperation.DRAINING, RegistrationOperation.CAPACITY_UPDATE])
def test_lifecycle_does_not_silently_drop_descriptors(profile, operation):
    reg = RuntimeRegistrationEnvelope(operation=operation, status_code=200 if operation == RegistrationOperation.RESULT else 0)
    desc = _profile_registration(profile).capabilities.descriptor
    reg.capabilities.descriptor.supported_vision_models = desc.supported_vision_models
    reg.capabilities.descriptor.supported_decision_models = desc.supported_decision_models
    with pytest.raises(ValueError):
        encode_runtime_registration(reg)


def test_decision_registration_count_boundary():
    reg = _profile_registration(RuntimeProfile.DECISION)
    d = reg.capabilities.descriptor
    d.supported_decision_models = [DecisionModelDescriptor(f"m{i}", "", "choice") for i in range(1024)]
    d.supported_models = [m.model_id for m in d.supported_decision_models]
    assert decode_runtime_registration(encode_runtime_registration(reg)) is not None
    d.supported_models.append("extra")
    d.supported_decision_models.append(DecisionModelDescriptor("extra", "", "choice"))
    with pytest.raises(ValueError):
        encode_runtime_registration(reg)
    assert decode_runtime_registration(_unchecked_registration(reg)) is None


def test_registration_unknown_profile_stays_rejected():
    reg = _make_valid_registration()
    reg.capabilities.descriptor.supported_profiles = [6]
    with pytest.raises(ValueError):
        encode_runtime_registration(reg)
    assert decode_runtime_registration(_unchecked_registration(reg)) is None


def test_registration_descriptor_bytes_are_in_budget():
    reg = _profile_registration(RuntimeProfile.VISION)
    reg.capabilities.descriptor.supported_vision_models[0].custom_labels = ["x" * 256] * 256
    with pytest.raises(ValueError):
        encode_runtime_registration(reg)
    # UTF-8 limits count bytes, not Python code points.
    reg = _profile_registration(RuntimeProfile.DECISION)
    reg.capabilities.descriptor.supported_decision_models[0].model_revision = "ä" * 129
    with pytest.raises(ValueError):
        encode_runtime_registration(reg)


def test_vision_registration_preserves_existing_custom_label_limit():
    reg = _profile_registration(RuntimeProfile.VISION)
    vm = reg.capabilities.descriptor.supported_vision_models[0]
    vm.label_set_id = "custom:test"
    vm.custom_labels = [f"label{i}" for i in range(2048)]
    assert decode_runtime_registration(encode_runtime_registration(reg)) is not None
    vm.custom_labels.append("extra")
    with pytest.raises(ValueError):
        encode_runtime_registration(reg)


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
