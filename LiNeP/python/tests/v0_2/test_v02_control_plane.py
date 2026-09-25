"""Unit tests for LiNeP V0.2 UDP Control Plane, CRC32, and Router State Machine."""

import time
import pytest
from linep.v0_2 import (
    LINEP_V02_UDP_MAGIC,
    LINEP_V02_UDP_DATAGRAM_SIZE,
    ControlMessageType,
    NodeAvailability,
    NodeHealth,
    NodeLifecycle,
    NodeEndpointIdentity,
    UdpControlDatagram,
    ControlPlaneRouter,
    RuntimeProfile,
    EnvelopeType,
    EventType,
    TerminalOutcome,
    ErrorCategory,
    StreamIdentity,
    RequestEnvelope,
    EventEnvelope,
    SessionBindEnvelope,
    encode_session_bind,
    decode_session_bind,
    decode_event,
    LiNePMockServer,
    MockServerConfig,
    LiNePClient,
    encode_control_datagram,
    decode_control_datagram,
    calc_crc32,
)


def test_udp_datagram_encoding_and_crc():
    dgram = UdpControlDatagram(
        node_id=1001,
        runtime_id=2001,
        endpoint_id=1,
        control_seq=1,
        control_epoch=1,
        message_type=int(ControlMessageType.NODE_HELLO),
        availability=int(NodeAvailability.AVAILABLE),
        health=int(NodeHealth.HEALTHY),
        tcp_port=11435,
    )
    dgram.set_trunk_ready(True)

    raw = encode_control_datagram(dgram)
    assert len(raw) == LINEP_V02_UDP_DATAGRAM_SIZE

    decoded = decode_control_datagram(raw)
    assert decoded is not None
    assert decoded.magic == LINEP_V02_UDP_MAGIC
    assert decoded.node_id == 1001
    assert decoded.runtime_id == 2001
    assert decoded.endpoint_id == 1
    assert decoded.control_seq == 1
    assert decoded.control_epoch == 1
    assert decoded.message_type == int(ControlMessageType.NODE_HELLO)
    assert decoded.is_trunk_ready() is True
    assert decoded.tcp_port == 11435


def test_strict_decoder_rejects_tampering():
    dgram = UdpControlDatagram(node_id=1, runtime_id=1, endpoint_id=1)
    raw = bytearray(encode_control_datagram(dgram))

    # 1. Corrupt payload bit -> CRC mismatch fails closed
    corrupt = bytearray(raw)
    corrupt[10] ^= 0xFF
    assert decode_control_datagram(bytes(corrupt)) is None

    # 2. Corrupt magic
    corrupt_magic = bytearray(raw)
    corrupt_magic[0] = 0x00
    # Recompute CRC to isolate magic check
    crc = calc_crc32(bytes(corrupt_magic[:76]))
    import struct
    struct.pack_into("<I", corrupt_magic, 76, crc)
    assert decode_control_datagram(bytes(corrupt_magic)) is None

    # 3. Reserved flag bit dirty
    dirty_flags = bytearray(raw)
    dirty_flags[7] = 0x02  # Bit 1 is reserved
    crc = calc_crc32(bytes(dirty_flags[:76]))
    struct.pack_into("<I", dirty_flags, 76, crc)
    assert decode_control_datagram(bytes(dirty_flags)) is None

    # 4. load_pct > 100
    invalid_load = bytearray(raw)
    invalid_load[46] = 105
    crc = calc_crc32(bytes(invalid_load[:76]))
    struct.pack_into("<I", invalid_load, 76, crc)
    assert decode_control_datagram(bytes(invalid_load)) is None


def test_normative_lifecycle_hello_invite_lease_active():
    router = ControlPlaneRouter()
    id = NodeEndpointIdentity(1001, 2001, 1)
    now = int(time.time() * 1_000_000)

    # 1. Send NODE_HELLO -> Node becomes SEEN
    hello = UdpControlDatagram(
        node_id=1001,
        runtime_id=2001,
        endpoint_id=1,
        control_seq=1,
        control_epoch=1,
        message_type=int(ControlMessageType.NODE_HELLO),
        tcp_port=11435,
    )
    hello.set_trunk_ready(True)
    assert router.ingest_datagram(hello, now) is True

    st = router.get_node_state(id)
    assert st is not None
    assert st.state == NodeLifecycle.SEEN
    assert st.is_routable() is False  # Not yet invited/active!

    # 2. Router issues INVITE -> Node becomes INVITED
    lease_token = 0xAABBCCDDEEFF0011
    inv = router.issue_invite(id, lease_token)
    assert inv is not None
    assert inv.lease_token == lease_token
    assert inv.message_type == int(ControlMessageType.INVITE)

    st = router.get_node_state(id)
    assert st.state == NodeLifecycle.INVITED
    assert st.active_lease_token == lease_token
    assert st.is_routable() is False

    # 3. Node responds with LEASE_ACK -> Node becomes ACTIVE
    ack = UdpControlDatagram(
        node_id=1001,
        runtime_id=2001,
        endpoint_id=1,
        control_seq=2,
        control_epoch=1,
        message_type=int(ControlMessageType.LEASE_ACK),
        lease_token=lease_token,
        tcp_port=11435,
    )
    ack.set_trunk_ready(True)
    assert router.ingest_datagram(ack, now) is True

    st = router.get_node_state(id)
    assert st.state == NodeLifecycle.ACTIVE
    assert st.is_routable() is True

    # 4. Valid candidate selection
    candidate = router.select_best_candidate()
    assert candidate is not None
    assert candidate[0] == id
    assert candidate[1] == 11435
    assert candidate[2] == lease_token


def test_heartbeat_cannot_bypass_lease_ack():
    router = ControlPlaneRouter()
    id = NodeEndpointIdentity(2001, 3001, 1)
    now = int(time.time() * 1_000_000)

    # Register via HELLO
    hello = UdpControlDatagram(
        node_id=2001, runtime_id=3001, endpoint_id=1, control_seq=1, control_epoch=1,
        message_type=int(ControlMessageType.NODE_HELLO), tcp_port=11435
    )
    hello.set_trunk_ready(True)
    assert router.ingest_datagram(hello, now) is True

    # Issue INVITE
    assert router.issue_invite(id, 0x12345678) is not None

    # Sending HEARTBEAT instead of LEASE_ACK must be REJECTED
    hb = UdpControlDatagram(
        node_id=2001, runtime_id=3001, endpoint_id=1, control_seq=2, control_epoch=1,
        message_type=int(ControlMessageType.HEARTBEAT), tcp_port=11435
    )
    assert router.ingest_datagram(hb, now) is False

    st = router.get_node_state(id)
    assert st.state == NodeLifecycle.INVITED
    assert st.is_routable() is False


def test_inbound_direction_enforcement():
    router = ControlPlaneRouter()
    now = int(time.time() * 1_000_000)

    # Inbound INVITE must be rejected
    inv = UdpControlDatagram(
        node_id=1, runtime_id=1, endpoint_id=1, message_type=int(ControlMessageType.INVITE)
    )
    assert router.ingest_datagram(inv, now) is False

    # Inbound PING must be rejected
    ping = UdpControlDatagram(
        node_id=1, runtime_id=1, endpoint_id=1, message_type=int(ControlMessageType.PING)
    )
    assert router.ingest_datagram(ping, now) is False


def test_same_epoch_hello_does_not_downgrade_active_lease():
    router = ControlPlaneRouter()
    id = NodeEndpointIdentity(5001, 6001, 1)
    now = int(time.time() * 1_000_000)

    # Setup Active node
    hello = UdpControlDatagram(
        node_id=5001, runtime_id=6001, endpoint_id=1, control_seq=1, control_epoch=1,
        message_type=int(ControlMessageType.NODE_HELLO), tcp_port=11435
    )
    hello.set_trunk_ready(True)
    router.ingest_datagram(hello, now)
    router.issue_invite(id, 0x9999)
    ack = UdpControlDatagram(
        node_id=5001, runtime_id=6001, endpoint_id=1, control_seq=2, control_epoch=1,
        message_type=int(ControlMessageType.LEASE_ACK), lease_token=0x9999, tcp_port=11435
    )
    ack.set_trunk_ready(True)
    router.ingest_datagram(ack, now)

    # Delayed same-epoch HELLO must be REJECTED to protect active session
    delayed_hello = UdpControlDatagram(
        node_id=5001, runtime_id=6001, endpoint_id=1, control_seq=3, control_epoch=1,
        message_type=int(ControlMessageType.NODE_HELLO), tcp_port=11435
    )
    assert router.ingest_datagram(delayed_hello, now) is False

    st = router.get_node_state(id)
    assert st.state == NodeLifecycle.ACTIVE
    assert st.active_lease_token == 0x9999

    # Higher-epoch HELLO represents valid new incarnation and resets state to SEEN
    new_incarnation = UdpControlDatagram(
        node_id=5001, runtime_id=6001, endpoint_id=1, control_seq=1, control_epoch=2,
        message_type=int(ControlMessageType.NODE_HELLO), tcp_port=11435
    )
    assert router.ingest_datagram(new_incarnation, now) is True
    st2 = router.get_node_state(id)
    assert st2.state == NodeLifecycle.SEEN
    assert st2.last_control_epoch == 2
    assert st2.active_lease_token == 0


def test_transactional_reject_does_not_consume_seq():
    router = ControlPlaneRouter()
    id = NodeEndpointIdentity(7001, 8001, 1)
    now = int(time.time() * 1_000_000)

    # 1. HELLO seq=1
    hello = UdpControlDatagram(
        node_id=7001, runtime_id=8001, endpoint_id=1, control_seq=1, control_epoch=1,
        message_type=int(ControlMessageType.NODE_HELLO), tcp_port=11435
    )
    hello.set_trunk_ready(True)
    router.ingest_datagram(hello, now)

    # 2. INVITE
    router.issue_invite(id, 0x5555)

    # 3. Rogue HEARTBEAT with seq=1000
    rogue_hb = UdpControlDatagram(
        node_id=7001, runtime_id=8001, endpoint_id=1, control_seq=1000, control_epoch=1,
        message_type=int(ControlMessageType.HEARTBEAT), tcp_port=11435
    )
    assert router.ingest_datagram(rogue_hb, now) is False

    st = router.get_node_state(id)
    assert st.last_inbound_seq == 1  # seq=1000 NOT consumed!

    # 4. Legitimate LEASE_ACK with seq=2 must succeed!
    valid_ack = UdpControlDatagram(
        node_id=7001, runtime_id=8001, endpoint_id=1, control_seq=2, control_epoch=1,
        message_type=int(ControlMessageType.LEASE_ACK), lease_token=0x5555, tcp_port=11435
    )
    valid_ack.set_trunk_ready(True)
    assert router.ingest_datagram(valid_ack, now) is True

    st_after = router.get_node_state(id)
    assert st_after.state == NodeLifecycle.ACTIVE
    assert st_after.last_inbound_seq == 2


def test_tcp_server_session_bind_lease_enforcement():
    """Verify Issue #15: Server rejects UNBOUND requests, rejects invalid BIND with 401,
    accepts valid BIND idempotently, and serves requests once BOUND."""
    router = ControlPlaneRouter()
    node_id = NodeEndpointIdentity(9001, 10001, 1)
    now = int(time.time() * 1_000_000)

    # 1. Establish ACTIVE lease in control plane
    hello = UdpControlDatagram(
        node_id=9001, runtime_id=10001, endpoint_id=1, control_seq=1, control_epoch=1,
        message_type=int(ControlMessageType.NODE_HELLO), tcp_port=11435
    )
    hello.set_trunk_ready(True)
    assert router.ingest_datagram(hello, now) is True

    lease_token = 0xAABBCCDDEEFF0011
    assert router.issue_invite(node_id, lease_token) is not None

    ack = UdpControlDatagram(
        node_id=9001, runtime_id=10001, endpoint_id=1, control_seq=2, control_epoch=1,
        message_type=int(ControlMessageType.LEASE_ACK), lease_token=lease_token, tcp_port=11435
    )
    ack.set_trunk_ready(True)
    assert router.ingest_datagram(ack, now) is True
    assert router.validate_tcp_session_binding(node_id, 1, lease_token) is True

    # 2. Start mock server requiring lease validation
    cfg = MockServerConfig(model_id="test-model", require_lease=True, router=router)
    server = LiNePMockServer(cfg)
    server.start(tcp_port=0)

    try:
        # A. UNBOUND Connection: submitting REQUEST directly must be rejected with 401
        with LiNePClient(port=server.tcp_port) as client_unbound:
            req = RequestEnvelope(
                stream=StreamIdentity(10, 100, 0),
                profile=RuntimeProfile.CHAT,
                model_id="test-model",
                payload="Prompt without bind",
                stream_requested=False,
            )
            events = list(client_unbound.execute_stream(req))
            assert len(events) == 1
            assert events[0].outcome == TerminalOutcome.FAILED
            assert events[0].error.code == 401
            assert "UNBOUND" in events[0].error.message

        # B. Connection with INVALID SESSION_BIND (tampered token): server emits 401 and disconnects
        with LiNePClient(port=server.tcp_port) as client_invalid:
            bad_bind = SessionBindEnvelope(
                identity=node_id,
                control_epoch=1,
                lease_token=0xDEADBEEF,
            )
            client_invalid.send_session_bind(bad_bind)
            raw_evt = client_invalid._recv_envelope()
            evt = decode_event(raw_evt)
            assert evt is not None
            assert evt.stream.is_connection_level() is True
            assert evt.error.code == 401
            assert evt.error.message == "lease_invalid"

        # B2. Connection with SYNTACTICALLY MALFORMED SESSION_BIND (dirty flags): server emits 400 invalid_session_bind and disconnects
        with LiNePClient(port=server.tcp_port) as client_malformed:
            good_bind = SessionBindEnvelope(
                identity=node_id,
                control_epoch=1,
                lease_token=lease_token,
            )
            malformed_bytes = bytearray(encode_session_bind(good_bind))
            malformed_bytes[7] = 0x01  # dirty flags (byte 7) -> syntactic decode fails!
            client_malformed._send_all(bytes(malformed_bytes))
            raw_evt = client_malformed._recv_envelope()
            evt = decode_event(raw_evt)
            assert evt is not None
            assert evt.stream.is_connection_level() is True
            assert evt.error.code == 400
            assert evt.error.message == "invalid_session_bind"

        # C. Connection with VALID SESSION_BIND + IDEMPOTENT DUPLICATE: succeeds and processes requests
        with LiNePClient(port=server.tcp_port) as client_valid:
            valid_bind = SessionBindEnvelope(
                identity=node_id,
                control_epoch=1,
                lease_token=lease_token,
            )
            client_valid.send_session_bind(valid_bind)
            # Duplicate idempotent bind
            client_valid.send_session_bind(valid_bind)

            req = RequestEnvelope(
                stream=StreamIdentity(20, 200, 0),
                profile=RuntimeProfile.CHAT,
                model_id="test-model",
                payload="Prompt with valid bind",
                stream_requested=False,
            )
            events = list(client_valid.execute_stream(req))
            assert len(events) > 0
            assert events[-1].outcome == TerminalOutcome.COMPLETED

        # D. Identity change on existing connection -> Server emits connection-level 401 and disconnects
        with LiNePClient(port=server.tcp_port) as client_id_change:
            valid_bind = SessionBindEnvelope(
                identity=node_id,
                control_epoch=1,
                lease_token=lease_token,
            )
            client_id_change.send_session_bind(valid_bind)

            # Attempt to change identity to different node_id on same TCP connection
            changed_bind = SessionBindEnvelope(
                identity=NodeEndpointIdentity(9999, 10001, 1),
                control_epoch=1,
                lease_token=lease_token,
            )
            client_id_change.send_session_bind(changed_bind)
            raw_evt = client_id_change._recv_envelope()
            evt = decode_event(raw_evt)
            assert evt is not None
            assert evt.stream.is_connection_level() is True
            assert evt.error.code == 401
            assert evt.error.message == "identity_change_on_existing_connection"

        # E. Stale binding: request rejected with 401, connection STAYS OPEN, re-bind with new lease, request succeeds!
        with LiNePClient(port=server.tcp_port) as client_stale:
            bind_ep1 = SessionBindEnvelope(
                identity=node_id,
                control_epoch=1,
                lease_token=lease_token,
            )
            client_stale.send_session_bind(bind_ep1)

            # Send first request to confirm BOUND_CURRENT
            req1 = RequestEnvelope(
                stream=StreamIdentity(30, 300, 0),
                profile=RuntimeProfile.CHAT,
                model_id="test-model",
                payload="First prompt",
                stream_requested=False,
            )
            evts1 = list(client_stale.execute_stream(req1))
            assert evts1[-1].outcome == TerminalOutcome.COMPLETED

            # Rotate lease on router to epoch 2, token 0x9988776655443322
            rotated_token = 0x9988776655443322
            hello2 = UdpControlDatagram(
                node_id=9001, runtime_id=10001, endpoint_id=1, control_seq=1, control_epoch=2,
                message_type=int(ControlMessageType.NODE_HELLO), tcp_port=11435
            )
            hello2.set_trunk_ready(True)
            assert router.ingest_datagram(hello2, now + 1000) is True
            assert router.issue_invite(node_id, rotated_token) is not None
            ack2 = UdpControlDatagram(
                node_id=9001, runtime_id=10001, endpoint_id=1, control_seq=2, control_epoch=2,
                message_type=int(ControlMessageType.LEASE_ACK), lease_token=rotated_token, tcp_port=11435
            )
            ack2.set_trunk_ready(True)
            assert router.ingest_datagram(ack2, now + 2000) is True

            # Send request on old stale binding: MUST BE REJECTED with 401, BUT TCP CONNECTION STAYS OPEN!
            req_stale = RequestEnvelope(
                stream=StreamIdentity(31, 310, 0),
                profile=RuntimeProfile.CHAT,
                model_id="test-model",
                payload="Prompt while stale",
                stream_requested=False,
            )
            stale_evts = list(client_stale.execute_stream(req_stale))
            assert len(stale_evts) == 1
            assert stale_evts[0].outcome == TerminalOutcome.FAILED
            assert stale_evts[0].error.code == 401
            assert "stale_binding" in stale_evts[0].error.message

            # Connection is STILL OPEN! Re-bind with epoch 2 on the SAME connection!
            bind_ep2 = SessionBindEnvelope(
                identity=node_id,
                control_epoch=2,
                lease_token=rotated_token,
            )
            client_stale.send_session_bind(bind_ep2)

            # Now submit request again -> SUCCEEDS!
            req_rebound = RequestEnvelope(
                stream=StreamIdentity(32, 320, 0),
                profile=RuntimeProfile.CHAT,
                model_id="test-model",
                payload="Prompt after re-bind",
                stream_requested=False,
            )
            rebound_evts = list(client_stale.execute_stream(req_rebound))
            assert len(rebound_evts) > 0
            assert rebound_evts[-1].outcome == TerminalOutcome.COMPLETED

    finally:
        server.stop()

