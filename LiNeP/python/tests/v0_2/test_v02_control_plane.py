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
