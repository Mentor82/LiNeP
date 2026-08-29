"""LiNeP V0.2 UDP Control Plane Datagrams, Serialization, and Router State Machine."""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, Optional, Tuple

from linep.v0_2.constants import (
    LINEP_V02_UDP_MAGIC,
    LINEP_V02_UDP_DATAGRAM_SIZE,
    ControlMessageType,
    NodeAvailability,
    NodeHealth,
    NodeLifecycle,
)


@dataclass(frozen=True)
class NodeEndpointIdentity:
    node_id: int = 0
    runtime_id: int = 0
    endpoint_id: int = 0

    def is_valid(self) -> bool:
        return self.node_id > 0 and self.runtime_id > 0


@dataclass
class UdpControlDatagram:
    magic: int = LINEP_V02_UDP_MAGIC
    version_major: int = 0
    version_minor: int = 2
    message_type: int = int(ControlMessageType.NODE_HELLO)
    flags: int = 0
    node_id: int = 0
    runtime_id: int = 0
    endpoint_id: int = 0
    control_seq: int = 0
    control_epoch: int = 0
    availability: int = int(NodeAvailability.AVAILABLE)
    health: int = int(NodeHealth.HEALTHY)
    load_pct: int = 0
    reserved: int = 0
    queue_depth: int = 0
    capability_revision: int = 0
    capability_digest: int = 0
    tcp_port: int = 0
    reserved2: int = 0
    lease_token: int = 0
    crc32: int = 0

    def is_trunk_ready(self) -> bool:
        return (self.flags & 0x01) != 0

    def set_trunk_ready(self, ready: bool) -> None:
        if ready:
            self.flags |= 0x01
        else:
            self.flags &= ~0x01


def calc_crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def encode_control_datagram(dgram: UdpControlDatagram) -> bytes:
    buf = bytearray(LINEP_V02_UDP_DATAGRAM_SIZE)
    struct.pack_into(
        "<IBBBBQQIQQBBBBIIQHHQ",
        buf,
        0,
        dgram.magic,
        dgram.version_major,
        dgram.version_minor,
        dgram.message_type,
        dgram.flags,
        dgram.node_id,
        dgram.runtime_id,
        dgram.endpoint_id,
        dgram.control_seq,
        dgram.control_epoch,
        dgram.availability,
        dgram.health,
        dgram.load_pct,
        dgram.reserved,
        dgram.queue_depth,
        dgram.capability_revision,
        dgram.capability_digest,
        dgram.tcp_port,
        dgram.reserved2,
        dgram.lease_token,
    )
    crc = calc_crc32(bytes(buf[:76]))
    struct.pack_into("<I", buf, 76, crc)
    return bytes(buf)


def decode_control_datagram(data: bytes) -> Optional[UdpControlDatagram]:
    if len(data) != LINEP_V02_UDP_DATAGRAM_SIZE:
        return None

    expected_crc = struct.unpack_from("<I", data, 76)[0]
    actual_crc = calc_crc32(data[:76])
    if expected_crc != actual_crc:
        return None  # Fail closed on CRC mismatch

    unpacked = struct.unpack_from("<IBBBBQQIQQBBBBIIQHHQ", data, 0)
    (
        magic,
        v_maj,
        v_min,
        msg_type,
        flags,
        node_id,
        runtime_id,
        endpoint_id,
        control_seq,
        control_epoch,
        availability,
        health,
        load_pct,
        reserved,
        queue_depth,
        cap_rev,
        cap_digest,
        tcp_port,
        reserved2,
        lease_token,
    ) = unpacked

    if magic != LINEP_V02_UDP_MAGIC or v_maj != 0 or v_min != 2:
        return None
    if msg_type < int(ControlMessageType.NODE_HELLO) or msg_type > int(ControlMessageType.PONG):
        return None
    if (flags & ~0x01) != 0:
        return None  # Reserved flags must be zero
    if availability > int(NodeAvailability.DEGRADED):
        return None
    if health > int(NodeHealth.UNHEALTHY):
        return None
    if load_pct > 100:
        return None
    if reserved != 0 or reserved2 != 0:
        return None

    return UdpControlDatagram(
        magic=magic,
        version_major=v_maj,
        version_minor=v_min,
        message_type=msg_type,
        flags=flags,
        node_id=node_id,
        runtime_id=runtime_id,
        endpoint_id=endpoint_id,
        control_seq=control_seq,
        control_epoch=control_epoch,
        availability=availability,
        health=health,
        load_pct=load_pct,
        reserved=reserved,
        queue_depth=queue_depth,
        capability_revision=cap_rev,
        capability_digest=cap_digest,
        tcp_port=tcp_port,
        reserved2=reserved2,
        lease_token=lease_token,
        crc32=expected_crc,
    )


@dataclass
class ControlPlaneNodeState:
    identity: NodeEndpointIdentity = field(default_factory=NodeEndpointIdentity)
    state: NodeLifecycle = NodeLifecycle.UNKNOWN
    last_control_epoch: int = 0
    last_inbound_seq: int = 0
    last_outbound_seq: int = 0
    active_lease_token: int = 0
    availability: NodeAvailability = NodeAvailability.UNAVAILABLE
    health: NodeHealth = NodeHealth.UNKNOWN
    load_pct: int = 0
    queue_depth: int = 0
    capability_revision: int = 0
    capability_digest: int = 0
    tcp_port: int = 0
    tcp_trunk_ready: bool = False
    last_seen_us: int = 0

    def is_routable(self) -> bool:
        return (
            (self.state == NodeLifecycle.ACTIVE or self.state == NodeLifecycle.DEGRADED)
            and (self.availability == NodeAvailability.AVAILABLE or self.availability == NodeAvailability.DEGRADED)
            and (self.health == NodeHealth.HEALTHY or self.health == NodeHealth.DEGRADED)
            and self.active_lease_token != 0
            and self.tcp_trunk_ready
            and self.tcp_port > 0
        )

    def has_active_lease(self) -> bool:
        return self.active_lease_token != 0


class ControlPlaneRouter:
    """Normative LiNeP V0.2 UDP Control Plane Router and State Machine."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._nodes: Dict[NodeEndpointIdentity, ControlPlaneNodeState] = {}
        self._capability_cache: Dict[NodeEndpointIdentity, Tuple[int, int]] = {}

    def issue_invite(
        self, id: NodeEndpointIdentity, lease_token: int
    ) -> Optional[UdpControlDatagram]:
        if id.node_id == 0 or lease_token == 0:
            return None
        with self._lock:
            node = self._nodes.get(id)
            if node is None or node.state != NodeLifecycle.SEEN:
                return None  # Invite can ONLY be issued from SEEN state

            node.state = NodeLifecycle.INVITED
            node.active_lease_token = lease_token
            node.last_outbound_seq += 1

            dgram = UdpControlDatagram(
                node_id=id.node_id,
                runtime_id=id.runtime_id,
                endpoint_id=id.endpoint_id,
                control_epoch=node.last_control_epoch,
                control_seq=node.last_outbound_seq,
                message_type=int(ControlMessageType.INVITE),
                lease_token=lease_token,
            )
            return dgram

    def ingest_datagram(self, dgram: UdpControlDatagram, current_time_us: int) -> bool:
        if dgram.node_id == 0:
            return False

        id = NodeEndpointIdentity(dgram.node_id, dgram.runtime_id, dgram.endpoint_id)
        msg_type = ControlMessageType(dgram.message_type)

        # 1. Message Direction Enforcement (Inbound Node -> Scheduler)
        if msg_type in (ControlMessageType.INVITE, ControlMessageType.PING):
            return False  # Unauthorized inbound message direction

        with self._lock:
            node = self._nodes.get(id)

            if node is None:
                if msg_type != ControlMessageType.NODE_HELLO:
                    return False
                node = ControlPlaneNodeState(
                    identity=id,
                    state=NodeLifecycle.SEEN,
                    last_control_epoch=dgram.control_epoch,
                    last_inbound_seq=dgram.control_seq,
                    last_outbound_seq=0,
                    active_lease_token=0,
                    availability=NodeAvailability(dgram.availability),
                    health=NodeHealth(dgram.health),
                    load_pct=dgram.load_pct,
                    queue_depth=dgram.queue_depth,
                    capability_revision=dgram.capability_revision,
                    capability_digest=dgram.capability_digest,
                    tcp_port=dgram.tcp_port,
                    tcp_trunk_ready=dgram.is_trunk_ready(),
                    last_seen_us=current_time_us,
                )
                self._nodes[id] = node
                return True

            # 2. Epoch & Incarnation Pre-Auth Checks
            if dgram.control_epoch < node.last_control_epoch:
                return False  # Stale epoch rejected without mutation

            if dgram.control_epoch > node.last_control_epoch:
                if msg_type != ControlMessageType.NODE_HELLO:
                    return False  # Higher epoch pre-auth reject without mutation
            else:
                if dgram.control_seq <= node.last_inbound_seq:
                    return True  # Replayed/duplicate sequence idempotent no-op

            # 3. Transactional Dispatch
            if msg_type == ControlMessageType.NODE_HELLO:
                if dgram.control_epoch > node.last_control_epoch:
                    self._capability_cache.pop(id, None)
                    node.last_control_epoch = dgram.control_epoch
                    node.state = NodeLifecycle.SEEN
                    node.active_lease_token = 0
                else:
                    if node.state in (NodeLifecycle.INVITED, NodeLifecycle.ACTIVE, NodeLifecycle.DEGRADED):
                        return False  # Protect active lease from same-epoch downgrade
                    node.state = NodeLifecycle.SEEN

                node.tcp_port = dgram.tcp_port
                node.tcp_trunk_ready = dgram.is_trunk_ready()
                node.capability_revision = dgram.capability_revision
                node.capability_digest = dgram.capability_digest
                node.availability = NodeAvailability(dgram.availability)
                node.health = NodeHealth(dgram.health)

                node.last_inbound_seq = dgram.control_seq
                node.last_seen_us = current_time_us
                return True

            elif msg_type == ControlMessageType.LEASE_ACK:
                if (
                    node.state != NodeLifecycle.INVITED
                    or node.active_lease_token == 0
                    or dgram.lease_token != node.active_lease_token
                ):
                    return False
                if not dgram.is_trunk_ready() or dgram.tcp_port == 0:
                    return False

                node.tcp_port = dgram.tcp_port
                node.tcp_trunk_ready = True
                node.availability = NodeAvailability(dgram.availability)
                node.health = NodeHealth(dgram.health)

                if node.health == NodeHealth.DEGRADED or node.availability == NodeAvailability.DEGRADED:
                    node.state = NodeLifecycle.DEGRADED
                else:
                    node.state = NodeLifecycle.ACTIVE

                node.last_inbound_seq = dgram.control_seq
                node.last_seen_us = current_time_us
                return True

            elif msg_type == ControlMessageType.HEARTBEAT:
                if node.state not in (NodeLifecycle.ACTIVE, NodeLifecycle.DEGRADED, NodeLifecycle.COOLING):
                    return False

                node.load_pct = dgram.load_pct
                node.queue_depth = dgram.queue_depth
                node.availability = NodeAvailability(dgram.availability)
                node.health = NodeHealth(dgram.health)

                if node.availability == NodeAvailability.UNAVAILABLE or node.health == NodeHealth.UNHEALTHY:
                    node.state = NodeLifecycle.COOLING
                elif node.health == NodeHealth.DEGRADED or node.availability == NodeAvailability.DEGRADED:
                    node.state = NodeLifecycle.DEGRADED
                elif node.has_active_lease() and node.tcp_trunk_ready and node.tcp_port > 0:
                    node.state = NodeLifecycle.ACTIVE

                node.last_inbound_seq = dgram.control_seq
                node.last_seen_us = current_time_us
                return True

            elif msg_type == ControlMessageType.STATUS:
                if node.state not in (NodeLifecycle.ACTIVE, NodeLifecycle.DEGRADED, NodeLifecycle.COOLING):
                    return False

                node.load_pct = dgram.load_pct
                node.queue_depth = dgram.queue_depth
                node.availability = NodeAvailability(dgram.availability)
                node.health = NodeHealth(dgram.health)
                node.tcp_port = dgram.tcp_port
                node.tcp_trunk_ready = dgram.is_trunk_ready()

                if (
                    node.capability_revision != dgram.capability_revision
                    or node.capability_digest != dgram.capability_digest
                ):
                    self._capability_cache.pop(id, None)
                    node.capability_revision = dgram.capability_revision
                    node.capability_digest = dgram.capability_digest

                if node.availability == NodeAvailability.UNAVAILABLE or node.health == NodeHealth.UNHEALTHY:
                    node.state = NodeLifecycle.COOLING
                elif node.health == NodeHealth.DEGRADED or node.availability == NodeAvailability.DEGRADED:
                    node.state = NodeLifecycle.DEGRADED
                elif node.has_active_lease() and node.tcp_trunk_ready and node.tcp_port > 0:
                    node.state = NodeLifecycle.ACTIVE

                node.last_inbound_seq = dgram.control_seq
                node.last_seen_us = current_time_us
                return True

            elif msg_type == ControlMessageType.PONG:
                if node.state == NodeLifecycle.UNKNOWN:
                    return False
                node.last_inbound_seq = dgram.control_seq
                node.last_seen_us = current_time_us
                return True

            return False

    def select_best_candidate(self) -> Optional[Tuple[NodeEndpointIdentity, int, int]]:
        with self._lock:
            best_node: Optional[ControlPlaneNodeState] = None
            lowest_score = float("inf")

            for node in self._nodes.values():
                if not node.is_routable():
                    continue

                score = (node.load_pct * 10) + (node.queue_depth * 50)
                if node.health == NodeHealth.DEGRADED:
                    score += 5000
                if node.availability == NodeAvailability.DEGRADED:
                    score += 5000

                if score < lowest_score:
                    lowest_score = score
                    best_node = node

            if best_node is None:
                return None
            return (best_node.identity, best_node.tcp_port, best_node.active_lease_token)

    def validate_tcp_session_binding(
        self, id: NodeEndpointIdentity, control_epoch: int, lease_token: int
    ) -> bool:
        with self._lock:
            node = self._nodes.get(id)
            if node is None:
                return False
            return (
                node.state in (NodeLifecycle.ACTIVE, NodeLifecycle.DEGRADED)
                and node.last_control_epoch == control_epoch
                and node.active_lease_token == lease_token
                and lease_token != 0
                and node.tcp_trunk_ready
                and node.tcp_port > 0
            )

    def sweep_stale_nodes(
        self, current_time_us: int, stale_timeout_us: int = 500_000, offline_timeout_us: int = 2_000_000
    ) -> int:
        with self._lock:
            transitions = 0
            for node in self._nodes.values():
                if current_time_us < node.last_seen_us:
                    continue
                elapsed = current_time_us - node.last_seen_us
                if elapsed > offline_timeout_us:
                    if node.state != NodeLifecycle.OFFLINE:
                        node.state = NodeLifecycle.OFFLINE
                        node.active_lease_token = 0
                        transitions += 1
                elif elapsed > stale_timeout_us:
                    if node.state in (NodeLifecycle.ACTIVE, NodeLifecycle.DEGRADED):
                        node.state = NodeLifecycle.COOLING
                        transitions += 1
            return transitions

    def is_capability_cache_valid(self, id: NodeEndpointIdentity) -> bool:
        with self._lock:
            node = self._nodes.get(id)
            if node is None:
                return False
            cached = self._capability_cache.get(id)
            if cached is None:
                return False
            return (
                cached[0] == node.capability_revision
                and cached[1] == node.capability_digest
            )

    def set_cached_capability_valid(self, id: NodeEndpointIdentity, rev: int, digest: int) -> None:
        with self._lock:
            self._capability_cache[id] = (rev, digest)

    def invalidate_capability_cache(self, id: NodeEndpointIdentity) -> None:
        with self._lock:
            self._capability_cache.pop(id, None)

    def get_node_count(self) -> int:
        with self._lock:
            return len(self._nodes)

    def get_routable_node_count(self) -> int:
        with self._lock:
            return sum(1 for n in self._nodes.values() if n.is_routable())

    def get_node_state(self, id: NodeEndpointIdentity) -> Optional[ControlPlaneNodeState]:
        with self._lock:
            return self._nodes.get(id)
