"""
LiNeP V0.2 — Dual-Plane Protocol Python Module
==============================================

Exposes high-level pure-Python implementations of the LiNeP V0.2 Dual-Plane
Runtime Baseline:
- 80-Byte UDP Control Plane Datagrams & Router State Machine
- 32-Byte TCP Data Plane Envelopes & Serialization
- Streaming Client & Deterministic Mock Server
- Conformance Test Runner
"""

from linep.v0_2.constants import (
    LINEP_V02_MAGIC,
    LINEP_V02_UDP_MAGIC,
    LINEP_V02_VERSION_MAJOR,
    LINEP_V02_VERSION_MINOR,
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
    NodeAvailability,
    NodeHealth,
    NodeLifecycle,
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
from linep.v0_2.control_plane import (
    UdpControlDatagram,
    NodeEndpointIdentity,
    ControlPlaneNodeState,
    ControlPlaneRouter,
    encode_control_datagram,
    decode_control_datagram,
    calc_crc32,
)
from linep.v0_2.client import LiNePClient
from linep.v0_2.server import LiNePMockServer, MockServerConfig
from linep.v0_2.conformance import (
    ConformanceRunner,
    ConformanceReport,
    TestResult,
    ProfileConformanceStatus,
)

__all__ = [
    # Constants & Enums
    "LINEP_V02_MAGIC",
    "LINEP_V02_UDP_MAGIC",
    "LINEP_V02_VERSION_MAJOR",
    "LINEP_V02_VERSION_MINOR",
    "LINEP_V02_HEADER_SIZE",
    "LINEP_V02_UDP_DATAGRAM_SIZE",
    "RuntimeProfile",
    "EnvelopeType",
    "EventType",
    "ControlType",
    "TerminalOutcome",
    "ErrorCategory",
    "EmbeddingNormalization",
    "EmbeddingDistanceMetric",
    "ControlMessageType",
    "NodeAvailability",
    "NodeHealth",
    "NodeLifecycle",
    # Envelopes
    "StreamIdentity",
    "WireEnvelopeHeader",
    "RequestEnvelope",
    "EventEnvelope",
    "ControlEnvelope",
    "CapabilitiesEnvelope",
    "CapabilitiesDescriptor",
    "EmbeddingSpaceDescriptor",
    "EmbeddingPayload",
    "RuntimeErrorPayload",
    "encode_header",
    "decode_header",
    "peek_envelope_type",
    "encode_request",
    "decode_request",
    "encode_event",
    "decode_event",
    "encode_control",
    "decode_control",
    "encode_capabilities",
    "decode_capabilities",
    # Control Plane
    "UdpControlDatagram",
    "NodeEndpointIdentity",
    "ControlPlaneNodeState",
    "ControlPlaneRouter",
    "encode_control_datagram",
    "decode_control_datagram",
    "calc_crc32",
    # Client & Server
    "LiNePClient",
    "LiNePMockServer",
    "MockServerConfig",
    # Conformance
    "ConformanceRunner",
    "ConformanceReport",
    "TestResult",
    "ProfileConformanceStatus",
]
