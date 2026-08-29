"""LiNeP V0.2 Protocol Constants and Enums."""

from enum import IntEnum

LINEP_V02_MAGIC: int = 0x504E4C32       # "2LNP" in little-endian (0x32, 0x4C, 0x4E, 0x50)
LINEP_V02_UDP_MAGIC: int = 0x504E4C55   # "ULNP" in little-endian (0x55, 0x4C, 0x4E, 0x50)
LINEP_V02_VERSION_MAJOR: int = 0
LINEP_V02_VERSION_MINOR: int = 2
LINEP_V02_HEADER_SIZE: int = 32
LINEP_V02_UDP_DATAGRAM_SIZE: int = 80
LINEP_V02_MAX_PAYLOAD_SIZE: int = 16 * 1024 * 1024  # 16 MB
LINEP_V02_MAX_EMBEDDING_DIMS: int = 65536

class RuntimeProfile(IntEnum):
    UNSPECIFIED = 0
    GENERATE = 1
    CHAT = 2
    EMBED = 3

class EnvelopeType(IntEnum):
    UNKNOWN = 0
    REQUEST = 1
    EVENT = 2
    CONTROL = 3
    CAPABILITIES = 4

class EventType(IntEnum):
    UNKNOWN = 0
    ACCEPTED = 1
    STARTED = 2
    CONTENT_DELTA = 3
    CONTENT_SNAPSHOT = 4
    REASONING_DELTA = 5
    TOOL_CALL = 6
    EMBEDDING_RESULT = 7
    METRICS = 8
    ERROR = 9
    COMPLETED = 10
    CANCELLED = 11
    FAILED = 12

class ControlType(IntEnum):
    UNKNOWN = 0
    CANCEL = 1
    WINDOW_UPDATE = 2

class TerminalOutcome(IntEnum):
    UNKNOWN = 0
    UNSPECIFIED = 0
    COMPLETED = 1
    CANCELLED = 2
    FAILED = 3

class ErrorCategory(IntEnum):
    NONE = 0
    TRANSIENT = 1
    BAD_REQUEST = 2
    UNAUTHORIZED = 3
    RESOURCE_EXHAUSTED = 4
    MODEL_ERROR = 5
    UNSUPPORTED = 6
    INTERNAL = 7

class EmbeddingNormalization(IntEnum):
    NONE = 0
    L2 = 1

class EmbeddingDistanceMetric(IntEnum):
    UNSPECIFIED = 0
    COSINE = 1
    DOT = 2
    EUCLIDEAN = 3

class ControlMessageType(IntEnum):
    UNKNOWN = 0
    NODE_HELLO = 1
    HEARTBEAT = 2
    STATUS = 3
    INVITE = 4
    LEASE_ACK = 5
    PING = 6
    PONG = 7

class NodeAvailability(IntEnum):
    UNKNOWN = 0
    UNAVAILABLE = 1
    AVAILABLE = 2
    DEGRADED = 3

class NodeHealth(IntEnum):
    UNKNOWN = 0
    HEALTHY = 1
    DEGRADED = 2
    UNHEALTHY = 3

class NodeLifecycle(IntEnum):
    UNKNOWN = 0
    SEEN = 1
    INVITED = 2
    ACTIVE = 3
    DEGRADED = 4
    COOLING = 5
    OFFLINE = 6
