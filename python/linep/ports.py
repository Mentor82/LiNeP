from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PortPair:
    """Explicit LiNeP port configuration.

    LiNeP uses two different transports and therefore two distinct ports:
    - tcp_port: TASK/RESULT over TCP
    - udp_port: HEARTBEAT over UDP
    """

    tcp_port: int
    udp_port: int

    def __post_init__(self) -> None:
        if not (1 <= int(self.tcp_port) <= 65535):
            raise ValueError(f"tcp_port must be in range 1..65535, got {self.tcp_port}")
        if not (1 <= int(self.udp_port) <= 65535):
            raise ValueError(f"udp_port must be in range 1..65535, got {self.udp_port}")
        if int(self.tcp_port) == int(self.udp_port):
            raise ValueError("tcp_port and udp_port must be different")
