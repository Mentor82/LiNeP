from __future__ import annotations

from enum import IntFlag

__all__ = ["CapFlags"]


class CapFlags(IntFlag):
    """Bitmask for SL2 role-based capabilities."""

    NONE            = 0x00
    INFERENCE_READ  = 0x01
    INFERENCE_WRITE = 0x02
    ADMIN           = 0x04
    SLOT_MANAGE     = 0x08
    METRICS_READ    = 0x10
    HEARTBEAT_EMIT  = 0x20
