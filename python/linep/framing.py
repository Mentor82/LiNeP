"""
linep.framing
-------------
Pythonic wrappers for LiNeP wire-format construction and validation.

These classes mirror the packed C structs in the wire format but present
them as ordinary Python dataclasses with named fields and proper types.
Conversion to/from the cffi structs is handled transparently.

Example — building a TASK header::

    from linep.framing import Header
    from linep.constants import MsgType, HeaderFlags

    h = Header.build(
        msg_type=MsgType.TASK,
        payload_len=len(payload),
        sequence=1,
        correlation_id=42,
        worker_id=3,
        slot_id=0,
    )
    h.validate()   # raises BadFrameError if CRC is wrong

Example — building and validating a heartbeat::

    from linep.framing import HeartbeatCompact
    from linep.constants import SlotFlags

    hb = HeartbeatCompact.build(
        worker_id=1, slot_id=0,
        slot_flags=SlotFlags.ALIVE | SlotFlags.READY,
        load=12, queue_depth=2, sequence=7,
        worker_score=120,
    )
    raw: bytes = hb.to_bytes()   # 19-byte UDP payload
    hb2 = HeartbeatCompact.from_bytes(raw)
    hb2.validate()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from linep._cabi import ffi, lib
from linep.constants import HeaderFlags, MsgType, SlotFlags
from linep.exceptions import ArgumentError, BadFrameError, raise_for_code

__all__ = [
    "Header",
    "BuildTimeExt",
    "HeartbeatCompact",
    "UdpInviteFrame",
    "UdpInviteAckFrame",
    "UdpHeartbeatAckFrame",
]

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------


@dataclass
class BuildTimeExt:
    """v1.1 build-time extension appended after the base header.

    Encodes the UTC compilation timestamp so receivers can identify which
    build sent a frame.  Only present when
    :attr:`~linep.constants.HeaderFlags.BUILD_TIME` is set.

    Attributes:
        year_2d: Years since 2000 (e.g. ``26`` for 2026).
        month: Month (1–12).
        day: Day (1–31).
        hour: Hour (0–23).
        minute: Minute (0–59).
        second: Second (0–59).
    """

    year_2d: int = 0
    month:   int = 0
    day:     int = 0
    hour:    int = 0
    minute:  int = 0
    second:  int = 0

    def to_datetime(self) -> datetime:
        """Convert to a timezone-aware :class:`datetime.datetime` in UTC.

        Returns:
            The build timestamp as a UTC-aware ``datetime`` object.
        """
        return datetime(
            2000 + self.year_2d, self.month, self.day,
            self.hour, self.minute, self.second,
            tzinfo=timezone.utc,
        )

    def to_bytes(self) -> bytes:
        """Serialise to the 6-byte on-wire representation.

        Returns:
            Exactly 6 bytes in the order ``[year_2d, month, day, hour, minute, second]``.
        """
        return bytes([
            self.year_2d, self.month, self.day,
            self.hour, self.minute, self.second,
        ])

    @classmethod
    def from_build(cls) -> "BuildTimeExt":
        """Create a :class:`BuildTimeExt` from the library's compile-time timestamp.

        This calls ``linep_apply_build_time_ext`` internally and extracts the
        extension bytes that were baked into the shared library at build time.

        Returns:
            A :class:`BuildTimeExt` populated from the library's build timestamp.
        """
        # We only need the ext_out here; build a throwaway header as carrier.
        c_hdr = ffi.new("linep_header_t *")
        c_ext = ffi.new("linep_build_time_ext_t *")
        # make_header fills magic/version/crc so apply_build_time_ext won't reject it.
        lib.linep_make_header(MsgType.PING, 0, 0, 0, 0, 0, 0, c_hdr)
        lib.linep_apply_build_time_ext(c_hdr, c_ext)
        return cls(
            year_2d=c_ext.year_2d,
            month=c_ext.month,
            day=c_ext.day,
            hour=c_ext.hour,
            minute=c_ext.minute,
            second=c_ext.second,
        )


@dataclass
class Header:
    """LiNeP common frame header — 24 bytes on the wire.

    This is the base header prepended to every TCP frame.  It carries routing
    information, a payload length, a monotone sequence counter, and a CRC-8
    over the first 23 bytes.

    Attributes:
        magic: Wire magic bytes (must be ``0x4C4E``).
        version: Protocol version (must be ``0x01``).
        msg_type: Frame type — one of :class:`~linep.constants.MsgType`.
        header_len: Total header size in bytes (24 base, 30 with v1.1 ext).
        flags: Bitmask of :class:`~linep.constants.HeaderFlags`.
        payload_len: Number of payload bytes following the full header.
        sequence: Sender-local monotone counter (wraps at 2³²).
        correlation_id: Ties a TASK request to its RESULT response.
        worker_id: Target or source worker identifier.
        slot_id: Slot on the worker (0–255).
        header_crc: CRC-8 over header bytes 0–22.
        build_time_ext: Present when :attr:`~linep.constants.HeaderFlags.BUILD_TIME`
            is set in ``flags``.
    """

    magic:          int = 0x4C4E
    version:        int = 0x01
    msg_type:       int = 0
    header_len:     int = 24
    flags:          int = 0
    payload_len:    int = 0
    sequence:       int = 0
    correlation_id: int = 0
    worker_id:      int = 0
    slot_id:        int = 0
    header_crc:     int = 0
    build_time_ext: BuildTimeExt | None = field(default=None, repr=False)

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def build(
        cls,
        msg_type: int,
        payload_len: int,
        sequence: int,
        correlation_id: int,
        worker_id: int,
        slot_id: int,
        flags: int = 0,
        with_build_time: bool = False,
    ) -> "Header":
        """Build a header with a valid CRC-8.

        Args:
            msg_type: One of :class:`~linep.constants.MsgType`.
            payload_len: Byte count of the payload that follows this header.
            sequence: Sender-local monotone counter.
            correlation_id: Request/response correlation token.
            worker_id: Target worker id.
            slot_id: Target slot on the worker.
            flags: :class:`~linep.constants.HeaderFlags` bitmask.
            with_build_time: If ``True``, append a v1.1 build-time extension and
                set :attr:`~linep.constants.HeaderFlags.BUILD_TIME` in ``flags``.

        Returns:
            A :class:`Header` with ``header_crc`` correctly computed.

        Raises:
            :exc:`~linep.exceptions.ArgumentError`: If any argument is invalid.
        """
        c_hdr = ffi.new("linep_header_t *")
        rc = lib.linep_make_header(
            msg_type, flags, payload_len, sequence, correlation_id,
            worker_id, slot_id, c_hdr,
        )
        raise_for_code(rc, "Header.build")

        ext: BuildTimeExt | None = None
        if with_build_time:
            c_ext = ffi.new("linep_build_time_ext_t *")
            rc = lib.linep_apply_build_time_ext(c_hdr, c_ext)
            raise_for_code(rc, "Header.build (build_time_ext)")
            ext = BuildTimeExt(
                year_2d=c_ext.year_2d,
                month=c_ext.month,
                day=c_ext.day,
                hour=c_ext.hour,
                minute=c_ext.minute,
                second=c_ext.second,
            )

        return cls(
            magic=c_hdr.magic,
            version=c_hdr.version,
            msg_type=c_hdr.msg_type,
            header_len=c_hdr.header_len,
            flags=c_hdr.flags,
            payload_len=c_hdr.payload_len,
            sequence=c_hdr.sequence,
            correlation_id=c_hdr.correlation_id,
            worker_id=c_hdr.worker_id,
            slot_id=c_hdr.slot_id,
            header_crc=c_hdr.header_crc,
            build_time_ext=ext,
        )

    @classmethod
    def from_bytes(cls, data: bytes | bytearray) -> "Header":
        """Deserialise a :class:`Header` from raw bytes.

        Args:
            data: At least 24 bytes containing a packed LiNeP header.

        Returns:
            The deserialised :class:`Header`.

        Raises:
            :exc:`ValueError`: If ``data`` is shorter than 24 bytes.
        """
        if len(data) < 24:
            raise ValueError(f"Header requires 24 bytes, got {len(data)}")
        c_hdr = ffi.new("linep_header_t *")
        ffi.memmove(c_hdr, data[:24], 24)

        ext: BuildTimeExt | None = None
        if (c_hdr.flags & HeaderFlags.BUILD_TIME) and len(data) >= 30:
            raw_ext = data[24:30]
            ext = BuildTimeExt(
                year_2d=raw_ext[0],
                month=raw_ext[1],
                day=raw_ext[2],
                hour=raw_ext[3],
                minute=raw_ext[4],
                second=raw_ext[5],
            )

        return cls(
            magic=c_hdr.magic,
            version=c_hdr.version,
            msg_type=c_hdr.msg_type,
            header_len=c_hdr.header_len,
            flags=c_hdr.flags,
            payload_len=c_hdr.payload_len,
            sequence=c_hdr.sequence,
            correlation_id=c_hdr.correlation_id,
            worker_id=c_hdr.worker_id,
            slot_id=c_hdr.slot_id,
            header_crc=c_hdr.header_crc,
            build_time_ext=ext,
        )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serialise this header to its on-wire byte representation.

        Includes the 6-byte :class:`BuildTimeExt` if present.

        Returns:
            24 bytes (base), or 30 bytes if ``build_time_ext`` is set.
        """
        c_hdr = ffi.new("linep_header_t *")
        c_hdr.magic          = self.magic
        c_hdr.version        = self.version
        c_hdr.msg_type       = self.msg_type
        c_hdr.header_len     = self.header_len
        c_hdr.flags          = self.flags
        c_hdr.payload_len    = self.payload_len
        c_hdr.sequence       = self.sequence
        c_hdr.correlation_id = self.correlation_id
        c_hdr.worker_id      = self.worker_id
        c_hdr.slot_id        = self.slot_id
        c_hdr.header_crc     = self.header_crc
        raw = bytes(ffi.buffer(c_hdr, 24))
        if self.build_time_ext is not None:
            raw += self.build_time_ext.to_bytes()
        return raw

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> None:
        """Validate magic, version, header_len, and CRC-8.

        Raises:
            :exc:`~linep.exceptions.BadFrameError`: If any field is invalid.
        """
        c_hdr = ffi.new("linep_header_t *")
        ffi.memmove(c_hdr, self.to_bytes()[:24], 24)
        rc = lib.linep_validate_header(c_hdr)
        raise_for_code(rc, "Header.validate")


# ---------------------------------------------------------------------------
# HeartbeatCompact
# ---------------------------------------------------------------------------


@dataclass
class HeartbeatCompact:
    """19-byte UDP heartbeat frame.

    Workers broadcast this frame at regular intervals so the scheduler can
    track slot liveness, load, and queue depth without an open TCP connection.

    Attributes:
        magic: Wire magic bytes (``0x4C4E``).
        version: Protocol version (``0x01``).
        msg_type: Always :attr:`~linep.constants.MsgType.HEARTBEAT` (``0x01``).
        worker_id: Identifies the worker process.
        slot_id: Identifies the inference slot within the worker.
        slot_flags: Bitmask of :class:`~linep.constants.SlotFlags`.
        load: CPU/GPU load in percent (0–100), or
            :data:`~linep.constants.LOAD_UNKNOWN` / :data:`~linep.constants.LOAD_OFFLINE`.
        queue_depth: Pending tasks in the worker queue (0–254, 255 = overflow).
        sequence: 8-bit counter, wraps at 255.
        worker_score: Coworker-computed score (lower is better).
        ts_month: UTC month (1-12).
        ts_day: UTC day (1-31).
        ts_hour: UTC hour (0-23).
        ts_minute: UTC minute (0-59).
        ts_second: UTC second (0-59).
        crc8: CRC-8 over bytes 0-17.
    """

    magic:       int = 0x4C4E
    version:     int = 0x01
    msg_type:    int = MsgType.HEARTBEAT
    worker_id:   int = 0
    slot_id:     int = 0
    slot_flags:  int = 0
    load:        int = 0
    queue_depth: int = 0
    sequence:    int = 0
    worker_score: int = 0
    ts_month:     int = 1
    ts_day:       int = 1
    ts_hour:      int = 0
    ts_minute:    int = 0
    ts_second:    int = 0
    crc8:        int = 0

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def build(
        cls,
        worker_id: int,
        slot_id: int,
        slot_flags: int,
        load: int,
        queue_depth: int,
        sequence: int,
        worker_score: int,
        ts_month: int | None = None,
        ts_day: int | None = None,
        ts_hour: int | None = None,
        ts_minute: int | None = None,
        ts_second: int | None = None,
    ) -> "HeartbeatCompact":
        """Build a heartbeat frame with a valid CRC-8.

        Args:
            worker_id: Worker identifier (``uint16_t``).
            slot_id: Slot index within the worker (``uint8_t``).
            slot_flags: Bitmask of :class:`~linep.constants.SlotFlags`.
            load: Load percentage (0–100) or
                :data:`~linep.constants.LOAD_UNKNOWN` / :data:`~linep.constants.LOAD_OFFLINE`.
            queue_depth: Number of queued tasks (0–254).
            sequence: Wrapping 8-bit sequence counter.
            worker_score: Coworker-computed score.

        Returns:
            A :class:`HeartbeatCompact` with ``crc8`` correctly computed.

        Raises:
            :exc:`~linep.exceptions.ArgumentError`: If any argument is out of range.
        """
        if None in (ts_month, ts_day, ts_hour, ts_minute, ts_second):
            now = datetime.now(timezone.utc)
            ts_month = now.month
            ts_day = now.day
            ts_hour = now.hour
            ts_minute = now.minute
            ts_second = now.second

        c_hb = ffi.new("linep_heartbeat_compact_t *")
        rc = lib.linep_make_heartbeat_compact(
            worker_id, slot_id, slot_flags, load, queue_depth, sequence,
            worker_score,
            ts_month, ts_day, ts_hour, ts_minute, ts_second,
            c_hb,
        )
        raise_for_code(rc, "HeartbeatCompact.build")
        return cls(
            magic=c_hb.magic,
            version=c_hb.version,
            msg_type=c_hb.msg_type,
            worker_id=c_hb.worker_id,
            slot_id=c_hb.slot_id,
            slot_flags=c_hb.slot_flags,
            load=c_hb.load,
            queue_depth=c_hb.queue_depth,
            sequence=c_hb.sequence,
            worker_score=c_hb.worker_score,
            ts_month=c_hb.ts_month,
            ts_day=c_hb.ts_day,
            ts_hour=c_hb.ts_hour,
            ts_minute=c_hb.ts_minute,
            ts_second=c_hb.ts_second,
            crc8=c_hb.crc8,
        )

    @classmethod
    def from_bytes(cls, data: bytes | bytearray) -> "HeartbeatCompact":
        """Deserialise from exactly 19 raw bytes.

        Args:
            data: At least 19 bytes of a packed heartbeat frame.

        Returns:
            A :class:`HeartbeatCompact` populated from the raw bytes.

        Raises:
            :exc:`ValueError`: If ``data`` is shorter than 19 bytes.
        """
        if len(data) < 19:
            raise ValueError(f"HeartbeatCompact requires 19 bytes, got {len(data)}")
        c_hb = ffi.new("linep_heartbeat_compact_t *")
        ffi.memmove(c_hb, data[:19], 19)
        return cls(
            magic=c_hb.magic,
            version=c_hb.version,
            msg_type=c_hb.msg_type,
            worker_id=c_hb.worker_id,
            slot_id=c_hb.slot_id,
            slot_flags=c_hb.slot_flags,
            load=c_hb.load,
            queue_depth=c_hb.queue_depth,
            sequence=c_hb.sequence,
            worker_score=c_hb.worker_score,
            ts_month=c_hb.ts_month,
            ts_day=c_hb.ts_day,
            ts_hour=c_hb.ts_hour,
            ts_minute=c_hb.ts_minute,
            ts_second=c_hb.ts_second,
            crc8=c_hb.crc8,
        )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serialise to the 19-byte on-wire representation.

        Returns:
            Exactly 19 bytes.
        """
        c_hb = ffi.new("linep_heartbeat_compact_t *")
        c_hb.magic       = self.magic
        c_hb.version     = self.version
        c_hb.msg_type    = self.msg_type
        c_hb.worker_id   = self.worker_id
        c_hb.slot_id     = self.slot_id
        c_hb.slot_flags  = self.slot_flags
        c_hb.load        = self.load
        c_hb.queue_depth = self.queue_depth
        c_hb.sequence    = self.sequence
        c_hb.worker_score = self.worker_score
        c_hb.ts_month    = self.ts_month
        c_hb.ts_day      = self.ts_day
        c_hb.ts_hour     = self.ts_hour
        c_hb.ts_minute   = self.ts_minute
        c_hb.ts_second   = self.ts_second
        c_hb.crc8        = self.crc8
        return bytes(ffi.buffer(c_hb, 19))

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> None:
        """Validate magic, version, msg_type, and CRC-8.

        Raises:
            :exc:`~linep.exceptions.BadFrameError`: If any field is invalid.
        """
        c_hb = ffi.new("linep_heartbeat_compact_t *")
        ffi.memmove(c_hb, self.to_bytes(), 19)
        rc = lib.linep_validate_heartbeat_compact(c_hb)
        raise_for_code(rc, "HeartbeatCompact.validate")

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def is_ready(self) -> bool:
        """``True`` when the slot is alive and ready to accept tasks."""
        return bool(self.slot_flags & SlotFlags.ALIVE) and bool(
            self.slot_flags & SlotFlags.READY
        )


# ---------------------------------------------------------------------------
# UDP Control Frames
# ---------------------------------------------------------------------------


@dataclass
class UdpInviteFrame:
    """14-byte UDP INVITE control frame (Scheduler -> Coworker)."""

    msg_type:      int = MsgType.INVITE
    invite_seq:    int = 0
    worker_id:     int = 0
    slot_id:       int = 0
    lease_ttl_ms:  int = 1200
    session_token: int = 0
    crc8:          int = 0

    @classmethod
    def build(
        cls,
        invite_seq: int,
        worker_id: int,
        slot_id: int,
        lease_ttl_ms: int,
        session_token: int,
    ) -> "UdpInviteFrame":
        c_inv = ffi.new("linep_udp_invite_t *")
        rc = lib.linep_make_udp_invite(invite_seq, worker_id, slot_id, lease_ttl_ms, session_token, c_inv)
        raise_for_code(rc, "UdpInviteFrame.build")
        return cls(
            msg_type=c_inv.msg_type,
            invite_seq=c_inv.invite_seq,
            worker_id=c_inv.worker_id,
            slot_id=c_inv.slot_id,
            lease_ttl_ms=c_inv.lease_ttl_ms,
            session_token=c_inv.session_token,
            crc8=c_inv.crc8,
        )

    @classmethod
    def from_bytes(cls, data: bytes | bytearray) -> "UdpInviteFrame":
        if len(data) < 14:
            raise ValueError(f"UdpInviteFrame requires 14 bytes, got {len(data)}")
        c_inv = ffi.new("linep_udp_invite_t *")
        ffi.memmove(c_inv, data[:14], 14)
        return cls(
            msg_type=c_inv.msg_type,
            invite_seq=c_inv.invite_seq,
            worker_id=c_inv.worker_id,
            slot_id=c_inv.slot_id,
            lease_ttl_ms=c_inv.lease_ttl_ms,
            session_token=c_inv.session_token,
            crc8=c_inv.crc8,
        )

    def to_bytes(self) -> bytes:
        c_inv = ffi.new("linep_udp_invite_t *")
        c_inv.msg_type      = self.msg_type
        c_inv.invite_seq    = self.invite_seq
        c_inv.worker_id     = self.worker_id
        c_inv.slot_id       = self.slot_id
        c_inv.lease_ttl_ms  = self.lease_ttl_ms
        c_inv.session_token = self.session_token
        c_inv.crc8          = self.crc8
        return bytes(ffi.buffer(c_inv, 14))

    def validate(self) -> None:
        c_inv = ffi.new("linep_udp_invite_t *")
        ffi.memmove(c_inv, self.to_bytes(), 14)
        rc = lib.linep_validate_udp_invite(c_inv)
        raise_for_code(rc, "UdpInviteFrame.validate")


@dataclass
class UdpInviteAckFrame:
    """11-byte UDP INVITE_ACK control frame (Coworker -> Scheduler)."""

    msg_type:      int = MsgType.INVITE_ACK
    invite_seq:    int = 0
    worker_id:     int = 0
    slot_id:       int = 0
    accepted:      int = 1
    session_token: int = 0
    crc8:          int = 0

    @classmethod
    def build(
        cls,
        invite_seq: int,
        worker_id: int,
        slot_id: int,
        accepted: int,
        session_token: int,
    ) -> "UdpInviteAckFrame":
        c_ack = ffi.new("linep_udp_invite_ack_t *")
        rc = lib.linep_make_udp_invite_ack(invite_seq, worker_id, slot_id, accepted, session_token, c_ack)
        raise_for_code(rc, "UdpInviteAckFrame.build")
        return cls(
            msg_type=c_ack.msg_type,
            invite_seq=c_ack.invite_seq,
            worker_id=c_ack.worker_id,
            slot_id=c_ack.slot_id,
            accepted=c_ack.accepted,
            session_token=c_ack.session_token,
            crc8=c_ack.crc8,
        )

    @classmethod
    def from_bytes(cls, data: bytes | bytearray) -> "UdpInviteAckFrame":
        if len(data) < 11:
            raise ValueError(f"UdpInviteAckFrame requires 11 bytes, got {len(data)}")
        c_ack = ffi.new("linep_udp_invite_ack_t *")
        ffi.memmove(c_ack, data[:11], 11)
        return cls(
            msg_type=c_ack.msg_type,
            invite_seq=c_ack.invite_seq,
            worker_id=c_ack.worker_id,
            slot_id=c_ack.slot_id,
            accepted=c_ack.accepted,
            session_token=c_ack.session_token,
            crc8=c_ack.crc8,
        )

    def to_bytes(self) -> bytes:
        c_ack = ffi.new("linep_udp_invite_ack_t *")
        c_ack.msg_type      = self.msg_type
        c_ack.invite_seq    = self.invite_seq
        c_ack.worker_id     = self.worker_id
        c_ack.slot_id       = self.slot_id
        c_ack.accepted      = self.accepted
        c_ack.session_token = self.session_token
        c_ack.crc8          = self.crc8
        return bytes(ffi.buffer(c_ack, 11))

    def validate(self) -> None:
        c_ack = ffi.new("linep_udp_invite_ack_t *")
        ffi.memmove(c_ack, self.to_bytes(), 11)
        rc = lib.linep_validate_udp_invite_ack(c_ack)
        raise_for_code(rc, "UdpInviteAckFrame.validate")


@dataclass
class UdpHeartbeatAckFrame:
    """10-byte UDP HEARTBEAT_ACK control frame (Scheduler -> Coworker)."""

    msg_type:           int = MsgType.HEARTBEAT_ACK
    heartbeat_seq:      int = 0
    worker_id:          int = 0
    slot_id:            int = 0
    scheduler_time_sec: int = 0
    crc8:               int = 0

    @classmethod
    def build(
        cls,
        heartbeat_seq: int,
        worker_id: int,
        slot_id: int,
        scheduler_time_sec: int,
    ) -> "UdpHeartbeatAckFrame":
        c_hb_ack = ffi.new("linep_udp_heartbeat_ack_t *")
        rc = lib.linep_make_udp_heartbeat_ack(heartbeat_seq, worker_id, slot_id, scheduler_time_sec, c_hb_ack)
        raise_for_code(rc, "UdpHeartbeatAckFrame.build")
        return cls(
            msg_type=c_hb_ack.msg_type,
            heartbeat_seq=c_hb_ack.heartbeat_seq,
            worker_id=c_hb_ack.worker_id,
            slot_id=c_hb_ack.slot_id,
            scheduler_time_sec=c_hb_ack.scheduler_time_sec,
            crc8=c_hb_ack.crc8,
        )

    @classmethod
    def from_bytes(cls, data: bytes | bytearray) -> "UdpHeartbeatAckFrame":
        if len(data) < 10:
            raise ValueError(f"UdpHeartbeatAckFrame requires 10 bytes, got {len(data)}")
        c_hb_ack = ffi.new("linep_udp_heartbeat_ack_t *")
        ffi.memmove(c_hb_ack, data[:10], 10)
        return cls(
            msg_type=c_hb_ack.msg_type,
            heartbeat_seq=c_hb_ack.heartbeat_seq,
            worker_id=c_hb_ack.worker_id,
            slot_id=c_hb_ack.slot_id,
            scheduler_time_sec=c_hb_ack.scheduler_time_sec,
            crc8=c_hb_ack.crc8,
        )

    def to_bytes(self) -> bytes:
        c_hb_ack = ffi.new("linep_udp_heartbeat_ack_t *")
        c_hb_ack.msg_type           = self.msg_type
        c_hb_ack.heartbeat_seq      = self.heartbeat_seq
        c_hb_ack.worker_id          = self.worker_id
        c_hb_ack.slot_id            = self.slot_id
        c_hb_ack.scheduler_time_sec = self.scheduler_time_sec
        c_hb_ack.crc8               = self.crc8
        return bytes(ffi.buffer(c_hb_ack, 10))

    def validate(self) -> None:
        c_hb_ack = ffi.new("linep_udp_heartbeat_ack_t *")
        ffi.memmove(c_hb_ack, self.to_bytes(), 10)
        rc = lib.linep_validate_udp_heartbeat_ack(c_hb_ack)
        raise_for_code(rc, "UdpHeartbeatAckFrame.validate")

