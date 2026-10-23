"""TrunkSession: lease, SESSION_BIND and SL1 against a minimal in-process linepd.

The reference encoders at the top are byte-for-byte those of L.I.A.R.A. OS
scripts/test-linep-session-bind.py, which runs against the real liara-noded
linepd, so the session is pinned to what the deployed trunk accepts.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import socket
import struct
import threading
import zlib

import pytest

from linep.v0_2 import (
    ControlMessageType,
    EmbeddingPayload,
    EmbeddingSpaceDescriptor,
    EnvelopeType,
    EventEnvelope,
    EventType,
    MessageDirection,
    NodeEndpointIdentity,
    RuntimeErrorPayload,
    SessionBindEnvelope,
    Sl1Credentials,
    StreamIdentity,
    TerminalOutcome,
    TrunkError,
    TrunkSession,
    decode_control_datagram,
    decode_header,
    decode_request,
    encode_control_datagram,
    encode_event,
    encode_session_bind,
    sign_envelope,
    verify_envelope,
)
from linep.v0_2.trunk import _CLIENT_TCP_PORT, _FLAG_TRUNK_READY

KEY = bytes(range(32))
KEY_ID = 2042

# ---- reference encoders (L.I.A.R.A. OS scripts/test-linep-session-bind.py) ----
UDP_MAGIC, MAGIC = 0x504E4C55, 0x504E4C32


def ref_datagram(mtype, ident, seq, epoch, lease=0, flags=0x01, tcp_port=40000):
    node, rt, ep = ident
    body = struct.pack("<IBBBBQQIQQBBBBIIQHHQ", UDP_MAGIC, 0, 2, mtype, flags, node, rt, ep, seq, epoch,
                       2, 1, 0, 0, 0, 0, 0, tcp_port, 0, lease)
    return body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)


def ref_bind_frame(ident, epoch, lease):
    payload = struct.pack("<QQIQQ", ident[0], ident[1], ident[2], epoch, lease)
    return struct.pack("<IBBBBQQII", MAGIC, 0, 2, 5, 0, 0, 0, 0, len(payload)) + payload


def ref_sl1_sign(plain, seq, kid, key, binding):
    header = bytearray(plain[:32])
    header[7] |= 0x01
    header = bytes(header)
    payload = plain[32:]
    node, rt, ep, epoch, lease = binding
    msg = (header + struct.pack("<IHH", seq, kid, 0) + struct.pack("<QQIQQ", node, rt, ep, epoch, lease)
           + bytes([1, 0, 0, 0]) + payload)
    mac = hmac.new(key, msg, hashlib.sha256).digest()[:16]
    return header + struct.pack("<IHH", seq, kid, 0) + mac + payload


# ---- fake linepd -------------------------------------------------------------
class FakeLinepd:
    """UDP control plane + one-connection TCP trunk with SL1 (auth = "required")."""

    def __init__(self, key: bytes = KEY, embed_dims: int = 4):
        self.key = key
        self.embed_dims = embed_dims
        self.lease = 0xC0FFEE
        self.datagrams = []
        self.binding = None
        self.requests = []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen(4)
        self.control_port = self.udp.getsockname()[1]
        self.trunk_port = self.tcp.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._udp_loop, daemon=True).start()
        threading.Thread(target=self._tcp_loop, daemon=True).start()

    def close(self):
        self._stop.set()
        self.udp.close()
        self.tcp.close()

    def _udp_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self.udp.recvfrom(256)
            except OSError:
                return
            d = decode_control_datagram(data)
            if d is None:
                continue
            self.datagrams.append(d)
            if d.message_type == int(ControlMessageType.NODE_HELLO):
                invite = dataclasses.replace(d, message_type=int(ControlMessageType.INVITE), lease_token=self.lease)
                self.udp.sendto(encode_control_datagram(invite), addr)

    def _recv_exact(self, conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _read(self, conn):
        hdr = self._recv_exact(conn, 32)
        if hdr is None:
            return None
        plen = struct.unpack("<I", hdr[28:32])[0]
        ext = 24 if hdr[7] & 0x01 else 0
        rest = self._recv_exact(conn, ext + plen) if ext + plen else b""
        return None if rest is None else hdr + rest

    def _tcp_loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _fail_unsigned(self, conn, code, msg):
        evt = EventEnvelope(stream=StreamIdentity(), event_seq=0, event_type=EventType.FAILED,
                            outcome=TerminalOutcome.FAILED, error=RuntimeErrorPayload(code=code, message=msg))
        conn.sendall(encode_event(evt))
        conn.close()

    def _serve(self, conn):
        out_seq = 0
        raw = self._read(conn)
        if raw is None:
            return
        if not raw[7] & 0x01:
            return self._fail_unsigned(conn, 401, "auth_required")
        payload = raw[56:]
        node, rt, ep, epoch, lease = struct.unpack("<QQIQQ", payload)
        binding = SessionBindEnvelope(identity=NodeEndpointIdentity(node, rt, ep), control_epoch=epoch,
                                      lease_token=lease)
        ok, ext, _, _ = verify_envelope(raw, binding, MessageDirection.INITIATOR_TO_RESPONDER, self.key)
        if not ok:
            return self._fail_unsigned(conn, 401, "auth_invalid")
        if lease != self.lease or not any(d.message_type == int(ControlMessageType.LEASE_ACK) for d in self.datagrams):
            return self._fail_unsigned(conn, 401, "lease_invalid")
        self.binding = binding
        out_seq += 1
        conn.sendall(sign_envelope(encode_session_bind(binding), binding, MessageDirection.RESPONDER_TO_INITIATOR,
                                   out_seq, ext.key_id, self.key))
        while True:
            raw = self._read(conn)
            if raw is None:
                return
            ok, ext, payload, _ = verify_envelope(raw, binding, MessageDirection.INITIATOR_TO_RESPONDER, self.key)
            if not ok:
                return self._fail_unsigned(conn, 401, "auth_invalid")
            plain = bytes([*raw[:7], raw[7] & ~0x01]) + raw[8:32] + payload
            if decode_header(plain).envelope_type != int(EnvelopeType.REQUEST):
                continue
            req = decode_request(plain)
            self.requests.append(req)
            for evt in self._answer(req):
                out_seq += 1
                conn.sendall(sign_envelope(encode_event(evt), binding, MessageDirection.RESPONDER_TO_INITIATOR,
                                           out_seq, ext.key_id, self.key))

    def _answer(self, req):
        if req.model_id == "task:missing":
            yield EventEnvelope(stream=req.stream, event_seq=1, event_type=EventType.FAILED,
                                outcome=TerminalOutcome.FAILED,
                                error=RuntimeErrorPayload(code=404, message="model_not_found"))
            return
        vec = [float(len(req.payload))] + [0.5] * (self.embed_dims - 1)
        space = EmbeddingSpaceDescriptor(embedding_space_id="test-space", model_id=req.model_id,
                                         dimensions=self.embed_dims)
        yield EventEnvelope(stream=req.stream, event_seq=1, event_type=EventType.EMBEDDING_RESULT,
                            embedding=EmbeddingPayload(space=space, vector=vec))
        yield EventEnvelope(stream=req.stream, event_seq=2, event_type=EventType.COMPLETED,
                            outcome=TerminalOutcome.COMPLETED)


@pytest.fixture
def linepd():
    server = FakeLinepd()
    yield server
    server.close()


def session(server, key=KEY, **kw):
    return TrunkSession("127.0.0.1", trunk_port=server.trunk_port, control_port=server.control_port,
                        credentials=Sl1Credentials(KEY_ID, key), timeout=5.0, **kw)


# ---- wire compatibility with the deployed trunk ------------------------------
def test_control_datagrams_match_the_reference_encoder():
    s = TrunkSession("127.0.0.1")
    s._identity, s._epoch, s._control_seq = NodeEndpointIdentity(77, 3, 1), 9, 0
    assert s._datagram(ControlMessageType.NODE_HELLO) == ref_datagram(1, (77, 3, 1), 1, 9)
    assert s._datagram(ControlMessageType.LEASE_ACK, 1234) == ref_datagram(5, (77, 3, 1), 2, 9, 1234)
    assert _FLAG_TRUNK_READY == 0x01 and _CLIENT_TCP_PORT == 40000


def test_signed_bind_matches_the_reference_signer():
    binding = SessionBindEnvelope(identity=NodeEndpointIdentity(77, 3, 1), control_epoch=9, lease_token=1234)
    plain = encode_session_bind(binding)
    assert plain == ref_bind_frame((77, 3, 1), 9, 1234)
    ours = sign_envelope(plain, binding, MessageDirection.INITIATOR_TO_RESPONDER, 1, KEY_ID, KEY)
    assert ours == ref_sl1_sign(plain, 1, KEY_ID, KEY, (77, 3, 1, 9, 1234))


# ---- credentials ---------------------------------------------------------------
def test_credentials_from_file(tmp_path):
    f = tmp_path / "linep-sl1.key"
    f.write_text("# client key\nkey_id = 2001\nkey = " + KEY.hex() + "\n", encoding="utf-8")
    c = Sl1Credentials.from_file(f)
    assert (c.key_id, c.key) == (2001, KEY)
    assert KEY.hex() not in repr(c)


@pytest.mark.parametrize("text", ["key = " + KEY.hex(), "key_id = 7", "key_id = 7\nkey = 00ff"])
def test_credentials_reject_incomplete_files(tmp_path, text):
    f = tmp_path / "bad.key"
    f.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError):
        Sl1Credentials.from_file(f)


# ---- session against the fake trunk ------------------------------------------
def test_lease_bind_and_embed(linepd):
    with session(linepd) as s:
        assert s.embed("task:embed-bge", "hallo") == [5.0, 0.5, 0.5, 0.5]
        assert s.embed("task:embed-bge", "LIARA") == [5.0, 0.5, 0.5, 0.5]
    types = [d.message_type for d in linepd.datagrams]
    assert types[:2] == [int(ControlMessageType.NODE_HELLO), int(ControlMessageType.LEASE_ACK)]
    assert linepd.binding.lease_token == linepd.lease
    assert [r.model_id for r in linepd.requests] == ["task:embed-bge", "task:embed-bge"]


def test_runtime_failure_raises_trunk_error(linepd):
    with session(linepd) as s:
        with pytest.raises(TrunkError) as e:
            s.embed("task:missing", "x")
        assert e.value.code == 404 and e.value.reason == "model_not_found"


def test_wrong_key_is_rejected_unsigned(linepd):
    with pytest.raises(TrunkError) as e:
        session(linepd, key=bytes(32)).connect()
    assert e.value.code == 401 and e.value.reason == "auth_invalid"


def test_no_invite_means_no_session():
    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind(("127.0.0.1", 0))
    try:
        s = TrunkSession("127.0.0.1", control_port=silent.getsockname()[1],
                         credentials=Sl1Credentials(KEY_ID, KEY), timeout=0.5)
        with pytest.raises(TrunkError):
            s.connect()
        assert not s.is_connected()
    finally:
        silent.close()


def test_heartbeats_keep_the_lease(linepd):
    with session(linepd, heartbeat_interval=0.05) as s:
        threading.Event().wait(0.3)
        assert s.is_connected()
    beats = [d for d in linepd.datagrams if d.message_type == int(ControlMessageType.HEARTBEAT)]
    assert len(beats) >= 2
    assert all(b.lease_token == linepd.lease for b in beats)
    assert [b.control_seq for b in beats] == sorted(b.control_seq for b in beats)
