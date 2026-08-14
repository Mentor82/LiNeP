from __future__ import annotations

import os
import sys
import socket
import threading
import time
from pathlib import Path
import pytest


def _ensure_linep_sl_lib_path() -> None:
    if os.environ.get("LINEP_SL_LIB_PATH"):
        return
    repo_root = Path(__file__).resolve().parents[2]
    if sys.platform == "win32":
        candidate = repo_root / "build" / "src" / "liblinep_sl.dll"
    else:
        candidate = repo_root / "build_linux" / "src" / "liblinep_sl.so"
    if candidate.exists():
        os.environ["LINEP_SL_LIB_PATH"] = str(candidate)


def test_cross_platform_tcp_interop():
    _ensure_linep_sl_lib_path()
    import linep_sl

    trust_domain = 0x4C4E5031  # "LNP1"
    master_secret = b"WIN_DEBIAN_INTEROP_MASTER_SECRET"

    # 1. Identity setup
    pubkey_windows = b"\xaa" * 32
    pubkey_debian = b"\xbb" * 32

    provider_windows = linep_sl.MemoryIdentityProvider(trust_domain)
    provider_windows.register_peer(10, pubkey_windows) # Windows node 10
    provider_windows.register_peer(20, pubkey_debian)  # Debian node 20

    peer_windows = linep_sl.PeerIdentity(trust_domain, 10, pubkey_windows)
    peer_debian = linep_sl.PeerIdentity(trust_domain, 20, pubkey_debian)

    # Validate mutual peer identities
    assert provider_windows.is_peer_trusted(peer_windows, trust_domain) is True
    assert provider_windows.is_peer_trusted(peer_debian, trust_domain) is True

    # 2. SL2 Security Negotiation & Downgrade Prevention
    ok_negotiate, negotiated_sl = linep_sl.negotiate_security_level(
        linep_sl.SecurityLevel.SL2_IDENTITY, # Client offers SL2
        linep_sl.SecurityLevel.SL3_CAPABILITIES, # Server supports SL3
        linep_sl.SecurityLevel.SL2_IDENTITY, # Policy requires SL2
    )
    assert ok_negotiate is True
    assert negotiated_sl == linep_sl.SecurityLevel.SL2_IDENTITY

    # Reject downgrade to SL1
    ok_downgrade, _ = linep_sl.negotiate_security_level(
        linep_sl.SecurityLevel.SL1_AUTH, # Client offers SL1
        linep_sl.SecurityLevel.SL3_CAPABILITIES,
        linep_sl.SecurityLevel.SL2_IDENTITY, # Required SL2
    )
    assert ok_downgrade is False

    # 3. Session Key Derivation & Rotation
    now = int(time.time())
    ttl = 3600

    session_windows = linep_sl.derive_session_key(master_secret, 0x5005, 1, 10, ttl, now)
    session_debian = linep_sl.derive_session_key(master_secret, 0x5005, 1, 10, ttl, now)

    assert session_windows.secret_key == session_debian.secret_key
    assert linep_sl.verify_session_key_freshness(session_windows, now + 100) is True

    # Rotated session key derivation
    session_windows_rot = linep_sl.derive_session_key(master_secret, 0x5005, 2, 10, ttl, now + 500)
    session_debian_rot = linep_sl.derive_session_key(master_secret, 0x5005, 2, 10, ttl, now + 500)

    assert session_windows_rot.secret_key == session_debian_rot.secret_key
    assert session_windows.secret_key != session_windows_rot.secret_key

    # 4. SL3 Capability Enforcement
    cap_token = linep_sl.create_capability_token(
        session_windows.secret_key,
        session_windows.session_id,
        linep_sl.CapFlags.INFERENCE_READ | linep_sl.CapFlags.METRICS_READ,
        now + ttl,
    )

    # Allowed operation (INFERENCE_READ)
    assert linep_sl.verify_capability_token(
        session_debian.secret_key,
        cap_token,
        session_windows.session_id,
        now + 10,
        linep_sl.CapFlags.INFERENCE_READ,
    ) is True

    # Denied operation (ADMIN)
    assert linep_sl.verify_capability_token(
        session_debian.secret_key,
        cap_token,
        session_windows.session_id,
        now + 10,
        linep_sl.CapFlags.ADMIN,
    ) is False

    # 5. Real TCP Socket Communication Test
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 19876))
    server_socket.listen(1)

    received_data = []

    def server_thread():
        conn, addr = server_socket.accept()
        hdr_bytes = conn.recv(24)
        ext_bytes = conn.recv(10)
        payload = conn.recv(1024)
        received_data.append((hdr_bytes, ext_bytes, payload))
        conn.sendall(b"OK_SL2_ACK")
        conn.close()

    t = threading.Thread(target=server_thread)
    t.start()

    time.sleep(0.1)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 19876))

    # Send SL1 authenticated packet over TCP socket
    hdr_bytes = b"LN\x01\x10\x38\x00\x08\x00\x08\x00\x00\x00\x64\x00\x00\x00\x2a\x00\x00\x00\x01\x00\x00\xab"
    payload = b"TESTDATA"
    mac = linep_sl.compute_sl1_mac(session_windows.secret_key, hdr_bytes, session_windows.session_id, 1, 100, payload)

    ext_bytes = session_windows.session_id.to_bytes(4, "little") + (1).to_bytes(2, "little") + (100).to_bytes(4, "little")

    client_socket.sendall(hdr_bytes + ext_bytes + payload)
    response = client_socket.recv(1024)
    client_socket.close()
    t.join()

    assert response == b"OK_SL2_ACK"
    assert len(received_data) == 1
    assert received_data[0][2] == b"TESTDATA"
