#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
import socket
import json
import time
from pathlib import Path

def _ensure_lib_path():
    if os.environ.get("LINEP_SL_LIB_PATH"):
        return
    repo_root = Path(__file__).resolve().parents[1]
    if sys.platform == "win32":
        cand = repo_root / "build" / "src" / "liblinep_sl.dll"
    else:
        cand = repo_root / "build_linux" / "src" / "liblinep_sl.so"
    if cand.exists():
        os.environ["LINEP_SL_LIB_PATH"] = str(cand)

_ensure_lib_path()
import linep_sl


def run_server(port: int, master_secret: bytes, trust_domain: int):
    pubkey_win = b"\xaa" * 32
    pubkey_deb = b"\xbb" * 32

    provider = linep_sl.MemoryIdentityProvider(trust_domain)
    provider.register_peer(10, pubkey_win) # Windows Node 10
    provider.register_peer(20, pubkey_deb) # Debian Node 20

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    print(f"[SERVER READY] Listening on 0.0.0.0:{port}", flush=True)

    conn, addr = s.accept()
    print(f"[SERVER] Connected by {addr}", flush=True)

    # 1. Read handshake request
    data = conn.recv(4096)
    req = json.loads(data.decode("utf-8"))

    peer_id = linep_sl.PeerIdentity(
        trust_domain_id=req["trust_domain_id"],
        node_id=req["node_id"],
        pubkey=bytes.fromhex(req["pubkey_hex"]),
    )

    # Check peer identity
    if not provider.is_peer_trusted(peer_id, trust_domain):
        resp = {"status": "REJECTED", "reason": "Untrusted peer identity"}
        conn.sendall(json.dumps(resp).encode("utf-8"))
        conn.close()
        s.close()
        return

    # Check Security Policy Negotiation
    ok_neg, sl = linep_sl.negotiate_security_level(
        linep_sl.SecurityLevel(req["offered_sl"]),
        linep_sl.SecurityLevel.SL3_CAPABILITIES,
        linep_sl.SecurityLevel.SL2_IDENTITY,
    )
    if not ok_neg:
        resp = {"status": "REJECTED", "reason": "Downgrade rejected"}
        conn.sendall(json.dumps(resp).encode("utf-8"))
        conn.close()
        s.close()
        return

    # Derive session key
    now = int(time.time())
    session = linep_sl.derive_session_key(master_secret, req["session_id"], req["key_id"], req["node_id"], 3600, now)

    # SL3 Capability check
    cap_token = linep_sl.CapabilityToken(
        session_id=req["session_id"],
        granted_caps=linep_sl.CapFlags(req["cap_flags"]),
        expires_at_sec=req["expires_at"],
        mac=bytes.fromhex(req["cap_mac_hex"]),
    )

    cap_read_ok = linep_sl.verify_capability_token(
        session.secret_key, cap_token, req["session_id"], now, linep_sl.CapFlags.INFERENCE_READ
    )
    cap_admin_ok = linep_sl.verify_capability_token(
        session.secret_key, cap_token, req["session_id"], now, linep_sl.CapFlags.ADMIN
    )

    # Verify SL1 packet MAC
    hdr_bytes = bytes.fromhex(req["hdr_hex"])
    payload_bytes = bytes.fromhex(req["payload_hex"])
    mac_bytes = bytes.fromhex(req["mac_hex"])

    mac_ok = linep_sl.verify_sl1_mac(
        session.secret_key, hdr_bytes, req["session_id"], req["key_id"], req["auth_seq"], mac_bytes, payload_bytes
    )

    resp = {
        "status": "ACCEPTED",
        "negotiated_sl": int(sl),
        "cap_read_ok": cap_read_ok,
        "cap_admin_ok": cap_admin_ok,
        "mac_ok": mac_ok,
        "derived_key_hex": session.secret_key.hex(),
    }
    conn.sendall(json.dumps(resp).encode("utf-8"))
    conn.close()
    s.close()
    print("[SERVER DONE] Successfully processed interop request", flush=True)


def run_client(host: str, port: int, master_secret: bytes, trust_domain: int):
    pubkey_win = b"\xaa" * 32
    pubkey_deb = b"\xbb" * 32

    now = int(time.time())
    session_id = 0x5005
    node_id = 20 # Debian node 20
    key_id = 1

    session = linep_sl.derive_session_key(master_secret, session_id, key_id, node_id, 3600, now)

    cap_token = linep_sl.create_capability_token(
        session.secret_key,
        session_id,
        linep_sl.CapFlags.INFERENCE_READ | linep_sl.CapFlags.METRICS_READ,
        now + 3600,
    )

    hdr_bytes = b"LN\x01\x10\x38\x00\x08\x00\x08\x00\x00\x00\x64\x00\x00\x00\x2a\x00\x00\x00\x01\x00\x00\xab"
    payload = b"CROSS_OS_TEST_PAYLOAD"
    mac = linep_sl.compute_sl1_mac(session.secret_key, hdr_bytes, session_id, key_id, 100, payload)

    req = {
        "trust_domain_id": trust_domain,
        "node_id": node_id,
        "pubkey_hex": pubkey_deb.hex(),
        "offered_sl": int(linep_sl.SecurityLevel.SL2_IDENTITY),
        "session_id": session_id,
        "key_id": key_id,
        "cap_flags": int(linep_sl.CapFlags.INFERENCE_READ | linep_sl.CapFlags.METRICS_READ),
        "expires_at": now + 3600,
        "cap_mac_hex": cap_token.mac.hex(),
        "hdr_hex": hdr_bytes.hex(),
        "payload_hex": payload.hex(),
        "auth_seq": 100,
        "mac_hex": mac.hex(),
    }

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(json.dumps(req).encode("utf-8"))

    data = s.recv(4096)
    s.close()

    resp = json.loads(data.decode("utf-8"))
    print(f"[CLIENT RECEIVED] {resp}", flush=True)

    assert resp["status"] == "ACCEPTED"
    assert resp["cap_read_ok"] is True
    assert resp["cap_admin_ok"] is False
    assert resp["mac_ok"] is True
    assert resp["derived_key_hex"] == session.secret_key.hex()
    print("[CLIENT SUCCESS] All cross-OS assertions PASSED!", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["server", "client"], required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19876)
    args = parser.parse_args()

    master_secret = b"WIN_DEBIAN_INTEROP_MASTER_SECRET"
    trust_domain = 0x4C4E5031

    if args.mode == "server":
        run_server(args.port, master_secret, trust_domain)
    else:
        run_client(args.host, args.port, master_secret, trust_domain)

if __name__ == "__main__":
    main()
