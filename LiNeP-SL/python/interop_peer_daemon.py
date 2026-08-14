#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
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

    last_stream_seq = 0

    while True:
        conn, addr = s.accept()
        data = conn.recv(4096)
        if not data:
            conn.close()
            continue

        req = json.loads(data.decode("utf-8"))
        msg_type = req.get("type", "TASK")

        # 1. Peer Identity Validation
        peer_id = linep_sl.PeerIdentity(
            trust_domain_id=req["trust_domain_id"],
            node_id=req["node_id"],
            pubkey=bytes.fromhex(req["pubkey_hex"]),
        )
        if not provider.is_peer_trusted(peer_id, trust_domain):
            resp = {"status": "REJECTED", "reason": "Untrusted or revoked peer identity"}
            conn.sendall(json.dumps(resp).encode("utf-8"))
            conn.close()
            continue

        # 2. Security Negotiation
        ok_neg, sl = linep_sl.negotiate_security_level(
            linep_sl.SecurityLevel(req["offered_sl"]),
            linep_sl.SecurityLevel.SL3_CAPABILITIES,
            linep_sl.SecurityLevel.SL2_IDENTITY,
        )
        if not ok_neg:
            resp = {"status": "REJECTED", "reason": "Security level negotiation / downgrade failed"}
            conn.sendall(json.dumps(resp).encode("utf-8"))
            conn.close()
            continue

        # 3. Derive Session Key
        now = int(time.time())
        session = linep_sl.derive_session_key(master_secret, req["session_id"], req["key_id"], req["node_id"], 3600, now)

        # 4. Verify SL1 MAC
        hdr_bytes = bytes.fromhex(req["hdr_hex"])
        payload_bytes = bytes.fromhex(req["payload_hex"])
        mac_bytes = bytes.fromhex(req["mac_hex"])

        mac_ok = linep_sl.verify_sl1_mac(
            session.secret_key, hdr_bytes, req["session_id"], req["key_id"], req["auth_seq"], mac_bytes, payload_bytes
        )

        # GATE 1: Fail closed if MAC verification fails!
        if not mac_ok:
            resp = {"status": "REJECTED", "reason": "Authentication failed (Invalid MAC)"}
            conn.sendall(json.dumps(resp).encode("utf-8"))
            conn.close()
            continue

        # 5. Verify SL3 Capability Token
        cap_token = linep_sl.CapabilityToken(
            session_id=req["session_id"],
            granted_caps=linep_sl.CapFlags(req["cap_flags"]),
            expires_at_sec=req["expires_at"],
            mac=bytes.fromhex(req["cap_mac_hex"]),
        )

        req_cap = linep_sl.CapFlags(req.get("required_cap", int(linep_sl.CapFlags.INFERENCE_READ)))
        cap_ok = linep_sl.verify_capability_token(
            session.secret_key, cap_token, req["session_id"], now, req_cap
        )

        # GATE 2: Fail closed if Capability check fails!
        if not cap_ok:
            resp = {"status": "REJECTED", "reason": "Capability authorization failed"}
            conn.sendall(json.dumps(resp).encode("utf-8"))
            conn.close()
            continue

        # Handling Specific Message Types:
        if msg_type == "STREAM_CHUNK":
            chunk_seq = req["chunk_seq"]
            # Enforce strictly monotonic fragment sequence numbers
            if chunk_seq <= last_stream_seq or chunk_seq > last_stream_seq + 1:
                resp = {"status": "REJECTED", "reason": f"Stream sequence error (duplicate/reordered chunk {chunk_seq})"}
                conn.sendall(json.dumps(resp).encode("utf-8"))
                conn.close()
                continue
            last_stream_seq = chunk_seq
            resp = {"status": "ACCEPTED", "chunk_seq": chunk_seq, "negotiated_sl": int(sl)}

        elif msg_type == "TASK_CANCEL":
            resp = {"status": "CANCEL_ACCEPTED", "correlation_id": req.get("correlation_id", 42)}

        else: # Standard TASK
            # Send key fingerprint hash, never raw secret key!
            key_fingerprint = hashlib.sha256(session.secret_key).hexdigest()[:16]
            resp = {
                "status": "ACCEPTED",
                "negotiated_sl": int(sl),
                "key_fingerprint": key_fingerprint,
            }

        conn.sendall(json.dumps(resp).encode("utf-8"))
        conn.close()

        if req.get("stop_after_test", False):
            break

    s.close()
    print("[SERVER DONE] Processed all requests with fail-closed security gates", flush=True)


def send_test_request(host: str, port: int, req: dict) -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(json.dumps(req).encode("utf-8"))
    data = s.recv(4096)
    s.close()
    return json.loads(data.decode("utf-8"))


def run_client(host: str, port: int, master_secret: bytes, trust_domain: int):
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

    base_req = {
        "trust_domain_id": trust_domain,
        "node_id": node_id,
        "pubkey_hex": (b"\xbb" * 32).hex(),
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

    # 1. Valid Standard TASK Request -> MUST be ACCEPTED
    resp = send_test_request(host, port, base_req)
    assert resp["status"] == "ACCEPTED"
    assert "derived_key_hex" not in resp # Verify no secret key leakage over wire!
    print("  [Client Test 1] Valid SL1/SL2/SL3 TASK Request -> ACCEPTED", flush=True)

    # 2. Tampered MAC -> MUST be REJECTED (Fail Closed Gate 1)
    tampered_mac_req = dict(base_req)
    tampered_mac_req["mac_hex"] = (b"\x00" * 16).hex()
    resp_tampered = send_test_request(host, port, tampered_mac_req)
    assert resp_tampered["status"] == "REJECTED"
    assert "Authentication failed" in resp_tampered["reason"]
    print("  [Client Test 2] Tampered MAC -> REJECTED (Fail Closed Gate 1 PASSED)", flush=True)

    # 3. Unauthorized Capability (Request ADMIN when only INFERENCE_READ is granted) -> MUST be REJECTED (Fail Closed Gate 2)
    unauth_cap_req = dict(base_req)
    unauth_cap_req["required_cap"] = int(linep_sl.CapFlags.ADMIN)
    resp_unauth = send_test_request(host, port, unauth_cap_req)
    assert resp_unauth["status"] == "REJECTED"
    assert "Capability authorization failed" in resp_unauth["reason"]
    print("  [Client Test 3] Unauthorized Capability (ADMIN) -> REJECTED (Fail Closed Gate 2 PASSED)", flush=True)

    # 4. Stream Fragments: Monotonic Chunk 1 and Chunk 2 -> ACCEPTED
    stream_req1 = dict(base_req)
    stream_req1["type"] = "STREAM_CHUNK"
    stream_req1["chunk_seq"] = 1
    resp_stream1 = send_test_request(host, port, stream_req1)
    assert resp_stream1["status"] == "ACCEPTED"
    assert resp_stream1["chunk_seq"] == 1

    stream_req2 = dict(base_req)
    stream_req2["type"] = "STREAM_CHUNK"
    stream_req2["chunk_seq"] = 2
    resp_stream2 = send_test_request(host, port, stream_req2)
    assert resp_stream2["status"] == "ACCEPTED"
    assert resp_stream2["chunk_seq"] == 2
    print("  [Client Test 4] Stream Fragments (Chunk 1 & Chunk 2) -> ACCEPTED", flush=True)

    # 5. Duplicate Stream Fragment (retransmitted Chunk 2) -> MUST be REJECTED
    stream_dup_req = dict(base_req)
    stream_dup_req["type"] = "STREAM_CHUNK"
    stream_dup_req["chunk_seq"] = 2 # Duplicate!
    resp_dup = send_test_request(host, port, stream_dup_req)
    assert resp_dup["status"] == "REJECTED"
    assert "Stream sequence error" in resp_dup["reason"]
    print("  [Client Test 5] Duplicate Stream Fragment -> REJECTED PASSED", flush=True)

    # 6. Authenticated TASK_CANCEL -> CANCEL_ACCEPTED
    cancel_payload = b"CANCEL_TASK_42"
    cancel_mac = linep_sl.compute_sl1_mac(session.secret_key, hdr_bytes, session_id, key_id, 101, cancel_payload)
    cancel_req = dict(base_req)
    cancel_req["type"] = "TASK_CANCEL"
    cancel_req["payload_hex"] = cancel_payload.hex()
    cancel_req["auth_seq"] = 101
    cancel_req["mac_hex"] = cancel_mac.hex()

    resp_cancel = send_test_request(host, port, cancel_req)
    assert resp_cancel["status"] == "CANCEL_ACCEPTED"
    print("  [Client Test 6] Authenticated TASK_CANCEL -> CANCEL_ACCEPTED PASSED", flush=True)

    # 7. Tampered TASK_CANCEL -> REJECTED
    tampered_cancel_req = dict(cancel_req)
    tampered_cancel_req["mac_hex"] = (b"\xff" * 16).hex()
    resp_tampered_cancel = send_test_request(host, port, tampered_cancel_req)
    assert resp_tampered_cancel["status"] == "REJECTED"
    print("  [Client Test 7] Tampered TASK_CANCEL -> REJECTED PASSED", flush=True)

    # Final shutdown request
    stop_req = dict(base_req)
    stop_req["stop_after_test"] = True
    send_test_request(host, port, stop_req)

    print("[CLIENT SUCCESS] ALL FAIL-CLOSED GATES, STREAMING & CANCEL TESTS PASSED 100%!", flush=True)


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
