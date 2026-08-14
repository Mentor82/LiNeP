#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import threading
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


def run_udp_server(udp_port: int, master_secret: bytes, trust_domain: int, stop_event: threading.Event):
    pubkey_win = b"\xaa" * 32
    pubkey_deb = b"\xbb" * 32

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", udp_port))
    s.settimeout(0.5)

    last_udp_seqs: dict[tuple[int, int], int] = {}

    while not stop_event.is_set():
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        except Exception:
            break

        try:
            req = json.loads(data.decode("utf-8"))
        except Exception:
            continue

        if req.get("type") != "UDP_HEARTBEAT":
            continue

        session_id = req["session_id"]
        key_id = req["key_id"]
        node_id = req["node_id"]
        seq = req["auth_seq"]
        pubkey_hex = req["pubkey_hex"]
        pubkey_bytes = bytes.fromhex(pubkey_hex)

        # 1. Derive Session Key
        now = int(time.time())
        session = linep_sl.derive_session_key(master_secret, session_id, key_id, node_id, 3600, now)
        if not session:
            resp = {"status": "REJECTED", "reason": "Failed to derive session key"}
            s.sendto(json.dumps(resp).encode("utf-8"), addr)
            continue

        # 2. Verify MAC
        hdr_bytes = bytes.fromhex(req["hdr_hex"])
        payload_bytes = bytes.fromhex(req["payload_hex"])
        mac_bytes = bytes.fromhex(req["mac_hex"])

        mac_ok = linep_sl.verify_sl1_mac(
            session.secret_key, hdr_bytes, session_id, key_id, seq, mac_bytes, payload_bytes
        )
        if not mac_ok:
            resp = {"status": "REJECTED", "reason": "UDP Heartbeat MAC Verification Failed"}
            s.sendto(json.dumps(resp).encode("utf-8"), addr)
            continue

        # 3. Transport-Scoped Replay Protection
        key = (session_id, node_id)
        if key in last_udp_seqs and seq <= last_udp_seqs[key]:
            resp = {"status": "REJECTED", "reason": f"UDP Heartbeat Replay Error (seq {seq} <= last {last_udp_seqs[key]})"}
            s.sendto(json.dumps(resp).encode("utf-8"), addr)
            continue
        last_udp_seqs[key] = seq

        # 4. Verify SL3 Capability Token for HEARTBEAT_EMIT
        cap_token = linep_sl.CapabilityToken(
            session_id=session_id,
            granted_caps=linep_sl.CapFlags(req["cap_flags"]),
            expires_at_sec=req["expires_at"],
            mac=bytes.fromhex(req["cap_mac_hex"]),
        )
        req_cap = linep_sl.CapFlags(req.get("required_cap", int(linep_sl.CapFlags.HEARTBEAT_EMIT)))
        cap_ok = linep_sl.verify_capability_token(session.secret_key, cap_token, session_id, now, req_cap)
        if not cap_ok:
            resp = {"status": "REJECTED", "reason": "UDP Heartbeat Capability Authorization Failed"}
            s.sendto(json.dumps(resp).encode("utf-8"), addr)
            continue

        # 5. Verify SL4 Engine
        sl4_engine = linep_sl.SecurityDecisionEngine(trust_domain)
        sl4_engine.register_peer(node_id, pubkey_bytes)

        if req.get("remote_trust_domain_id") and req["remote_trust_domain_id"] != trust_domain:
            sl4_engine.add_federation(trust_domain, req["remote_trust_domain_id"], linep_sl.CapFlags.HEARTBEAT_EMIT)
            pol = linep_sl.GovernancePolicy(
                policy_id="default-policy",
                policy_revision=1,
                allowed_capabilities=linep_sl.CapFlags.HEARTBEAT_EMIT,
                allow_cross_domain=False,
            )
            sl4_engine.set_policy(pol)
        else:
            pol = linep_sl.GovernancePolicy(
                policy_id="default-policy",
                policy_revision=1,
                allowed_capabilities=linep_sl.CapFlags.INFERENCE_READ | linep_sl.CapFlags.HEARTBEAT_EMIT,
                allow_cross_domain=False,
            )
            sl4_engine.set_policy(pol)

        sl4_dec, sl4_reason = sl4_engine.evaluate(
            trust_domain_id=trust_domain,
            session_id=session_id,
            key_id=key_id,
            local_node_id=1,
            remote_node_id=node_id,
            remote_trust_domain_id=req.get("remote_trust_domain_id", trust_domain),
            remote_revoked=False,
            negotiated_sl=linep_sl.SecurityLevel(req["offered_sl"]),
            requested_cap=req_cap,
            remote_pubkey_32bytes=pubkey_bytes,
            policy_id=req.get("policy_id", "default-policy"),
        )

        if sl4_dec != linep_sl.Decision.ALLOW:
            resp = {"status": "REJECTED", "reason": f"SL4 Governance Denied UDP Heartbeat: {sl4_reason}"}
            s.sendto(json.dumps(resp).encode("utf-8"), addr)
            continue

        resp = {"status": "HEARTBEAT_ACCEPTED", "reason": "Protected UDP Heartbeat Verified"}
        s.sendto(json.dumps(resp).encode("utf-8"), addr)

    s.close()


def run_server(tcp_port: int, udp_port: int, master_secret: bytes, trust_domain: int):
    pubkey_win = b"\xaa" * 32
    pubkey_deb = b"\xbb" * 32

    provider = linep_sl.MemoryIdentityProvider(trust_domain)
    provider.register_peer(10, pubkey_win) # Windows Node 10
    provider.register_peer(20, pubkey_deb) # Debian Node 20

    stop_udp = threading.Event()
    udp_thread = threading.Thread(target=run_udp_server, args=(udp_port, master_secret, trust_domain, stop_udp), daemon=True)
    udp_thread.start()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", tcp_port))
    s.listen(5)
    print(f"[SERVER READY] TCP listening on 0.0.0.0:{tcp_port}, UDP listening on 0.0.0.0:{udp_port}", flush=True)

    stream_sequences: dict[tuple[int, int], int] = {}

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

        if not mac_ok:
            resp = {"status": "REJECTED", "reason": "Authentication failed (Invalid MAC)"}
            conn.sendall(json.dumps(resp).encode("utf-8"))
            conn.close()
            continue

        # Handle Stream Sequences per (session_id, correlation_id)
        if msg_type == "STREAM_CHUNK":
            chunk_seq = req.get("chunk_seq", 1)
            corr_id = req.get("correlation_id", 0)
            scope_key = (req["session_id"], corr_id)

            last_seq = stream_sequences.get(scope_key, 0)
            if chunk_seq <= last_seq:
                resp = {"status": "REJECTED", "reason": f"Stream sequence error (chunk {chunk_seq} <= last {last_seq})"}
                conn.sendall(json.dumps(resp).encode("utf-8"))
                conn.close()
                continue

            stream_sequences[scope_key] = chunk_seq
            resp = {"status": "STREAM_ACCEPTED", "chunk_seq": chunk_seq}
            conn.sendall(json.dumps(resp).encode("utf-8"))
            conn.close()
            continue

        if msg_type == "TASK_CANCEL":
            resp = {"status": "CANCEL_ACCEPTED", "reason": "Task cancellation verified"}
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

        if not cap_ok:
            resp = {"status": "REJECTED", "reason": "Capability authorization failed"}
            conn.sendall(json.dumps(resp).encode("utf-8"))
            conn.close()
            continue

        # 6. Verify SL4 Governance, Zero-Trust & Federation Engine using persistent SecurityDecisionEngine
        sl4_engine = linep_sl.SecurityDecisionEngine(trust_domain)
        sl4_engine.register_peer(req["node_id"], bytes.fromhex(req["pubkey_hex"]))

        if req.get("remote_trust_domain_id") and req["remote_trust_domain_id"] != trust_domain:
            sl4_engine.add_federation(trust_domain, req["remote_trust_domain_id"], linep_sl.CapFlags.INFERENCE_READ)
            pol = linep_sl.GovernancePolicy(
                policy_id="default-policy",
                policy_revision=1,
                allowed_capabilities=linep_sl.CapFlags.INFERENCE_READ,
                allow_cross_domain=False,
            )
            sl4_engine.set_policy(pol)

        sl4_dec, sl4_reason = sl4_engine.evaluate(
            trust_domain_id=trust_domain,
            session_id=req["session_id"],
            key_id=req["key_id"],
            local_node_id=1,
            remote_node_id=req["node_id"],
            remote_trust_domain_id=req.get("remote_trust_domain_id", trust_domain),
            remote_revoked=False,
            negotiated_sl=linep_sl.SecurityLevel(req["offered_sl"]),
            requested_cap=req_cap,
            remote_pubkey_32bytes=bytes.fromhex(req["pubkey_hex"]),
            policy_id=req.get("policy_id", "default-policy"),
        )

        if sl4_dec != linep_sl.Decision.ALLOW:
            resp = {"status": "REJECTED", "reason": f"SL4 Governance Denied: {sl4_reason}"}
            conn.sendall(json.dumps(resp).encode("utf-8"))
            conn.close()
            continue

        resp = {"status": "ACCEPTED", "reason": "All security layers verified"}
        conn.sendall(json.dumps(resp).encode("utf-8"))
        conn.close()

        if req.get("stop_after_test"):
            print("[SERVER DONE] Processed all requests with fail-closed security gates", flush=True)
            stop_udp.set()
            s.close()
            break


def send_test_request(host: str, port: int, req: dict) -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(json.dumps(req).encode("utf-8"))
    data = s.recv(4096)
    s.close()
    return json.loads(data.decode("utf-8"))


def send_udp_heartbeat(host: str, udp_port: int, req: dict, timeout: float = 2.0) -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(json.dumps(req).encode("utf-8"), (host, udp_port))
    try:
        data, _ = s.recvfrom(4096)
        s.close()
        return json.loads(data.decode("utf-8"))
    except socket.timeout:
        s.close()
        return {"status": "TIMEOUT", "reason": "UDP Heartbeat socket timeout"}


def run_client(host: str, tcp_port: int, udp_port: int, master_secret: bytes, trust_domain: int):
    pubkey_debian = b"\xbb" * 32  # Client node 20 (Debian)
    session_id = 0x2001
    key_id = 1
    node_id = 20

    print(f"[CLIENT START] Connecting to server {host} TCP:{tcp_port} UDP:{udp_port}...", flush=True)
    now = int(time.time())
    session = linep_sl.derive_session_key(master_secret, session_id, key_id, node_id, 3600, now)

    hdr_bytes = b"\x4e\x4c\x01\x00" + b"\x00" * 20
    payload = b"TASK_INFERENCE_EXECUTE"
    mac_bytes = linep_sl.compute_sl1_mac(session.secret_key, hdr_bytes, session_id, key_id, 1, payload)

    cap_token = linep_sl.create_capability_token(
        session.secret_key, session_id, linep_sl.CapFlags.INFERENCE_READ, now + 3600
    )

    base_req = {
        "trust_domain_id": trust_domain,
        "node_id": node_id,
        "pubkey_hex": pubkey_debian.hex(),
        "offered_sl": linep_sl.SecurityLevel.SL3_CAPABILITIES.value,
        "session_id": session_id,
        "key_id": key_id,
        "auth_seq": 1,
        "hdr_hex": hdr_bytes.hex(),
        "payload_hex": payload.hex(),
        "mac_hex": mac_bytes.hex(),
        "cap_flags": linep_sl.CapFlags.INFERENCE_READ.value,
        "expires_at": now + 3600,
        "cap_mac_hex": cap_token.mac.hex(),
    }

    # 1. Valid SL1/SL2/SL3 TASK Request -> ACCEPTED
    resp1 = send_test_request(host, tcp_port, base_req)
    assert resp1["status"] == "ACCEPTED"
    print("  [Client Test 1] Valid SL1/SL2/SL3 TASK Request -> ACCEPTED", flush=True)

    # 2. Tampered MAC -> REJECTED
    tampered_req = dict(base_req)
    tampered_req["mac_hex"] = (b"\xff" * 16).hex()
    resp2 = send_test_request(host, tcp_port, tampered_req)
    assert resp2["status"] == "REJECTED"
    print("  [Client Test 2] Tampered MAC -> REJECTED (Fail Closed Gate 1 PASSED)", flush=True)

    # 3. Unauthorized Capability -> REJECTED
    unauth_req = dict(base_req)
    unauth_req["required_cap"] = int(linep_sl.CapFlags.ADMIN)
    resp3 = send_test_request(host, tcp_port, unauth_req)
    assert resp3["status"] == "REJECTED"
    print("  [Client Test 3] Unauthorized Capability (ADMIN) -> REJECTED (Fail Closed Gate 2 PASSED)", flush=True)

    # 4. Stream Fragments -> ACCEPTED
    stream1_req = dict(base_req)
    stream1_req["type"] = "STREAM_CHUNK"
    stream1_req["chunk_seq"] = 1
    resp_stream1 = send_test_request(host, tcp_port, stream1_req)
    assert resp_stream1["status"] == "STREAM_ACCEPTED"

    stream2_req = dict(base_req)
    stream2_req["type"] = "STREAM_CHUNK"
    stream2_req["chunk_seq"] = 2
    resp_stream2 = send_test_request(host, tcp_port, stream2_req)
    assert resp_stream2["status"] == "STREAM_ACCEPTED"
    print("  [Client Test 4] Stream Fragments (Chunk 1 & Chunk 2) -> ACCEPTED", flush=True)

    # 5. Duplicate Stream Fragment -> REJECTED
    stream_dup_req = dict(base_req)
    stream_dup_req["type"] = "STREAM_CHUNK"
    stream_dup_req["chunk_seq"] = 2
    resp_dup = send_test_request(host, tcp_port, stream_dup_req)
    assert resp_dup["status"] == "REJECTED"
    print("  [Client Test 5] Duplicate Stream Fragment -> REJECTED PASSED", flush=True)

    # 6. Authenticated TASK_CANCEL -> CANCEL_ACCEPTED
    cancel_payload = b"CANCEL_TASK_42"
    cancel_mac = linep_sl.compute_sl1_mac(session.secret_key, hdr_bytes, session_id, key_id, 101, cancel_payload)
    cancel_req = dict(base_req)
    cancel_req["type"] = "TASK_CANCEL"
    cancel_req["payload_hex"] = cancel_payload.hex()
    cancel_req["auth_seq"] = 101
    cancel_req["mac_hex"] = cancel_mac.hex()
    resp_cancel = send_test_request(host, tcp_port, cancel_req)
    assert resp_cancel["status"] == "CANCEL_ACCEPTED"
    print("  [Client Test 6] Authenticated TASK_CANCEL -> CANCEL_ACCEPTED PASSED", flush=True)

    # 7. Tampered TASK_CANCEL -> REJECTED
    tampered_cancel_req = dict(cancel_req)
    tampered_cancel_req["mac_hex"] = (b"\xff" * 16).hex()
    resp_tampered_cancel = send_test_request(host, tcp_port, tampered_cancel_req)
    assert resp_tampered_cancel["status"] == "REJECTED"
    print("  [Client Test 7] Tampered TASK_CANCEL -> REJECTED PASSED", flush=True)

    # 8. SL4 Cross-Domain without Federation -> REJECTED
    cross_domain_req = dict(base_req)
    cross_domain_req["remote_trust_domain_id"] = 0x4C4E5039
    resp_cross_domain = send_test_request(host, tcp_port, cross_domain_req)
    assert resp_cross_domain["status"] == "REJECTED"
    print("  [Client Test 8] SL4 Cross-Domain without Federation -> REJECTED (Fail Closed Gate 3 PASSED)", flush=True)

    # --- UDP HEARTBEAT TESTS (Tests 9-12) ---
    hb_cap_token = linep_sl.create_capability_token(
        session.secret_key, session_id, linep_sl.CapFlags.HEARTBEAT_EMIT, now + 3600
    )
    hb_payload = b"UDP_HEARTBEAT_NODE_20"
    hb_mac = linep_sl.compute_sl1_mac(session.secret_key, hdr_bytes, session_id, key_id, 200, hb_payload)

    hb_req = {
        "type": "UDP_HEARTBEAT",
        "trust_domain_id": trust_domain,
        "node_id": node_id,
        "pubkey_hex": pubkey_debian.hex(),
        "offered_sl": linep_sl.SecurityLevel.SL3_CAPABILITIES.value,
        "session_id": session_id,
        "key_id": key_id,
        "auth_seq": 200,
        "hdr_hex": hdr_bytes.hex(),
        "payload_hex": hb_payload.hex(),
        "mac_hex": hb_mac.hex(),
        "cap_flags": linep_sl.CapFlags.HEARTBEAT_EMIT.value,
        "expires_at": now + 3600,
        "cap_mac_hex": hb_cap_token.mac.hex(),
    }

    # 9. Valid Protected UDP Heartbeat -> HEARTBEAT_ACCEPTED
    resp9 = send_udp_heartbeat(host, udp_port, hb_req)
    assert resp9["status"] == "HEARTBEAT_ACCEPTED"
    print("  [Client Test 9] Protected UDP Heartbeat -> ACCEPTED PASSED", flush=True)

    # 10. Tampered UDP Heartbeat MAC -> REJECTED
    tampered_hb = dict(hb_req)
    tampered_hb["auth_seq"] = 201
    tampered_hb["mac_hex"] = (b"\xff" * 16).hex()
    resp10 = send_udp_heartbeat(host, udp_port, tampered_hb)
    assert resp10["status"] == "REJECTED"
    print("  [Client Test 10] Tampered UDP Heartbeat MAC -> REJECTED PASSED", flush=True)

    # 11. Duplicate UDP Heartbeat Replay (retransmitted seq 200) -> REJECTED
    dup_hb = dict(hb_req)
    dup_hb["auth_seq"] = 200
    resp11 = send_udp_heartbeat(host, udp_port, dup_hb)
    assert resp11["status"] == "REJECTED"
    assert "Replay Error" in resp11["reason"]
    print("  [Client Test 11] Duplicate UDP Heartbeat Replay -> REJECTED PASSED", flush=True)

    # 12. Cross-Domain UDP Heartbeat without Federation -> REJECTED
    cross_hb = dict(hb_req)
    cross_hb["auth_seq"] = 202
    cross_hb["mac_hex"] = linep_sl.compute_sl1_mac(session.secret_key, hdr_bytes, session_id, key_id, 202, hb_payload).hex()
    cross_hb["remote_trust_domain_id"] = 0x4C4E5039
    resp12 = send_udp_heartbeat(host, udp_port, cross_hb)
    assert resp12["status"] == "REJECTED"
    print("  [Client Test 12] Cross-Domain UDP Heartbeat without Federation -> REJECTED PASSED", flush=True)

    # Final shutdown request
    stop_req = dict(base_req)
    stop_req["stop_after_test"] = True
    send_test_request(host, tcp_port, stop_req)

    print("[CLIENT SUCCESS] ALL TCP STREAMING, CANCEL & UDP HEARTBEAT TESTS PASSED 100%!", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["server", "client"], required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19876)
    parser.add_argument("--udp-port", type=int, default=0)
    args = parser.parse_args()

    udp_port = args.udp_port if args.udp_port > 0 else (args.port + 10)
    master_secret = b"WIN_DEBIAN_INTEROP_MASTER_SECRET"
    trust_domain = 0x4C4E5031

    if args.mode == "server":
        run_server(args.port, udp_port, master_secret, trust_domain)
    else:
        run_client(args.host, args.port, udp_port, master_secret, trust_domain)

if __name__ == "__main__":
    main()
