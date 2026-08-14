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


class ServerSessionStore:
    """Persistent Server SessionStore enforcing key rotation, TTL freshness, and active key ID lookups."""
    def __init__(self, master_secret: bytes):
        self.master_secret = master_secret
        self.sessions: dict[tuple[int, int, int], linep_sl.SessionKey] = {} # (session_id, key_id, node_id) -> SessionKey

    def establish_session(self, session_id: int, key_id: int, node_id: int, ttl_sec: int, established_at_sec: int) -> linep_sl.SessionKey:
        sk = linep_sl.derive_session_key(self.master_secret, session_id, key_id, node_id, ttl_sec, established_at_sec)
        self.sessions[(session_id, key_id, node_id)] = sk
        return sk

    def revoke_key_id(self, session_id: int, key_id: int, node_id: int):
        self.sessions.pop((session_id, key_id, node_id), None)

    def get_session(self, session_id: int, key_id: int, node_id: int, current_time_sec: int) -> linep_sl.SessionKey | None:
        sk = self.sessions.get((session_id, key_id, node_id))
        if not sk:
            return None # Revoked or non-existent key ID -> Fail closed!
        if not linep_sl.verify_session_key_freshness(sk, current_time_sec):
            return None # Expired session key -> Fail closed!
        return sk


def run_udp_server(udp_port: int, session_store: ServerSessionStore, trust_domain: int, stop_event: threading.Event):
    pubkey_win = b"\xaa" * 32
    pubkey_deb = b"\xbb" * 32

    # Pre-provision trusted identities with domain-scoped keying at server startup
    sl4_engine = linep_sl.SecurityDecisionEngine(trust_domain)
    sl4_engine.register_peer(10, pubkey_win, trust_domain_id=trust_domain)
    sl4_engine.register_peer(20, pubkey_deb, trust_domain_id=trust_domain)

    pol_init = linep_sl.GovernancePolicy(
        policy_id="default-policy",
        policy_revision=1,
        allowed_capabilities=linep_sl.CapFlags.INFERENCE_READ | linep_sl.CapFlags.INFERENCE_WRITE | linep_sl.CapFlags.METRICS_READ | linep_sl.CapFlags.HEARTBEAT_EMIT | linep_sl.CapFlags.ADMIN,
        allow_cross_domain=False,
    )
    sl4_engine.set_policy(pol_init)

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
        pubkey_bytes = bytes.fromhex(req["pubkey_hex"])
        now = int(time.time())

        # 1. Look up active session from persistent SessionStore & verify freshness
        session = session_store.get_session(session_id, key_id, node_id, now)
        if not session:
            resp = {"status": "REJECTED", "reason": "Expired, revoked or non-existent session key"}
            s.sendto(json.dumps(resp).encode("utf-8"), addr)
            continue

        # 2. Verify MAC (SL1)
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
        remote_td = req.get("remote_trust_domain_id", trust_domain)
        if req.get("explicit_federation_denied"):
            pol = linep_sl.GovernancePolicy(
                policy_id="default-policy",
                policy_revision=1,
                allowed_capabilities=linep_sl.CapFlags.HEARTBEAT_EMIT,
                allow_cross_domain=False,
            )
            sl4_engine.set_policy(pol)
            sl4_engine.add_federation(trust_domain, remote_td, linep_sl.CapFlags.HEARTBEAT_EMIT)

        sl4_dec, sl4_reason = sl4_engine.evaluate(
            trust_domain_id=trust_domain,
            session_id=session_id,
            key_id=key_id,
            local_node_id=1,
            remote_node_id=node_id,
            remote_trust_domain_id=remote_td,
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

        last_udp_seqs[key] = seq
        resp = {"status": "HEARTBEAT_ACCEPTED", "reason": "Protected UDP Heartbeat Verified"}
        s.sendto(json.dumps(resp).encode("utf-8"), addr)

    s.close()


def run_server(tcp_port: int, udp_port: int, master_secret: bytes, trust_domain: int):
    pubkey_win = b"\xaa" * 32
    pubkey_deb = b"\xbb" * 32

    provider = linep_sl.MemoryIdentityProvider(trust_domain)
    provider.register_peer(10, pubkey_win) # Windows Node 10 (Domain-scoped)
    provider.register_peer(20, pubkey_deb) # Debian Node 20 (Domain-scoped)

    session_store = ServerSessionStore(master_secret)

    # Establish initial session keys in persistent SessionStore
    now_init = int(time.time())
    session_store.establish_session(0x1001, 1, 10, 3600, now_init) # Session 0x1001 key 1 for Win Node 10
    session_store.establish_session(0x2001, 1, 20, 3600, now_init) # Session 0x2001 key 1 for Debian Node 20
    session_store.establish_session(0x2001, 2, 20, 3600, now_init) # Session 0x2001 rotated key 2 for Debian Node 20

    # Establish an expired session for explicit testing
    session_store.establish_session(0x9999, 1, 20, 10, now_init - 5000) # Expired 5000s ago!

    # Persistent Engine pre-provisioned with domain-scoped trusted identities and policy
    sl4_engine = linep_sl.SecurityDecisionEngine(trust_domain)
    sl4_engine.register_peer(10, pubkey_win, trust_domain_id=trust_domain)
    sl4_engine.register_peer(20, pubkey_deb, trust_domain_id=trust_domain)

    pol_init = linep_sl.GovernancePolicy(
        policy_id="default-policy",
        policy_revision=1,
        allowed_capabilities=linep_sl.CapFlags.INFERENCE_READ | linep_sl.CapFlags.INFERENCE_WRITE | linep_sl.CapFlags.METRICS_READ | linep_sl.CapFlags.HEARTBEAT_EMIT | linep_sl.CapFlags.ADMIN,
        allow_cross_domain=False,
    )
    sl4_engine.set_policy(pol_init)

    stop_udp = threading.Event()
    udp_thread = threading.Thread(target=run_udp_server, args=(udp_port, session_store, trust_domain, stop_udp), daemon=True)
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

        # 1. Peer Identity Validation (SL2 Identity Anchor)
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

        # 3. Look up active session key from persistent SessionStore & verify freshness
        now = int(time.time())
        session = session_store.get_session(req["session_id"], req["key_id"], req["node_id"], now)
        if not session:
            resp = {"status": "REJECTED", "reason": "Expired, revoked or non-existent session key"}
            conn.sendall(json.dumps(resp).encode("utf-8"))
            conn.close()
            continue

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

        # 5. Verify SL3 Capability Token (ALL MESSAGE TYPES MUST PASS SL3!)
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

        # 6. Verify SL4 Governance, Zero-Trust & Federation Engine (ALL MESSAGE TYPES MUST PASS SL4!)
        remote_td = req.get("remote_trust_domain_id", trust_domain)
        if req.get("explicit_federation_denied"):
            pol = linep_sl.GovernancePolicy(
                policy_id="default-policy",
                policy_revision=1,
                allowed_capabilities=linep_sl.CapFlags.INFERENCE_READ | linep_sl.CapFlags.HEARTBEAT_EMIT | linep_sl.CapFlags.ADMIN,
                allow_cross_domain=False,
            )
            sl4_engine.set_policy(pol)
            sl4_engine.add_federation(trust_domain, remote_td, linep_sl.CapFlags.INFERENCE_READ | linep_sl.CapFlags.HEARTBEAT_EMIT | linep_sl.CapFlags.ADMIN)

        sl4_dec, sl4_reason = sl4_engine.evaluate(
            trust_domain_id=trust_domain,
            session_id=req["session_id"],
            key_id=req["key_id"],
            local_node_id=1,
            remote_node_id=req["node_id"],
            remote_trust_domain_id=remote_td,
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

        # 7. AFTER SL1-SL4 GATING HAS PASSED: Process message-type specific handlers!
        if msg_type == "ROTATE_KEY":
            # Authenticated key rotation command (Passed SL1, SL2, SL3 ADMIN capability & SL4 Governance!)
            session_store.revoke_key_id(req["session_id"], req["revoke_key_id"], req["node_id"])
            resp = {"status": "KEY_ROTATED", "reason": f"Key ID {req['revoke_key_id']} revoked after SL1-SL4 authentication"}
            conn.sendall(json.dumps(resp).encode("utf-8"))
            conn.close()
            continue

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

    # 5. STREAM_CHUNK with Unauthorized Capability -> MUST BE REJECTED!
    unauth_stream_req = dict(stream2_req)
    unauth_stream_req["chunk_seq"] = 3
    unauth_stream_req["required_cap"] = int(linep_sl.CapFlags.ADMIN)
    resp_unauth_stream = send_test_request(host, tcp_port, unauth_stream_req)
    assert resp_unauth_stream["status"] == "REJECTED"
    print("  [Client Test 5] STREAM_CHUNK with Unauthorized Capability -> REJECTED PASSED", flush=True)

    # 6. Duplicate Stream Fragment -> REJECTED
    stream_dup_req = dict(base_req)
    stream_dup_req["type"] = "STREAM_CHUNK"
    stream_dup_req["chunk_seq"] = 2
    resp_dup = send_test_request(host, tcp_port, stream_dup_req)
    assert resp_dup["status"] == "REJECTED"
    print("  [Client Test 6] Duplicate Stream Fragment -> REJECTED PASSED", flush=True)

    # 7. Authenticated TASK_CANCEL -> CANCEL_ACCEPTED
    cancel_payload = b"CANCEL_TASK_42"
    cancel_mac = linep_sl.compute_sl1_mac(session.secret_key, hdr_bytes, session_id, key_id, 101, cancel_payload)
    cancel_req = dict(base_req)
    cancel_req["type"] = "TASK_CANCEL"
    cancel_req["payload_hex"] = cancel_payload.hex()
    cancel_req["auth_seq"] = 101
    cancel_req["mac_hex"] = cancel_mac.hex()
    resp_cancel = send_test_request(host, tcp_port, cancel_req)
    assert resp_cancel["status"] == "CANCEL_ACCEPTED"
    print("  [Client Test 7] Authenticated TASK_CANCEL -> CANCEL_ACCEPTED PASSED", flush=True)

    # 8. TASK_CANCEL with Unauthorized Capability (SL3 Gate Test with VALID MAC recalculation!)
    unauth_cancel_payload = b"CANCEL_TASK_42"
    valid_unauth_mac = linep_sl.compute_sl1_mac(session.secret_key, hdr_bytes, session_id, key_id, 102, unauth_cancel_payload)
    unauth_cancel_req = dict(cancel_req)
    unauth_cancel_req["auth_seq"] = 102
    unauth_cancel_req["mac_hex"] = valid_unauth_mac.hex()
    unauth_cancel_req["required_cap"] = int(linep_sl.CapFlags.ADMIN)
    resp_unauth_cancel = send_test_request(host, tcp_port, unauth_cancel_req)
    assert resp_unauth_cancel["status"] == "REJECTED"
    assert "Capability authorization failed" in resp_unauth_cancel["reason"]
    print("  [Client Test 8] TASK_CANCEL with Unauthorized Capability (Valid MAC) -> REJECTED (SL3 Gate PASSED)", flush=True)

    # 9. Tampered TASK_CANCEL -> REJECTED
    tampered_cancel_req = dict(cancel_req)
    tampered_cancel_req["auth_seq"] = 103
    tampered_cancel_req["mac_hex"] = (b"\xff" * 16).hex()
    resp_tampered_cancel = send_test_request(host, tcp_port, tampered_cancel_req)
    assert resp_tampered_cancel["status"] == "REJECTED"
    print("  [Client Test 9] Tampered TASK_CANCEL -> REJECTED PASSED", flush=True)

    # 10A. SL4 Cross-Domain WITHOUT Federation Trust -> REJECTED (CROSS_DOMAIN_FEDERATION_DENIED)
    no_fed_cross_req = dict(base_req)
    no_fed_cross_req["remote_trust_domain_id"] = 0x4C4E5039 # Foreign trust domain without federation
    resp_no_fed = send_test_request(host, tcp_port, no_fed_cross_req)
    assert resp_no_fed["status"] == "REJECTED"
    assert "CROSS_DOMAIN_FEDERATION_DENIED" in resp_no_fed["reason"]
    print("  [Client Test 10A] Cross-Domain WITHOUT Federation Trust -> REJECTED PASSED", flush=True)

    # 10B. SL4 Cross-Domain WITH Federation Trust BUT Policy allow_cross_domain = False -> REJECTED
    fed_denied_cross_req = dict(base_req)
    fed_denied_cross_req["remote_trust_domain_id"] = 0x4C4E5039
    fed_denied_cross_req["explicit_federation_denied"] = True
    resp_fed_denied = send_test_request(host, tcp_port, fed_denied_cross_req)
    assert resp_fed_denied["status"] == "REJECTED"
    assert "GOVERNANCE_POLICY_CROSS_DOMAIN_DENIED" in resp_fed_denied["reason"]
    print("  [Client Test 10B] Cross-Domain WITH Federation Trust BUT Policy allow_cross_domain = False -> REJECTED PASSED", flush=True)

    # 11. Stale / Expired Session Key Test -> REJECTED
    expired_sess_req = dict(base_req)
    expired_sess_req["session_id"] = 0x9999 # Pre-established expired session
    resp_expired = send_test_request(host, tcp_port, expired_sess_req)
    assert resp_expired["status"] == "REJECTED"
    assert "Expired, revoked or non-existent session key" in resp_expired["reason"]
    print("  [Client Test 11] Stale / Expired Session Key -> REJECTED (Session Store PASSED)", flush=True)

    # 12. Authenticated Key Rotation Lifecycle Test
    # Key ID 2 active for Debian Node 20
    session_k2 = linep_sl.derive_session_key(master_secret, session_id, 2, node_id, 3600, now)
    mac_k2 = linep_sl.compute_sl1_mac(session_k2.secret_key, hdr_bytes, session_id, 2, 20, payload)
    cap_token_k2 = linep_sl.create_capability_token(session_k2.secret_key, session_id, linep_sl.CapFlags.INFERENCE_READ, now + 3600)
    k2_req = dict(base_req)
    k2_req["key_id"] = 2
    k2_req["auth_seq"] = 20
    k2_req["mac_hex"] = mac_k2.hex()
    k2_req["cap_mac_hex"] = cap_token_k2.mac.hex()
    resp_k2 = send_test_request(host, tcp_port, k2_req)
    assert resp_k2["status"] == "ACCEPTED"

    # Send Authenticated ROTATE_KEY command (signed with session_k2 and ADMIN capability token!)
    rotate_cap_token = linep_sl.create_capability_token(session_k2.secret_key, session_id, linep_sl.CapFlags.ADMIN, now + 3600)
    rotate_payload = b"ROTATE_KEY_ID_1"
    rotate_mac = linep_sl.compute_sl1_mac(session_k2.secret_key, hdr_bytes, session_id, 2, 400, rotate_payload)
    rotate_req = dict(base_req)
    rotate_req["type"] = "ROTATE_KEY"
    rotate_req["key_id"] = 2
    rotate_req["revoke_key_id"] = 1
    rotate_req["auth_seq"] = 400
    rotate_req["payload_hex"] = rotate_payload.hex()
    rotate_req["mac_hex"] = rotate_mac.hex()
    rotate_req["required_cap"] = int(linep_sl.CapFlags.ADMIN)
    rotate_req["cap_flags"] = linep_sl.CapFlags.ADMIN.value
    rotate_req["cap_mac_hex"] = rotate_cap_token.mac.hex()
    resp_rot = send_test_request(host, tcp_port, rotate_req)
    assert resp_rot["status"] == "KEY_ROTATED"

    # Try using Revoked Key ID 1 -> MUST BE REJECTED!
    resp_k1_revoked = send_test_request(host, tcp_port, base_req)
    assert resp_k1_revoked["status"] == "REJECTED"
    assert "Expired, revoked or non-existent session key" in resp_k1_revoked["reason"]
    print("  [Client Test 12] Authenticated Key Rotation (Revoked Key ID 1 -> REJECTED, Key ID 2 -> ACCEPTED) PASSED", flush=True)

    # --- UDP HEARTBEAT TESTS (Tests 13-16) ---
    hb_cap_token = linep_sl.create_capability_token(
        session_k2.secret_key, session_id, linep_sl.CapFlags.HEARTBEAT_EMIT, now + 3600
    )
    hb_payload = b"UDP_HEARTBEAT_NODE_20"
    hb_mac = linep_sl.compute_sl1_mac(session_k2.secret_key, hdr_bytes, session_id, 2, 300, hb_payload)

    hb_req = {
        "type": "UDP_HEARTBEAT",
        "trust_domain_id": trust_domain,
        "node_id": node_id,
        "pubkey_hex": pubkey_debian.hex(),
        "offered_sl": linep_sl.SecurityLevel.SL3_CAPABILITIES.value,
        "session_id": session_id,
        "key_id": 2,
        "auth_seq": 300,
        "hdr_hex": hdr_bytes.hex(),
        "payload_hex": hb_payload.hex(),
        "mac_hex": hb_mac.hex(),
        "cap_flags": linep_sl.CapFlags.HEARTBEAT_EMIT.value,
        "expires_at": now + 3600,
        "cap_mac_hex": hb_cap_token.mac.hex(),
    }

    # 13. Valid Protected UDP Heartbeat -> HEARTBEAT_ACCEPTED
    resp13 = send_udp_heartbeat(host, udp_port, hb_req)
    assert resp13["status"] == "HEARTBEAT_ACCEPTED", f"Test 13 failed: {resp13}"
    print("  [Client Test 13] Protected UDP Heartbeat -> ACCEPTED PASSED", flush=True)

    # 14. Tampered UDP Heartbeat MAC -> REJECTED
    tampered_hb = dict(hb_req)
    tampered_hb["auth_seq"] = 301
    tampered_hb["mac_hex"] = (b"\xff" * 16).hex()
    resp14 = send_udp_heartbeat(host, udp_port, tampered_hb)
    assert resp14["status"] == "REJECTED"
    print("  [Client Test 14] Tampered UDP Heartbeat MAC -> REJECTED PASSED", flush=True)

    # 15. Duplicate UDP Heartbeat Replay (retransmitted seq 300) -> REJECTED
    dup_hb = dict(hb_req)
    dup_hb["auth_seq"] = 300
    resp15 = send_udp_heartbeat(host, udp_port, dup_hb)
    assert resp15["status"] == "REJECTED"
    assert "Replay Error" in resp15["reason"]
    print("  [Client Test 15] Duplicate UDP Heartbeat Replay -> REJECTED PASSED", flush=True)

    # 16. Cross-Domain UDP Heartbeat WITHOUT Federation Trust -> REJECTED
    cross_hb = dict(hb_req)
    cross_hb["auth_seq"] = 302
    cross_hb["mac_hex"] = linep_sl.compute_sl1_mac(session_k2.secret_key, hdr_bytes, session_id, 2, 302, hb_payload).hex()
    cross_hb["remote_trust_domain_id"] = 0x4C4E5039
    resp16 = send_udp_heartbeat(host, udp_port, cross_hb)
    assert resp16["status"] == "REJECTED"
    print("  [Client Test 16] Cross-Domain UDP Heartbeat without Federation -> REJECTED PASSED", flush=True)

    # Final shutdown request
    stop_req = dict(base_req)
    stop_req["key_id"] = 2
    stop_req["auth_seq"] = 500
    stop_req["mac_hex"] = linep_sl.compute_sl1_mac(session_k2.secret_key, hdr_bytes, session_id, 2, 500, payload).hex()
    stop_req["stop_after_test"] = True
    send_test_request(host, tcp_port, stop_req)

    print("[CLIENT SUCCESS] ALL TCP STREAMING, CANCEL, KEY ROTATION & UDP HEARTBEAT SL1-SL4 SECURITY GATES PASSED 100%!", flush=True)


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
