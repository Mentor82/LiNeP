#!/usr/bin/env python3
from __future__ import annotations

import os
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


def run_python_benchmark(num_iterations: int = 20_000):
    print("================================================================================")
    print("        LiNeP vs LiNeP-SL Python Binding Performance Benchmark                 ")
    print("================================================================================")

    domain_a = 0x4C4E5031
    master_secret = b"\xaa" * 32
    pubkey_node = b"\xbb" * 32
    session_id = 0x1001
    key_id = 1
    node_id = 10
    now = int(time.time())

    hdr_bytes = b"\x4e\x4c\x01\x01" + b"\x00" * 20
    payload = b"BENCHMARK_PAYLOAD_DATA" * 10

    # Derive Session Key
    session = linep_sl.derive_session_key(master_secret, session_id, key_id, node_id, 3600, now)
    mac = linep_sl.compute_sl1_mac(session.secret_key, hdr_bytes, session_id, key_id, 1, payload)

    cap_token = linep_sl.create_capability_token(
        session.secret_key, session_id, linep_sl.CapFlags.INFERENCE_READ, now + 3600
    )

    engine = linep_sl.SecurityDecisionEngine(domain_a)
    engine.register_peer(node_id, pubkey_node)
    pol = linep_sl.GovernancePolicy(
        policy_id="default-policy",
        policy_revision=1,
        allowed_capabilities=linep_sl.CapFlags.INFERENCE_READ,
        allow_cross_domain=False,
    )
    engine.set_policy(pol)

    # 1. SL1 MAC Verification Benchmark
    t0 = time.perf_counter()
    for _ in range(num_iterations):
        _ = linep_sl.verify_sl1_mac(session.secret_key, hdr_bytes, session_id, key_id, 1, mac, payload)
    t1 = time.perf_counter()
    sl1_fps = num_iterations / (t1 - t0)
    sl1_lat_us = ((t1 - t0) / num_iterations) * 1_000_000

    # 2. SL2 Session Key Derivation Benchmark
    t0 = time.perf_counter()
    for _ in range(num_iterations):
        _ = linep_sl.derive_session_key(master_secret, session_id, key_id, node_id, 3600, now)
    t1 = time.perf_counter()
    sl2_fps = num_iterations / (t1 - t0)
    sl2_lat_us = ((t1 - t0) / num_iterations) * 1_000_000

    # 3. SL3 Capability Verification Benchmark
    t0 = time.perf_counter()
    for _ in range(num_iterations):
        _ = linep_sl.verify_capability_token(session.secret_key, cap_token, session_id, now, linep_sl.CapFlags.INFERENCE_READ)
    t1 = time.perf_counter()
    sl3_fps = num_iterations / (t1 - t0)
    sl3_lat_us = ((t1 - t0) / num_iterations) * 1_000_000

    # 4. SL4 Governance Engine Benchmark
    t0 = time.perf_counter()
    for _ in range(num_iterations):
        _ = engine.evaluate(
            trust_domain_id=domain_a,
            session_id=session_id,
            key_id=key_id,
            local_node_id=1,
            remote_node_id=node_id,
            remote_trust_domain_id=domain_a,
            remote_revoked=False,
            negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
            requested_cap=linep_sl.CapFlags.INFERENCE_READ,
            remote_pubkey_32bytes=pubkey_node,
            policy_id="default-policy",
        )
    t1 = time.perf_counter()
    sl4_fps = num_iterations / (t1 - t0)
    sl4_lat_us = ((t1 - t0) / num_iterations) * 1_000_000

    # 5. Full Stack Benchmark (SL1 + SL2 + SL3 + SL4)
    t0 = time.perf_counter()
    for _ in range(num_iterations):
        m = linep_sl.verify_sl1_mac(session.secret_key, hdr_bytes, session_id, key_id, 1, mac, payload)
        c = linep_sl.verify_capability_token(session.secret_key, cap_token, session_id, now, linep_sl.CapFlags.INFERENCE_READ)
        d, _ = engine.evaluate(
            trust_domain_id=domain_a,
            session_id=session_id,
            key_id=key_id,
            local_node_id=1,
            remote_node_id=node_id,
            remote_trust_domain_id=domain_a,
            remote_revoked=False,
            negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
            requested_cap=linep_sl.CapFlags.INFERENCE_READ,
            remote_pubkey_32bytes=pubkey_node,
            policy_id="default-policy",
        )
    t1 = time.perf_counter()
    full_fps = num_iterations / (t1 - t0)
    full_lat_us = ((t1 - t0) / num_iterations) * 1_000_000

    print(f"Iterations per Benchmark: {num_iterations:,} messages\n")
    print("--------------------------------------------------------------------------------")
    print(" Layer / Component                |  Ops / sec (msg/s)  | Latency per Msg (us)  ")
    print("--------------------------------------------------------------------------------")
    print(f" SL1: HMAC-SHA256 MAC Verification| {sl1_fps:17,.2f} | {sl1_lat_us:19.2f} us")
    print(f" SL2: Session Key Derivation      | {sl2_fps:17,.2f} | {sl2_lat_us:19.2f} us")
    print(f" SL3: Capability Verification     | {sl3_fps:17,.2f} | {sl3_lat_us:19.2f} us")
    print(f" SL4: Governance Engine & Audit   | {sl4_fps:17,.2f} | {sl4_lat_us:19.2f} us")
    print("--------------------------------------------------------------------------------")
    print(f" Full Security Stack (SL1-SL4)    | {full_fps:17,.2f} | {full_lat_us:19.2f} us")
    print("================================================================================\n")


if __name__ == "__main__":
    run_python_benchmark()
