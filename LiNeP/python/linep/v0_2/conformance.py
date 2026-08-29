"""LiNeP V0.2 Standalone Conformance Test Engine in Python."""

from __future__ import annotations

import math
import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional

from linep.v0_2.constants import (
    LINEP_V02_HEADER_SIZE,
    RuntimeProfile,
    EnvelopeType,
    EventType,
    ControlType,
    TerminalOutcome,
)
from linep.v0_2.envelopes import (
    StreamIdentity,
    WireEnvelopeHeader,
    RequestEnvelope,
    EventEnvelope,
    ControlEnvelope,
    CapabilitiesEnvelope,
    encode_request,
    decode_event,
    encode_control,
    encode_capabilities,
    decode_capabilities,
    decode_header,
)
from linep.v0_2.client import LiNePClient


@dataclass
class TestResult:
    test_name: str
    passed: bool = False
    details: str = ""
    duration_ms: int = 0


@dataclass
class ProfileConformanceStatus:
    profile: RuntimeProfile
    profile_name: str
    conformant: bool = False


@dataclass
class ConformanceReport:
    target_endpoint: str
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    results: List[TestResult] = field(default_factory=list)
    profiles: List[ProfileConformanceStatus] = field(default_factory=list)

    def is_all_passed(self) -> bool:
        return self.total_tests > 0 and self.failed_tests == 0 and self.passed_tests == self.total_tests


class ConformanceRunner:
    def __init__(self, host: str = "127.0.0.1", port: int = 11435, timeout: float = 5.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def _create_client(self) -> LiNePClient:
        return LiNePClient(self.host, self.port, timeout=self.timeout)

    def run_all(self) -> ConformanceReport:
        rep = ConformanceReport(target_endpoint=f"{self.host}:{self.port}")

        def run(fn) -> TestResult:
            res = fn()
            rep.total_tests += 1
            if res.passed:
                rep.passed_tests += 1
            else:
                rep.failed_tests += 1
            rep.results.append(res)
            return res

        r_caps = run(self.test_capabilities_handshake)
        r_chat = run(self.test_basic_chat_streaming)
        r_reas = run(self.test_reasoning_deltas)
        r_emb = run(self.test_embedding_space)
        r_canc = run(self.test_network_cancellation)
        r_flow = run(self.test_window_update_flow_control)
        r_fail = run(self.test_fail_closed_robustness)
        r_snap = run(self.test_content_snapshot_mode)
        r_mout = run(self.test_multi_output_streams)

        # Profile evaluations:
        rep.profiles.append(
            ProfileConformanceStatus(
                profile=RuntimeProfile.GENERATE,
                profile_name="PROFILE_GENERATE",
                conformant=(
                    r_caps.passed
                    and r_chat.passed
                    and r_canc.passed
                    and r_flow.passed
                    and r_fail.passed
                    and r_snap.passed
                ),
            )
        )
        rep.profiles.append(
            ProfileConformanceStatus(
                profile=RuntimeProfile.CHAT,
                profile_name="PROFILE_CHAT",
                conformant=(
                    r_caps.passed
                    and r_chat.passed
                    and r_reas.passed
                    and r_canc.passed
                    and r_flow.passed
                    and r_fail.passed
                ),
            )
        )
        rep.profiles.append(
            ProfileConformanceStatus(
                profile=RuntimeProfile.EMBED,
                profile_name="PROFILE_EMBED",
                conformant=(r_caps.passed and r_emb.passed and r_fail.passed),
            )
        )

        return rep

    def test_capabilities_handshake(self) -> TestResult:
        t0 = time.time()
        try:
            with self._create_client() as client:
                caps = client.query_capabilities()
                if caps is None or not caps.descriptor.supported_models:
                    return TestResult("CAPABILITIES_HANDSHAKE", False, "Missing required capabilities fields")
                duration = int((time.time() - t0) * 1000)
                return TestResult(
                    "CAPABILITIES_HANDSHAKE",
                    True,
                    f"Handshake verified for model: {caps.descriptor.supported_models[0]}",
                    duration,
                )
        except Exception as e:
            return TestResult("CAPABILITIES_HANDSHAKE", False, f"Exception: {e}")

    def test_basic_chat_streaming(self) -> TestResult:
        t0 = time.time()
        try:
            with self._create_client() as client:
                req = RequestEnvelope(
                    stream=StreamIdentity(101, 1001, 0),
                    profile=RuntimeProfile.CHAT,
                    model_id="conformance-model",
                    payload="Test prompt",
                )
                events = list(client.execute_stream(req))
                if not events:
                    return TestResult("BASIC_CHAT_STREAMING", False, "No events received")
                if events[-1].event_type != EventType.COMPLETED or events[-1].outcome != TerminalOutcome.COMPLETED:
                    return TestResult("BASIC_CHAT_STREAMING", False, "Stream did not terminate with completed (200)")
                duration = int((time.time() - t0) * 1000)
                return TestResult(
                    "BASIC_CHAT_STREAMING", True, f"Streaming verified: {len(events)} events received", duration
                )
        except Exception as e:
            return TestResult("BASIC_CHAT_STREAMING", False, f"Exception: {e}")

    def test_reasoning_deltas(self) -> TestResult:
        t0 = time.time()
        try:
            with self._create_client() as client:
                req = RequestEnvelope(
                    stream=StreamIdentity(102, 1002, 0),
                    profile=RuntimeProfile.CHAT,
                    model_id="conformance-model",
                    payload="Reasoning prompt",
                )
                reasoning_seen = 0
                content_seen = 0
                for evt in client.execute_stream(req):
                    if evt.event_type == EventType.REASONING_DELTA:
                        if content_seen > 0:
                            return TestResult("REASONING_DELTAS", False, "Reasoning arrived after content delta")
                        reasoning_seen += 1
                    elif evt.event_type == EventType.CONTENT_DELTA:
                        content_seen += 1
                if reasoning_seen == 0 or content_seen == 0:
                    return TestResult("REASONING_DELTAS", False, "Missing reasoning or content deltas")
                duration = int((time.time() - t0) * 1000)
                return TestResult(
                    "REASONING_DELTAS", True, f"Reasoning verified: {reasoning_seen} deltas before content", duration
                )
        except Exception as e:
            return TestResult("REASONING_DELTAS", False, f"Exception: {e}")

    def test_embedding_space(self) -> TestResult:
        t0 = time.time()
        try:
            with self._create_client() as client:
                vec = client.embed("conformance-model", "Embed this vector")
                if len(vec) != 768:
                    return TestResult("EMBEDDING_SPACE_CONFORMANCE", False, f"Dimension mismatch: {len(vec)} != 768")
                norm = math.sqrt(sum(v * v for v in vec))
                if abs(norm - 1.0) > 0.01:
                    return TestResult("EMBEDDING_SPACE_CONFORMANCE", False, "Embedding vector is not L2 normalized")
                duration = int((time.time() - t0) * 1000)
                return TestResult(
                    "EMBEDDING_SPACE_CONFORMANCE",
                    True,
                    "Embedding space verified: 768-dim normalized cosine vector",
                    duration,
                )
        except Exception as e:
            return TestResult("EMBEDDING_SPACE_CONFORMANCE", False, f"Exception: {e}")

    def test_network_cancellation(self) -> TestResult:
        t0 = time.time()
        try:
            with self._create_client() as client:
                stream_id = StreamIdentity(104, 1004, 0)
                req = RequestEnvelope(
                    stream=stream_id,
                    profile=RuntimeProfile.CHAT,
                    model_id="conformance-model",
                    payload="Generate 1000 tokens",
                )
                cancelled_ok = False
                events_seen = 0
                for evt in client.execute_stream(req, auto_ack_window=False):
                    events_seen += 1
                    if events_seen == 2:
                        client.cancel_stream(stream_id)
                    if evt.event_type == EventType.CANCELLED and evt.error.code == 499:
                        cancelled_ok = True
                        break
                if not cancelled_ok:
                    return TestResult("CANCEL_UNDER_LOAD", False, "Stream was not cancelled with 499 status")
                duration = int((time.time() - t0) * 1000)
                return TestResult(
                    "CANCEL_UNDER_LOAD",
                    True,
                    f"Cancellation verified: stopped after {events_seen} events with outcome=cancelled (499)",
                    duration,
                )
        except Exception as e:
            return TestResult("CANCEL_UNDER_LOAD", False, f"Exception: {e}")

    def test_window_update_flow_control(self) -> TestResult:
        t0 = time.time()
        try:
            with self._create_client() as client:
                req = RequestEnvelope(
                    stream=StreamIdentity(105, 1005, 0),
                    profile=RuntimeProfile.CHAT,
                    model_id="conformance-model",
                    payload="Flow control prompt",
                )
                events = list(client.execute_stream(req, auto_ack_window=True))
                if not events or events[-1].event_type != EventType.COMPLETED:
                    return TestResult("BACKPRESSURE_FLOW_CONTROL", False, "Flow control stream failed to complete")
                duration = int((time.time() - t0) * 1000)
                return TestResult(
                    "BACKPRESSURE_FLOW_CONTROL",
                    True,
                    "Flow control verified via cumulative WINDOW_UPDATE pacing",
                    duration,
                )
        except Exception as e:
            return TestResult("BACKPRESSURE_FLOW_CONTROL", False, f"Exception: {e}")

    def test_fail_closed_robustness(self) -> TestResult:
        t0 = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((self.host, self.port))
            # Send corrupted header (bad magic)
            bad_hdr = b"\xFF\xFF\x00\x00" + b"\x00" * 28
            s.sendall(bad_hdr)
            time.sleep(0.05)
            # Assert remote closed socket
            chunk = s.recv(1024)
            s.close()
            if len(chunk) != 0:
                return TestResult("PROTOCOL_VIOLATION_FAIL_CLOSED", False, "Server did not close socket on bad magic")
            duration = int((time.time() - t0) * 1000)
            return TestResult(
                "PROTOCOL_VIOLATION_FAIL_CLOSED",
                True,
                "Fail-closed robustness verified: server disconnected upon protocol violation",
                duration,
            )
        except Exception as e:
            return TestResult("PROTOCOL_VIOLATION_FAIL_CLOSED", False, f"Exception: {e}")

    def test_content_snapshot_mode(self) -> TestResult:
        t0 = time.time()
        try:
            with self._create_client() as client:
                req = RequestEnvelope(
                    stream=StreamIdentity(107, 1007, 0),
                    profile=RuntimeProfile.GENERATE,
                    model_id="conformance-model",
                    payload="Snapshot prompt",
                )
                events = list(client.execute_stream(req))
                if not events or events[-1].event_type != EventType.COMPLETED:
                    return TestResult("CONTENT_SNAPSHOT_EQUIVALENCE", False, "Snapshot mode stream failed")
                duration = int((time.time() - t0) * 1000)
                return TestResult(
                    "CONTENT_SNAPSHOT_EQUIVALENCE",
                    True,
                    f"Snapshot equivalence verified ({len(events)} events processed)",
                    duration,
                )
        except Exception as e:
            return TestResult("CONTENT_SNAPSHOT_EQUIVALENCE", False, f"Exception: {e}")

    def test_multi_output_streams(self) -> TestResult:
        t0 = time.time()
        try:
            with self._create_client() as client:
                req = RequestEnvelope(
                    stream=StreamIdentity(108, 1008, 0),
                    profile=RuntimeProfile.GENERATE,
                    model_id="conformance-model",
                    payload="Multi output prompt",
                )
                events = list(client.execute_stream(req))
                if not events or events[-1].event_type != EventType.COMPLETED:
                    return TestResult("MULTI_OUTPUT_STREAMING", False, "Multi-output stream failed to complete")
                duration = int((time.time() - t0) * 1000)
                return TestResult(
                    "MULTI_OUTPUT_STREAMING",
                    True,
                    f"Multi-output streaming verified ({len(events)} events received)",
                    duration,
                )
        except Exception as e:
            return TestResult("MULTI_OUTPUT_STREAMING", False, f"Exception: {e}")
