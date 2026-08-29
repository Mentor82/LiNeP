"""Cross-Language Binary Golden Frames Interoperability Tests (Python <-> C++ Core)."""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
import pytest

from linep.v0_2 import (
    LINEP_V02_MAGIC,
    LINEP_V02_UDP_MAGIC,
    RuntimeProfile,
    EnvelopeType,
    EventType,
    ControlType,
    TerminalOutcome,
    ErrorCategory,
    EmbeddingNormalization,
    EmbeddingDistanceMetric,
    ControlMessageType,
    StreamIdentity,
    RequestEnvelope,
    EventEnvelope,
    ControlEnvelope,
    CapabilitiesEnvelope,
    CapabilitiesDescriptor,
    EmbeddingSpaceDescriptor,
    EmbeddingPayload,
    RuntimeErrorPayload,
    UdpControlDatagram,
    decode_request,
    decode_event,
    decode_control,
    decode_capabilities,
    decode_control_datagram,
    encode_request,
    encode_event,
    encode_control,
    encode_capabilities,
    encode_control_datagram,
)


def find_cpp_golden_tool() -> Optional[Path]:
    repo_root = Path(__file__).resolve().parents[3]
    if os.name == "nt":
        candidates = [
            repo_root / "build" / "tools" / "v0_2" / "linep-v02-golden-frames.exe",
            repo_root / "build_win" / "tools" / "v0_2" / "linep-v02-golden-frames.exe",
            repo_root / "LiNeP" / "build" / "tools" / "v0_2" / "linep-v02-golden-frames.exe",
        ]
    else:
        candidates = [
            repo_root / "build_linux" / "tools" / "v0_2" / "linep-v02-golden-frames",
            repo_root / "build" / "tools" / "v0_2" / "linep-v02-golden-frames",
            repo_root / "LiNeP" / "build_linux" / "tools" / "v0_2" / "linep-v02-golden-frames",
            repo_root / "LiNeP" / "build" / "tools" / "v0_2" / "linep-v02-golden-frames",
        ]
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK if os.name != "nt" else os.F_OK):
            return c
    return None


def test_python_decodes_cpp_generated_golden_frames():
    cpp_tool = find_cpp_golden_tool()
    if cpp_tool is None:
        pytest.skip("C++ golden frames tool executable not found in build directory")

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Run C++ tool in generate mode
        res = subprocess.run([str(cpp_tool), "generate", tmp_dir], capture_output=True, text=True)
        assert res.returncode == 0, f"C++ generator failed: {res.stderr}"

        p = Path(tmp_dir)

        # 1. Verify C++ Request Frame
        req_bytes = (p / "request_chat_cpp.bin").read_bytes()
        req = decode_request(req_bytes)
        assert req is not None
        assert req.stream.request_id == 1001
        assert req.stream.execution_id == 2001
        assert req.profile == RuntimeProfile.CHAT
        assert req.model_id == "meta-llama/Llama-3.1-8B-Instruct"
        assert req.max_tokens == 512
        assert abs(req.temperature - 0.8) < 1e-4

        # 2. Verify C++ Content Delta Event
        delta_bytes = (p / "event_content_delta_cpp.bin").read_bytes()
        evt_delta = decode_event(delta_bytes)
        assert evt_delta is not None
        assert evt_delta.event_seq == 42
        assert evt_delta.event_type == EventType.CONTENT_DELTA
        assert evt_delta.payload == "Neural"

        # 3. Verify C++ Reasoning Delta Event
        reason_bytes = (p / "event_reasoning_delta_cpp.bin").read_bytes()
        evt_reason = decode_event(reason_bytes)
        assert evt_reason is not None
        assert evt_reason.event_seq == 43
        assert evt_reason.event_type == EventType.REASONING_DELTA
        assert evt_reason.payload == "Analyzing user intent deeply..."

        # 4. Verify C++ Embedding Event
        embed_bytes = (p / "event_embedding_cpp.bin").read_bytes()
        evt_embed = decode_event(embed_bytes)
        assert evt_embed is not None
        assert evt_embed.embedding.space.embedding_space_id == "nomic-embed-text-v1.5"
        assert evt_embed.embedding.space.dimensions == 4
        assert evt_embed.embedding.space.normalization == EmbeddingNormalization.L2
        assert evt_embed.embedding.space.distance_metric == EmbeddingDistanceMetric.COSINE
        assert len(evt_embed.embedding.vector) == 4
        assert abs(evt_embed.embedding.vector[0] - 0.1) < 1e-4

        # 5. Verify C++ Completed Event
        comp_bytes = (p / "event_completed_cpp.bin").read_bytes()
        evt_comp = decode_event(comp_bytes)
        assert evt_comp is not None
        assert evt_comp.event_type == EventType.COMPLETED
        assert evt_comp.outcome == TerminalOutcome.COMPLETED

        # 6. Verify C++ Error Event
        err_bytes = (p / "event_error_cpp.bin").read_bytes()
        evt_err = decode_event(err_bytes)
        assert evt_err is not None
        assert evt_err.error.category == ErrorCategory.RESOURCE_EXHAUSTED
        assert evt_err.error.code == 503
        assert evt_err.error.message == "CUDA out of memory"

        # 7. Verify C++ Cancel Control
        cancel_bytes = (p / "control_cancel_cpp.bin").read_bytes()
        ctrl_cancel = decode_control(cancel_bytes)
        assert ctrl_cancel is not None
        assert ctrl_cancel.control_type == ControlType.CANCEL
        assert ctrl_cancel.reason == "User requested cancellation via UI"

        # 8. Verify C++ Window Update Control
        win_bytes = (p / "control_window_update_cpp.bin").read_bytes()
        ctrl_win = decode_control(win_bytes)
        assert ctrl_win is not None
        assert ctrl_win.control_type == ControlType.WINDOW_UPDATE
        assert ctrl_win.ack_offset_bytes == 8192

        # 9. Verify C++ Capabilities Envelope
        caps_bytes = (p / "capabilities_cpp.bin").read_bytes()
        caps = decode_capabilities(caps_bytes)
        assert caps is not None
        assert len(caps.descriptor.supported_profiles) == 3
        assert caps.descriptor.max_context_tokens == 8192
        assert caps.descriptor.supported_models == ["llama3:8b", "qwen2.5:7b"]

        # 10. Verify C++ UDP Hello Datagram
        udp_hello_bytes = (p / "udp_hello_cpp.bin").read_bytes()
        udp_hello = decode_control_datagram(udp_hello_bytes)
        assert udp_hello is not None
        assert udp_hello.message_type == int(ControlMessageType.NODE_HELLO)
        assert udp_hello.node_id == 1001
        assert udp_hello.runtime_id == 2001
        assert udp_hello.tcp_port == 11435
        assert udp_hello.is_trunk_ready() is True

        # 11. Verify C++ UDP Invite Datagram
        udp_inv_bytes = (p / "udp_invite_cpp.bin").read_bytes()
        udp_inv = decode_control_datagram(udp_inv_bytes)
        assert udp_inv is not None
        assert udp_inv.message_type == int(ControlMessageType.INVITE)
        assert udp_inv.lease_token == 0xAABBCCDDEEFF0011

        # 12. Verify C++ UDP LeaseAck Datagram
        udp_ack_bytes = (p / "udp_lease_ack_cpp.bin").read_bytes()
        udp_ack = decode_control_datagram(udp_ack_bytes)
        assert udp_ack is not None
        assert udp_ack.message_type == int(ControlMessageType.LEASE_ACK)
        assert udp_ack.lease_token == 0xAABBCCDDEEFF0011

        # 13. Verify C++ UDP Heartbeat Datagram
        udp_hb_bytes = (p / "udp_heartbeat_cpp.bin").read_bytes()
        udp_hb = decode_control_datagram(udp_hb_bytes)
        assert udp_hb is not None
        assert udp_hb.message_type == int(ControlMessageType.HEARTBEAT)
        assert udp_hb.load_pct == 45
        assert udp_hb.queue_depth == 3


def test_cpp_verifies_python_generated_golden_frames():
    cpp_tool = find_cpp_golden_tool()
    if cpp_tool is None:
        pytest.skip("C++ golden frames tool executable not found in build directory")

    with tempfile.TemporaryDirectory() as tmp_dir:
        p = Path(tmp_dir)

        # 1. Request Frame (matching Go / external format expected by C++ verify)
        req = RequestEnvelope(
            stream=StreamIdentity(5001, 6001, 0),
            profile=RuntimeProfile.CHAT,
            model_id="llama3.1:8b",
            payload='{"prompt":"Hello from Go/Python!"}',
            max_tokens=1024,
            temperature=0.7,
            stream_requested=True,
        )
        (p / "request_chat_go.bin").write_bytes(encode_request(req))

        # 2. Content Delta Event
        evt_delta = EventEnvelope(
            stream=StreamIdentity(5001, 6001, 2),
            event_seq=10,
            event_type=EventType.CONTENT_DELTA,
            payload="Hello from Go!",
        )
        (p / "event_content_delta_go.bin").write_bytes(encode_event(evt_delta))

        # 3. Reasoning Delta Event
        evt_reason = EventEnvelope(
            stream=StreamIdentity(5001, 6001, 2),
            event_seq=11,
            event_type=EventType.REASONING_DELTA,
            payload="Thinking deeply in Go...",
        )
        (p / "event_reasoning_delta_go.bin").write_bytes(encode_event(evt_reason))

        # 4. Embedding Event
        sp = EmbeddingSpaceDescriptor(
            embedding_space_id="nomic-embed-text-v1.5",
            model_id="nomic-ai/nomic-embed-text-v1.5",
            model_revision="v1.5",
            dimensions=4,
            normalization=EmbeddingNormalization.L2,
            distance_metric=EmbeddingDistanceMetric.COSINE,
        )
        evt_embed = EventEnvelope(
            stream=StreamIdentity(5001, 6001, 0),
            event_seq=1,
            event_type=EventType.EMBEDDING_RESULT,
            embedding=EmbeddingPayload(space=sp, vector=[0.1, -0.25, 0.77, 0.05]),
        )
        (p / "event_embedding_go.bin").write_bytes(encode_event(evt_embed))

        # 5. Completed Event
        evt_comp = EventEnvelope(
            stream=StreamIdentity(5001, 6001, 2),
            event_seq=12,
            event_type=EventType.COMPLETED,
            outcome=TerminalOutcome.COMPLETED,
        )
        (p / "event_completed_go.bin").write_bytes(encode_event(evt_comp))

        # 6. Error Event
        evt_err = EventEnvelope(
            stream=StreamIdentity(5001, 6001, 2),
            event_seq=13,
            event_type=EventType.FAILED,
            outcome=TerminalOutcome.FAILED,
            error=RuntimeErrorPayload(
                category=ErrorCategory.RESOURCE_EXHAUSTED,
                code=503,
                message="CUDA out of memory",
                backend_diagnostic="vLLM KV cache full, 0 blocks free",
            ),
        )
        (p / "event_error_go.bin").write_bytes(encode_event(evt_err))

        # 7. Cancel Control
        ctrl_cancel = ControlEnvelope(
            stream=StreamIdentity(5001, 6001, 2),
            control_type=ControlType.CANCEL,
            reason="User canceled via Go UI",
        )
        (p / "control_cancel_go.bin").write_bytes(encode_control(ctrl_cancel))

        # 8. Window Update Control
        ctrl_win = ControlEnvelope(
            stream=StreamIdentity(5001, 6001, 2),
            control_type=ControlType.WINDOW_UPDATE,
            reason="ACK",
            ack_offset_bytes=16384,
        )
        (p / "control_window_update_go.bin").write_bytes(encode_control(ctrl_win))

        # 9. Capabilities Envelope
        caps = CapabilitiesEnvelope(
            descriptor=CapabilitiesDescriptor(
                supported_profiles=[RuntimeProfile.GENERATE, RuntimeProfile.CHAT],
                max_context_tokens=8192,
                max_output_tokens=4096,
                supports_streaming=True,
                supports_cancellation=True,
                supports_tool_calling=True,
                supports_reasoning_deltas=True,
                supported_models=["llama3.1:8b", "qwen2.5:7b"],
                supported_embedding_spaces=[
                    EmbeddingSpaceDescriptor(
                        embedding_space_id="nomic-embed-text-v1.5",
                        model_id="nomic-ai/nomic-embed-text-v1.5",
                        model_revision="v1.5",
                        dimensions=768,
                        normalization=EmbeddingNormalization.L2,
                        distance_metric=EmbeddingDistanceMetric.COSINE,
                    )
                ],
            )
        )
        (p / "capabilities_go.bin").write_bytes(encode_capabilities(caps))

        # 10. UDP Hello Datagram
        udp_hello = UdpControlDatagram(
            node_id=8001,
            runtime_id=9001,
            endpoint_id=1,
            control_seq=1,
            control_epoch=1,
            message_type=int(ControlMessageType.NODE_HELLO),
            tcp_port=11435,
        )
        udp_hello.set_trunk_ready(True)
        (p / "udp_hello_go.bin").write_bytes(encode_control_datagram(udp_hello))

        # 11. UDP LeaseAck Datagram
        udp_ack = UdpControlDatagram(
            node_id=8001,
            runtime_id=9001,
            endpoint_id=1,
            control_seq=3,
            control_epoch=1,
            message_type=int(ControlMessageType.LEASE_ACK),
            lease_token=0x9988776655443322,
            tcp_port=11435,
        )
        udp_ack.set_trunk_ready(True)
        (p / "udp_lease_ack_go.bin").write_bytes(encode_control_datagram(udp_ack))

        # 12. UDP Heartbeat Datagram
        udp_hb = UdpControlDatagram(
            node_id=8001,
            runtime_id=9001,
            endpoint_id=1,
            control_seq=4,
            control_epoch=1,
            message_type=int(ControlMessageType.HEARTBEAT),
            load_pct=60,
            queue_depth=4,
            tcp_port=11435,
        )
        udp_hb.set_trunk_ready(True)
        (p / "udp_heartbeat_go.bin").write_bytes(encode_control_datagram(udp_hb))

        # Execute C++ verifier against Python-generated frames!
        res = subprocess.run([str(cpp_tool), "verify", tmp_dir], capture_output=True, text=True)
        assert res.returncode == 0, f"C++ verification of Python frames failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
