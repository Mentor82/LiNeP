"""End-to-end tests for LiNeP V0.2 TCP client, server, and multi-stream streaming."""

import time
import pytest
from linep.v0_2 import (
    RuntimeProfile,
    EventType,
    TerminalOutcome,
    StreamIdentity,
    RequestEnvelope,
    LiNePClient,
    LiNePMockServer,
    MockServerConfig,
)


@pytest.fixture
def mock_server():
    server = LiNePMockServer(MockServerConfig(model_id="test-mock-model", tokens_per_stream=8))
    server.start(tcp_port=0, udp_port=0)
    yield server
    server.stop()


def test_client_server_chat_streaming(mock_server):
    with LiNePClient(port=mock_server.tcp_port) as client:
        events = list(client.stream_chat(model="test-mock-model", prompt="Hello LiNeP!"))
        assert len(events) > 0

        # Assert reasoning deltas precede content deltas
        reasoning_deltas = [e for e in events if e.event_type == EventType.REASONING_DELTA]
        content_deltas = [e for e in events if e.event_type == EventType.CONTENT_DELTA]
        terminal_events = [e for e in events if e.event_type == EventType.COMPLETED]

        assert len(reasoning_deltas) == 2
        assert len(content_deltas) == 8
        assert len(terminal_events) == 1
        assert terminal_events[0].outcome == TerminalOutcome.COMPLETED


def test_client_server_embedding_vector(mock_server):
    with LiNePClient(port=mock_server.tcp_port) as client:
        vec = client.embed(model="test-mock-model", text="Vectorize this sentence")
        assert len(vec) == 768

        # Assert unit sphere L2 normalization
        import math
        norm = math.sqrt(sum(v * v for v in vec))
        assert abs(norm - 1.0) < 1e-3


def test_client_server_cancellation():
    server = LiNePMockServer(MockServerConfig(tokens_per_stream=100, delay_per_event_s=0.01))
    server.start(tcp_port=0)
    try:
        with LiNePClient(port=server.tcp_port) as client:
            stream_id = StreamIdentity(request_id=901, execution_id=902, output_id=0)
            req = RequestEnvelope(
                stream=stream_id,
                profile=RuntimeProfile.CHAT,
                model_id="test-mock-model",
                payload="Long text",
            )
            received = 0
            cancelled_seen = False
            for evt in client.execute_stream(req, auto_ack_window=False):
                received += 1
                if received == 3:
                    client.cancel_stream(stream_id)
                if evt.event_type == EventType.CANCELLED:
                    cancelled_seen = True
                    assert evt.outcome == TerminalOutcome.CANCELLED
                    assert evt.error.code == 499
                    break
            assert cancelled_seen is True
            assert received < 20  # Stream stopped early
    finally:
        server.stop()
