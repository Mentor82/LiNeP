"""Failure matrix on isolated sockets; never stops the host's Hailo service."""

import dataclasses
import socket

import pytest
from linep.v0_2.constants import EnvelopeType, ErrorCategory, EventType
from linep.v0_2.envelopes import WireEnvelopeHeader, encode_header, encode_request
from linep.v0_2.vision import VisionBox2D, VisionDetection, VisionDetectResult
from linep_vision.conformance import validate_events
from linep_vision.server import VisionServer
from test_runtime import TestBackend, client, request, runtime


@pytest.mark.parametrize("header", [
    WireEnvelopeHeader(version_minor=3), WireEnvelopeHeader(version_major=1),
    WireEnvelopeHeader(flags=1), WireEnvelopeHeader(envelope_type=255),
    WireEnvelopeHeader(magic=0),
])
def test_invalid_frame_header_closes_connection(runtime, header):
    _, server = runtime
    with socket.create_connection(server.server_address, timeout=2) as sock:
        sock.sendall(encode_header(header))
        assert sock.recv(1) == b""


@pytest.mark.parametrize("payload", [b"2LNP", encode_header(WireEnvelopeHeader(
    envelope_type=int(EnvelopeType.REQUEST), payload_len=100)) + b"partial"])
def test_stalled_partial_frame_times_out(payload):
    backend = TestBackend()
    server = VisionServer(backend, port=0, io_timeout=0.1).start()
    try:
        with socket.create_connection(server.server_address, timeout=2) as sock:
            sock.sendall(payload)
            assert sock.recv(1) == b""
        assert not backend.started.is_set()
    finally:
        server.stop()


def test_connection_limit_does_not_allocate_more_handlers():
    server = VisionServer(TestBackend(), port=0, max_clients=1).start()
    try:
        with client(server) as first:
            assert first.query_capabilities() is not None
            with socket.create_connection(server.server_address, timeout=2) as extra:
                assert extra.recv(1) == b""
    finally:
        server.stop()


def test_duplicate_active_identity_closes_without_second_terminal(runtime):
    backend, server = runtime
    backend.release.clear()
    with client(server) as c:
        stream = c.execute_stream(request(), auto_ack_window=False)
        assert next(stream).event_type == EventType.ACCEPTED
        assert backend.started.wait(2)
        c._send_all(encode_request(request()))
        assert c._sock.recv(1) == b""
        backend.release.set()
        stream.close()
        assert server.slot.acquire(timeout=2)
        server.slot.release()


@pytest.mark.parametrize("detection", [
    VisionDetection(0, "wrong-label", 0.8, VisionBox2D(0, 0, 1, 1)),
    VisionDetection(0, "person", float("nan"), VisionBox2D(0, 0, 1, 1)),
    VisionDetection(0, "person", 0.8, VisionBox2D(0.5, 0, 0.1, 1)),
    VisionDetection(0, "person", 0.8, VisionBox2D(0, 0, 2, 1)),
])
def test_invalid_backend_result_is_failed_not_empty_success(runtime, detection):
    backend, server = runtime
    backend.detect = lambda *_: VisionDetectResult("coco80:v1", 810, 1080, [detection])
    with client(server) as c:
        events = list(c.execute_stream(request(), auto_ack_window=False))
    validate_events(events, request().stream, EventType.FAILED)
    assert events[-1].error.category == ErrorCategory.MODEL_ERROR
    assert not any(e.event_type == EventType.VISION_RESULT for e in events)


def test_conformance_rejects_duplicate_terminal_and_cross_stream(runtime):
    _, server = runtime
    with client(server) as c:
        events = list(c.execute_stream(request(), auto_ack_window=False))
    validate_events(events, request().stream, EventType.COMPLETED)
    with pytest.raises(AssertionError):
        validate_events(events + [events[-1]], request().stream, EventType.COMPLETED)
    bad = [dataclasses.replace(events[0], stream=request(999).stream), *events[1:]]
    with pytest.raises(AssertionError, match="cross-stream"):
        validate_events(bad, request().stream, EventType.COMPLETED)


def test_conformance_rejects_sequence_gap(runtime):
    _, server = runtime
    with client(server) as c:
        events = list(c.execute_stream(request(), auto_ack_window=False))
    events[1].event_seq += 1
    with pytest.raises(AssertionError, match="event_seq"):
        validate_events(events, request().stream, EventType.COMPLETED)
