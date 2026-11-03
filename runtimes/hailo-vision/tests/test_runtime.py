import dataclasses
import socket
import threading

import pytest
from linep.v0_2.client import LiNePClient
from linep.v0_2.constants import (
    LINEP_V02_MAX_PAYLOAD_SIZE, ControlType, ErrorCategory, EventType, RuntimeProfile,
)
from linep.v0_2.envelopes import (
    ControlEnvelope, GenerationOptions, RequestEnvelope, StreamIdentity,
    WireEnvelopeHeader, encode_header,
)
from linep.v0_2.vision import VisionDetectResult, VisionModelDescriptor
from linep_vision.detection import (
    DetectOptions, Letterbox, VisionError, decode_detections, validate_request,
)
from linep_vision.server import VisionServer

MODELS = {"yolov8s-detect": object()}
JPEG = b"\xff\xd8\xff\xe0\x00\xff"


def request(number=1, extras=None, **kwargs):
    return RequestEnvelope(
        stream=StreamIdentity(number, number * 10, 0), model_id="yolov8s-detect",
        profile=RuntimeProfile.VISION, payload=JPEG, has_options=True,
        options=GenerationOptions(extra_options=extras if extras is not None else [("vision.task", "detect")]),
        **kwargs,
    )


def test_request_defaults_and_signature_validation():
    assert validate_request(request(), MODELS) == DetectOptions()


@pytest.mark.parametrize("change,reason", [
    ({"profile": RuntimeProfile.CHAT}, "VISION_UNSUPPORTED_PROFILE"),
    ({"model_id": "unknown"}, "VISION_UNKNOWN_MODEL"),
    ({"payload": b""}, "VISION_INVALID_PAYLOAD"),
    ({"payload": "text"}, "VISION_INVALID_PAYLOAD"),
    ({"payload": b"not an image"}, "VISION_INVALID_PAYLOAD"),
    ({"stream": StreamIdentity(1, 10, 1)}, "VISION_SINGLE_IMAGE_ONLY"),
    ({"has_options": False}, "VISION_UNSUPPORTED_TASK"),
])
def test_invalid_request(change, reason):
    with pytest.raises(VisionError, match=reason):
        validate_request(dataclasses.replace(request(), **change), MODELS)


@pytest.mark.parametrize("key,value", [
    ("vision.confidence_threshold", "nan"), ("vision.confidence_threshold", "-0.1"),
    ("vision.iou_threshold", "inf"), ("vision.iou_threshold", "1.1"),
    ("vision.max_detections", "1001"), ("vision.max_detections", "0"),
    ("vision.max_detections", "1.0"), ("vision.max_detections", "-1"),
    ("vision.task", "segment"), ("vision.content_type", "image/png"),
    ("vision.unknown", "1"),
])
def test_invalid_options(key, value):
    extras = dict(request().options.extra_options)
    extras[key] = value
    with pytest.raises(VisionError):
        validate_request(request(extras=list(extras.items())), MODELS)


def test_image_limit():
    with pytest.raises(VisionError, match="VISION_INVALID_PAYLOAD"):
        validate_request(dataclasses.replace(request(), payload=b"x" * (16 * 1024 * 1024 + 1)), MODELS)


@pytest.mark.parametrize("width,height", [(1280, 720), (720, 1280), (1001, 333), (1, 65535)])
def test_letterbox_maps_original_boundaries(width, height):
    g = Letterbox.create(width, height, 640, 640)
    box = g.box(g.top / 640, g.left / 640,
                (g.top + g.resized_height) / 640, (g.left + g.resized_width) / 640)
    assert box.is_valid()
    assert (box.x_min, box.y_min, box.x_max, box.y_max) == pytest.approx((0, 0, 1, 1))


def test_padding_only_box_is_removed():
    assert Letterbox.create(1280, 720, 640, 640).box(0, 0, 0.01, 0.1) is None


def test_coco_mapping_score_order_and_limit():
    classes = [[] for _ in range(80)]
    classes[0] = [[0.2, 0.1, 0.6, 0.5, 0.8]]
    classes[5] = [[0.1, 0.1, 0.9, 0.9, 0.9]]
    result = decode_detections(classes, Letterbox.create(640, 640, 640, 640), DetectOptions(max_detections=1))
    assert result.is_valid()
    assert len(result.detections) == 1
    assert (result.detections[0].class_id, result.detections[0].label) == (5, "bus")


@pytest.mark.parametrize("row", [[0, 0, 1, 1, float("nan")], [0.7, 0, 0.1, 1, 0.9], [0, 0, 1.1, 1, 0.9], [1, 2]])
def test_invalid_model_output_is_failure(row):
    classes = [[] for _ in range(80)]
    classes[0] = [row]
    with pytest.raises(VisionError):
        decode_detections(classes, Letterbox.create(640, 640, 640, 640), DetectOptions())


def test_valid_empty_result():
    assert decode_detections([[] for _ in range(80)], Letterbox.create(640, 480, 640, 640), DetectOptions()).detections == []


class TestBackend:
    __test__ = False

    def __init__(self):
        self.descriptors = [VisionModelDescriptor(model_id="yolov8s-detect", model_revision="test", label_set_id="coco80:v1")]
        self.started = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.failure = None

    def detect(self, model_id, payload, options):
        self.started.set()
        assert self.release.wait(5), "test inference timed out"
        if self.failure:
            raise self.failure
        return VisionDetectResult("coco80:v1", 640, 480, [])


@pytest.fixture
def runtime():
    backend = TestBackend()
    server = VisionServer(backend, port=0, io_timeout=2).start()
    yield backend, server
    backend.release.set()
    server.stop()


def client(server):
    return LiNePClient(*server.server_address, timeout=3)


def test_capabilities_and_two_sequential_requests(runtime):
    _, server = runtime
    with client(server) as c:
        caps = c.query_capabilities().descriptor
        assert caps.supported_profiles == [RuntimeProfile.VISION]
        assert caps.supports_vision_model("yolov8s-detect")
        for number in (1, 2):
            events = list(c.execute_stream(request(number), auto_ack_window=False))
            assert [e.event_type for e in events] == [EventType.ACCEPTED, EventType.VISION_RESULT, EventType.COMPLETED]
            assert [e.event_seq for e in events] == [1, 2, 3]
            assert events[1].vision.model_revision == "test"
            assert all(e.stream == request(number).stream for e in events)


def test_hardware_failure_is_not_empty_success(runtime):
    backend, server = runtime
    backend.failure = RuntimeError("Hailo disconnected")
    with client(server) as c:
        events = list(c.execute_stream(request(), auto_ack_window=False))
        assert [e.event_type for e in events] == [EventType.ACCEPTED, EventType.FAILED]
        assert events[-1].error.category == ErrorCategory.MODEL_ERROR


def test_busy_and_cancellation(runtime):
    backend, server = runtime
    backend.release.clear()
    with client(server) as c, client(server) as other:
        stream = c.execute_stream(request(), auto_ack_window=False)
        assert next(stream).event_type == EventType.ACCEPTED
        assert backend.started.wait(2)
        busy = list(other.execute_stream(request(2), auto_ack_window=False))
        assert len(busy) == 1 and busy[0].error.code == 429
        c.send_control(ControlEnvelope(stream=request().stream, control_type=ControlType.CANCEL))
        # Capability reply is a deterministic barrier: CANCEL was processed first.
        assert c.query_capabilities() is not None
        backend.release.set()
        assert [e.event_type for e in stream] == [EventType.CANCELLED]
        assert list(other.execute_stream(request(3), auto_ack_window=False))[-1].event_type == EventType.COMPLETED


def test_invalid_task_fails_before_hardware(runtime):
    backend, server = runtime
    with client(server) as c:
        events = list(c.execute_stream(request(extras=[("vision.task", "pose")]), auto_ack_window=False))
    assert len(events) == 1 and events[0].event_type == EventType.FAILED
    assert not backend.started.is_set()


def test_disconnect_keeps_device_slot_until_inference_returns(runtime):
    backend, server = runtime
    backend.release.clear()
    c = client(server)
    stream = c.execute_stream(request(), auto_ack_window=False)
    try:
        assert next(stream).event_type == EventType.ACCEPTED
        assert backend.started.wait(2)
        c.close()
        stream.close()
        with client(server) as other:
            events = list(other.execute_stream(request(2), auto_ack_window=False))
            assert len(events) == 1 and events[0].error.code == 429
        backend.release.set()
        assert server.slot.acquire(timeout=2)
        server.slot.release()
        with client(server) as other:
            assert list(other.execute_stream(request(3), auto_ack_window=False))[-1].event_type == EventType.COMPLETED
    finally:
        c.close()
        stream.close()


def test_wrong_stream_cancellation_does_not_cancel_active_job(runtime):
    backend, server = runtime
    backend.release.clear()
    with client(server) as c:
        stream = c.execute_stream(request(), auto_ack_window=False)
        assert next(stream).event_type == EventType.ACCEPTED
        assert backend.started.wait(2)
        c.send_control(ControlEnvelope(stream=request(99).stream, control_type=ControlType.CANCEL))
        assert c.query_capabilities() is not None
        backend.release.set()
        assert [e.event_type for e in stream] == [EventType.VISION_RESULT, EventType.COMPLETED]


def test_oversized_frame_is_closed_without_reading_body(runtime):
    _, server = runtime
    with socket.create_connection(server.server_address, timeout=2) as sock:
        sock.sendall(encode_header(WireEnvelopeHeader(payload_len=LINEP_V02_MAX_PAYLOAD_SIZE + 1)))
        assert sock.recv(1) == b""


def test_non_loopback_bind_rejected():
    with pytest.raises(ValueError, match="loopback"):
        VisionServer(TestBackend(), host="0.0.0.0", port=0)
