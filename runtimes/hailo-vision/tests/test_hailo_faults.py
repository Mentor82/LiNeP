"""Real image decode/preprocess with injected SDK-boundary failures, no device reset."""

from types import SimpleNamespace
import sys
import pytest

cv2 = pytest.importorskip("cv2", reason="image/backend tests run on the Pi with host OpenCV")
np = pytest.importorskip("numpy")

from linep_vision.hailo import HailoBackend
from linep_vision.detection import DetectOptions, VisionError


class PipelineProbe:
    def __init__(self, failure=None, result=None):
        self.failure = failure
        self.result = [[] for _ in range(80)] if result is None else result
        self.calls = 0

    def set_nms_score_threshold(self, value):
        self.confidence = value

    def set_nms_iou_threshold(self, value):
        self.iou = value

    def infer(self, inputs):
        self.calls += 1
        image, = inputs.values()
        assert image.shape == (1, 640, 640, 3) and image.dtype == np.uint8
        if self.failure:
            raise self.failure
        return {"out": [self.result]}


def backend(pipeline):
    b = HailoBackend.__new__(HailoBackend)
    b.cv2, b.np = cv2, np
    b.max_pixels = 16_000_000
    b._faulted = False
    b._models = {"model": (SimpleNamespace(name="in", shape=(640, 640, 3)), SimpleNamespace(name="out"), pipeline)}
    return b


def image():
    ok, encoded = cv2.imencode(".jpg", np.zeros((32, 64, 3), dtype=np.uint8))
    assert ok
    return encoded.tobytes()


@pytest.mark.parametrize("error", [RuntimeError("injected Hailo disconnected"), TimeoutError("injected VStream timeout")])
def test_device_failure_latches_unavailable_without_retry(error):
    p = PipelineProbe(failure=error)
    b = backend(p)
    with pytest.raises(VisionError, match="VISION_BACKEND_FAILED"):
        b.detect("model", image(), DetectOptions())
    with pytest.raises(VisionError, match="VISION_BACKEND_UNAVAILABLE"):
        b.detect("model", image(), DetectOptions())
    assert p.calls == 1


def test_malformed_model_output_latches_unavailable():
    p = PipelineProbe(result=[[[0, 0, 1, 1, float("nan")]]] + [[] for _ in range(79)])
    b = backend(p)
    with pytest.raises(VisionError, match="VISION_INVALID_COORDINATES"):
        b.detect("model", image(), DetectOptions())
    assert b._faulted


def test_bad_client_image_does_not_poison_backend():
    p = PipelineProbe()
    b = backend(p)
    with pytest.raises(VisionError, match="VISION_INVALID_PAYLOAD"):
        b.detect("model", b"\xff\xd8\xffbroken", DetectOptions())
    assert not b._faulted and p.calls == 0
    result = b.detect("model", image(), DetectOptions(confidence=0.5, iou=0.3))
    assert result.is_valid() and not result.detections
    assert (p.confidence, p.iou) == (0.5, 0.3)


def test_decompressed_pixel_budget_rejects_before_inference():
    p = PipelineProbe()
    b = backend(p)
    b.max_pixels = 100
    with pytest.raises(VisionError, match="VISION_INVALID_PAYLOAD"):
        b.detect("model", image(), DetectOptions())
    assert p.calls == 0 and not b._faulted


def test_missing_device_at_startup_never_constructs_a_mock_fallback(monkeypatch):
    class GoneDevice:
        @staticmethod
        def create_params():
            return SimpleNamespace()

        def __init__(self, params):
            raise RuntimeError("injected device absent at startup")

    monkeypatch.setitem(sys.modules, "hailo_platform", SimpleNamespace(
        VDevice=GoneDevice, HailoSchedulingAlgorithm=SimpleNamespace(ROUND_ROBIN=1)))
    with pytest.raises(RuntimeError, match="device absent"):
        HailoBackend({"model": "/unused/model.hef"})
