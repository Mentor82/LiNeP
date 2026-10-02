"""Unit and Negative Tests for LiNeP V0.2 PROFILE_VISION (Phase 1)."""

import math
import pytest

from linep.v0_2.constants import (
    EventType,
    RuntimeProfile,
    VisionTask,
)
from linep.v0_2.envelopes import (
    CapabilitiesDescriptor,
    CapabilitiesEnvelope,
    EventEnvelope,
    StreamIdentity,
    decode_capabilities,
    decode_event,
    encode_capabilities,
    encode_event,
)
from linep.v0_2.vision import (
    LABEL_SET_COCO80_V1,
    LABEL_SET_VOC20_V1,
    LABEL_SET_WIDERFACE_V1,
    VisionBox2D,
    VisionDetection,
    VisionDetectResult,
    VisionModelDescriptor,
    VisionResultPayload,
    is_valid_label_for_class,
    resolve_standard_label,
)


def test_vision_positive_coco80_roundtrip():
    """Test full COCO-80 detection event encoding and decoding."""
    evt = EventEnvelope(
        stream=StreamIdentity(request_id=100, execution_id=200, output_id=0),
        event_seq=1,
        event_type=EventType.VISION_RESULT,
        timestamp_us=12345678,
        vision=VisionResultPayload(
            task=VisionTask.DETECT,
            model_id="yolov8n-detect",
            model_revision="v1.0.0",
            detect=VisionDetectResult(
                label_set_id=LABEL_SET_COCO80_V1,
                original_width=1920,
                original_height=1080,
                detections=[
                    VisionDetection(
                        class_id=0,
                        label="person",
                        score=0.95,
                        box=VisionBox2D(x_min=0.10, y_min=0.20, x_max=0.40, y_max=0.80),
                    ),
                    VisionDetection(
                        class_id=2,
                        label="car",
                        score=0.88,
                        box=VisionBox2D(x_min=0.50, y_min=0.60, x_max=0.90, y_max=0.95),
                    ),
                    VisionDetection(
                        class_id=16,
                        label="dog",
                        score=0.77,
                        box=VisionBox2D(x_min=0.20, y_min=0.60, x_max=0.45, y_max=0.85),
                    ),
                ],
            ),
        ),
    )

    assert evt.is_valid()
    encoded = encode_event(evt)
    assert len(encoded) > 0

    decoded = decode_event(encoded)
    assert decoded is not None
    assert decoded.event_type == EventType.VISION_RESULT
    assert decoded.vision.task == VisionTask.DETECT
    assert decoded.vision.model_id == "yolov8n-detect"
    assert decoded.vision.model_revision == "v1.0.0"
    assert decoded.vision.detect.label_set_id == LABEL_SET_COCO80_V1
    assert decoded.vision.detect.original_width == 1920
    assert decoded.vision.detect.original_height == 1080
    assert len(decoded.vision.detect.detections) == 3

    d1 = decoded.vision.detect.detections[0]
    assert d1.class_id == 0
    assert d1.label == "person"
    assert math.isclose(d1.score, 0.95, rel_tol=1e-5)
    assert math.isclose(d1.box.x_min, 0.10, rel_tol=1e-5)
    assert math.isclose(d1.box.y_min, 0.20, rel_tol=1e-5)
    assert math.isclose(d1.box.x_max, 0.40, rel_tol=1e-5)
    assert math.isclose(d1.box.y_max, 0.80, rel_tol=1e-5)


def test_vision_positive_empty_detections():
    """Test frame where zero objects were detected."""
    evt = EventEnvelope(
        stream=StreamIdentity(request_id=101, execution_id=201, output_id=0),
        event_seq=1,
        event_type=EventType.VISION_RESULT,
        timestamp_us=999,
        vision=VisionResultPayload(
            task=VisionTask.DETECT,
            model_id="scrfd-2.5g",
            model_revision="v2.1",
            detect=VisionDetectResult(
                label_set_id=LABEL_SET_WIDERFACE_V1,
                original_width=640,
                original_height=480,
                detections=[],
            ),
        ),
    )
    assert evt.is_valid()
    encoded = encode_event(evt)
    decoded = decode_event(encoded)
    assert decoded is not None
    assert len(decoded.vision.detect.detections) == 0
    assert decoded.vision.detect.original_width == 640
    assert decoded.vision.detect.original_height == 480


def test_vision_positive_omitted_label():
    """Test detection with omitted (empty) label string."""
    evt = EventEnvelope(
        stream=StreamIdentity(request_id=102, execution_id=202, output_id=0),
        event_seq=1,
        event_type=EventType.VISION_RESULT,
        vision=VisionResultPayload(
            task=VisionTask.DETECT,
            model_id="voc-model",
            detect=VisionDetectResult(
                label_set_id=LABEL_SET_VOC20_V1,
                original_width=800,
                original_height=600,
                detections=[
                    VisionDetection(
                        class_id=0,
                        label="",  # Omitted label
                        score=0.91,
                        box=VisionBox2D(x_min=0.05, y_min=0.15, x_max=0.85, y_max=0.65),
                    )
                ],
            ),
        ),
    )
    assert evt.is_valid()
    encoded = encode_event(evt)
    decoded = decode_event(encoded)
    assert decoded is not None
    assert decoded.vision.detect.detections[0].label == ""
    assert resolve_standard_label(LABEL_SET_VOC20_V1, 0) == "aeroplane"


def test_vision_positive_custom_label_set():
    """Test custom labelset identifier and custom label string."""
    evt = EventEnvelope(
        stream=StreamIdentity(request_id=103, execution_id=203, output_id=0),
        event_seq=1,
        event_type=EventType.VISION_RESULT,
        vision=VisionResultPayload(
            task=VisionTask.DETECT,
            model_id="custom-vision",
            detect=VisionDetectResult(
                label_set_id="custom:drone_parts_v1",
                original_width=1280,
                original_height=720,
                detections=[
                    VisionDetection(
                        class_id=0,
                        label="rotor_blade",
                        score=0.92,
                        box=VisionBox2D(x_min=0.2, y_min=0.3, x_max=0.5, y_max=0.7),
                    )
                ],
            ),
        ),
    )
    assert evt.is_valid()
    encoded = encode_event(evt)
    decoded = decode_event(encoded)
    assert decoded is not None
    assert decoded.vision.detect.detections[0].label == "rotor_blade"


def test_vision_capabilities_descriptor():
    """Test capabilities declaration and backward-compatible serialization."""
    caps = CapabilitiesEnvelope(
        descriptor=CapabilitiesDescriptor(
            supported_profiles=[RuntimeProfile.VISION],
            supported_models=["yolov8n-detect"],
            supported_vision_models=[
                VisionModelDescriptor(
                    model_id="yolov8n-detect",
                    model_revision="v1.0.0",
                    label_set_id=LABEL_SET_COCO80_V1,
                    task=VisionTask.DETECT,
                    max_detections=100,
                )
            ],
        )
    )

    assert caps.descriptor.supports_profile(RuntimeProfile.VISION)
    assert caps.descriptor.supports_vision_model("yolov8n-detect", VisionTask.DETECT)
    assert not caps.descriptor.supports_vision_model("other")

    encoded = encode_capabilities(caps)
    decoded = decode_capabilities(encoded)
    assert decoded is not None
    assert decoded.descriptor.supports_profile(RuntimeProfile.VISION)
    assert decoded.descriptor.supports_vision_model("yolov8n-detect", VisionTask.DETECT)
    assert len(decoded.descriptor.supported_vision_models) == 1
    assert decoded.descriptor.supported_vision_models[0].label_set_id == LABEL_SET_COCO80_V1


def test_vision_negatives():
    """Test strict validation and negative vector rejection."""
    valid_box = VisionBox2D(x_min=0.1, y_min=0.2, x_max=0.4, y_max=0.5)
    assert valid_box.is_valid()

    # 1. NaN coordinate
    assert not VisionBox2D(x_min=float("nan"), y_min=0.2, x_max=0.4, y_max=0.5).is_valid()

    # 2. Inf coordinate
    assert not VisionBox2D(x_min=0.1, y_min=0.2, x_max=float("inf"), y_max=0.5).is_valid()

    # 3. Negative coordinate
    assert not VisionBox2D(x_min=-0.01, y_min=0.2, x_max=0.4, y_max=0.5).is_valid()

    # 4. Collapsed box (x_min == x_max)
    assert not VisionBox2D(x_min=0.4, y_min=0.2, x_max=0.4, y_max=0.5).is_valid()

    # 5. Inverted box (x_min > x_max)
    assert not VisionBox2D(x_min=0.6, y_min=0.2, x_max=0.4, y_max=0.5).is_valid()

    # 6. Zero height box (y_min == y_max)
    assert not VisionBox2D(x_min=0.1, y_min=0.5, x_max=0.4, y_max=0.5).is_valid()

    # 7. Out of bounds (x_max > 1.0)
    assert not VisionBox2D(x_min=0.1, y_min=0.2, x_max=1.01, y_max=0.5).is_valid()

    # 8. Score out of bounds
    assert not VisionDetection(box=valid_box, score=1.05).is_valid()
    assert not VisionDetection(box=valid_box, score=-0.1).is_valid()
    assert not VisionDetection(box=valid_box, score=float("nan")).is_valid()

    # 9. Zero dimensions in result
    assert not VisionDetectResult(
        label_set_id=LABEL_SET_COCO80_V1, original_width=0, original_height=1080
    ).is_valid()
    assert not VisionDetectResult(
        label_set_id=LABEL_SET_COCO80_V1, original_width=1920, original_height=0
    ).is_valid()

    # 10. Label mismatch in standard registry
    # In COCO-80: class 0 is "person", NOT "bicycle"
    bad_det = VisionDetection(class_id=0, label="bicycle", score=0.9, box=valid_box)
    assert not VisionDetectResult(
        label_set_id=LABEL_SET_COCO80_V1,
        original_width=1920,
        original_height=1080,
        detections=[bad_det],
    ).is_valid()

    # 11. Unsupported task
    bad_payload = VisionResultPayload(
        task=VisionTask.UNSPECIFIED,
        model_id="yolo",
        detect=VisionDetectResult(
            label_set_id=LABEL_SET_COCO80_V1,
            original_width=1920,
            original_height=1080,
        ),
    )
    assert not bad_payload.is_valid()
