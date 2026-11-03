"""VISION-specific wire conformance; never runs chat/embedding probes on a detector."""

import time
from contextlib import contextmanager

from linep.v0_2.constants import (
    ErrorCategory, EventType, RuntimeProfile, TerminalOutcome,
)
from linep.v0_2.envelopes import (
    CapabilitiesEnvelope, GenerationOptions, RequestEnvelope, StreamIdentity,
    decode_capabilities, encode_capabilities,
)
from linep.v0_2.vision import resolve_standard_label

TERMINALS = {EventType.COMPLETED, EventType.FAILED, EventType.CANCELLED}


def capabilities(session):
    if hasattr(session, "query_capabilities"):
        return session.query_capabilities()
    # TrunkSession signs and verifies these frames, preserving auth_seq order.
    session._send_frame(encode_capabilities(CapabilitiesEnvelope()))
    return decode_capabilities(session._recv_frame())


def validate_events(events, stream, expected_terminal):
    if not events or events[-1].event_type != expected_terminal:
        raise AssertionError("unexpected terminal: " + str([(e.event_type.name, e.error.message) for e in events]))
    if any(e.stream != stream for e in events):
        raise AssertionError("cross-stream event")
    if [e.event_seq for e in events] != list(range(1, len(events) + 1)):
        raise AssertionError("event_seq is not contiguous from 1")
    if sum(e.event_type in TERMINALS for e in events) != 1:
        raise AssertionError("terminal must occur exactly once")
    outcomes = {EventType.COMPLETED: TerminalOutcome.COMPLETED,
                EventType.FAILED: TerminalOutcome.FAILED, EventType.CANCELLED: TerminalOutcome.CANCELLED}
    if events[-1].outcome != outcomes[expected_terminal]:
        raise AssertionError("terminal outcome mismatch")


class VisionConformance:
    """A fresh session per case; explicit identity and known model attribution."""

    def __init__(self, session_factory, image, model="yolov8s-detect", resolved_model="yolov8s-detect",
                 expected_size=(810, 1080), expected_labels=("bus", "person")):
        self.session_factory = session_factory
        self.image = image
        self.model = model
        self.resolved_model = resolved_model
        self.expected_size = expected_size
        self.expected_labels = set(expected_labels)
        self.counter = 60000
        self.revision = None

    def request(self, payload=None, extras=None):
        self.counter += 1
        return RequestEnvelope(
            stream=StreamIdentity(self.counter, self.counter * 10, 0), profile=RuntimeProfile.VISION,
            model_id=self.model, payload=self.image if payload is None else payload,
            has_options=True, options=GenerationOptions(extra_options=[("vision.task", "detect")] if extras is None else extras),
        )

    @contextmanager
    def session(self):
        with self.session_factory() as session:
            yield session

    def detection(self, session, req, empty=False, expected_labels=None):
        events = list(session.execute_stream(req, auto_ack_window=False))
        validate_events(events, req.stream, EventType.COMPLETED)
        if [e.event_type for e in events] != [EventType.ACCEPTED, EventType.VISION_RESULT, EventType.COMPLETED]:
            raise AssertionError("VISION success lifecycle mismatch")
        v = events[1].vision
        if v.model_id != self.resolved_model or not v.is_valid():
            raise AssertionError("invalid VISION payload or resolved model")
        if self.revision is not None and v.model_revision != self.revision:
            raise AssertionError("result revision differs from advertised HEF")
        if (v.detect.original_width, v.detect.original_height) != self.expected_size:
            raise AssertionError("box reference dimensions differ from original image")
        if v.detect.label_set_id != "coco80:v1":
            raise AssertionError("unexpected label set")
        for d in v.detect.detections:
            canonical = resolve_standard_label(v.detect.label_set_id, d.class_id)
            if canonical is None or (d.label and d.label != canonical):
                raise AssertionError("label does not match class registry")
        if empty:
            if v.detect.detections:
                raise AssertionError("expected a valid zero-detection result")
        elif not (self.expected_labels if expected_labels is None else expected_labels) <= {
                resolve_standard_label(v.detect.label_set_id, d.class_id) for d in v.detect.detections}:
            raise AssertionError("expected fixture objects not detected")
        # SDK iterators stop at terminal. A queued extra terminal must not hide
        # behind that boundary: the next frame must be this capability reply.
        if capabilities(session) is None:
            raise AssertionError("unexpected queued frame after terminal")
        return v

    def check_capabilities(self):
        with self.session() as s:
            c = capabilities(s)
            if c is None or RuntimeProfile.VISION not in c.descriptor.supported_profiles:
                raise AssertionError("missing/undecodable VISION capabilities")
            models = [m for m in c.descriptor.supported_vision_models if m.model_id == self.resolved_model]
            if len(models) != 1 or models[0].label_set_id != "coco80:v1" or not 1 <= models[0].max_detections <= 1000:
                raise AssertionError("missing or invalid vision model descriptor")
            revision = models[0].model_revision
            if len(revision) != 64 or any(c not in "0123456789abcdef" for c in revision):
                raise AssertionError("HEF SHA-256 revision is missing")
            self.revision = revision

    def check_detection_and_reuse(self):
        with self.session() as s:
            first = self.detection(s, self.request())
            second = self.detection(s, self.request())
            if first.model_revision != second.model_revision:
                raise AssertionError("model revision changed within session")

    def check_empty_result(self):
        with self.session() as s:
            self.detection(s, self.request(extras=[("vision.task", "detect"), ("vision.confidence_threshold", "1")]), empty=True)

    def check_detection_limit(self):
        with self.session() as s:
            v = self.detection(s, self.request(extras=[("vision.task", "detect"), ("vision.max_detections", "1")]), expected_labels=set())
            if len(v.detect.detections) != 1:
                raise AssertionError("max_detections=1 was not applied")

    def check_error(self, payload=None, extras=None, reason=None, category=ErrorCategory.BAD_REQUEST):
        with self.session() as s:
            req = self.request(payload, extras)
            events = list(s.execute_stream(req, auto_ack_window=False))
            validate_events(events, req.stream, EventType.FAILED)
            if any(e.event_type == EventType.VISION_RESULT for e in events):
                raise AssertionError("error was disguised as a detection result")
            if events[-1].error.message != reason or events[-1].error.category != category:
                raise AssertionError("unexpected failure reason/category")
            self.detection(s, self.request())  # bad client input must not poison the worker/session

    def run(self):
        cases = [
            ("capabilities", self.check_capabilities),
            ("detection_identity_boxes_labels_and_reuse", self.check_detection_and_reuse),
            ("valid_empty_result", self.check_empty_result),
            ("max_detections", self.check_detection_limit),
            ("empty_image", lambda: self.check_error(payload=b"", reason="VISION_INVALID_PAYLOAD")),
            ("corrupt_jpeg", lambda: self.check_error(payload=b"\xff\xd8\xff\xe0broken", reason="VISION_INVALID_PAYLOAD")),
            ("unsupported_image_format", lambda: self.check_error(payload=b"BMnot-jpeg", reason="VISION_INVALID_PAYLOAD")),
            ("unsupported_task", lambda: self.check_error(extras=[("vision.task", "pose")], reason="VISION_UNSUPPORTED_TASK", category=ErrorCategory.UNSUPPORTED)),
            ("missing_task", lambda: self.check_error(extras=[], reason="VISION_UNSUPPORTED_TASK", category=ErrorCategory.UNSUPPORTED)),
            ("unknown_option", lambda: self.check_error(extras=[("vision.task", "detect"), ("vision.unknown", "1")], reason="VISION_UNSUPPORTED_OPTION", category=ErrorCategory.UNSUPPORTED)),
            ("invalid_confidence", lambda: self.check_error(extras=[("vision.task", "detect"), ("vision.confidence_threshold", "nan")], reason="VISION_INVALID_OPTIONS")),
            ("invalid_iou", lambda: self.check_error(extras=[("vision.task", "detect"), ("vision.iou_threshold", "1.1")], reason="VISION_INVALID_OPTIONS")),
            ("invalid_detection_limit", lambda: self.check_error(extras=[("vision.task", "detect"), ("vision.max_detections", "1001")], reason="VISION_INVALID_OPTIONS")),
            ("content_type_mismatch", lambda: self.check_error(extras=[("vision.task", "detect"), ("vision.content_type", "image/png")], reason="VISION_INVALID_CONTENT_TYPE")),
        ]
        report = []
        for name, run in cases:
            started = time.monotonic()
            try:
                run()
                report.append({"name": name, "passed": True})
            except Exception as error:
                report.append({"name": name, "passed": False, "error": str(error)})
            report[-1]["duration_ms"] = round((time.monotonic() - started) * 1000, 2)
        return {"profile": "VISION", "passed": sum(c["passed"] for c in report), "total": len(report), "cases": report}
