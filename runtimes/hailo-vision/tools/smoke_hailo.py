"""Real-hardware socket smoke test; no installed service or trunk required."""

import argparse
import json
import time
from pathlib import Path

from linep.v0_2.client import LiNePClient
from linep.v0_2.constants import EventType, RuntimeProfile
from linep.v0_2.envelopes import GenerationOptions, RequestEnvelope, StreamIdentity
from linep_vision.hailo import HailoBackend
from linep_vision.server import VisionServer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hef", required=True)
    parser.add_argument("--images", default="/usr/local/hailo/resources/images")
    args = parser.parse_args()
    model_id = "yolov8s-detect"
    backend = HailoBackend({model_id: args.hef})
    server = VisionServer(backend, port=0).start()
    try:
        with LiNePClient(*server.server_address, timeout=10) as client:
            caps = client.query_capabilities().descriptor
            assert caps.supported_profiles == [RuntimeProfile.VISION]
            assert caps.supports_vision_model(model_id)
            print(json.dumps({"capabilities": caps.supported_models, "revision": backend.descriptors[0].model_revision}))
            for number, filename in enumerate(("bus.jpg", "dog_bicycle.jpg", "zidane.jpg"), 1):
                image_bytes = (Path(args.images) / filename).read_bytes()
                # The installed dog_bicycle.jpg fixture is actually a BMP.
                # Convert only this test input in memory to a contract-supported PNG.
                if image_bytes.startswith(b"BM"):
                    import cv2
                    import numpy as np
                    image = cv2.imdecode(np.frombuffer(image_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
                    ok, encoded = cv2.imencode(".png", image)
                    assert ok
                    image_bytes = encoded.tobytes()
                    print(json.dumps({"fixture": filename, "conversion": "BMP to PNG in memory"}))
                req = RequestEnvelope(
                    stream=StreamIdentity(number, number * 10, 0), profile=RuntimeProfile.VISION,
                    model_id=model_id, payload=image_bytes,
                    has_options=True, options=GenerationOptions(extra_options=[("vision.task", "detect")]),
                )
                started = time.perf_counter()
                events = list(client.execute_stream(req, auto_ack_window=False))
                elapsed_ms = (time.perf_counter() - started) * 1000
                assert [e.event_type for e in events] == [EventType.ACCEPTED, EventType.VISION_RESULT, EventType.COMPLETED], [
                    (e.event_type.name, e.error.code, e.error.message) for e in events]
                assert [e.event_seq for e in events] == [1, 2, 3]
                assert all(e.stream == req.stream for e in events)
                result = events[1].vision.detect
                assert result.is_valid()
                labels = {d.label for d in result.detections}
                expected = {"bus.jpg": {"bus", "person"}, "dog_bicycle.jpg": {"dog", "bicycle"}, "zidane.jpg": {"person"}}
                assert expected[filename] <= labels, (filename, labels)
                print(json.dumps({"image": filename, "elapsed_ms": round(elapsed_ms, 2),
                                  "size": [result.original_width, result.original_height],
                                  "detections": [{"label": d.label, "score": round(d.score, 3),
                                                  "box": [d.box.x_min, d.box.y_min, d.box.x_max, d.box.y_max]}
                                                 for d in result.detections]}))
            req.stream = StreamIdentity(4, 40, 0)
            req.payload = b"\xff\xd8\xff\xe0broken jpeg"
            events = list(client.execute_stream(req, auto_ack_window=False))
            assert events[-1].event_type == EventType.FAILED
            assert events[-1].error.message == "VISION_INVALID_PAYLOAD"
            assert not any(e.event_type == EventType.VISION_RESULT for e in events)
            print(json.dumps({"corrupt_jpeg": events[-1].error.message}))
            req.stream = StreamIdentity(5, 50, 0)
            req.payload = (Path(args.images) / "bus.jpg").read_bytes()
            req.options.extra_options = [("vision.task", "detect"), ("vision.confidence_threshold", "1.0")]
            events = list(client.execute_stream(req, auto_ack_window=False))
            assert [e.event_type for e in events] == [EventType.ACCEPTED, EventType.VISION_RESULT, EventType.COMPLETED]
            assert not events[1].vision.detect.detections
            print(json.dumps({"after_corrupt_jpeg": "healthy", "confidence_1_0": "valid empty result"}))
    finally:
        server.stop()
        backend.close()


if __name__ == "__main__":
    main()
