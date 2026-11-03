"""Verify VISION through a direct/tunnel endpoint or leased SL1 trunk."""

import argparse
import json
import time
from pathlib import Path

from linep.v0_2.client import LiNePClient
from linep.v0_2.constants import EventType, RuntimeProfile
from linep.v0_2.envelopes import (
    CapabilitiesEnvelope, GenerationOptions, RequestEnvelope, StreamIdentity,
    decode_capabilities, encode_capabilities,
)
from linep.v0_2.trunk import Sl1Credentials, TrunkSession


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=11436)
    parser.add_argument("--control-port", type=int, default=9001)
    parser.add_argument("--key-file", help="Read in place on trunk host; never prints credentials")
    parser.add_argument("--skip-trunk-capabilities", action="store_true",
                        help="Explicit request-only check when trunk advertises profiles newer than this SDK; verify worker capabilities separately")
    parser.add_argument("--model", default="yolov8s-detect")
    parser.add_argument("--image", type=Path, required=True)
    args = parser.parse_args()
    if args.skip_trunk_capabilities and not args.key_file:
        parser.error("--skip-trunk-capabilities is only valid for an authenticated trunk check")
    if args.key_file:
        session = TrunkSession(args.host, trunk_port=args.port, control_port=args.control_port,
                               credentials=Sl1Credentials.from_file(args.key_file), timeout=15)
    else:
        session = LiNePClient(args.host, args.port, timeout=15)
    with session:
        if args.skip_trunk_capabilities:
            caps = None
        elif args.key_file:
            session._send_frame(encode_capabilities(CapabilitiesEnvelope()))
            caps = decode_capabilities(session._recv_frame())
        else:
            caps = session.query_capabilities()
        if not args.skip_trunk_capabilities:
            assert caps is not None and RuntimeProfile.VISION in caps.descriptor.supported_profiles
            assert caps.descriptor.supports_vision_model("yolov8s-detect")
        req = RequestEnvelope(
            stream=StreamIdentity(71001, 710010, 0), profile=RuntimeProfile.VISION,
            model_id=args.model, payload=args.image.read_bytes(), has_options=True,
            options=GenerationOptions(extra_options=[("vision.task", "detect")]),
        )
        start = time.perf_counter()
        events = list(session.execute_stream(req, auto_ack_window=False))
        assert [e.event_type for e in events] == [EventType.ACCEPTED, EventType.VISION_RESULT, EventType.COMPLETED], [
            (e.event_type.name, e.error.code, e.error.message) for e in events]
        result = events[1].vision
        assert result.model_id == "yolov8s-detect" and result.detect.is_valid()
        labels = sorted({d.label for d in result.detect.detections})
        assert {"bus", "person"} <= set(labels), labels
        print(json.dumps({"host": args.host, "port": args.port, "sl1": bool(args.key_file),
                          "capabilities_checked": not args.skip_trunk_capabilities,
                          "requested_model": args.model, "resolved_model": result.model_id,
                          "model_revision": result.model_revision, "labels": labels,
                          "events": [e.event_type.name for e in events],
                          "elapsed_ms": round((time.perf_counter() - start) * 1000, 2)}))


if __name__ == "__main__":
    main()
