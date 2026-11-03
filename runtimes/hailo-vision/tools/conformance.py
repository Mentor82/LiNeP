"""Run the non-disruptive VISION conformance cases against a real endpoint."""

import argparse
import json
import struct
import time
from pathlib import Path
from linep.v0_2.client import LiNePClient
from linep.v0_2.trunk import TrunkSession, Sl1Credentials
from linep_vision.conformance import VisionConformance


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=11436)
    parser.add_argument("--control-port", type=int, default=9001)
    parser.add_argument("--key-file")
    parser.add_argument("--model", default="yolov8s-detect")
    parser.add_argument("--image", type=Path, required=True, help="bus.jpg fixture, 810x1080")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--oversized-decoded-image", type=Path,
                        help="Valid PNG fixture with >16 million pixels; reject before inference")
    args = parser.parse_args()
    if args.key_file:
        credentials = Sl1Credentials.from_file(args.key_file)
        factory = lambda: TrunkSession(args.host, trunk_port=args.port, control_port=args.control_port,
                                      credentials=credentials, timeout=15)
    else:
        factory = lambda: LiNePClient(args.host, args.port, timeout=15)
    suite = VisionConformance(factory, args.image.read_bytes(), model=args.model)
    report = suite.run()
    if args.oversized_decoded_image:
        image = args.oversized_decoded_image.read_bytes()
        assert image.startswith(b"\x89PNG\r\n\x1a\n") and len(image) >= 24
        width, height = struct.unpack_from(">II", image, 16)
        assert width * height > 16_000_000, "fixture must exceed decoded pixel budget"
        started = time.monotonic()
        try:
            suite.check_error(payload=image, reason="VISION_INVALID_PAYLOAD")
            case = {"name": "decompressed_pixel_budget", "passed": True}
        except Exception as error:
            case = {"name": "decompressed_pixel_budget", "passed": False, "error": str(error)}
        case["duration_ms"] = round((time.monotonic() - started) * 1000, 2)
        report["cases"].append(case)
        report["total"] += 1
        report["passed"] += case["passed"]
    report.update({"host": args.host, "port": args.port, "sl1": bool(args.key_file), "model": args.model})
    text = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)
    raise SystemExit(0 if report["passed"] == report["total"] else 1)


if __name__ == "__main__":
    main()
