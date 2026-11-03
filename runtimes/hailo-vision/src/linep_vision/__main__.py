import argparse
import logging
import signal
import threading

from .hailo import HailoBackend
from .server import VisionServer


def main():
    parser = argparse.ArgumentParser(description="LiNeP Hailo-8L object detection runtime")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=11436)
    parser.add_argument("--model", action="append", required=True, metavar="ID=HEF",
                        help="Advertised model and host-provided HEF; repeat for multiple models")
    args = parser.parse_args()
    models = {}
    for item in args.model:
        model_id, sep, path = item.partition("=")
        if not sep or not path or not model_id or len(model_id.encode("utf-8")) > 256 or model_id in models:
            parser.error("each --model must be a unique ID=HEF (ID <= 256 UTF-8 bytes)")
        models[model_id] = path
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    backend = HailoBackend(models)
    server = None
    try:
        server = VisionServer(backend, host=args.host, port=args.port).start()
        logging.info("VISION ready on %s:%d; models=%s", *server.server_address, list(models))
        stop.wait()
    finally:
        if server is not None:
            server.stop()
        backend.close()


if __name__ == "__main__":
    main()
