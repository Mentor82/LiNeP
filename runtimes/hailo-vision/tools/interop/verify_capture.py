"""Independent Python roundtrip and image identity checks for C++/Go captures."""
import argparse
import hashlib
import json
from pathlib import Path
from linep.v0_2 import (
    RuntimeProfile, EventType, TerminalOutcome,
    decode_capabilities, encode_capabilities, decode_request, encode_request, decode_event, encode_event,
)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("capture",type=Path)
    p.add_argument("--image",type=Path,required=True)
    args=p.parse_args()
    values={}
    for name,decoder,encoder in [
        ("capabilities",decode_capabilities,encode_capabilities),
        ("request",decode_request,encode_request),
        ("vision_result",decode_event,encode_event),("terminal",decode_event,encode_event),
    ]:
        raw=(args.capture/(name+".bin")).read_bytes()
        obj=decoder(raw)
        assert obj is not None and encoder(obj)==raw, name
        values[name]=obj
    req=values["request"]
    assert req.profile==RuntimeProfile.VISION and req.payload==args.image.read_bytes()
    assert values["capabilities"].descriptor.supports_vision_model("yolov8s-detect")
    result=values["vision_result"]
    assert result.event_type==EventType.VISION_RESULT and result.stream==req.stream and result.vision.is_valid()
    terminal=values["terminal"]
    assert terminal.event_type==EventType.COMPLETED and terminal.outcome==TerminalOutcome.COMPLETED and terminal.stream==req.stream
    invalid=list(args.capture.glob("invalid_*.bin"))
    for path in invalid:
        assert decode_event(path.read_bytes()) is None, path.name
    print(json.dumps({"language":"python","passed":True,"roundtrip_frames":4,"invalid_rejected":len(invalid),"image_sha256":hashlib.sha256(req.payload).hexdigest()}))


if __name__=="__main__":
    main()
