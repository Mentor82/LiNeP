"""Non-privileged negative trunk authentication checks; no real key is read."""
import argparse
import json
from pathlib import Path
from linep.v0_2.client import LiNePClient
from linep.v0_2.constants import RuntimeProfile, EventType
from linep.v0_2.envelopes import RequestEnvelope, StreamIdentity, GenerationOptions, encode_request, decode_event
from linep.v0_2.trunk import TrunkSession, Sl1Credentials, TrunkError


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--host",required=True)
    p.add_argument("--port",type=int,default=9000)
    p.add_argument("--control-port",type=int,default=9001)
    p.add_argument("--image",type=Path,required=True)
    args=p.parse_args()
    req=RequestEnvelope(stream=StreamIdentity(99001,990010,0),profile=RuntimeProfile.VISION,
                        model_id="yolov8s-detect",payload=args.image.read_bytes(),has_options=True,
                        options=GenerationOptions(extra_options=[("vision.task","detect")]))
    with LiNePClient(args.host,args.port) as c:
        c._send_all(encode_request(req))
        event=decode_event(c._recv_envelope())
        assert event is not None and event.event_type==EventType.FAILED and event.error.code==401
    unsigned_reason=event.error.message
    try:
        with TrunkSession(args.host,trunk_port=args.port,control_port=args.control_port,
                          credentials=Sl1Credentials(65000,bytes(range(32))),timeout=5):
            raise AssertionError("unregistered synthetic SL1 credentials were accepted")
    except TrunkError as error:
        assert error.code==401, str(error)
        bad_key_reason=error.reason
    print(json.dumps({"unsigned_inference":"rejected","unsigned_reason":unsigned_reason,
                      "unregistered_synthetic_key":"rejected","bad_key_reason":bad_key_reason,"passed":True}))


if __name__=="__main__":
    main()
