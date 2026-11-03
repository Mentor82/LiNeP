"""Mutate real result captures into well-framed semantic negative vectors."""
import argparse
import json
import struct
from pathlib import Path
from linep.v0_2 import decode_event
from linep.v0_2.envelopes import BufferReader


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("capture",type=Path)
    args=parser.parse_args()
    raw=(args.capture/"vision_result.bin").read_bytes()
    evt=decode_event(raw)
    assert evt is not None and evt.vision.detect.detections
    r=BufferReader(raw[32:])
    r.read_u64();r.read_u8();r.read_u8();r.read_u8();r.read_u32()
    r.read_string_u16();r.read_string_u16();r.read_string_u32();r.read_u64()
    task=32+r._offset
    r.read_u8();r.read_string_u16();r.read_string_u16()
    labelset=32+r._offset+2
    r.read_string_u16()
    width=32+r._offset
    r.read_u32();r.read_u32()
    count=32+r._offset;r.read_u32()
    detection=32+r._offset
    label=detection+24+2
    negatives={}
    def change(name,offset,fmt,value):
        b=bytearray(raw);struct.pack_into(fmt,b,offset,value);negatives[name]=b
    change("nan_score",detection+4,"<f",float("nan"))
    change("infinite_score",detection+4,"<f",float("inf"))
    change("score_above_one",detection+4,"<f",1.1)
    change("out_of_bounds_box",detection+8,"<f",2.0)
    change("zero_area_box",detection+16,"<f",struct.unpack_from("<f",raw,detection+8)[0])
    change("zero_dimensions",width,"<I",0)
    change("oversized_dimensions",width,"<I",65536)
    change("too_many_detections",count,"<I",1001)
    change("unsupported_task",task,"<B",2)
    change("wrong_label",label,"<B",ord("x"))
    change("unknown_label_set",labelset+5,"<B",ord("1"))
    truncated=bytearray(raw[:-1]);struct.pack_into("<I",truncated,28,len(truncated)-32)
    negatives["truncated_inner_payload"]=truncated
    for name,b in negatives.items():
        assert decode_event(bytes(b)) is None, name
        (args.capture/("invalid_"+name+".bin")).write_bytes(b)
    (args.capture/"NEGATIVE_CASES.json").write_text(json.dumps(sorted(negatives),indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"negative_frames":len(negatives),"python_rejected":len(negatives)}))


if __name__=="__main__":
    main()
