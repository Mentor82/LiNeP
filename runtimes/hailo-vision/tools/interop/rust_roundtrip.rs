// Compile beside codec/{linep_v02,sl1}.rs from an explicitly pinned LIARA OS tree.
#[path = "codec/sl1.rs"] mod sl1;
#[path = "codec/linep_v02.rs"] mod v;
use std::{env,fs,path::Path};
fn main() {
    let dir=env::args().nth(1).expect("capture directory required");
    for name in ["capabilities.bin","request.bin","vision_result.bin","terminal.bin"] {
        let raw=fs::read(Path::new(&dir).join(name)).unwrap();
        let encoded=match name {
            "capabilities.bin" => {let(c,l)=v::decode_capabilities_layout(&raw).unwrap();v::encode_capabilities_as(&c,l).unwrap()},
            "request.bin" => v::encode_request(&v::decode_request(&raw).unwrap()).unwrap(),
            _ => v::encode_event(&v::decode_event(&raw).unwrap()).unwrap(),
        };
        assert_eq!(raw,encoded,"Rust byte drift: {name}");
    }
    let mut rejected=0;
    for entry in fs::read_dir(&dir).unwrap() {
        let p=entry.unwrap().path();
        if p.file_name().unwrap().to_str().unwrap().starts_with("invalid_") && p.extension().map_or(false, |x|x=="bin") {
            assert!(v::decode_event(&fs::read(p).unwrap()).is_err(),"Rust accepted invalid vision event");
            rejected+=1;
        }
    }
    println!("{{\"language\":\"rust\",\"roundtrip_frames\":4,\"invalid_rejected\":{rejected},\"passed\":true}}");
}
