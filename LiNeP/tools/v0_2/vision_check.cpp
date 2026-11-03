// Real VISION client using the reference codec/transport; optional leased SL1.
#include "linep/v0_2/transport.hpp"
#include "linep/v0_2/udp_transport.hpp"
#include <algorithm>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <random>
#include <set>
#include <stdexcept>
#include <thread>
using namespace linep::v0_2;
using Bytes = std::vector<std::uint8_t>;
void require(bool ok, const char* reason) { if (!ok) throw std::runtime_error(reason); }
Bytes load(const std::string& p) {
    std::ifstream f(p, std::ios::binary); require(bool(f), "cannot read input file");
    return Bytes(std::istreambuf_iterator<char>(f), {});
}
void save(const std::filesystem::path& p, const Bytes& b) {
    std::ofstream f(p, std::ios::binary); f.write(reinterpret_cast<const char*>(b.data()), b.size());
    require(bool(f), "cannot write capture");
}
int verify_directory(const std::filesystem::path& dir) {
    for(const auto* name:{"capabilities.bin","request.bin","vision_result.bin","terminal.bin"}) {
        const auto raw=load((dir/name).string()); Bytes out;
        if(std::string(name)=="capabilities.bin") {capabilities_envelope x;require(decode_capabilities(raw.data(),raw.size(),x)&&encode_capabilities(x,out),"caps decode/encode failed");}
        else if(std::string(name)=="request.bin") {request_envelope x;require(decode_request(raw.data(),raw.size(),x)&&encode_request(x,out),"request decode/encode failed");}
        else {event_envelope x;require(decode_event(raw.data(),raw.size(),x)&&encode_event(x,out),"event decode/encode failed");}
        require(out==raw,"C++ byte drift");
    }
    unsigned rejected=0;
    for(const auto& entry:std::filesystem::directory_iterator(dir)) {
        if(entry.path().filename().string().rfind("invalid_",0)==0&&entry.path().extension()==".bin") {
            const auto raw=load(entry.path().string());event_envelope out;
            require(!decode_event(raw.data(),raw.size(),out),"C++ accepted invalid vision event");++rejected;
        }
    }
    std::cout<<"{\"language\":\"cpp\",\"passed\":true,\"roundtrip_frames\":4,\"invalid_rejected\":"<<rejected<<"}\n";
    return 0;
}
int main(int argc, char** argv) {
 try {
    if(argc==3&&std::string(argv[1])=="--verify-dir")return verify_directory(argv[2]);
    std::map<std::string, std::string> a{{"--host", "127.0.0.1"}, {"--port", "11436"},
        {"--control-port", "9001"}, {"--model", "yolov8s-detect"}};
    for (int i=1; i<argc; i+=2) { require(i+1<argc, "arguments must be --name value"); a[argv[i]]=argv[i+1]; }
    require(a.count("--image") && a.count("--out-dir"), "--image bus.jpg and --out-dir required");
    const auto port_number = std::stoul(a["--port"]), udp_number = std::stoul(a["--control-port"]);
    require(port_number>0 && port_number<=65535 && udp_number>0 && udp_number<=65535, "invalid port");
    const auto port=static_cast<std::uint16_t>(port_number), control=static_cast<std::uint16_t>(udp_number);
    const auto output=std::filesystem::path(a["--out-dir"]); std::filesystem::create_directories(output);
    auto image=load(a["--image"]); require(!image.empty(), "empty input image");
    Bytes key; std::uint16_t key_id=0; session_bind_envelope bind;
    udp_endpoint_channel udp;
    if (a.count("--key-file")) {
        std::ifstream file(a["--key-file"]); require(bool(file), "cannot read SL1 credentials");
        std::string line, hex;
        while(std::getline(file,line)) {
            line.erase(std::remove_if(line.begin(),line.end(),[](unsigned char c){return std::isspace(c);}),line.end());
            if(line.rfind("key_id=",0)==0) {auto n=std::stoul(line.substr(7)); require(n>0&&n<=65535,"invalid key id"); key_id=static_cast<std::uint16_t>(n);}
            if(line.rfind("key=",0)==0) hex=line.substr(4);
        }
        require(key_id && hex.size()>=64 && hex.size()%2==0, "invalid SL1 credentials");
        for(std::size_t i=0;i<hex.size();i+=2) {require(std::isxdigit(static_cast<unsigned char>(hex[i]))&&std::isxdigit(static_cast<unsigned char>(hex[i+1])),"invalid key encoding");key.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i,2),nullptr,16)));}
        std::random_device random;
        bind.identity={((std::uint64_t(random())<<32)|random())|1,3,1};
        bind.control_epoch=std::uint64_t(random())+1;
        require(udp.open_and_bind(0,5000), "cannot open control socket");
        udp_control_datagram hello; hello.message_type=1; hello.flags=1;
        hello.node_id=bind.identity.node_id; hello.runtime_id=3; hello.endpoint_id=1;
        hello.control_epoch=bind.control_epoch; hello.control_seq=1;
        hello.availability=2; hello.health=1; hello.tcp_port=40000;
        require(udp.send_datagram(a["--host"].c_str(),control,hello), "NODE_HELLO failed");
        udp_control_datagram invite;
        require(udp.recv_datagram(invite) && invite.message_type==4 && invite.node_id==hello.node_id
            && invite.runtime_id==3 && invite.endpoint_id==1 && invite.control_epoch==hello.control_epoch && invite.lease_token,
            "missing or mismatched INVITE");
        bind.lease_token=invite.lease_token; hello.message_type=5; hello.control_seq=2; hello.lease_token=bind.lease_token;
        require(udp.send_datagram(a["--host"].c_str(),control,hello), "LEASE_ACK failed");
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    auto conn=envelope_connection::connect(a["--host"],port,5000);
    require(bool(conn), "connection failed"); conn->set_recv_timeout(15000);
    std::uint32_t last_auth=0;
    auto receive=[&]() {
        Bytes raw; require(conn->receive_envelope_raw(raw), "frame receive failed");
        if(!key.empty()) {
            wire_auth_extension auth; std::string error;
            require(verify_envelope_buffer(raw.data(),raw.size(),bind,message_direction::responder_to_initiator,key.data(),key.size(),auth,&error),"SL1 verification failed");
            require(auth.key_id==key_id && auth.auth_seq>last_auth,"wrong key identity or replay"); last_auth=auth.auth_seq;
        }
        return raw;
    };
    if(!key.empty()) {
        bind.sl1_requested=true; bind.key_id=key_id;
        conn->set_sl1_auth(bind,message_direction::initiator_to_responder,key_id,key);
        require(conn->send_session_bind(bind),"SESSION_BIND send failed");
        auto raw=receive(); session_bind_envelope confirmed;
        require(decode_session_bind(raw.data(),raw.size(),confirmed) && confirmed.identity==bind.identity
            && confirmed.control_epoch==bind.control_epoch && confirmed.lease_token==bind.lease_token,"bind not confirmed");
    }
    require(conn->send_capabilities({}),"CAPABILITIES query failed");
    auto raw=receive(); capabilities_envelope caps;
    require(decode_capabilities(raw.data(),raw.size(),caps) && caps.descriptor.supports_profile(runtime_profile::vision),"VISION discovery failed");
    bool advertised=false;std::string advertised_revision;
    for(const auto& m:caps.descriptor.supported_vision_models)
        if(m.model_id=="yolov8s-detect" && m.label_set_id=="coco80:v1") {advertised=true;advertised_revision=m.model_revision;}
    require(advertised,"model not advertised"); Bytes canonical;
    require(encode_capabilities(caps,canonical),"caps encode failed"); save(output/"capabilities.bin",canonical);
    request_envelope req; req.stream={88001,880010,0}; req.profile=runtime_profile::vision;
    req.model_id=a["--model"]; req.payload.assign(image.begin(),image.end()); req.has_options=true;
    req.options.extra_options={{"vision.task","detect"}};
    require(encode_request(req,canonical),"request encode failed"); save(output/"request.bin",canonical);
    require(conn->send_request(req),"request send failed");
    std::set<std::string> labels; unsigned results=0; std::uint64_t seq=0;
    for (unsigned frame=0;frame<4;++frame) {
        raw=receive(); event_envelope evt; require(decode_event(raw.data(),raw.size(),evt),"event decode failed");
        require(evt.stream==req.stream && evt.event_seq==++seq,"stream/sequence mismatch");
        require(encode_event(evt,canonical),"event encode failed");
        if(seq==1) require(evt.event_type==runtime_event_type::accepted,"missing ACCEPTED");
        if(evt.event_type==runtime_event_type::vision_result) {
            ++results; require(seq==2 && evt.vision.is_valid() && evt.vision.model_id=="yolov8s-detect"
                && evt.vision.detect.label_set_id=="coco80:v1" && evt.vision.detect.original_width==810
                && evt.vision.detect.original_height==1080 && evt.vision.model_revision==advertised_revision,"invalid vision attribution or geometry");
            for(const auto& d:evt.vision.detect.detections) {
                const auto* label=resolve_standard_label("coco80:v1",d.class_id);
                require(label && (d.label.empty()||d.label==label),"invalid COCO label"); labels.insert(label);
            }
            save(output/"vision_result.bin",canonical);
        }
        if(evt.is_terminal()) {
            require(evt.event_type==runtime_event_type::completed && evt.outcome==terminal_outcome::completed
                && seq==3 && results==1 && labels.count("bus") && labels.count("person"),"unexpected terminal or missing objects");
            save(output/"terminal.bin",canonical);
            require(conn->send_capabilities({}),"post-terminal query failed"); raw=receive();
            require(decode_capabilities(raw.data(),raw.size(),caps),"extra frame after terminal");
            std::cout<<"{\"language\":\"cpp\",\"passed\":true,\"sl1\":"<<(!key.empty()?"true":"false")<<",\"vision_results\":1,\"labels\":[\"bus\",\"person\"]}\n";
            return 0;
        }
    }
    throw std::runtime_error("missing terminal");
 } catch(const std::exception& e) { std::cerr<<"VISION check failed: "<<e.what()<<"\n"; return 1; }
}
