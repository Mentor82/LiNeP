#include "linep/v0_2/registration.hpp"
#include "linep/v0_2/transport.hpp"
#include <cstdlib>
#include <iostream>
#include <thread>
#define CHECK(x) do { if (!(x)) { std::cerr << #x << " line " << __LINE__ << '\n'; std::exit(1); } } while(0)
using namespace linep::v0_2;

runtime_registration_envelope registration() {
    runtime_registration_envelope e; e.concurrent_slots=1;
    e.capabilities.descriptor.supported_models={"test-model"};
    e.capabilities.descriptor.supported_profiles={runtime_profile::generate}; return e;
}
session_bind_envelope bind() {
    session_bind_envelope b; b.identity={1,2,3}; b.lease_token=4; return b;
}
std::vector<std::uint8_t> encode(const runtime_registration_envelope& e) {
    std::vector<std::uint8_t> v; CHECK(encode_runtime_registration(e,v)); return v;
}
bool allow(const session_bind_envelope& b, const runtime_capabilities_descriptor& c) {
    return b.identity.runtime_id==2 && c.supported_models==std::vector<std::string>{"test-model"};
}
void wire_tests() {
    runtime_registration_envelope e; e.operation=registration_operation::capacity_update; e.concurrent_slots=2;
    const std::vector<std::uint8_t> golden={0x32,0x4c,0x4e,0x50,0,2,6,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,14,0,0,0,
        1,0,5,0,1,0,4,0,0,0,2,0,0,0};
    CHECK(encode(e)==golden);
    auto v=encode(registration()); runtime_registration_envelope out;
    CHECK(decode_runtime_registration(v.data(),v.size(),out)); CHECK(out.concurrent_slots==1);
    for (std::size_t n=0;n<v.size();++n) CHECK(!decode_runtime_registration(v.data(),n,out));
    auto invalid=v; invalid[32]=2; CHECK(!decode_runtime_registration(invalid.data(),invalid.size(),out));
    invalid=v; invalid[8]=1; CHECK(!decode_runtime_registration(invalid.data(),invalid.size(),out));
    invalid=v; invalid.push_back(0); CHECK(!decode_runtime_registration(invalid.data(),invalid.size(),out));
    e=registration(); e.extensions={{0x8000,{1,2,3}}}; v=encode(e);
    CHECK(decode_runtime_registration(v.data(),v.size(),out)); CHECK(encode(out)==v);
    invalid=v; invalid[v.size()-9]=5; invalid[v.size()-8]=0; // unknown required field
    CHECK(!decode_runtime_registration(invalid.data(),invalid.size(),out));
    e.extensions.push_back(e.extensions.front()); CHECK(!encode_runtime_registration(e,v));
    e={}; e.operation=registration_operation::draining;
    e.capabilities.descriptor.supported_profiles={runtime_profile::generate};
    CHECK(!encode_runtime_registration(e,v)); // never silently drop supplied capabilities
}
void lifecycle_tests() {
    session_manager m; runtime_error err; runtime_registration_envelope reply;
    runtime_registration_session router(m,allow); auto v=encode(registration());
    CHECK(!router.receive_worker_frame(v.data(),v.size(),reply,err)); CHECK(err.code==401);
    CHECK(m.process_session_bind(bind(),err));
    CHECK(router.receive_worker_frame(v.data(),v.size(),reply,err)); CHECK(reply.status_code==200);
    runtime_registration_envelope query; query.operation=registration_operation::capabilities_query;
    v=encode(query); CHECK(router.send_router_frame(v.data(),v.size(),err));
    CHECK(encode_capabilities(registration().capabilities,v)); CHECK(router.receive_worker_frame(v.data(),v.size(),reply,err));
    runtime_registration_envelope capacity; capacity.operation=registration_operation::capacity_update;
    capacity.concurrent_slots=0; v=encode(capacity); CHECK(router.receive_worker_frame(v.data(),v.size(),reply,err));
    CHECK(router.concurrent_slots()==0); capacity.concurrent_slots=1; v=encode(capacity);
    CHECK(router.receive_worker_frame(v.data(),v.size(),reply,err));
    request_envelope req; req.stream={10,20,0}; req.model_id="test-model";
    CHECK(encode_request(req,v)); CHECK(router.send_router_frame(v.data(),v.size(),err));
    req.stream={11,21,0}; CHECK(encode_request(req,v));
    CHECK(!router.send_router_frame(v.data(),v.size(),err)); CHECK(err.code==503 && err.category==error_category::transient);
    control_envelope cancel; cancel.stream={10,20,0}; CHECK(encode_control(cancel,v));
    CHECK(router.send_router_frame(v.data(),v.size(),err)); CHECK(m.is_cancel_requested(cancel.stream));
    control_envelope window; window.stream=cancel.stream; window.control_type=runtime_control_type::window_update;
    CHECK(encode_control(window,v)); CHECK(router.receive_worker_frame(v.data(),v.size(),reply,err));
    runtime_registration_envelope drain; drain.operation=registration_operation::draining; v=encode(drain);
    CHECK(router.receive_worker_frame(v.data(),v.size(),reply,err)); CHECK(router.draining());
    event_envelope done; done.stream=cancel.stream; done.event_seq=1;
    done.event_type=runtime_event_type::cancelled; done.outcome=terminal_outcome::cancelled;
    CHECK(encode_event(done,v)); CHECK(router.receive_worker_frame(v.data(),v.size(),reply,err));
    CHECK(encode_request(req,v)); CHECK(!router.send_router_frame(v.data(),v.size(),err)); CHECK(err.code==503);
    drain.operation=registration_operation::deregister; v=encode(drain);
    CHECK(router.receive_worker_frame(v.data(),v.size(),reply,err)); CHECK(!router.registered());
    v=encode(registration()); CHECK(router.receive_worker_frame(v.data(),v.size(),reply,err));
    m.mark_binding_stale(); CHECK(!router.registered());
    auto b=bind(); b.lease_token=5; CHECK(m.process_session_bind(b,err));
    CHECK(!router.registered()); CHECK(router.receive_worker_frame(v.data(),v.size(),reply,err));
    m.mark_binding_stale(); CHECK(m.process_session_bind(b,err)); // same binding, no intermediate observation
    CHECK(!router.registered()); CHECK(router.receive_worker_frame(v.data(),v.size(),reply,err));
    CHECK(encode_request(req,v)); // worker must never send REQUEST
    CHECK(!router.receive_worker_frame(v.data(),v.size(),reply,err)); CHECK(router.closed());
    session_manager denied; CHECK(denied.process_session_bind(bind(),err));
    runtime_registration_session default_deny(denied); v=encode(registration());
    CHECK(!default_deny.receive_worker_frame(v.data(),v.size(),reply,err)); CHECK(reply.status_code==403);
}
void sl1_tests() {
    std::vector<std::uint8_t> key(32,0x42); session_descriptor d; d.require_sl1=true; d.sl1_keys[1]=key;
    session_manager m(d); auto b=bind(); b.sl1_requested=true; b.auth_ext.auth_seq=1; b.auth_ext.key_id=1;
    runtime_error err; CHECK(m.process_session_bind(b,err));
    runtime_registration_session router(m,allow); auto v=encode(registration());
    CHECK(sign_envelope_buffer(v,b,message_direction::initiator_to_responder,2,1,key.data(),key.size()));
    runtime_registration_envelope reply; CHECK(router.receive_worker_frame(v.data(),v.size(),reply,err));
    CHECK(!router.receive_worker_frame(v.data(),v.size(),reply,err)); CHECK(router.closed()); // replay
    session_manager wrong(d); CHECK(wrong.process_session_bind(b,err));
    runtime_registration_session wrong_router(wrong,allow); v=encode(registration());
    CHECK(sign_envelope_buffer(v,b,message_direction::responder_to_initiator,2,1,key.data(),key.size()));
    CHECK(!wrong_router.receive_worker_frame(v.data(),v.size(),reply,err)); CHECK(wrong_router.closed());
    session_manager unsigned_session(d); CHECK(unsigned_session.process_session_bind(b,err));
    runtime_registration_session unsigned_router(unsigned_session,allow); v=encode(registration());
    CHECK(!unsigned_router.receive_worker_frame(v.data(),v.size(),reply,err)); CHECK(unsigned_router.closed());
    session_manager tampered(d); CHECK(tampered.process_session_bind(b,err));
    runtime_registration_session tampered_router(tampered,allow); v=encode(registration());
    CHECK(sign_envelope_buffer(v,b,message_direction::initiator_to_responder,2,1,key.data(),key.size()));
    v.back()^=1; CHECK(!tampered_router.receive_worker_frame(v.data(),v.size(),reply,err)); CHECK(tampered_router.closed());
}
void socket_test() {
    envelope_server server; CHECK(server.listen(0));
    std::thread worker([&] {
        auto c=envelope_connection::connect("127.0.0.1",server.get_bound_port()); CHECK(c);
        CHECK(c->send_session_bind(bind())); CHECK(c->send_runtime_registration(registration()));
        std::vector<std::uint8_t> v; CHECK(c->receive_envelope_raw(v)); runtime_registration_envelope result;
        CHECK(decode_runtime_registration(v.data(),v.size(),result)); CHECK(result.status_code==200);
        runtime_registration_envelope drain; drain.operation=registration_operation::draining;
        CHECK(c->send_runtime_registration(drain));
    });
    auto c=server.accept_connection(); CHECK(c); c->set_recv_timeout(5000);
    session_manager m; runtime_error err; std::vector<std::uint8_t> v; session_bind_envelope b;
    CHECK(c->receive_envelope_raw(v)); CHECK(decode_session_bind(v.data(),v.size(),b)); CHECK(m.process_session_bind(b,err));
    runtime_registration_session router(m,allow); runtime_registration_envelope result;
    CHECK(router.receive_worker(*c,result,err));
    CHECK(c->send_runtime_registration(result));
    CHECK(router.receive_worker(*c,result,err)); CHECK(router.draining()); worker.join();
}
int main() { wire_tests(); lifecycle_tests(); sl1_tests(); socket_test(); std::cout << "runtime_registration conformance passed\n"; }
