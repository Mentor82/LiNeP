#include "linep/v0_2/registration.hpp"
#include "linep/v0_2/transport.hpp"
#include <algorithm>
#include <set>

namespace linep::v0_2 {
namespace {
constexpr std::size_t max_registration_bytes = 65536;
void put(std::vector<std::uint8_t>& b, std::uint32_t v, unsigned n) {
    for (unsigned i = 0; i < n; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8*i)));
}
std::uint32_t get(const std::uint8_t* p, unsigned n) {
    std::uint32_t v = 0;
    for (unsigned i = 0; i < n; ++i) v |= std::uint32_t(p[i]) << (8*i);
    return v;
}
void field(std::vector<std::uint8_t>& b, std::uint16_t tag, const std::vector<std::uint8_t>& v) {
    put(b, tag, 2); put(b, static_cast<std::uint32_t>(v.size()), 4);
    b.insert(b.end(), v.begin(), v.end());
}
bool frame(const std::uint8_t* p, std::size_t n, wire_envelope_header& h, std::size_t& offset) {
    if (!decode_header(p,n,h) || h.magic != LINEP_V02_MAGIC ||
        h.version_major != 0 || h.version_minor != 2 || (h.flags & ~LINEP_V02_FLAG_AUTHENTICATED)) return false;
    offset = LINEP_V02_HEADER_SIZE + ((h.flags & LINEP_V02_FLAG_AUTHENTICATED) ? LINEP_V02_AUTH_EXTENSION_SIZE : 0);
    return h.payload_len <= LINEP_V02_MAX_PAYLOAD_BYTES && n == offset + h.payload_len;
}
bool valid(const runtime_registration_envelope& e) {
    const auto op = static_cast<unsigned>(e.operation);
    if (op < 1 || op > 6 || e.reason.size() > 8192) return false;
    const auto& d = e.capabilities.descriptor;
    const bool empty_capabilities = d.supported_models.empty() && d.supported_profiles.empty() &&
        d.supported_embedding_spaces.empty() && !d.max_context_tokens && !d.max_output_tokens &&
        d.supports_streaming && d.supports_cancellation && !d.supports_tool_calling &&
        !d.supports_reasoning_deltas && !d.supports_structured_messages;
    if (e.operation == registration_operation::result)
        return (e.status_code == 200 || (e.status_code >= 400 && e.status_code <= 599)) &&
               e.concurrent_slots == 0 && empty_capabilities;
    if (e.status_code || !e.reason.empty()) return false;
    if (e.operation != registration_operation::register_runtime)
        return empty_capabilities &&
               (e.operation == registration_operation::capacity_update || e.concurrent_slots == 0);
    if (!e.concurrent_slots || d.supported_models.empty() || d.supported_profiles.empty()) return false;
    if (d.supported_models.size()>2048 || d.supported_embedding_spaces.size()>2048) return false;
    std::size_t bytes=64;
    for (const auto& m : d.supported_models) bytes+=m.size()+2;
    for (const auto& sp : d.supported_embedding_spaces) {
        if (sp.embedding_space_id.empty() || sp.model_id.empty() || !sp.dimensions ||
            sp.dimensions>LINEP_V02_MAX_EMBEDDING_DIMENSIONS ||
            static_cast<unsigned>(sp.normalization)>1 || static_cast<unsigned>(sp.distance_metric)<1 ||
            static_cast<unsigned>(sp.distance_metric)>3 ||
            std::find(d.supported_models.begin(),d.supported_models.end(),sp.model_id)==d.supported_models.end() ||
            sp.embedding_space_id.size()>8192 || sp.model_id.size()>8192 || sp.model_revision.size()>8192)
            return false;
        bytes+=sp.embedding_space_id.size()+sp.model_id.size()+sp.model_revision.size()+12;
    }
    if (bytes>max_registration_bytes-64) return false;
    std::set<std::string> models;
    for (const auto& m : d.supported_models) if (m.empty() || m.size() > 8192 || !models.insert(m).second) return false;
    std::set<unsigned> profiles;
    for (auto p : d.supported_profiles) {
        const auto v = static_cast<unsigned>(p);
        if (v < 1 || v > 3 || !profiles.insert(v).second) return false;
    }
    return true;
}
}

bool encode_runtime_registration(const runtime_registration_envelope& e, std::vector<std::uint8_t>& out) {
    if (!valid(e)) return false;
    std::vector<std::uint8_t> b{1,0,static_cast<std::uint8_t>(e.operation),0}; // schema 1.0, op, reserved
    if (e.operation == registration_operation::register_runtime || e.operation == registration_operation::capacity_update) {
        std::vector<std::uint8_t> v; put(v,e.concurrent_slots,4); field(b,1,v);
    }
    if (e.operation == registration_operation::result) {
        std::vector<std::uint8_t> v; put(v,e.status_code,4); field(b,2,v);
        field(b,3,{e.reason.begin(),e.reason.end()});
    }
    if (e.operation == registration_operation::register_runtime) {
        std::vector<std::uint8_t> v;
        if (!encode_capabilities(e.capabilities,v)) return false;
        field(b,4,v);
    }
    std::uint16_t previous = 0x7fff;
    for (const auto& x : e.extensions) {
        if (x.tag <= previous || x.value.size() > max_registration_bytes) return false;
        previous = x.tag; field(b,x.tag,x.value);
        if (b.size() > max_registration_bytes) return false;
    }
    if (b.size() > max_registration_bytes) return false;
    wire_envelope_header h{}; h.envelope_type = static_cast<std::uint8_t>(runtime_envelope_type::runtime_register);
    h.payload_len = static_cast<std::uint32_t>(b.size());
    std::vector<std::uint8_t> result; encode_header(h,result); result.insert(result.end(),b.begin(),b.end());
    out = std::move(result); return true;
}

bool decode_runtime_registration(const std::uint8_t* p, std::size_t n, runtime_registration_envelope& out) {
    wire_envelope_header h{}; std::size_t pos{};
    if (!frame(p,n,h,pos) || h.envelope_type != 6 || h.request_id || h.execution_id || h.output_id ||
        h.payload_len < 4 || h.payload_len > max_registration_bytes) return false;
    if (p[pos] != 1 || p[pos+1] || p[pos+3]) return false;
    runtime_registration_envelope e; e.operation = static_cast<registration_operation>(p[pos+2]); pos += 4;
    std::uint16_t previous=0; unsigned seen=0;
    while (pos < n) {
        if (n-pos < 6) return false;
        const auto tag=static_cast<std::uint16_t>(get(p+pos,2)); const auto len=get(p+pos+2,4); pos+=6;
        if (tag <= previous || len > n-pos) return false;
        previous=tag;
        if (tag == 1 || tag == 2) {
            if (len != 4) return false;
            if (tag == 1) e.concurrent_slots=get(p+pos,4); else e.status_code=get(p+pos,4);
        } else if (tag == 3) {
            if (len > 8192) return false;
            e.reason.assign(reinterpret_cast<const char*>(p+pos),len);
        } else if (tag == 4) {
            wire_envelope_header ch{}; std::size_t co{};
            if (!frame(p+pos,len,ch,co) || ch.flags || ch.request_id || ch.execution_id || ch.output_id ||
                !decode_capabilities(p+pos,len,e.capabilities)) return false;
            // Reject non-canonical/trailing nested capability data.
            std::vector<std::uint8_t> canonical;
            if (!encode_capabilities(e.capabilities,canonical) || canonical.size()!=len ||
                !std::equal(canonical.begin(),canonical.end(),p+pos)) return false;
        } else if (tag < 0x8000) return false;
        else e.extensions.push_back({tag,{p+pos,p+pos+len}});
        if (tag <= 4) seen |= 1u << tag;
        pos+=len;
    }
    const unsigned expected = e.operation==registration_operation::register_runtime ? 18 :
        e.operation==registration_operation::result ? 12 : e.operation==registration_operation::capacity_update ? 2 : 0;
    if (seen != expected || !valid(e)) return false;
    out=std::move(e); return true;
}

bool runtime_registration_session::synchronize_binding() {
    const auto b=session_.bound_session();
    const auto generation=session_.binding_generation();
    if (session_.binding_state()!=session_binding_state::bound_current || b!=binding_ || generation!=binding_generation_) {
        registered_=false; draining_=false; slots_=0; capabilities_={}; binding_=b;
        binding_generation_=generation;
    }
    return session_.binding_state()==session_binding_state::bound_current;
}

bool runtime_registration_session::receive_worker(envelope_connection& connection,
    runtime_registration_envelope& reply, runtime_error& err) {
    std::vector<std::uint8_t> bytes;
    if (!connection.receive_envelope_raw(bytes)) {
        connection.close();
        return reject(err,503,error_category::transient,"runtime_disconnected",true);
    }
    const bool ok=receive_worker_frame(bytes.data(),bytes.size(),reply,err);
    if (closed_) connection.close();
    return ok;
}
bool runtime_registration_session::registered() { synchronize_binding(); return registered_ && !closed_; }
bool runtime_registration_session::reject(runtime_error& e, std::uint32_t code, error_category cat, const char* msg, bool close) {
    e={cat,code,msg,{}};
    if (close) { closed_=true; registered_=false; session_.terminate_all_active_streams(terminal_outcome::failed,e); }
    return false;
}

bool runtime_registration_session::receive_worker_frame(const std::uint8_t* p, std::size_t n,
    runtime_registration_envelope& reply, runtime_error& err) {
    reply={}; reply.operation=registration_operation::result;
    if (closed_) return reject(err,410,error_category::bad_request,"registration_connection_closed",false);
    if (!synchronize_binding()) { reply.status_code=401; reply.reason="binding_required";
        return reject(err,401,error_category::unauthorized,"binding_required",false); }
    wire_envelope_header h{}; std::size_t offset{};
    if (!frame(p,n,h,offset)) return reject(err,400,error_category::bad_request,"invalid_frame",true);
    wire_auth_extension auth{};
    if (!session_.verify_inbound_frame(p,n,message_direction::initiator_to_responder,auth,err)) {
        closed_=true; registered_=false; session_.terminate_all_active_streams(terminal_outcome::failed,err); return false;
    }
    if (h.envelope_type==6) {
        runtime_registration_envelope e;
        if (!decode_runtime_registration(p,n,e)) return reject(err,400,error_category::bad_request,"invalid_registration",true);
        if (e.operation==registration_operation::register_runtime) {
            if (registered_) return reject(err,409,error_category::bad_request,"already_registered",true);
            if (!authorize_ || !authorize_(binding_,e.capabilities.descriptor)) {
                reply.status_code=403; reply.reason="runtime_not_authorized";
                return reject(err,403,error_category::unauthorized,"runtime_not_authorized",false);
            }
            capabilities_=e.capabilities.descriptor; slots_=e.concurrent_slots;
            registered_=true; reply.status_code=200; err={}; return true;
        }
        if (!registered_) return reject(err,401,error_category::unauthorized,"registration_required",true);
        if (e.operation==registration_operation::draining) { draining_=true; err={}; return true; }
        if (e.operation==registration_operation::capacity_update) { slots_=e.concurrent_slots; err={}; return true; }
        if (e.operation==registration_operation::deregister) {
            if (session_.get_active_stream_count()) return reject(err,409,error_category::bad_request,"streams_still_active",true);
            registered_=false; slots_=0; capabilities_={}; draining_=false; err={}; return true;
        }
        return reject(err,400,error_category::bad_request,"wrong_direction",true);
    }
    if (!registered_) return reject(err,401,error_category::unauthorized,"registration_required",true);
    if (h.envelope_type==2) {
        event_envelope e;
        if (!decode_event(p,n,e)) return reject(err,400,error_category::bad_request,"invalid_event",true);
        if (session_.dispatch_event(e,err)) return true;
    } else if (h.envelope_type==3) {
        control_envelope c;
        if (!decode_control(p,n,c) || c.control_type!=runtime_control_type::window_update)
            return reject(err,400,error_category::bad_request,"wrong_direction",true);
        if (session_.process_control(c,err)) return true;
    } else if (h.envelope_type==4) {
        capabilities_envelope c;
        runtime_registration_envelope candidate; candidate.concurrent_slots=1;
        if (!decode_capabilities(p,n,c)) return reject(err,400,error_category::bad_request,"invalid_capabilities",true);
        candidate.capabilities=c;
        if (h.request_id || h.execution_id || h.output_id || !valid(candidate) || !authorize_ || !authorize_(binding_,c.descriptor))
            return reject(err,403,error_category::unauthorized,"capabilities_not_authorized",true);
        capabilities_=std::move(c.descriptor); err={}; return true;
    } else return reject(err,400,error_category::bad_request,"wrong_direction",true);
    closed_=true; registered_=false; session_.terminate_all_active_streams(terminal_outcome::failed,err); return false;
}

bool runtime_registration_session::send_router_frame(const std::uint8_t* p, std::size_t n, runtime_error& err) {
    if (!registered()) return reject(err,401,error_category::unauthorized,"registration_required",false);
    wire_envelope_header h{}; std::size_t offset{};
    if (!frame(p,n,h,offset) || h.flags) return reject(err,400,error_category::bad_request,"invalid_unsigned_outbound_frame",true);
    if (h.envelope_type==1) {
        request_envelope r;
        if (!decode_request(p,n,r)) return reject(err,400,error_category::bad_request,"invalid_request",true);
        if (draining_ || session_.get_active_stream_count()>=slots_)
            return reject(err,503,error_category::transient,"runtime_unavailable",false);
        if (!capabilities_.supports_profile(r.profile) || std::find(capabilities_.supported_models.begin(),
            capabilities_.supported_models.end(),r.model_id)==capabilities_.supported_models.end())
            return reject(err,403,error_category::unauthorized,"model_or_profile_not_advertised",false);
        return session_.submit_request(r,err);
    }
    if (h.envelope_type==3) {
        control_envelope c;
        if (!decode_control(p,n,c) || c.control_type!=runtime_control_type::cancel)
            return reject(err,400,error_category::bad_request,"wrong_direction",true);
        return session_.process_control(c,err);
    }
    if (h.envelope_type==6) {
        runtime_registration_envelope e;
        if (decode_runtime_registration(p,n,e) && e.operation==registration_operation::capabilities_query) { err={}; return true; }
    }
    return reject(err,400,error_category::bad_request,"wrong_direction",true);
}
} // namespace linep::v0_2
