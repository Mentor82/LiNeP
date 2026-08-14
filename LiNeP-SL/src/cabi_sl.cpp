#include <linep_sl/cabi_sl.h>
#include <linep_sl/sl1.hpp>
#include <linep_sl/sl2.hpp>
#include <linep_sl/sl3.hpp>
#include <cstring>

extern "C" {

LINEP_SL_API int linep_sl1_compute_mac(
    const uint8_t* secret_key, uint32_t key_len,
    const void* header_ptr, uint32_t session_id,
    uint16_t key_id, uint32_t auth_seq,
    const uint8_t* payload, uint32_t payload_len,
    uint8_t out_mac[16])
{
    if (!secret_key || key_len == 0 || !header_ptr || !out_mac) return 0;
    const auto* hdr = reinterpret_cast<const linep::Header*>(header_ptr);
    linep::sl::compute_sl1_mac(secret_key, key_len, *hdr, session_id, key_id, auth_seq, payload, payload_len, out_mac);
    return 1;
}

LINEP_SL_API int linep_sl1_verify_mac(
    const uint8_t* secret_key, uint32_t key_len,
    const void* header_ptr, const linep_sl_auth_ext_t* auth_ext,
    const uint8_t* payload, uint32_t payload_len)
{
    if (!secret_key || key_len == 0 || !header_ptr || !auth_ext) return 0;
    const auto* hdr = reinterpret_cast<const linep::Header*>(header_ptr);
    const auto* ext = reinterpret_cast<const linep::sl::HeaderAuthExt*>(auth_ext);
    return linep::sl::verify_sl1_mac(secret_key, key_len, *hdr, *ext, payload, payload_len) ? 1 : 0;
}

LINEP_SL_API int linep_sl3_create_cap_token(
    const uint8_t* secret_key, uint32_t key_len,
    uint32_t session_id, uint64_t granted_caps,
    uint64_t expires_at_sec, linep_sl_cap_ext_t* out_token)
{
    if (!secret_key || key_len == 0 || !out_token) return 0;
    out_token->session_id = session_id;
    out_token->granted_caps = granted_caps;
    out_token->expires_at_sec = expires_at_sec;
    linep::sl::compute_cap_token_mac(secret_key, key_len, session_id, granted_caps, expires_at_sec, out_token->cap_mac);
    return 1;
}

LINEP_SL_API int linep_sl3_verify_cap_token(
    const uint8_t* secret_key, uint32_t key_len,
    const linep_sl_cap_ext_t* cap_token,
    uint32_t expected_session_id,
    uint64_t current_time_sec,
    uint64_t required_capability)
{
    if (!secret_key || key_len == 0 || !cap_token) return 0;
    const auto* tok = reinterpret_cast<const linep::sl::HeaderCapExt*>(cap_token);
    return linep::sl::verify_cap_token(
        secret_key, key_len, *tok, expected_session_id, current_time_sec,
        static_cast<linep::sl::CapFlags>(required_capability)) ? 1 : 0;
}

} // extern "C"
