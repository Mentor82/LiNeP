#ifndef LINEP_SL_CABI_SL_H
#define LINEP_SL_CABI_SL_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) || defined(__CYGWIN__)
  #if defined(LINEP_SL_BUILDING_DLL)
    #define LINEP_SL_API __declspec(dllexport)
  #else
    #define LINEP_SL_API __declspec(dllimport)
  #endif
#else
  #define LINEP_SL_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Capability bitmasks (SL3) */
#define LINEP_CAP_NONE            0x00ULL
#define LINEP_CAP_INFERENCE_READ  0x01ULL
#define LINEP_CAP_INFERENCE_WRITE 0x02ULL
#define LINEP_CAP_ADMIN           0x04ULL
#define LINEP_CAP_SLOT_MANAGE     0x08ULL
#define LINEP_CAP_METRICS_READ    0x10ULL

#pragma pack(push, 1)

typedef struct {
    uint32_t session_id;
    uint16_t key_id;
    uint32_t auth_seq;
    uint8_t  mac[16];
} linep_sl_auth_ext_t;

typedef struct {
    uint32_t session_id;
    uint64_t granted_caps;
    uint64_t expires_at_sec;
    uint8_t  cap_mac[16];
} linep_sl_cap_ext_t;

typedef struct {
    uint32_t trust_domain_id;
    uint16_t node_id;
    uint8_t  pubkey[32];
    uint8_t  revoked;
} linep_sl2_peer_identity_t;

typedef struct {
    uint32_t session_id;
    uint16_t key_id;
    uint64_t established_at_sec;
    uint64_t expires_at_sec;
    uint8_t  secret_key[32];
} linep_sl2_session_key_t;

#pragma pack(pop)

/* SL1 Authentication Functions */
LINEP_SL_API int linep_sl1_compute_mac(
    const uint8_t* secret_key, uint32_t key_len,
    const void* header_ptr, uint32_t session_id,
    uint16_t key_id, uint32_t auth_seq,
    const uint8_t* payload, uint32_t payload_len,
    uint8_t out_mac[16]);

LINEP_SL_API int linep_sl1_verify_mac(
    const uint8_t* secret_key, uint32_t key_len,
    const void* header_ptr, const linep_sl_auth_ext_t* auth_ext,
    const uint8_t* payload, uint32_t payload_len);

/* SL2 Cryptographic Identity & Session Key Management Functions */
LINEP_SL_API int linep_sl2_negotiate_level(
    uint8_t peer_supported,
    uint8_t local_supported,
    uint8_t local_required,
    uint8_t* out_negotiated);

LINEP_SL_API int linep_sl2_validate_peer_identity(
    const linep_sl2_peer_identity_t* peer,
    uint32_t expected_trust_domain);

LINEP_SL_API int linep_sl2_derive_session_key(
    const uint8_t* master_secret, uint32_t master_len,
    uint32_t session_id, uint16_t key_id,
    uint16_t node_id, uint64_t ttl_sec,
    uint64_t current_time_sec,
    linep_sl2_session_key_t* out_key);

LINEP_SL_API int linep_sl2_verify_session_key_freshness(
    const linep_sl2_session_key_t* key,
    uint64_t current_time_sec);

/* SL3 Authorization & Capability Functions */
LINEP_SL_API int linep_sl3_create_cap_token(
    const uint8_t* secret_key, uint32_t key_len,
    uint32_t session_id, uint64_t granted_caps,
    uint64_t expires_at_sec, linep_sl_cap_ext_t* out_token);

LINEP_SL_API int linep_sl3_verify_cap_token(
    const uint8_t* secret_key, uint32_t key_len,
    const linep_sl_cap_ext_t* cap_token,
    uint32_t expected_session_id,
    uint64_t current_time_sec,
    uint64_t required_capability);

/* SL4 Governance, Audit, Zero-Trust & Federation Functions */
LINEP_SL_API int linep_sl4_evaluate_decision(
    uint32_t trust_domain_id,
    uint32_t session_id,
    uint16_t key_id,
    uint16_t remote_node_id,
    uint32_t remote_trust_domain_id,
    uint8_t  remote_revoked,
    uint8_t  negotiated_sl,
    uint64_t requested_cap,
    const char* policy_id,
    uint8_t* out_decision,
    char* out_reason_buf,
    uint32_t reason_buf_len);

/* Backward compatibility aliases */
#define linep_sl_compute_mac      linep_sl1_compute_mac
#define linep_sl_verify_mac       linep_sl1_verify_mac
#define linep_sl_create_cap_token linep_sl3_create_cap_token
#define linep_sl_verify_cap_token linep_sl3_verify_cap_token

#ifdef __cplusplus
}
#endif

#endif // LINEP_SL_CABI_SL_H
