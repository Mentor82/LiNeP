#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <linep_sl/v0_2/negotiation.hpp>

namespace linep::sl::v0_2 {

constexpr std::size_t x25519_key_bytes = 32;
constexpr std::size_t ed25519_pubkey_bytes = 32;
constexpr std::size_t ed25519_privkey_bytes = 32;
constexpr std::size_t ed25519_signature_bytes = 64;
constexpr std::size_t aead_key_bytes = 32;
constexpr std::size_t aead_nonce_bytes = 12;
constexpr std::size_t aead_tag_bytes = 16;
constexpr std::size_t sha256_digest_bytes = 32;

// X25519 Diffie-Hellman Key Exchange (RFC 7748)
bool generate_x25519_keypair(
    std::vector<std::uint8_t>& out_priv,
    std::vector<std::uint8_t>& out_pub) noexcept;

bool diffie_hellman_x25519(
    const std::vector<std::uint8_t>& my_priv,
    const std::vector<std::uint8_t>& peer_pub,
    std::vector<std::uint8_t>& out_shared_secret) noexcept;

// Ed25519 Digital Signatures (RFC 8032)
bool generate_ed25519_keypair(
    std::vector<std::uint8_t>& out_priv,
    std::vector<std::uint8_t>& out_pub) noexcept;

bool ed25519_sign(
    const std::vector<std::uint8_t>& privkey,
    const std::uint8_t* msg,
    std::size_t msg_len,
    std::vector<std::uint8_t>& out_sig) noexcept;

bool ed25519_verify(
    const std::vector<std::uint8_t>& pubkey,
    const std::uint8_t* msg,
    std::size_t msg_len,
    const std::uint8_t* sig,
    std::size_t sig_len) noexcept;

// HKDF-SHA-256 (RFC 5869)
bool hkdf_extract(
    const std::vector<std::uint8_t>& salt,
    const std::vector<std::uint8_t>& ikm,
    std::vector<std::uint8_t>& out_prk) noexcept;

bool hkdf_expand(
    const std::vector<std::uint8_t>& prk,
    const std::string& info,
    std::size_t out_len,
    std::vector<std::uint8_t>& out_key) noexcept;

// Authenticated Encryption with Associated Data (AEAD)
// Supports ChaCha20-Poly1305 and AES-256-GCM
bool aead_encrypt(
    crypto_suite suite,
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& nonce,
    const std::vector<std::uint8_t>& aad,
    const std::vector<std::uint8_t>& plaintext,
    std::vector<std::uint8_t>& out_ciphertext,
    std::vector<std::uint8_t>& out_tag) noexcept;

bool aead_decrypt(
    crypto_suite suite,
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& nonce,
    const std::vector<std::uint8_t>& aad,
    const std::vector<std::uint8_t>& ciphertext,
    const std::vector<std::uint8_t>& tag,
    std::vector<std::uint8_t>& out_plaintext) noexcept;

// Secure zeroization of sensitive memory (wraps OPENSSL_cleanse)
void secure_zero(void* ptr, std::size_t len) noexcept;

} // namespace linep::sl::v0_2
