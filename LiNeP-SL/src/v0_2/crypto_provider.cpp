#include <linep_sl/v0_2/crypto_provider.hpp>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <cstring>

namespace linep::sl::v0_2 {

void secure_zero(void* ptr, std::size_t len) noexcept {
    if (ptr && len > 0) {
        OPENSSL_cleanse(ptr, len);
    }
}

bool generate_x25519_keypair(
    std::vector<std::uint8_t>& out_priv,
    std::vector<std::uint8_t>& out_pub) noexcept {
    out_priv.clear();
    out_pub.clear();

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!pctx) return false;

    EVP_PKEY* pkey = nullptr;
    bool ok = false;
    if (EVP_PKEY_keygen_init(pctx) > 0 && EVP_PKEY_keygen(pctx, &pkey) > 0 && pkey) {
        out_priv.resize(x25519_key_bytes);
        out_pub.resize(x25519_key_bytes);
        std::size_t priv_len = x25519_key_bytes;
        std::size_t pub_len = x25519_key_bytes;
        if (EVP_PKEY_get_raw_private_key(pkey, out_priv.data(), &priv_len) > 0 &&
            EVP_PKEY_get_raw_public_key(pkey, out_pub.data(), &pub_len) > 0 &&
            priv_len == x25519_key_bytes && pub_len == x25519_key_bytes) {
            ok = true;
        }
    }

    if (pkey) EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    if (!ok) {
        secure_zero(out_priv.data(), out_priv.size());
        out_priv.clear();
        out_pub.clear();
    }
    return ok;
}

bool diffie_hellman_x25519(
    const std::vector<std::uint8_t>& my_priv,
    const std::vector<std::uint8_t>& peer_pub,
    std::vector<std::uint8_t>& out_shared_secret) noexcept {
    out_shared_secret.clear();
    if (my_priv.size() != x25519_key_bytes || peer_pub.size() != x25519_key_bytes) {
        return false;
    }

    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, my_priv.data(), my_priv.size());
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub.data(), peer_pub.size());
    if (!priv || !peer) {
        if (priv) EVP_PKEY_free(priv);
        if (peer) EVP_PKEY_free(peer);
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    bool ok = false;
    if (ctx && EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_derive_set_peer(ctx, peer) > 0) {
        std::size_t secret_len = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &secret_len) > 0 && secret_len == x25519_key_bytes) {
            out_shared_secret.resize(secret_len);
            if (EVP_PKEY_derive(ctx, out_shared_secret.data(), &secret_len) > 0 && secret_len == x25519_key_bytes) {
                // Reject all-zero shared secret (contributory behavior check per RFC 7748)
                std::uint8_t mask = 0;
                for (auto b : out_shared_secret) mask |= b;
                ok = (mask != 0);
            }
        }
    }

    if (ctx) EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(priv);

    if (!ok) {
        secure_zero(out_shared_secret.data(), out_shared_secret.size());
        out_shared_secret.clear();
    }
    return ok;
}

bool generate_ed25519_keypair(
    std::vector<std::uint8_t>& out_priv,
    std::vector<std::uint8_t>& out_pub) noexcept {
    out_priv.clear();
    out_pub.clear();

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!pctx) return false;

    EVP_PKEY* pkey = nullptr;
    bool ok = false;
    if (EVP_PKEY_keygen_init(pctx) > 0 && EVP_PKEY_keygen(pctx, &pkey) > 0 && pkey) {
        out_priv.resize(ed25519_privkey_bytes);
        out_pub.resize(ed25519_pubkey_bytes);
        std::size_t priv_len = ed25519_privkey_bytes;
        std::size_t pub_len = ed25519_pubkey_bytes;
        if (EVP_PKEY_get_raw_private_key(pkey, out_priv.data(), &priv_len) > 0 &&
            EVP_PKEY_get_raw_public_key(pkey, out_pub.data(), &pub_len) > 0 &&
            priv_len == ed25519_privkey_bytes && pub_len == ed25519_pubkey_bytes) {
            ok = true;
        }
    }

    if (pkey) EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    if (!ok) {
        secure_zero(out_priv.data(), out_priv.size());
        out_priv.clear();
        out_pub.clear();
    }
    return ok;
}

bool ed25519_sign(
    const std::vector<std::uint8_t>& privkey,
    const std::uint8_t* msg,
    std::size_t msg_len,
    std::vector<std::uint8_t>& out_sig) noexcept {
    out_sig.clear();
    if (privkey.size() != ed25519_privkey_bytes || (!msg && msg_len > 0)) {
        return false;
    }

    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, privkey.data(), privkey.size());
    if (!priv) return false;

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    bool ok = false;
    if (mctx && EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, priv) > 0) {
        std::size_t sig_len = 0;
        if (EVP_DigestSign(mctx, nullptr, &sig_len, msg, msg_len) > 0 && sig_len == ed25519_signature_bytes) {
            out_sig.resize(sig_len);
            if (EVP_DigestSign(mctx, out_sig.data(), &sig_len, msg, msg_len) > 0 && sig_len == ed25519_signature_bytes) {
                ok = true;
            }
        }
    }

    if (mctx) EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(priv);

    if (!ok) out_sig.clear();
    return ok;
}

bool ed25519_verify(
    const std::vector<std::uint8_t>& pubkey,
    const std::uint8_t* msg,
    std::size_t msg_len,
    const std::uint8_t* sig,
    std::size_t sig_len) noexcept {
    if (pubkey.size() != ed25519_pubkey_bytes || sig_len != ed25519_signature_bytes || !sig || (!msg && msg_len > 0)) {
        return false;
    }

    EVP_PKEY* pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubkey.data(), pubkey.size());
    if (!pub) return false;

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    bool ok = false;
    if (mctx && EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, pub) > 0) {
        if (EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len) > 0) {
            ok = true;
        }
    }

    if (mctx) EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pub);
    return ok;
}

bool hkdf_extract(
    const std::vector<std::uint8_t>& salt,
    const std::vector<std::uint8_t>& ikm,
    std::vector<std::uint8_t>& out_prk) noexcept {
    out_prk.clear();
    if (ikm.empty()) return false;

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) return false;

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    bool ok = false;
    if (kctx) {
        int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
        char md_name[] = "SHA256";
        OSSL_PARAM params[4];
        params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md_name, 0);
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)ikm.data(), ikm.size());
        if (!salt.empty()) {
            params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt.data(), salt.size());
        } else {
            // Salt defaults to 32 zero bytes
            static const std::uint8_t zeros[32]{};
            params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)zeros, sizeof(zeros));
        }

        OSSL_PARAM params_with_end[5];
        for (int i = 0; i < 4; ++i) params_with_end[i] = params[i];
        params_with_end[4] = OSSL_PARAM_construct_end();

        out_prk.resize(sha256_digest_bytes);
        if (EVP_KDF_derive(kctx, out_prk.data(), out_prk.size(), params_with_end) > 0) {
            ok = true;
        }
        EVP_KDF_CTX_free(kctx);
    }

    EVP_KDF_free(kdf);
    if (!ok) {
        secure_zero(out_prk.data(), out_prk.size());
        out_prk.clear();
    }
    return ok;
}

bool hkdf_expand(
    const std::vector<std::uint8_t>& prk,
    const std::string& info,
    std::size_t out_len,
    std::vector<std::uint8_t>& out_key) noexcept {
    out_key.clear();
    if (prk.size() != sha256_digest_bytes || out_len == 0 || out_len > 255 * sha256_digest_bytes) {
        return false;
    }

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) return false;

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    bool ok = false;
    if (kctx) {
        int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
        char md_name[] = "SHA256";
        OSSL_PARAM params[5];
        params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md_name, 0);
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)prk.data(), prk.size());
        params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info.data(), info.size());
        params[4] = OSSL_PARAM_construct_end();

        out_key.resize(out_len);
        if (EVP_KDF_derive(kctx, out_key.data(), out_len, params) > 0) {
            ok = true;
        }
        EVP_KDF_CTX_free(kctx);
    }

    EVP_KDF_free(kdf);
    if (!ok) {
        secure_zero(out_key.data(), out_key.size());
        out_key.clear();
    }
    return ok;
}

static const EVP_CIPHER* get_aead_cipher(crypto_suite suite) noexcept {
    if (suite == crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305) {
        return EVP_chacha20_poly1305();
    }
    if (suite == crypto_suite::x25519_ed25519_hkdf_sha256_aes256_gcm) {
        return EVP_aes_256_gcm();
    }
    return nullptr;
}

bool aead_encrypt(
    crypto_suite suite,
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& nonce,
    const std::vector<std::uint8_t>& aad,
    const std::vector<std::uint8_t>& plaintext,
    std::vector<std::uint8_t>& out_ciphertext,
    std::vector<std::uint8_t>& out_tag) noexcept {
    out_ciphertext.clear();
    out_tag.clear();

    const EVP_CIPHER* cipher = get_aead_cipher(suite);
    if (!cipher || key.size() != aead_key_bytes || nonce.size() != aead_nonce_bytes) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    out_ciphertext.resize(plaintext.size());
    out_tag.resize(aead_tag_bytes);

    int len = 0;
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) > 0 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, aead_nonce_bytes, nullptr) > 0 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) > 0) {

        // Provide AAD if present
        if (!aad.empty()) {
            if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) <= 0) {
                goto cleanup;
            }
        }

        // Encrypt plaintext
        if (!plaintext.empty()) {
            if (EVP_EncryptUpdate(ctx, out_ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) <= 0) {
                goto cleanup;
            }
        }

        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx, out_ciphertext.data() + len, &final_len) > 0) {
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, aead_tag_bytes, out_tag.data()) > 0) {
                ok = true;
            }
        }
    }

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        out_ciphertext.clear();
        out_tag.clear();
    }
    return ok;
}

bool aead_decrypt(
    crypto_suite suite,
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& nonce,
    const std::vector<std::uint8_t>& aad,
    const std::vector<std::uint8_t>& ciphertext,
    const std::vector<std::uint8_t>& tag,
    std::vector<std::uint8_t>& out_plaintext) noexcept {
    out_plaintext.clear();

    const EVP_CIPHER* cipher = get_aead_cipher(suite);
    if (!cipher || key.size() != aead_key_bytes || nonce.size() != aead_nonce_bytes || tag.size() != aead_tag_bytes) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    out_plaintext.resize(ciphertext.size());

    int len = 0;
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) > 0 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, aead_nonce_bytes, nullptr) > 0 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) > 0) {

        // Provide AAD if present
        if (!aad.empty()) {
            if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) <= 0) {
                goto cleanup;
            }
        }

        // Decrypt ciphertext
        if (!ciphertext.empty()) {
            if (EVP_DecryptUpdate(ctx, out_plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) <= 0) {
                goto cleanup;
            }
        }

        // Set expected tag before finalizing
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, aead_tag_bytes, const_cast<std::uint8_t*>(tag.data())) <= 0) {
            goto cleanup;
        }

        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, out_plaintext.data() + len, &final_len) > 0) {
            ok = true;
        }
    }

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        secure_zero(out_plaintext.data(), out_plaintext.size());
        out_plaintext.clear();
    }
    return ok;
}

} // namespace linep::sl::v0_2
