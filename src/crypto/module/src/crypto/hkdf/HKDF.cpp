//===----------------------------------------------------------------------===//
///
/// \hkdf.cpp
/// KiaCi HKDF key derivation implementation.
/// Implements OpenSSL's EVP HKDF interface to expand shared secrets
/// into session encryption and authentication keys.
///
//===----------------------------------------------------------------------===//
#include "crypto/hkdf/HKDF.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>

/// Derives keys from shared secret using HKDF-SHA256.
/// Uses fixed protocol salt and application-specific labels to
/// produce distinct encryption and authentication keys.
std::vector<uint8_t> hkdf(const uint8_t* secret, size_t secretLen, size_t outLen, const std::string& label) {
    std::vector<uint8_t> out(outLen);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);

    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(ctx, (const uint8_t*)"tunnel-v1-salt", 14);
    EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, (int)secretLen);
    EVP_PKEY_CTX_add1_hkdf_info(ctx, (const uint8_t*)label.c_str(), (int)label.size());

    size_t len = outLen;
    EVP_PKEY_derive(ctx, out.data(), &len);
    EVP_PKEY_CTX_free(ctx);
    return out;
}