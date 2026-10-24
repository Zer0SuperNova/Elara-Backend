//===----------------------------------------------------------------------===//
///
/// \aes.cpp
/// KiaCi AES-GCM encryption and decryption implementation.
/// Provides authenticated encryption and decryption using
/// OpenSSL's EVP interface for the KiaCi tunnel layer.
/// 
/// 
///
//===----------------------------------------------------------------------===//
#include "crypto/aes/AES.h"

#include <openssl/evp.h>
#include <sodium/sodium.h>
#include <stdexcept>
#include <cstring> 

/// RAII guard for EVP_CIPHER_CTX.
/// Ensures context cleanup even if exceptions occur.
/// IMPORTANT: OpenSSL contexts must be freed to avoid memory leaks.
struct EvpCtxGuard {
    EVP_CIPHER_CTX* ctx;
    explicit EvpCtxGuard(EVP_CIPHER_CTX* c) : ctx(c) {}
    ~EvpCtxGuard() { if (ctx) EVP_CIPHER_CTX_free(ctx); }
};

/// Encrypts plaintext using AES-256-GCM.
/// Generates a random nonce and produces an authentication tag.
Encrypted aesEncrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& plaintext)
{
    Encrypted enc;
    randombytes_buf(enc.nonce, sizeof(enc.nonce));
    enc.ciphertext.resize(plaintext.size());

    EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
    if (!raw) throw std::runtime_error("AES-GCM: ctx allocation failed");
    EvpCtxGuard guard(raw);

    int len = 0;

	// TODO: clean this up. OpenSSL's EVP API is very clunky and error-prone !
    if (EVP_EncryptInit_ex(raw, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("AES-GCM: EncryptInit (cipher) failed");
    if (EVP_EncryptInit_ex(raw, nullptr, nullptr, key.data(), enc.nonce) != 1)
        throw std::runtime_error("AES-GCM: EncryptInit (key/nonce) failed");
    if (EVP_EncryptUpdate(raw, enc.ciphertext.data(), &len,
        plaintext.data(), (int)plaintext.size()) != 1)
        throw std::runtime_error("AES-GCM: EncryptUpdate failed");
    if (EVP_EncryptFinal_ex(raw, enc.ciphertext.data() + len, &len) != 1)
        throw std::runtime_error("AES-GCM: EncryptFinal failed");
    if (EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_GCM_GET_TAG, 16, enc.tag) != 1)
        throw std::runtime_error("AES-GCM: GET_TAG failed");

    return enc;
}

/// Decrypts and authenticates an AES-GCM payload.
/// Verifies the authentication tag before returning plaintext.
std::vector<uint8_t> aesDecrypt(
    const std::vector<uint8_t>& key,
    const Encrypted& enc)
{
    std::vector<uint8_t> plaintext(enc.ciphertext.size());

    EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
    if (!raw) throw std::runtime_error("AES-GCM: ctx allocation failed");
    EvpCtxGuard guard(raw);

    int len = 0;

    // TODO: clean this up. OpenSSL's EVP API is very clunky and error-prone !
    if (EVP_DecryptInit_ex(raw, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("AES-GCM: DecryptInit (cipher) failed");
    if (EVP_DecryptInit_ex(raw, nullptr, nullptr, key.data(), enc.nonce) != 1)
        throw std::runtime_error("AES-GCM: DecryptInit (key/nonce) failed");
    if (EVP_DecryptUpdate(raw, plaintext.data(), &len,
        enc.ciphertext.data(), (int)enc.ciphertext.size()) != 1)
        throw std::runtime_error("AES-GCM: DecryptUpdate failed");

    if (EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_GCM_SET_TAG, 16, (void*)enc.tag) != 1)
        throw std::runtime_error("AES-GCM: SET_TAG failed");

    if (EVP_DecryptFinal_ex(raw, plaintext.data() + len, &len) <= 0)
        return {};

    return plaintext;
}

/// Encrypts plaintext using AES-256-GCM with a caller-supplied nonce.
/// this is for streaming encryption where the nonce is derived from a counter or other non-random source.
/// Identical to aesEncrypt() but skips randombytes_buf().
Encrypted aesEncryptWithNonce(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& plaintext,
    const uint8_t               nonce[12])
{
    Encrypted enc;
    memcpy(enc.nonce, nonce, 12);  // use supplied nonce
    enc.ciphertext.resize(plaintext.size());

    EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
    if (!raw) throw std::runtime_error("AES-GCM: ctx allocation failed");
    EvpCtxGuard guard(raw);

    int len = 0;

    if (EVP_EncryptInit_ex(raw, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("AES-GCM: EncryptInit (cipher) failed");
    if (EVP_EncryptInit_ex(raw, nullptr, nullptr, key.data(), enc.nonce) != 1)
        throw std::runtime_error("AES-GCM: EncryptInit (key/nonce) failed");
    if (EVP_EncryptUpdate(raw, enc.ciphertext.data(), &len,
        plaintext.data(), (int)plaintext.size()) != 1)
        throw std::runtime_error("AES-GCM: EncryptUpdate failed");
    if (EVP_EncryptFinal_ex(raw, enc.ciphertext.data() + len, &len) != 1)
        throw std::runtime_error("AES-GCM: EncryptFinal failed");
    if (EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_GCM_GET_TAG, 16, enc.tag) != 1)
        throw std::runtime_error("AES-GCM: GET_TAG failed");

    return enc;
}