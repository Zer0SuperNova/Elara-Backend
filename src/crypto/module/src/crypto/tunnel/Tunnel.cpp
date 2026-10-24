//===----------------------------------------------------------------------===//
///
/// \tunnel.cpp
/// KiaCi E2E tunnel implementation.
/// Provides authenticated message protection by combining
/// AES-GCM encryption with HMAC-based message authentication.
///
//===----------------------------------------------------------------------===//
#include "Tunnel.h"
#include "../aes/AES.h"

#include <sodium/sodium.h>
#include <stdexcept>

// Constructs a tunnel with encryption and authentication keys.
Tunnel::Tunnel(const std::vector<uint8_t>& encKey,
    const std::vector<uint8_t>& hmacKey)
    : m_encKey(encKey), m_hmacKey(hmacKey) {
}

/// Builds the byte buffer used as HMAC input.
/// Includes nonce, ciphertext, and authentication tag.
static std::vector<uint8_t> mac_input(const Encrypted& enc) {
    std::vector<uint8_t> buf;
    buf.reserve(sizeof(enc.nonce) + enc.ciphertext.size() + sizeof(enc.tag));
    buf.insert(buf.end(), enc.nonce, enc.nonce + sizeof(enc.nonce));
    buf.insert(buf.end(), enc.ciphertext.begin(), enc.ciphertext.end());
    buf.insert(buf.end(), enc.tag, enc.tag + sizeof(enc.tag));
    return buf;
}

// Computes an HMAC-SHA256 over the provided message.
static std::vector<uint8_t> hmac_sign(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& message)
{
    std::vector<uint8_t> out(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, key.data(), key.size());
    crypto_auth_hmacsha256_update(&state, message.data(), message.size());
    crypto_auth_hmacsha256_final(&state, out.data());
    return out;
}

// Verifies an HMAC-SHA256 for the provided message.
static bool hmac_verify(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& mac)
{
    if (mac.size() != crypto_auth_hmacsha256_BYTES) return false;
    auto expected = hmac_sign(key, message);
    return sodium_memcmp(expected.data(), mac.data(),
        crypto_auth_hmacsha256_BYTES) == 0;
}

// Encrypts and authenticates plaintext into a tunnel message.
Message Tunnel::send(const std::vector<uint8_t>& plaintext) const {
    Message msg;
    msg.enc = aesEncrypt(m_encKey, plaintext);
    msg.mac = hmac_sign(m_hmacKey, mac_input(msg.enc));
    return msg;
}

// Encrypts plaintext using the provided symmetric key and nonce.
Message Tunnel::sendWithNonce(const std::vector<uint8_t>& plaintext,
                               const uint8_t nonce[12]) const {
    Message msg;
    msg.enc = aesEncryptWithNonce(m_encKey, plaintext, nonce);
    msg.mac = hmac_sign(m_hmacKey, mac_input(msg.enc));
    return msg;
}

/// Verifies and decrypts a tunnel message.
/// @returns empty vector on authentication failure.
std::vector<uint8_t> Tunnel::receive(const Message& msg) const {
    if (!hmac_verify(m_hmacKey, mac_input(msg.enc), msg.mac))
        return {};
    return aesDecrypt(m_encKey, msg.enc);
}


