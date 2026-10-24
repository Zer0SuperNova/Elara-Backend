//===----------------------------------------------------------------------===//
///
/// \tunnel.h
/// KiaCi secure tunnel interface declarations.
/// Defines the encrypted message structure and tunnel class for
/// authenticated encryption and decryption of KiaCi payloads.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "../aes/AES.h"

#include <vector>
#include <cstdint>

/// KiaCi encrypted tunnel message structure.
/// Contains the AES-GCM encrypted payload and outer HMAC.
struct Message {
    Encrypted            enc;
    std::vector<uint8_t> mac;
};

/// KiaCi secure tunnel class.
/// Provides authenticated encryption and decryption using
/// separate encryption and message authentication keys.
class Tunnel {
public:
    // Constructs a tunnel with encryption and authentication keys.
    Tunnel(const std::vector<uint8_t>& encKey,
        const std::vector<uint8_t>& hmacKey);

    // Encrypts plaintext into an authenticated tunnel message.
    Message send(const std::vector<uint8_t>& plaintext) const;

    // Encrypts plaintext using the provided symmetric key and nonce.
    Message sendWithNonce(const std::vector<uint8_t>& plaintext, const uint8_t nonce[12]) const; 

    /// Decrypts and authenticates a tunnel message.
    /// Returns empty vector on authentication failure.
    std::vector<uint8_t> receive(const Message& msg) const;

private:
    std::vector<uint8_t> m_encKey;
    std::vector<uint8_t> m_hmacKey;
};