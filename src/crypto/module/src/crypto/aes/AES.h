//===----------------------------------------------------------------------===//
///
/// \aes.h
/// KiaCi AES-GCM interface.
/// Defines the encrypted payload container and functions used
/// for authenticated encryption and decryption of tunnel data.
///
//===----------------------------------------------------------------------===//
#pragma once

#include <vector>
#include <cstdint>

/// KiaCi AES-GCM encrypted payload.
/// Stores the nonce, ciphertext, and authentication tag
/// produced during authenticated encryption.
struct Encrypted {
    uint8_t              nonce[12] = {};
    std::vector<uint8_t> ciphertext;
    uint8_t              tag[16] = {};
};

/// Encrypts plaintext using the provided symmetric key.
/// Returns an AES-GCM payload containing nonce, ciphertext, and tag.
Encrypted aesEncrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext);

/// Decrypts and verifies an AES-GCM encrypted payload.
/// Returns plaintext on success, or an empty vector on failure.
std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& key, const Encrypted& enc);


/// Encrypts plaintext using the provided symmetric key and nonce.
/// Returns an AES-GCM payload containing nonce, ciphertext, and tag.
Encrypted aesEncryptWithNonce(const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& plaintext,
                               const uint8_t nonce[12]);
