//===----------------------------------------------------------------------===//
///
/// \keygen.h
/// KiaCi single-use key generation interface.
/// Generates ephemeral Ed25519 signing keys and X25519 key exchange keys
/// for one-time use in KiaCi authentication and session establishment.
///
//===----------------------------------------------------------------------===//
#pragma once

#include <sodium/sodium.h>
#include <cstdint>

/// KiaCi single-use local key set.
/// Ephemeral keypairs used for one authentication session.
/// Contains signing and key exchange keys that MUST NOT be reused.
struct Keys {
    // Public Keys
    uint8_t ed25519PK[crypto_sign_PUBLICKEYBYTES];  ///< Single-use Ed25519 signing public key
    uint8_t x25519PK[crypto_scalarmult_BYTES];      ///< Single-use X25519 key exchange public key

    // Secret Keys  
    uint8_t ed25519SK[crypto_sign_SECRETKEYBYTES];  ///< Single-use Ed25519 signing secret key
    uint8_t x25519SK[crypto_scalarmult_SCALARBYTES]; ///< Single-use X25519 key exchange secret key
};

/// Generates fresh single-use KiaCi key set.
/// Creates ephemeral signing and key exchange keypairs
/// that must only be used for one authentication session.
Keys generateKeys();