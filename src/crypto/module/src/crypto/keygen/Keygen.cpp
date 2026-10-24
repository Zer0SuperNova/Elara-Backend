//===----------------------------------------------------------------------===//
///
/// \keygen.cpp
/// KiaCi single-use key generation implementation.
/// Generates ephemeral Ed25519 signing keys and X25519 key exchange keys
/// used for one-time authentication and session establishment.
///
//===----------------------------------------------------------------------===//
#include "crypto/keygen/Keygen.h"

#include <sodium/sodium.h>

/// Generates fresh signing and key exchange keypairs.
/// Uses libsodium's crypto_sign_keypair() and crypto_scalarmult_keypair()
/// to create cryptographically secure ephemeral keypairs.
/// @returns a Keys struct containing the generated public and secret keys.
Keys generateKeys() {
    Keys keys;
    crypto_sign_keypair(keys.ed25519PK, keys.ed25519SK);
    crypto_box_keypair(keys.x25519PK, keys.x25519SK); 
    return keys;
}