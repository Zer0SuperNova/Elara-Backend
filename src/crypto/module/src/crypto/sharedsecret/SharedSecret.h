//===----------------------------------------------------------------------===//
///
/// \shared_secret.h
/// KiaCi X25519 shared secret derivation interface.
/// Defines the shared secret structure and function used to
/// compute a common secret from a remote public key and local secret key.
///
//===----------------------------------------------------------------------===//
#pragma once

#include <sodium/sodium.h>
#include <cstdint>

/// KiaCi X25519 shared secret.
/// 32 bytes of raw Curve25519 shared secret material.
/// Must be KDF'd before use as a symmetric key.
struct SharedSecret {
    uint8_t bytes[crypto_scalarmult_BYTES];
};

/// Derives a shared secret from a remote public key and local secret key.
/// Returns true on success, false on invalid input.
/// Out parameter receives the raw shared secret.
bool deriveSharedSecret(
    const uint8_t* theirPK,
    const uint8_t* ourSK,
    SharedSecret& out
);