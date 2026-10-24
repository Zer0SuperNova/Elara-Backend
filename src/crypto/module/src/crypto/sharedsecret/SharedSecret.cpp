//===----------------------------------------------------------------------===//
///
/// \shared_secret.cpp
/// KiaCi X25519 shared secret derivation implementation.
/// Computes a common secret from a remote public key and local secret key
/// using Curve25519 scalar multiplication.
///
//===----------------------------------------------------------------------===//
#include "crypto/sharedsecret/SharedSecret.h"

/// Derives a shared X25519 secret from a remote public key and local secret key.
/// Uses crypto_scalarmult to compute the shared secret point.
/// @returns true on success, false on invalid input keys.
bool deriveSharedSecret(
    const uint8_t* theirPK,
    const uint8_t* ourSK,
    SharedSecret& out)
{
    return crypto_scalarmult(out.bytes, ourSK, theirPK) == 0;
}