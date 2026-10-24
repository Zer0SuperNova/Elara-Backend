//===----------------------------------------------------------------------===//
///
/// \handshake.h
/// KiaCi handshake interface.
/// Defines the signed handshake payload used to authenticate peers
/// and exchange public key material for session establishment.
///
//===----------------------------------------------------------------------===//
#pragma once

#include <sodium/sodium.h>
#include <cstdint>

/// KiaCi handshake payload.
/// Contains the signing public key, key exchange public key,
/// and detached signature used for peer authentication.
struct HandshakePayload {
    uint8_t ed25519PK[crypto_sign_PUBLICKEYBYTES];
    uint8_t x25519PK[crypto_scalarmult_BYTES];
    uint8_t sig[crypto_sign_BYTES];
};

struct Keys;

/// Creates a signed handshake payload from a local key set.
HandshakePayload createHandshake(const Keys& keys);

/// Verifies the signature and integrity of a handshake payload.
bool verifyHandshake(const HandshakePayload& payload);