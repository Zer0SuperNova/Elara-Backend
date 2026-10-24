//===----------------------------------------------------------------------===//
///
/// \handshake.cpp
/// KiaCi handshake implementation.
/// Builds signed handshake payloads and verifies peer authenticity
/// during session establishment.
///
//===----------------------------------------------------------------------===//
#include "crypto/handshake/Handshake.h"
#include "crypto/keygen/Keygen.h"

#include <cstring>

/// Creates a signed handshake payload from a local key set.
/// Copies public key material into the payload and signs the
/// key exchange public key using the signing secret key.
HandshakePayload createHandshake(const Keys& keys) {
    HandshakePayload payload;

    memcpy(payload.ed25519PK, keys.ed25519PK, crypto_sign_PUBLICKEYBYTES);
    memcpy(payload.x25519PK, keys.x25519PK, crypto_scalarmult_BYTES);

    unsigned long long siglen;
    crypto_sign_detached(
        payload.sig, &siglen,
        keys.x25519PK, crypto_scalarmult_BYTES,
        keys.ed25519SK
    );

    return payload;
}

/// Verifies the signature and integrity of a handshake payload.
/// Checks that the key exchange public key was signed by the
/// owner of the included signing public key.
bool verifyHandshake(const HandshakePayload& payload) {
    return crypto_sign_verify_detached(
        payload.sig,
        payload.x25519PK, crypto_scalarmult_BYTES,
        payload.ed25519PK
    ) == 0;
}