//===----------------------------------------------------------------------===//
///
/// \crypto_lib.cpp
/// KiaCi E2E authentication and secure tunnel implementation.
/// Provides high-level cryptographic operations for key generation,
/// handshake validation, session establishment, signing, and tunnel messaging.
///
/// -- 
/// This file is really ugly i know..
/// - Zer0
/// 
//===----------------------------------------------------------------------===//

#include "crypto/CryptoLib.h"
#include <sodium/sodium.h>

#include <stdexcept>
#include <cstring>

// Generates a new signing and key exchange key set.
Keys cryptoGenerateKeys() {
    return generateKeys();
}

// Creates a signed handshake payload from a local key set.
HandshakePayload cryptoCreateHandshake(const Keys& keys) {
    return createHandshake(keys);
}

// Verifies the signature and integrity of a handshake payload.
bool cryptoVerifyHandshake(const HandshakePayload& payload) {
    return verifyHandshake(payload);
}

// Derives a shared X25519 secret from a remote public key and local secret key.
bool cryptoDeriveSharedSecret(const uint8_t* theirPK, const uint8_t* ourSK, SharedSecret& out)
{
    return deriveSharedSecret(theirPK, ourSK, out);
}

// Derives symmetric session keys for encryption and message authentication.
SessionKeys cryptoDeriveSessionKeys(const SharedSecret& secret) {
    SessionKeys keys;
    keys.encKey = hkdf(secret.bytes, sizeof(secret.bytes), 32, "enc");
    keys.hmacKey = hkdf(secret.bytes, sizeof(secret.bytes), 32, "mac");
    return keys;
}

// Produces a detached Ed25519 signature for the given message.
std::vector<uint8_t> cryptoSign(const uint8_t* message, size_t len, const uint8_t* sk)
{
    if (!message || !sk || len == 0)
        throw std::invalid_argument("cryptoSign: null or empty input");

    std::vector<uint8_t> sig(crypto_sign_BYTES);
    crypto_sign_detached(sig.data(), nullptr, message, len, sk);
    return sig;
}

// Encrypts and authenticates plaintext into a tunnel message.
TunnelMessage cryptoTunnelSend(const SessionKeys& keys, const std::vector<uint8_t>& plaintext)
{
    Tunnel tunnel(keys.encKey, keys.hmacKey);
    Message msg = tunnel.send(plaintext);

    TunnelMessage out;
    memcpy(out.nonce, msg.enc.nonce, 12);
    memcpy(out.tag, msg.enc.tag, 16);
    out.ciphertext = msg.enc.ciphertext;
    out.mac = msg.mac;
    return out;
}

/// Verifies and decrypts a tunnel message into plaintext.
/// @returns empty vector on MAC failure or decryption error.
std::vector<uint8_t> cryptoTunnelReceive(const SessionKeys& keys, const TunnelMessage& in)
{
    Message msg;
    memcpy(msg.enc.nonce, in.nonce, 12);
    memcpy(msg.enc.tag, in.tag, 16);
    msg.enc.ciphertext = in.ciphertext;
    msg.mac = in.mac;

    Tunnel tunnel(keys.encKey, keys.hmacKey);
    return tunnel.receive(msg);
}

// Combines three DH outputs into a single session key material.
SharedSecret cryptoDeriveTripleSharedSecret(
    const uint8_t* dh1,
    const uint8_t* dh2,
    const uint8_t* dh3)
{
    if (!dh1 || !dh2 || !dh3)
        throw std::invalid_argument("cryptoDeriveTripleSharedSecret: null input");

    uint8_t combined[96];
    memcpy(combined,      dh1, 32);
    memcpy(combined + 32, dh2, 32);
    memcpy(combined + 64, dh3, 32);

    SharedSecret out;
    crypto_generichash(out.bytes, sizeof(out.bytes), combined, sizeof(combined), nullptr, 0);
    sodium_memzero(combined, sizeof(combined));
    return out;
}

// Hashes all four handshake public keys in a fixed order.
// Both sides compute this identically after key exchange.
// Server signs the result; client verifies before stream opens.
std::vector<uint8_t> cryptoBuildTranscriptHash(
    const uint8_t* clientEphX25519PK,
    const uint8_t* clientStaticEd25519PK,
    const uint8_t* serverEphX25519PK,
    const uint8_t* serverStaticEd25519PK)
{
    if (!clientEphX25519PK || !clientStaticEd25519PK ||
        !serverEphX25519PK || !serverStaticEd25519PK)
        throw std::invalid_argument("cryptoBuildTranscriptHash: null input");

    uint8_t transcript[128];
    memcpy(transcript,       clientEphX25519PK,     32);
    memcpy(transcript + 32,  clientStaticEd25519PK, 32);
    memcpy(transcript + 64,  serverEphX25519PK,     32);
    memcpy(transcript + 96,  serverStaticEd25519PK, 32);

    std::vector<uint8_t> hash(crypto_generichash_BYTES);
    crypto_generichash(hash.data(), hash.size(), transcript, sizeof(transcript), nullptr, 0);
    return hash;
}

// Encrypts with a caller-supplied nonce. for all streaming chunks.
TunnelMessage cryptoTunnelSendWithNonce(
    const SessionKeys& keys,
    const std::vector<uint8_t>& plaintext,
    const uint8_t nonce[12])
{
    Tunnel tunnel(keys.encKey, keys.hmacKey);
    Message msg = tunnel.sendWithNonce(plaintext, nonce);

    TunnelMessage out;
    memcpy(out.nonce, msg.enc.nonce, 12);
    memcpy(out.tag,   msg.enc.tag,   16);
    out.ciphertext = msg.enc.ciphertext;
    out.mac        = msg.mac;
    return out;
}