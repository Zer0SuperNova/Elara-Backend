//===----------------------------------------------------------------------===//
///
/// \crypto_lib.h
/// KiaCi E2E authentication and secure tunnel interface.
/// Declares key generation, handshake verification, shared secret derivation,
/// session key derivation, signing, and encrypted tunnel messaging operations.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "crypto/keygen/Keygen.h"
#include "crypto/handshake/Handshake.h"
#include "crypto/sharedsecret/SharedSecret.h"
#include "crypto/hkdf/HKDF.h"
#include "crypto/tunnel/Tunnel.h"

#include <vector>
#include <stdexcept>
#include <cstdint>

/// Encrypted KiaCi tunnel payload.
/// Stores the AES-GCM nonce, authentication tag,
/// ciphertext, and outer message authentication code.
struct TunnelMessage {
    uint8_t              nonce[12];
    uint8_t              tag[16];
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> mac;
};

/// Symmetric session keys derived from a shared secret.
/// Contains the encryption key and the message
/// authentication key used by the tunnel layer.
struct SessionKeys {
    std::vector<uint8_t> encKey;   // 32 bytes � AES-256
    std::vector<uint8_t> hmacKey;  // 32 bytes � HMAC-SHA256
};

// Generates a new Ed25519 signing keypair and X25519 key exchange keypair
Keys cryptoGenerateKeys();

// Creates a signed handshake payload from a local key set
HandshakePayload cryptoCreateHandshake(const Keys& keys);

// Verifies the signature and integrity of a handshake payload
bool cryptoVerifyHandshake(const HandshakePayload& payload);

// Derives a shared X25519 secret from a remote public key and local secret key
bool cryptoDeriveSharedSecret(const uint8_t* theirPK, const uint8_t* ourSK, SharedSecret& out);

// Derives symmetric session keys for encryption and message authentication
SessionKeys cryptoDeriveSessionKeys(const SharedSecret& secret);

// Produces a detached Ed25519 signature for the given message
std::vector<uint8_t> cryptoSign(const uint8_t* message, size_t len, const uint8_t* sk);

// Encrypts and authenticates plaintext into a tunnel message
TunnelMessage cryptoTunnelSend(const SessionKeys& keys, const std::vector<uint8_t>& plaintext);

// Verifies and decrypts a tunnel message into plaintext
std::vector<uint8_t> cryptoTunnelReceive(const SessionKeys& keys, const TunnelMessage& msg);

// Combines three DH outputs into a single session key material
SharedSecret cryptoDeriveTripleSharedSecret(
    const uint8_t* dh1,
    const uint8_t* dh2,
    const uint8_t* dh3);

// Hashes all four handshake public keys into a transcript digest
std::vector<uint8_t> cryptoBuildTranscriptHash(
    const uint8_t* clientEphX25519PK,
    const uint8_t* clientStaticEd25519PK,
    const uint8_t* serverEphX25519PK,
    const uint8_t* serverStaticEd25519PK);

// Encrypts with a caller-supplied nonce — use for all streaming chunks
TunnelMessage cryptoTunnelSendWithNonce(
    const SessionKeys& keys,
    const std::vector<uint8_t>& plaintext,
    const uint8_t nonce[12]);