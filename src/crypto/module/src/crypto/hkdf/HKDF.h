//===----------------------------------------------------------------------===//
///
/// \hkdf.h
/// KiaCi HKDF key derivation interface.
/// Implements HMAC-based Extract-and-Expand key derivation
/// used to expand shared secrets into session encryption keys.
///
//===----------------------------------------------------------------------===//
#pragma once

#include <vector>
#include <string>
#include <cstdint>

/// Derives session keys from shared secret using HKDF.
/// Extracts pseudorandom key from input secret, then expands into
/// application-specific keys using context-specific labels.
std::vector<uint8_t> hkdf(
    const uint8_t* secret, size_t secretLen,
    size_t outLen,
    const std::string& label
);