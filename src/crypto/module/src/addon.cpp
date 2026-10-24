//------------------------------------------------------------------------//
///
/// addon.cpp
/// Node.js NAPI addon for KiaCi E2E cryptographic operations.
///
///-------------------------------------------------------------------------//

#include <napi.h>
#include <crypto/CryptoLib.h>
#include <crypto/validators/ValidateBuffer.h>
#include <sodium/sodium.h>
#include <stdexcept>
#include <limits>
#include <cmath> 

// For safety, define a maximum buffer size for plaintext, ciphertext, etc.
constexpr size_t kMaxReasonableBuffer = (1ULL << 30); // 1 GiB

/// Helper: read the JS-visible .length property from a Buffer-like object.
/// This catches spoofed lengths (e.g., Object.defineProperty(length...)).
static bool TryGetDeclaredLength(const Napi::Env& env, const Napi::Value& value, double& outLen) {
    if (!value.IsObject()) return false;
    Napi::Value lenVal = value.As<Napi::Object>().Get("length");
    if (!lenVal.IsNumber()) return false;
    outLen = lenVal.As<Napi::Number>().DoubleValue();
    if (!std::isfinite(outLen) || outLen < 0) return false;
    return true;
}

/// Extract session keys, enforcing nonzero buffer lengths.
static bool ExtractSessionKeys(Napi::Env env, Napi::Object keysObj, SessionKeys& sk) {
    Napi::Value encVal = keysObj.Get("encKey");
    Napi::Value macVal = keysObj.Get("hmacKey");

    if (encVal.IsUndefined()) {
        Napi::TypeError::New(env, "encKey: required field not found").ThrowAsJavaScriptException();
        return false;
    }
    if (macVal.IsUndefined()) {
        Napi::TypeError::New(env, "hmacKey: required field not found").ThrowAsJavaScriptException();
        return false;
    }
    if (!encVal.IsBuffer()) {
        Napi::TypeError::New(env, "encKey: expected a Buffer").ThrowAsJavaScriptException();
        return false;
    }
    if (!macVal.IsBuffer()) {
        Napi::TypeError::New(env, "hmacKey: expected a Buffer").ThrowAsJavaScriptException();
        return false;
    }

    auto encBuf = encVal.As<Napi::Buffer<uint8_t>>();
    auto macBuf = macVal.As<Napi::Buffer<uint8_t>>();
    if (encBuf.ByteLength() == 0) {
        Napi::RangeError::New(env, "encKey: buffer must not be empty").ThrowAsJavaScriptException();
        return false;
    }
    if (macBuf.ByteLength() == 0) {
        Napi::RangeError::New(env, "hmacKey: buffer must not be empty").ThrowAsJavaScriptException();
        return false;
    }
    if (encBuf.ByteLength() > kMaxReasonableBuffer) {
        Napi::RangeError::New(env, "encKey: length exceeds safe maximum").ThrowAsJavaScriptException();
        return false;
    }
    if (macBuf.ByteLength() > kMaxReasonableBuffer) {
        Napi::RangeError::New(env, "hmacKey: length exceeds safe maximum").ThrowAsJavaScriptException();
        return false;
    }

    sk.encKey  = std::vector<uint8_t>(encBuf.Data(), encBuf.Data() + encBuf.ByteLength());
    sk.hmacKey = std::vector<uint8_t>(macBuf.Data(), macBuf.Data() + macBuf.ByteLength());
    return true;
}


Napi::Value GenerateKeys(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    try {
        Keys keys = cryptoGenerateKeys();
        Napi::Object obj = Napi::Object::New(env);
        obj.Set("ed25519PK", Napi::Buffer<uint8_t>::Copy(env, keys.ed25519PK, sizeof(keys.ed25519PK)));
        obj.Set("x25519PK",  Napi::Buffer<uint8_t>::Copy(env, keys.x25519PK,  sizeof(keys.x25519PK)));
        obj.Set("ed25519SK", Napi::Buffer<uint8_t>::Copy(env, keys.ed25519SK, sizeof(keys.ed25519SK)));
        obj.Set("x25519SK",  Napi::Buffer<uint8_t>::Copy(env, keys.x25519SK,  sizeof(keys.x25519SK)));
        return obj;
    }
    catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}


Napi::Value CreateHandshake(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "Expected keys object").ThrowAsJavaScriptException();
        return env.Null();
    }
    try {
        Napi::Object keysObj = info[0].As<Napi::Object>();
        Keys keys{};
        NAPI_REQUIRE_OBJECT_BUFFER_EXACT(env, keysObj, "ed25519PK", keys.ed25519PK, sizeof(keys.ed25519PK));
        NAPI_REQUIRE_OBJECT_BUFFER_EXACT(env, keysObj, "x25519PK",  keys.x25519PK,  sizeof(keys.x25519PK));
        NAPI_REQUIRE_OBJECT_BUFFER_EXACT(env, keysObj, "ed25519SK", keys.ed25519SK, sizeof(keys.ed25519SK));
        NAPI_REQUIRE_OBJECT_BUFFER_EXACT(env, keysObj, "x25519SK",  keys.x25519SK,  sizeof(keys.x25519SK));

        HandshakePayload payload = cryptoCreateHandshake(keys);
        Napi::Object obj = Napi::Object::New(env);
        obj.Set("ed25519PK", Napi::Buffer<uint8_t>::Copy(env, payload.ed25519PK, sizeof(payload.ed25519PK)));
        obj.Set("x25519PK",  Napi::Buffer<uint8_t>::Copy(env, payload.x25519PK,  sizeof(payload.x25519PK)));
        obj.Set("sig",       Napi::Buffer<uint8_t>::Copy(env, payload.sig,        sizeof(payload.sig)));
        return obj;
    }
    catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value VerifyHandshake(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "Expected payload object").ThrowAsJavaScriptException();
        return env.Null();
    }
    try {
        Napi::Object p = info[0].As<Napi::Object>();
        HandshakePayload payload{};
        NAPI_REQUIRE_OBJECT_BUFFER_EXACT(env, p, "ed25519PK", payload.ed25519PK, sizeof(payload.ed25519PK));
        NAPI_REQUIRE_OBJECT_BUFFER_EXACT(env, p, "x25519PK",  payload.x25519PK,  sizeof(payload.x25519PK));
        NAPI_REQUIRE_OBJECT_BUFFER_EXACT(env, p, "sig",       payload.sig,       sizeof(payload.sig));

        return Napi::Boolean::New(env, cryptoVerifyHandshake(payload));
    }
    catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// Explicitly require actual Node Buffer for consistent error message (DataView should fail here).
static bool RequireBuffer(Napi::Env env, const Napi::Value& val, const char* name) {
    bool isBuffer  = false;
    bool isDataView = false;
    napi_is_buffer(env, val, &isBuffer);
    napi_is_dataview(env, val, &isDataView);

    if (!isBuffer || isDataView) {
        Napi::TypeError::New(env, std::string(name) + ": expected a Buffer").ThrowAsJavaScriptException();
        return false;
    }
    return true;
}

Napi::Value DeriveSharedSecret(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2) {
        Napi::TypeError::New(env, "Expected (theirX25519PK: Buffer, ourX25519SK: Buffer)").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!RequireBuffer(env, info[0], "theirX25519PK")) return env.Null();
    if (!RequireBuffer(env, info[1], "ourX25519SK"))   return env.Null();

    // Use declared .length to catch spoofed lengths (e.g., MAX_SAFE_INTEGER).
    double declaredLen = 0;
    if (TryGetDeclaredLength(env, info[0], declaredLen) && declaredLen != 32.0) {
        Napi::RangeError::New(env, "theirX25519PK: expected exactly 32 bytes").ThrowAsJavaScriptException();
        return env.Null();
    }
    if (TryGetDeclaredLength(env, info[1], declaredLen) && declaredLen != 32.0) {
        Napi::RangeError::New(env, "ourX25519SK: expected exactly 32 bytes").ThrowAsJavaScriptException();
        return env.Null();
    }

    NAPI_REQUIRE_BUFFER(env, info[0], "theirX25519PK");
    NAPI_REQUIRE_BUFFER(env, info[1], "ourX25519SK");

    auto theirPK = info[0].As<Napi::Buffer<uint8_t>>();
    auto ourSK   = info[1].As<Napi::Buffer<uint8_t>>();
    // Fail early for absurdly large buffers (e.g. length spoofing)
    if (theirPK.ByteLength() > 32) {
        Napi::RangeError::New(env, "theirX25519PK: expected exactly 32 bytes").ThrowAsJavaScriptException();
        return env.Null();
    }
    if (ourSK.ByteLength() > 32) {
        Napi::RangeError::New(env, "ourX25519SK: expected exactly 32 bytes").ThrowAsJavaScriptException();
        return env.Null();
    }
    NAPI_REQUIRE_BUFFER_EXACT(env, theirPK, 32, "theirX25519PK");
    NAPI_REQUIRE_BUFFER_EXACT(env, ourSK,   32, "ourX25519SK");

    SharedSecret secret{};
    if (!cryptoDeriveSharedSecret(theirPK.Data(), ourSK.Data(), secret)) {
        Napi::Error::New(env, "deriveSharedSecret: ECDH failed").ThrowAsJavaScriptException();
        return env.Null();
    }
    return Napi::Buffer<uint8_t>::Copy(env, secret.bytes, sizeof(secret.bytes));
}


Napi::Value DeriveTripleSharedSecret(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3) {
        Napi::TypeError::New(env, "Expected (dh1: Buffer, dh2: Buffer, dh3: Buffer)").ThrowAsJavaScriptException();
        return env.Null();
    }
    NAPI_REQUIRE_BUFFER(env, info[0], "dh1");
    NAPI_REQUIRE_BUFFER(env, info[1], "dh2");
    NAPI_REQUIRE_BUFFER(env, info[2], "dh3");
    try {
        auto dh1 = info[0].As<Napi::Buffer<uint8_t>>();
        auto dh2 = info[1].As<Napi::Buffer<uint8_t>>();
        auto dh3 = info[2].As<Napi::Buffer<uint8_t>>();
        NAPI_REQUIRE_BUFFER_EXACT(env, dh1, 32, "dh1");
        NAPI_REQUIRE_BUFFER_EXACT(env, dh2, 32, "dh2");
        NAPI_REQUIRE_BUFFER_EXACT(env, dh3, 32, "dh3");

        SharedSecret secret = cryptoDeriveTripleSharedSecret(dh1.Data(), dh2.Data(), dh3.Data());
        return Napi::Buffer<uint8_t>::Copy(env, secret.bytes, sizeof(secret.bytes));
    }
    catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value DeriveSessionKeys(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1) {
        Napi::TypeError::New(env, "Expected secret Buffer").ThrowAsJavaScriptException();
        return env.Null();
    }
    NAPI_REQUIRE_BUFFER(env, info[0], "secret");
    try {
        auto buf = info[0].As<Napi::Buffer<uint8_t>>();
        NAPI_REQUIRE_BUFFER_EXACT(env, buf, sizeof(SharedSecret::bytes), "secret");

        SharedSecret secret{};
        memcpy(secret.bytes, buf.Data(), sizeof(secret.bytes));

        SessionKeys sk = cryptoDeriveSessionKeys(secret);
        Napi::Object obj = Napi::Object::New(env);
        obj.Set("encKey",  Napi::Buffer<uint8_t>::Copy(env, sk.encKey.data(),  sk.encKey.size()));
        obj.Set("hmacKey", Napi::Buffer<uint8_t>::Copy(env, sk.hmacKey.data(), sk.hmacKey.size()));
        return obj;
    }
    catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value BuildTranscriptHash(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 4) {
        Napi::TypeError::New(env, "Expected (clientEphX25519PK, clientStaticEd25519PK, serverEphX25519PK, serverStaticEd25519PK: Buffer x4)").ThrowAsJavaScriptException();
        return env.Null();
    }
    NAPI_REQUIRE_BUFFER(env, info[0], "clientEphX25519PK");
    NAPI_REQUIRE_BUFFER(env, info[1], "clientStaticEd25519PK");
    NAPI_REQUIRE_BUFFER(env, info[2], "serverEphX25519PK");
    NAPI_REQUIRE_BUFFER(env, info[3], "serverStaticEd25519PK");
    try {
        auto b0 = info[0].As<Napi::Buffer<uint8_t>>();
        auto b1 = info[1].As<Napi::Buffer<uint8_t>>();
        auto b2 = info[2].As<Napi::Buffer<uint8_t>>();
        auto b3 = info[3].As<Napi::Buffer<uint8_t>>();
        NAPI_REQUIRE_BUFFER_EXACT(env, b0, 32, "clientEphX25519PK");
        NAPI_REQUIRE_BUFFER_EXACT(env, b1, 32, "clientStaticEd25519PK");
        NAPI_REQUIRE_BUFFER_EXACT(env, b2, 32, "serverEphX25519PK");
        NAPI_REQUIRE_BUFFER_EXACT(env, b3, 32, "serverStaticEd25519PK");

        auto hash = cryptoBuildTranscriptHash(b0.Data(), b1.Data(), b2.Data(), b3.Data());
        return Napi::Buffer<uint8_t>::Copy(env, hash.data(), hash.size());
    }
    catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

/// Signs a message with an Ed25519 private key (>= 1 byte)
Napi::Value Sign(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2) {
        Napi::TypeError::New(env, "Expected (message: Buffer, ed25519SK: Buffer)").ThrowAsJavaScriptException();
        return env.Null();
    }
    NAPI_REQUIRE_BUFFER(env, info[0], "message");
    NAPI_REQUIRE_BUFFER(env, info[1], "ed25519SK");
    try {
        auto msg = info[0].As<Napi::Buffer<uint8_t>>();
        auto sk  = info[1].As<Napi::Buffer<uint8_t>>();
        if (msg.ByteLength() == 0) {
            Napi::RangeError::New(env, "message: at least 1 byte").ThrowAsJavaScriptException();
            return env.Null();
        }
        if (msg.ByteLength() > kMaxReasonableBuffer) {
            Napi::RangeError::New(env, "message: length exceeds safe maximum").ThrowAsJavaScriptException();
            return env.Null();
        }
        NAPI_REQUIRE_BUFFER_EXACT(env, sk, 64, "ed25519SK");

        auto sig = cryptoSign(msg.Data(), msg.ByteLength(), sk.Data());
        return Napi::Buffer<uint8_t>::Copy(env, sig.data(), sig.size());
    }
    catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

/**
 * Encrypts and authenticates plaintext using tunnel session keys.
 */
Napi::Value TunnelSend(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "Expected (keys: object, plaintext: Buffer)").ThrowAsJavaScriptException();
        return env.Null();
    }
    NAPI_REQUIRE_BUFFER(env, info[1], "plaintext");
    try {
        Napi::Object keysObj = info[0].As<Napi::Object>();
        SessionKeys sk;
        if (!ExtractSessionKeys(env, keysObj, sk)) return env.Null();

        auto plainBuf = info[1].As<Napi::Buffer<uint8_t>>();

        // Use declared .length to catch spoofed lengths (e.g., 4GB-1).
        double declaredLen = 0;
        if (TryGetDeclaredLength(env, info[1], declaredLen)) {
            if (declaredLen == 0.0) {
                Napi::RangeError::New(env, "plaintext: at least 1 byte").ThrowAsJavaScriptException();
                return env.Null();
            }
            if (declaredLen > static_cast<double>(kMaxReasonableBuffer)) {
                Napi::RangeError::New(env, "plaintext: length").ThrowAsJavaScriptException();
                return env.Null();
            }
        }

        // Fix #1: disallow empty plaintext
        if (plainBuf.ByteLength() == 0) {
            Napi::RangeError::New(env, "plaintext: at least 1 byte").ThrowAsJavaScriptException();
            return env.Null();
        }
        // Fix #2: absurd length check
        if (plainBuf.ByteLength() > kMaxReasonableBuffer) {
            Napi::RangeError::New(env, "plaintext: length").ThrowAsJavaScriptException();
            return env.Null();
        }
        std::vector<uint8_t> plain(plainBuf.Data(), plainBuf.Data() + plainBuf.ByteLength());

        TunnelMessage tm = cryptoTunnelSend(sk, plain);
        Napi::Object obj = Napi::Object::New(env);
        obj.Set("nonce",      Napi::Buffer<uint8_t>::Copy(env, tm.nonce,             12));
        obj.Set("tag",        Napi::Buffer<uint8_t>::Copy(env, tm.tag,               16));
        obj.Set("ciphertext", Napi::Buffer<uint8_t>::Copy(env, tm.ciphertext.data(), tm.ciphertext.size()));
        obj.Set("mac",        Napi::Buffer<uint8_t>::Copy(env, tm.mac.data(),        tm.mac.size()));
        return obj;
    }
    catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

/**
 * Encrypts and authenticates plaintext with a caller-supplied nonce.
 */
Napi::Value TunnelSendWithNonce(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "Expected (keys: object, plaintext: Buffer, nonce: Buffer)").ThrowAsJavaScriptException();
        return env.Null();
    }
    NAPI_REQUIRE_BUFFER(env, info[1], "plaintext");
    NAPI_REQUIRE_BUFFER(env, info[2], "nonce");
    try {
        Napi::Object keysObj = info[0].As<Napi::Object>();
        SessionKeys sk;
        if (!ExtractSessionKeys(env, keysObj, sk)) return env.Null();

        auto plainBuf = info[1].As<Napi::Buffer<uint8_t>>();
        auto nonceBuf = info[2].As<Napi::Buffer<uint8_t>>();

        double declaredLen = 0;
        if (TryGetDeclaredLength(env, info[1], declaredLen)) {
            if (declaredLen == 0.0) {
                Napi::RangeError::New(env, "plaintext: at least 1 byte").ThrowAsJavaScriptException();
                return env.Null();
            }
            if (declaredLen > static_cast<double>(kMaxReasonableBuffer)) {
                Napi::RangeError::New(env, "plaintext: length").ThrowAsJavaScriptException();
                return env.Null();
            }
        }

        if (plainBuf.ByteLength() == 0) {
            Napi::RangeError::New(env, "plaintext: at least 1 byte").ThrowAsJavaScriptException();
            return env.Null();
        }
        if (plainBuf.ByteLength() > kMaxReasonableBuffer) {
            Napi::RangeError::New(env, "plaintext: length").ThrowAsJavaScriptException();
            return env.Null();
        }
        NAPI_REQUIRE_BUFFER_EXACT(env, nonceBuf, 12, "nonce");

        std::vector<uint8_t> plain(plainBuf.Data(), plainBuf.Data() + plainBuf.ByteLength());

        TunnelMessage tm = cryptoTunnelSendWithNonce(sk, plain, nonceBuf.Data());
        Napi::Object obj = Napi::Object::New(env);
        obj.Set("nonce",      Napi::Buffer<uint8_t>::Copy(env, tm.nonce,             12));
        obj.Set("tag",        Napi::Buffer<uint8_t>::Copy(env, tm.tag,               16));
        obj.Set("ciphertext", Napi::Buffer<uint8_t>::Copy(env, tm.ciphertext.data(), tm.ciphertext.size()));
        obj.Set("mac",        Napi::Buffer<uint8_t>::Copy(env, tm.mac.data(),        tm.mac.size()));
        return obj;
    }
    catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}


Napi::Value TunnelReceive(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsObject() || !info[1].IsObject()) {
        Napi::TypeError::New(env, "Expected (keys: object, message: object)").ThrowAsJavaScriptException();
        return env.Null();
    }
    try {
        Napi::Object keysObj = info[0].As<Napi::Object>();
        SessionKeys sk;
        if (!ExtractSessionKeys(env, keysObj, sk)) return env.Null();

        Napi::Object msgObj = info[1].As<Napi::Object>();

        Napi::Value nonceVal = msgObj.Get("nonce");
        Napi::Value tagVal   = msgObj.Get("tag");
        Napi::Value ciphVal  = msgObj.Get("ciphertext");
        Napi::Value macVal   = msgObj.Get("mac");
        NAPI_REQUIRE_BUFFER(env, nonceVal, "nonce");
        NAPI_REQUIRE_BUFFER(env, tagVal,   "tag");
        NAPI_REQUIRE_BUFFER(env, ciphVal,  "ciphertext");
        NAPI_REQUIRE_BUFFER(env, macVal,   "mac");

        auto nonce = nonceVal.As<Napi::Buffer<uint8_t>>();
        auto tag   = tagVal.As<Napi::Buffer<uint8_t>>();
        auto ciph  = ciphVal.As<Napi::Buffer<uint8_t>>();
        auto mac   = macVal.As<Napi::Buffer<uint8_t>>();
        NAPI_REQUIRE_BUFFER_EXACT(env, nonce, 12, "nonce");
        NAPI_REQUIRE_BUFFER_EXACT(env, tag,   16, "tag");
        NAPI_REQUIRE_SAFE_SIZE(env, ciph.ByteLength(), mac.ByteLength(), "ciphertext+mac");

        // Clamp message size to a hard limit too
        if (ciph.ByteLength() > kMaxReasonableBuffer) {
            Napi::RangeError::New(env, "ciphertext: length").ThrowAsJavaScriptException();
            return env.Null();
        }
        if (mac.ByteLength() > kMaxReasonableBuffer) {
            Napi::RangeError::New(env, "mac: length").ThrowAsJavaScriptException();
            return env.Null();
        }

        TunnelMessage tm{};
        memcpy(tm.nonce, nonce.Data(), 12);
        memcpy(tm.tag,   tag.Data(),   16);
        tm.ciphertext = std::vector<uint8_t>(ciph.Data(), ciph.Data() + ciph.ByteLength());
        tm.mac        = std::vector<uint8_t>(mac.Data(),  mac.Data()  + mac.ByteLength());

        auto result = cryptoTunnelReceive(sk, tm);
        if (result.empty()) {
            Napi::Error::New(env, "tunnelReceive: decryption failed or authentication mismatch").ThrowAsJavaScriptException();
            return env.Null();
        }
        return Napi::Buffer<uint8_t>::Copy(env, result.data(), result.size());
    }
    catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}


Napi::Value Verify(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3) {
        Napi::TypeError::New(env, "Expected (message: Buffer, sig: Buffer, ed25519PK: Buffer)").ThrowAsJavaScriptException();
        return env.Null();
    }
    NAPI_REQUIRE_BUFFER(env, info[0], "message");
    NAPI_REQUIRE_BUFFER(env, info[1], "sig");
    NAPI_REQUIRE_BUFFER(env, info[2], "ed25519PK");
    try {
        auto msg = info[0].As<Napi::Buffer<uint8_t>>();
        auto sig = info[1].As<Napi::Buffer<uint8_t>>();
        auto pk  = info[2].As<Napi::Buffer<uint8_t>>();
        if (msg.ByteLength() == 0) {
            Napi::RangeError::New(env, "message: at least 1 byte").ThrowAsJavaScriptException();
            return env.Null();
        }
        if (msg.ByteLength() > kMaxReasonableBuffer) {
            Napi::RangeError::New(env, "message: length exceeds safe maximum").ThrowAsJavaScriptException();
            return env.Null();
        }
        NAPI_REQUIRE_BUFFER_EXACT(env, sig, 64, "sig");
        NAPI_REQUIRE_BUFFER_EXACT(env, pk,  32, "ed25519PK");
        bool valid = crypto_sign_ed25519_verify_detached(
            sig.Data(),
            msg.Data(), msg.ByteLength(),
            pk.Data()
        ) == 0;
        return Napi::Boolean::New(env, valid);
    }
    catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

Napi::Value Ed25519PKToX25519(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1) {
        Napi::TypeError::New(env, "Expected (ed25519PK: Buffer)").ThrowAsJavaScriptException();
        return env.Null();
    }
    NAPI_REQUIRE_BUFFER(env, info[0], "ed25519PK");
    auto pk = info[0].As<Napi::Buffer<uint8_t>>();
    NAPI_REQUIRE_BUFFER_EXACT(env, pk, 32, "ed25519PK");

    uint8_t x25519PK[32];
    if (crypto_sign_ed25519_pk_to_curve25519(x25519PK, pk.Data()) != 0) {
        Napi::Error::New(env, "ed25519PKToX25519: conversion failed").ThrowAsJavaScriptException();
        return env.Null();
    }
    return Napi::Buffer<uint8_t>::Copy(env, x25519PK, 32);
}


Napi::Object Init(Napi::Env env, Napi::Object exports) {
    if (sodium_init() < 0) {
        Napi::Error::New(env, "libsodium failed to initialize").ThrowAsJavaScriptException();
        return exports;
    }

    exports.Set("generateKeys",             Napi::Function::New(env, GenerateKeys));
    exports.Set("createHandshake",          Napi::Function::New(env, CreateHandshake));
    exports.Set("verifyHandshake",          Napi::Function::New(env, VerifyHandshake));
    exports.Set("deriveSharedSecret",       Napi::Function::New(env, DeriveSharedSecret));
    exports.Set("deriveTripleSharedSecret", Napi::Function::New(env, DeriveTripleSharedSecret));
    exports.Set("deriveSessionKeys",        Napi::Function::New(env, DeriveSessionKeys));
    exports.Set("buildTranscriptHash",      Napi::Function::New(env, BuildTranscriptHash));
    exports.Set("sign",                     Napi::Function::New(env, Sign));
    exports.Set("tunnelSend",               Napi::Function::New(env, TunnelSend));
    exports.Set("tunnelSendWithNonce",      Napi::Function::New(env, TunnelSendWithNonce));
    exports.Set("tunnelReceive",            Napi::Function::New(env, TunnelReceive));
    exports.Set("verify",                   Napi::Function::New(env, Verify));
    exports.Set("ed25519PKToX25519",        Napi::Function::New(env, Ed25519PKToX25519));
    return exports;
}

NODE_API_MODULE(kiacitunnel, Init)