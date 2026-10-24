#pragma once

//===----------------------------------------------------------------------===//
///
/// ValidateBuffer.h
/// Compile-time and runtime guards for NAPI Buffer arguments.
///
/// Every check throws a typed JS exception and returns env.Null()
/// to the caller, so no further code in the calling function executes.
///
/// Macro families:
///
///   NAPI_REQUIRE_BUFFER(env, val, label)
///     Asserts a Napi::Value is a Buffer (not detached).
///     Call this before any .As<Napi::Buffer<uint8_t>>() cast.
///
///   NAPI_REQUIRE_BUFFER_EXACT(env, buf, expected, label)
///     Asserts buf.ByteLength() == expected.
///     Use for fixed-size cryptographic keys, nonces, tags, and signatures.
///
///   NAPI_REQUIRE_BUFFER_RANGE(env, buf, lo, hi, label)
///     Asserts lo <= buf.ByteLength() <= hi.
///     Use for variable-length payloads with sensible bounds.
///
///   NAPI_REQUIRE_BUFFER_MIN(env, buf, min, label)
///     Asserts buf.ByteLength() >= min.
///
///   NAPI_REQUIRE_SAFE_SIZE(env, a, b, label)
///     Asserts a + b does not exceed SIZE_MAX.
///     Use before any size arithmetic that feeds an allocation or memcpy.
///
///   NAPI_REQUIRE_OBJECT_BUFFER_EXACT(env, obj, field, dest, expected)
///     Extracts a named Buffer field, asserts exact size, and memcpy's to dest.
///     Emits a clear "required field not found" error if the field is absent,
///     distinct from a wrong-type error.
///
/// Inline helper:
///
///   ValidateBuffer(env, val, expected, label)
///     Bool-returning equivalent of NAPI_REQUIRE_BUFFER + NAPI_REQUIRE_BUFFER_EXACT.
///     Use when a conditional check is needed instead of an early return.
///     NOTE: rejects expected == 0 as a safety guard against accidental
///     zero-size crypto buffers.
///
//===----------------------------------------------------------------------===//

#include <napi.h>
#include <cstddef>
#include <cstring>
#include <limits>

namespace detail {

/// Returns the JS type name of val for use in error messages.
inline std::string NapiTypeName(const Napi::Value& v) {
    if (v.IsNull())      return "null";
    if (v.IsUndefined()) return "undefined";
    if (v.IsNumber())    return "number";
    if (v.IsString())    return "string";
    if (v.IsBoolean())   return "boolean";
    if (v.IsBuffer())    return "Buffer";
    if (v.IsArray())     return "Array";
    if (v.IsObject())    return "object";
    return "unknown";
}

/// Returns true if the ArrayBuffer backing a Buffer value has been detached.
///
/// Node.js Buffers are Uint8Array TypedArrays internally, so we resolve the
/// backing ArrayBuffer via napi_get_buffer_info, then test it with
/// napi_is_detached_arraybuffer.  Using napi_get_typedarray_info here would
/// be semantically wrong (Buffers are not plain TypedArrays at the API level)
/// and was the previous implementation's flaw.
///
/// NOTE: In some Node.js versions a detached Buffer may already fail
/// IsBuffer(); this check is a belt-and-suspenders guard for runtimes where
/// that is not guaranteed.
inline bool IsDetachedBuffer(const Napi::Value& val) {
    void*  data   = nullptr;
    size_t length = 0;
    napi_value backing = nullptr;

    // Resolve raw data pointer and byte length from the Buffer.
    napi_status st = napi_get_buffer_info(
        val.Env(), static_cast<napi_value>(val),
        &data, &length
    );
    if (st != napi_ok) return true; // conservatively reject on unexpected failure

    // Obtain the underlying ArrayBuffer handle.
    // napi_get_typedarray_info works on the Uint8Array layer of the Buffer
    // and gives us the backing napi_value we need for the detach test.
    napi_status st2 = napi_get_typedarray_info(
        val.Env(), static_cast<napi_value>(val),
        nullptr, nullptr, nullptr, &backing, nullptr
    );
    if (st2 != napi_ok || backing == nullptr) return true;

    bool detached = false;
    napi_is_detached_arraybuffer(val.Env(), backing, &detached);
    return detached;
}

} 


/// Assert val is a non-detached Buffer. Call before any .As<Napi::Buffer<T>>().
///
/// Two-stage check:
///   1. IsBuffer() — type guard, handles undefined/null/wrong-type gracefully.
///   2. IsDetachedBuffer() — detach guard.  In most Node.js versions a
///      detached buffer will already fail IsBuffer(), but this second check
///      is retained for runtimes where that is not guaranteed.
/// NOTE: This macro returns env.Null() on failure, so it must be used in a function
#define NAPI_REQUIRE_BUFFER(env, val, label)                                    \
    do {                                                                        \
        if (!(val).IsBuffer()) {                                                \
            Napi::TypeError::New((env),                                         \
                std::string(label) + ": expected a Buffer, got " +             \
                detail::NapiTypeName(val))                                      \
                .ThrowAsJavaScriptException();                                  \
            return (env).Null();                                                \
        }                                                                       \
        if (detail::IsDetachedBuffer(val)) {                                   \
            Napi::TypeError::New((env),                                         \
                std::string(label) + ": detached ArrayBuffer is not permitted")\
                .ThrowAsJavaScriptException();                                  \
            return (env).Null();                                                \
        }                                                                       \
    } while (0)


/// Assert buf.ByteLength() == expected. Use for fixed-size keys, nonces, tags, signatures.
#define NAPI_REQUIRE_BUFFER_EXACT(env, buf, expected, label)                    \
    do {                                                                        \
        const size_t _got = (buf).ByteLength();                                \
        const size_t _exp = static_cast<size_t>(expected);                     \
        if (_got != _exp) {                                                     \
            Napi::RangeError::New((env),                                        \
                std::string(label) + ": expected exactly " +                   \
                std::to_string(_exp) + " bytes, got " +                        \
                std::to_string(_got))                                           \
                .ThrowAsJavaScriptException();                                  \
            return (env).Null();                                                \
        }                                                                       \
    } while (0)


/// Assert lo <= buf.ByteLength() <= hi.
#define NAPI_REQUIRE_BUFFER_RANGE(env, buf, lo, hi, label)                      \
    do {                                                                        \
        const size_t _got = (buf).ByteLength();                                \
        const size_t _lo  = static_cast<size_t>(lo);                           \
        const size_t _hi  = static_cast<size_t>(hi);                           \
        if (_got < _lo || _got > _hi) {                                        \
            Napi::RangeError::New((env),                                        \
                std::string(label) + ": expected " +                           \
                std::to_string(_lo) + "\u2013" + std::to_string(_hi) +        \
                " bytes, got " + std::to_string(_got))                         \
                .ThrowAsJavaScriptException();                                  \
            return (env).Null();                                                \
        }                                                                       \
    } while (0)


/// Assert buf.ByteLength() >= min.
#define NAPI_REQUIRE_BUFFER_MIN(env, buf, min, label)                           \
    do {                                                                        \
        const size_t _got = (buf).ByteLength();                                \
        const size_t _min = static_cast<size_t>(min);                          \
        if (_got < _min) {                                                      \
            Napi::RangeError::New((env),                                        \
                std::string(label) + ": expected at least " +                  \
                std::to_string(_min) + " bytes, got " +                        \
                std::to_string(_got))                                           \
                .ThrowAsJavaScriptException();                                  \
            return (env).Null();                                                \
        }                                                                       \
    } while (0)


/// Assert a + b does not overflow size_t. Use before allocation or memcpy sizing.
#define NAPI_REQUIRE_SAFE_SIZE(env, a, b, label)                                \
    do {                                                                        \
        const size_t _a = static_cast<size_t>(a);                              \
        const size_t _b = static_cast<size_t>(b);                              \
        if (_b > 0 && _a > std::numeric_limits<size_t>::max() - _b) {         \
            Napi::RangeError::New((env),                                        \
                std::string(label) + ": size arithmetic overflow (" +          \
                std::to_string(_a) + " + " + std::to_string(_b) + ")")        \
                .ThrowAsJavaScriptException();                                  \
            return (env).Null();                                                \
        }                                                                       \
    } while (0)


/// Extract a named Buffer field from obj, assert exact size, and memcpy to dest.
///
/// Emits a distinct "required field not found" TypeError when the field is
/// absent (undefined), rather than the generic "expected a Buffer, got
/// undefined" message that NAPI_REQUIRE_BUFFER alone would produce.
///
/// Usage: NAPI_REQUIRE_OBJECT_BUFFER_EXACT(env, obj, "ed25519PK", dest, 32);
#define NAPI_REQUIRE_OBJECT_BUFFER_EXACT(env, obj, field, dest, expected)       \
    do {                                                                        \
        Napi::Value _fv = (obj).Get(field);                                    \
        if (_fv.IsUndefined()) {                                                \
            Napi::TypeError::New((env),                                         \
                std::string(field) + ": required field not found")             \
                .ThrowAsJavaScriptException();                                  \
            return (env).Null();                                                \
        }                                                                       \
        NAPI_REQUIRE_BUFFER(env, _fv, field);                                  \
        auto _fb = _fv.As<Napi::Buffer<uint8_t>>();                            \
        NAPI_REQUIRE_BUFFER_EXACT(env, _fb, expected, field);                  \
        std::memcpy((dest), _fb.Data(), static_cast<size_t>(expected));        \
    } while (0)


/// Bool-returning validation for use in conditional expressions.
/// Throws a typed JS exception and returns false on any failure.
/// Use when an early macro return is not appropriate.
///
/// Rejects expected == 0 as a safety guard: accepting a zero-length buffer
/// in a cryptographic context is almost certainly a bug (e.g. sizeof on an
/// empty struct), and silently passing such values downstream is dangerous.
inline bool ValidateBuffer(Napi::Env env, Napi::Value val,
                           size_t expected, const char* label) {
    if (expected == 0) {
        Napi::RangeError::New(env,
            std::string(label) + ": expected size is 0, which is not permitted "
            "for cryptographic buffers — likely a sizeof() error")
            .ThrowAsJavaScriptException();
        return false;
    }
    if (!val.IsBuffer()) {
        Napi::TypeError::New(env,
            std::string(label) + ": expected a Buffer, got " +
            detail::NapiTypeName(val))
            .ThrowAsJavaScriptException();
        return false;
    }
    if (detail::IsDetachedBuffer(val)) {
        Napi::TypeError::New(env,
            std::string(label) + ": detached ArrayBuffer is not permitted")
            .ThrowAsJavaScriptException();
        return false;
    }
    const size_t got = val.As<Napi::Buffer<uint8_t>>().ByteLength();
    if (got != expected) {
        Napi::RangeError::New(env,
            std::string(label) + ": expected exactly " +
            std::to_string(expected) + " bytes, got " + std::to_string(got))
            .ThrowAsJavaScriptException();
        return false;
    }
    return true;
}