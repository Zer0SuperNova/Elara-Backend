const NONCE_LEN      = 12;                 // 96-bit nonce  (AES-GCM, fixed)
const TAG_LEN        = 16;                 // 128-bit GCM auth tag (fixed)
const MIN_MAC_LEN    = 32;                 // HMAC-SHA-256 minimum  — tighten if suite is pinned
const MAX_MAC_LEN    = 64;                 // HMAC-SHA-512 ceiling  — must fit UInt8  (≤ 0xFF)
const MAX_CIPHER_LEN = 16 * 1024 * 1024;  // 16 MiB hard cap       — must fit UInt32 (≤ 0xFFFF_FFFF)

// Wire layout: [nonceLen u8][tagLen u8][macLen u8][cipherLen u32be] | nonce | tag | mac | ciphertext
const NONCE_LEN_OFF  = 0;
const TAG_LEN_OFF    = 1;
const MAC_LEN_OFF    = 2;
const CIPHER_LEN_OFF = 3;                  // u32be occupies bytes 3-6
const HEADER_LEN     = CIPHER_LEN_OFF + 4; // 7 bytes — derived, not a separate literal

if (MAX_MAC_LEN > 0xFF) {
  throw new Error(`MAX_MAC_LEN (${MAX_MAC_LEN}) overflows its UInt8 wire field (max 255)`);
}
if (MAX_CIPHER_LEN > 0xFFFF_FFFF) {
  throw new Error(`MAX_CIPHER_LEN (${MAX_CIPHER_LEN}) overflows its UInt32 wire field (max 4 294 967 295)`);
}
if (MIN_MAC_LEN < 1 || MIN_MAC_LEN > MAX_MAC_LEN) {
  throw new Error(`MIN_MAC_LEN (${MIN_MAC_LEN}) must be between 1 and MAX_MAC_LEN (${MAX_MAC_LEN})`);
}
// ─────────────────────────────────────────────────────────────────────────────────────────────

/**
 * Rejects Buffers backed by SharedArrayBuffer.
 *
 * Buffer.isBuffer() returns true for shared-memory-backed Buffers, but those
 * can be mutated by another thread between the header-validation step and the
 * slice step (TOCTOU). We reject them outright rather than copying eagerly,
 * because the copy itself would still race on multi-byte reads.
 */
function assertNotShared(buf: Buffer, label: string): void {
  if (buf.buffer instanceof SharedArrayBuffer) {
    throw new TypeError(
      `${label}: SharedArrayBuffer-backed Buffers are not permitted (TOCTOU hazard)`,
    );
  }
}

/**
 * Decodes a binary frame into its constituent cryptographic fields.
 *
 * Wire layout (7-byte header followed by payload fields in order):
 *   [nonceLen u8][tagLen u8][macLen u8][cipherLen u32be] | nonce | tag | mac | ciphertext
 *
 * @remarks
 *   **MAC authenticity is NOT verified here.** The caller is responsible for
 *   verifying `mac` over the appropriate data before trusting or using
 *   `nonce` or `ciphertext`. Returning the fields without verification is
 *   intentional: this function does not have access to the HMAC key.
 *
 * @throws {TypeError}   if `buf` is not a Buffer, or is SharedArrayBuffer-backed.
 * @throws {RangeError}  if any length field is out of protocol range, or if
 *                       the total frame length does not match exactly.
 */
export function decodeFrame(buf: Buffer): {
  nonce: Buffer;
  tag: Buffer;
  mac: Buffer;
  ciphertext: Buffer;
} {

  if (!Buffer.isBuffer(buf)) {
    throw new TypeError(`decodeFrame: argument must be a Buffer (got ${Object.prototype.toString.call(buf)})`);
  }

  assertNotShared(buf, 'decodeFrame');

  if (buf.length < HEADER_LEN) {
    throw new RangeError(`Frame too short for header: need ${HEADER_LEN} bytes, got ${buf.length}`);
  }

  const nonceLen  = buf.readUInt8(NONCE_LEN_OFF);
  const tagLen    = buf.readUInt8(TAG_LEN_OFF);
  const macLen    = buf.readUInt8(MAC_LEN_OFF);
  const cipherLen = buf.readUInt32BE(CIPHER_LEN_OFF);


  if (nonceLen !== NONCE_LEN) {
    throw new RangeError(`Invalid nonce length: expected ${NONCE_LEN}, got ${nonceLen}`);
  }
  if (tagLen !== TAG_LEN) {
    throw new RangeError(`Invalid tag length: expected ${TAG_LEN}, got ${tagLen}`);
  }
  if (macLen < MIN_MAC_LEN || macLen > MAX_MAC_LEN) {
    throw new RangeError(`Invalid MAC length: ${macLen} (must be ${MIN_MAC_LEN}–${MAX_MAC_LEN})`);
  }
  if (cipherLen === 0 || cipherLen > MAX_CIPHER_LEN) {
    throw new RangeError(`Invalid ciphertext length: ${cipherLen} (must be 1–${MAX_CIPHER_LEN})`);
  }

  const expectedTotal = HEADER_LEN + nonceLen + tagLen + macLen + cipherLen;
  if (buf.length !== expectedTotal) {
    throw new RangeError(
      `Frame length mismatch: expected ${expectedTotal} bytes, got ${buf.length}`,
    );
  }

  let offset = HEADER_LEN;
  const nonce      = Buffer.from(buf.subarray(offset, offset + nonceLen));  offset += nonceLen;
  const tag        = Buffer.from(buf.subarray(offset, offset + tagLen));    offset += tagLen;
  const mac        = Buffer.from(buf.subarray(offset, offset + macLen));    offset += macLen;
  const ciphertext = Buffer.from(buf.subarray(offset, offset + cipherLen)); offset += cipherLen;

  if (offset !== buf.length) {
    throw new RangeError(`decodeFrame: internal offset mismatch (${offset} !== ${buf.length})`);
  }

  return { nonce, tag, mac, ciphertext };
}

/**
 * Encodes cryptographic fields into a binary frame.
 *
 * Wire layout (7-byte header followed by payload fields in order):
 *   [nonceLen u8][tagLen u8][macLen u8][cipherLen u32be] | nonce | tag | mac | ciphertext
 *
 * @throws {TypeError}   if any argument is not a Buffer, or is SharedArrayBuffer-backed.
 * @throws {RangeError}  if any length field is out of protocol range.
 */
export function encodeFrame(
  nonce: Buffer,
  tag: Buffer,
  mac: Buffer,
  ciphertext: Buffer,
): Buffer {
  if (!Buffer.isBuffer(nonce))      throw new TypeError('encodeFrame: nonce must be a Buffer');
  if (!Buffer.isBuffer(tag))        throw new TypeError('encodeFrame: tag must be a Buffer');
  if (!Buffer.isBuffer(mac))        throw new TypeError('encodeFrame: mac must be a Buffer');
  if (!Buffer.isBuffer(ciphertext)) throw new TypeError('encodeFrame: ciphertext must be a Buffer');

  assertNotShared(nonce,      'encodeFrame: nonce');
  assertNotShared(tag,        'encodeFrame: tag');
  assertNotShared(mac,        'encodeFrame: mac');
  assertNotShared(ciphertext, 'encodeFrame: ciphertext');

  if (nonce.length !== NONCE_LEN) {
    throw new RangeError(`Invalid nonce length: expected ${NONCE_LEN}, got ${nonce.length}`);
  }
  if (tag.length !== TAG_LEN) {
    throw new RangeError(`Invalid tag length: expected ${TAG_LEN}, got ${tag.length}`);
  }
  if (mac.length < MIN_MAC_LEN || mac.length > MAX_MAC_LEN) {
    throw new RangeError(`Invalid MAC length: ${mac.length} (must be ${MIN_MAC_LEN}–${MAX_MAC_LEN})`);
  }
  if (ciphertext.length === 0 || ciphertext.length > MAX_CIPHER_LEN) {
    throw new RangeError(
      `Invalid ciphertext length: ${ciphertext.length} (must be 1–${MAX_CIPHER_LEN})`,
    );
  }

  const header = Buffer.allocUnsafe(HEADER_LEN);
  header.writeUInt8(nonce.length,         NONCE_LEN_OFF);
  header.writeUInt8(tag.length,           TAG_LEN_OFF);
  header.writeUInt8(mac.length,           MAC_LEN_OFF);
  header.writeUInt32BE(ciphertext.length, CIPHER_LEN_OFF);

  return Buffer.concat([header, nonce, tag, mac, ciphertext]);
}