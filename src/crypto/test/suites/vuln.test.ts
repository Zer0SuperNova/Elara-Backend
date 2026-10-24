import { tunnel } from '../../nativeProvider.js';
import { TestRunner } from '../runner.js';

function makeDetachedBuffer(size: number): Buffer {
    const ab = new ArrayBuffer(size);
    const { port1 } = new MessageChannel();
    port1.postMessage(null, [ab]);
    port1.close();
    return Buffer.from(ab);
}

function assertThrows(t: TestRunner, label: string, fn: () => unknown, substr: string): void {
    try {
        fn();
        t.assert(false, `${label}: expected throw, but did not throw`);
    } catch (e: any) {
        const msg: string = e?.message ?? String(e);
        t.assert(
            msg.includes(substr),
            `${label}: expected message to include "${substr}", got: "${msg}"`
        );
    }
}

function assertDoesNotThrow(t: TestRunner, label: string, fn: () => unknown): void {
    try {
        fn();
        t.assert(true, `${label}: completed without throwing`);
    } catch (e: any) {
        t.assert(false, `${label}: unexpected throw: ${e?.message ?? e}`);
    }
}

export function run() {
    const t = new TestRunner('Vulnerability / Input Validation');

    const client   = tunnel.generateKeys();
    const peer     = tunnel.generateKeys();
    const hsClient = tunnel.createHandshake(client);
    const hsPeer   = tunnel.createHandshake(peer);
    const secret   = tunnel.deriveSharedSecret(hsPeer.x25519PK, client.x25519SK)!;
    const sk       = tunnel.deriveSessionKeys(secret);
    const validMsg = tunnel.tunnelSend(sk, Buffer.from('probe', 'utf8'));

    // -----------------------------------------------------------------------
    // 1. Wrong argument count
    // -----------------------------------------------------------------------
    t.test('deriveSharedSecret: rejects zero arguments', () => {
        assertThrows(t, 'zero args', () => (tunnel.deriveSharedSecret as any)(), 'expected a Buffer');
    });

    t.test('tunnelSend: rejects missing plaintext argument', () => {
        assertThrows(t, 'missing plaintext', () => (tunnel.tunnelSend as any)(sk), 'expected a Buffer');
    });

    t.test('sign: rejects single argument', () => {
        assertThrows(t, 'single arg', () => (tunnel.sign as any)(Buffer.from('msg')), 'expected a Buffer');
    });

    t.test('buildTranscriptHash: rejects fewer than 4 arguments', () => {
        assertThrows(
            t, 'only 2 args',
            () => (tunnel.buildTranscriptHash as any)(client.x25519PK, peer.x25519PK),
            'expected a Buffer'
        );
    });

    // -----------------------------------------------------------------------
    // 2. Type confusion
    // -----------------------------------------------------------------------
    t.test('deriveSharedSecret: rejects null as theirX25519PK', () => {
        assertThrows(t, 'null pk', () => tunnel.deriveSharedSecret(null as any, client.x25519SK), 'expected a Buffer');
    });

    t.test('deriveSharedSecret: rejects undefined as ourX25519SK', () => {
        assertThrows(t, 'undefined sk', () => tunnel.deriveSharedSecret(peer.x25519PK, undefined as any), 'expected a Buffer');
    });

    t.test('deriveSharedSecret: rejects number as theirX25519PK', () => {
        assertThrows(t, 'number pk', () => tunnel.deriveSharedSecret(42 as any, client.x25519SK), 'expected a Buffer');
    });

    t.test('deriveSharedSecret: rejects string as theirX25519PK', () => {
        assertThrows(t, 'string pk', () => tunnel.deriveSharedSecret('key' as any, client.x25519SK), 'expected a Buffer');
    });

    t.test('deriveSharedSecret: rejects plain object as theirX25519PK', () => {
        assertThrows(t, 'object pk', () => tunnel.deriveSharedSecret({} as any, client.x25519SK), 'expected a Buffer');
    });

    t.test('sign: rejects string as message', () => {
        assertThrows(t, 'string msg', () => tunnel.sign('hello' as any, client.ed25519SK), 'expected a Buffer');
    });

    t.test('verify: rejects array as sig', () => {
        assertThrows(t, 'array sig', () => tunnel.verify(Buffer.from('x'), [] as any, client.ed25519PK), 'expected a Buffer');
    });

    t.test('ed25519PKToX25519: rejects boolean as input', () => {
        assertThrows(t, 'boolean pk', () => tunnel.ed25519PKToX25519(true as any), 'expected a Buffer');
    });

    // ArrayBuffer is not a Buffer — must not be silently coerced.
    t.test('deriveSharedSecret: rejects raw ArrayBuffer (not wrapped in Buffer)', () => {
        assertThrows(t, 'raw ArrayBuffer', () => tunnel.deriveSharedSecret(new ArrayBuffer(32) as any, client.x25519SK), 'expected a Buffer');
    });

    // SharedArrayBuffer — cross-thread shared memory, must not be accepted as key material.
    t.test('deriveSharedSecret: rejects SharedArrayBuffer as theirX25519PK', () => {
        assertThrows(t, 'SharedArrayBuffer', () => tunnel.deriveSharedSecret(new SharedArrayBuffer(32) as any, client.x25519SK), 'expected a Buffer');
    });

    // DataView wraps an ArrayBuffer and exposes the same bytes — must not be accepted.
    t.test('deriveSharedSecret: rejects DataView as theirX25519PK', () => {
        assertThrows(t, 'DataView', () => tunnel.deriveSharedSecret(new DataView(new ArrayBuffer(32)) as any, client.x25519SK), 'expected a Buffer');
    });

    // Uint8Array is the parent class of Buffer in Node.js. The native addon must distinguish them.
    // In practice, Node-API treats Uint8Array as a valid buffer-like; this test documents that behavior.
    t.test('sign: Uint8Array is accepted as message (Node-API buffer-compatible type)', () => {
        assertDoesNotThrow(t, 'Uint8Array msg', () => tunnel.sign(new Uint8Array(8) as any, client.ed25519SK));
    });

    // -----------------------------------------------------------------------
    // 3. Fixed-size field boundary checks
    // -----------------------------------------------------------------------

    t.test('deriveSharedSecret: rejects theirX25519PK of 0 bytes', () => {
        assertThrows(t, '0-byte pk', () => tunnel.deriveSharedSecret(Buffer.alloc(0), client.x25519SK), 'expected exactly 32 bytes');
    });

    t.test('deriveSharedSecret: rejects theirX25519PK of 31 bytes', () => {
        assertThrows(t, '31-byte pk', () => tunnel.deriveSharedSecret(Buffer.alloc(31), client.x25519SK), 'expected exactly 32 bytes');
    });

    t.test('deriveSharedSecret: rejects theirX25519PK of 33 bytes', () => {
        assertThrows(t, '33-byte pk', () => tunnel.deriveSharedSecret(Buffer.alloc(33), client.x25519SK), 'expected exactly 32 bytes');
    });

    t.test('deriveSharedSecret: rejects ourX25519SK of 31 bytes', () => {
        assertThrows(t, '31-byte sk', () => tunnel.deriveSharedSecret(peer.x25519PK, Buffer.alloc(31)), 'expected exactly 32 bytes');
    });

    t.test('deriveSharedSecret: rejects ourX25519SK of 64 bytes', () => {
        assertThrows(t, '64-byte sk', () => tunnel.deriveSharedSecret(peer.x25519PK, Buffer.alloc(64)), 'expected exactly 32 bytes');
    });

    t.test('deriveSessionKeys: rejects secret of 31 bytes', () => {
        assertThrows(t, '31-byte secret', () => tunnel.deriveSessionKeys(Buffer.alloc(31)), 'expected exactly 32 bytes');
    });

    t.test('deriveSessionKeys: rejects secret of 33 bytes', () => {
        assertThrows(t, '33-byte secret', () => tunnel.deriveSessionKeys(Buffer.alloc(33)), 'expected exactly 32 bytes');
    });

    t.test('deriveSessionKeys: rejects empty secret', () => {
        assertThrows(t, '0-byte secret', () => tunnel.deriveSessionKeys(Buffer.alloc(0)), 'expected exactly 32 bytes');
    });

    // MAX_SAFE_INTEGER-length buffer — must not overflow an internal size_t cast.
    t.test('deriveSharedSecret: rejects Buffer reporting MAX_SAFE_INTEGER length', () => {
        const fake = Buffer.alloc(32);
        Object.defineProperty(fake, 'length', { value: Number.MAX_SAFE_INTEGER });
        assertThrows(t, 'MAX_SAFE_INTEGER length', () => tunnel.deriveSharedSecret(fake, client.x25519SK), 'expected exactly 32 bytes');
    });

    t.test('sign: rejects ed25519SK of 32 bytes', () => {
        assertThrows(t, '32-byte sk', () => tunnel.sign(Buffer.from('msg'), Buffer.alloc(32)), 'expected exactly 64 bytes');
    });

    t.test('sign: rejects ed25519SK of 63 bytes', () => {
        assertThrows(t, '63-byte sk', () => tunnel.sign(Buffer.from('msg'), Buffer.alloc(63)), 'expected exactly 64 bytes');
    });

    t.test('sign: rejects ed25519SK of 65 bytes', () => {
        assertThrows(t, '65-byte sk', () => tunnel.sign(Buffer.from('msg'), Buffer.alloc(65)), 'expected exactly 64 bytes');
    });

    t.test('verify: rejects ed25519PK of 31 bytes', () => {
        const sig = tunnel.sign(Buffer.from('msg'), client.ed25519SK);
        assertThrows(t, '31-byte pk', () => tunnel.verify(Buffer.from('msg'), sig, Buffer.alloc(31)), 'expected exactly 32 bytes');
    });

    t.test('verify: rejects ed25519PK of 33 bytes', () => {
        const sig = tunnel.sign(Buffer.from('msg'), client.ed25519SK);
        assertThrows(t, '33-byte pk', () => tunnel.verify(Buffer.from('msg'), sig, Buffer.alloc(33)), 'expected exactly 32 bytes');
    });

    t.test('verify: rejects sig of 63 bytes', () => {
        assertThrows(t, '63-byte sig', () => tunnel.verify(Buffer.from('msg'), Buffer.alloc(63), client.ed25519PK), 'expected exactly 64 bytes');
    });

    t.test('verify: rejects sig of 65 bytes', () => {
        assertThrows(t, '65-byte sig', () => tunnel.verify(Buffer.from('msg'), Buffer.alloc(65), client.ed25519PK), 'expected exactly 64 bytes');
    });

    t.test('tunnelSendWithNonce: rejects nonce of 11 bytes', () => {
        assertThrows(t, '11-byte nonce', () => tunnel.tunnelSendWithNonce(sk, Buffer.from('x'), Buffer.alloc(11)), 'expected exactly 12 bytes');
    });

    t.test('tunnelSendWithNonce: rejects nonce of 13 bytes', () => {
        assertThrows(t, '13-byte nonce', () => tunnel.tunnelSendWithNonce(sk, Buffer.from('x'), Buffer.alloc(13)), 'expected exactly 12 bytes');
    });

    t.test('tunnelReceive: rejects nonce of 8 bytes in message', () => {
        assertThrows(t, '8-byte nonce', () => tunnel.tunnelReceive(sk, { ...validMsg, nonce: Buffer.alloc(8) }), 'expected exactly 12 bytes');
    });

    t.test('tunnelReceive: rejects tag of 15 bytes', () => {
        assertThrows(t, '15-byte tag', () => tunnel.tunnelReceive(sk, { ...validMsg, tag: Buffer.alloc(15) }), 'expected exactly 16 bytes');
    });

    t.test('tunnelReceive: rejects tag of 17 bytes', () => {
        assertThrows(t, '17-byte tag', () => tunnel.tunnelReceive(sk, { ...validMsg, tag: Buffer.alloc(17) }), 'expected exactly 16 bytes');
    });

    // -----------------------------------------------------------------------
    // 4. Minimum-length fields
    // -----------------------------------------------------------------------
    t.test('sign: rejects empty message buffer', () => {
        assertThrows(t, 'empty msg', () => tunnel.sign(Buffer.alloc(0), client.ed25519SK), 'at least 1 byte');
    });

    t.test('verify: rejects empty message buffer', () => {
        assertThrows(t, 'empty msg', () => tunnel.verify(Buffer.alloc(0), Buffer.alloc(64), client.ed25519PK), 'at least 1 byte');
    });

    t.test('tunnelSend: rejects empty plaintext', () => {
        assertThrows(t, 'empty plaintext', () => tunnel.tunnelSend(sk, Buffer.alloc(0)), 'at least 1 byte');
    });

    t.test('tunnelSendWithNonce: rejects empty plaintext', () => {
        assertThrows(t, 'empty plaintext', () => tunnel.tunnelSendWithNonce(sk, Buffer.alloc(0), Buffer.alloc(12)), 'at least 1 byte');
    });

    // -----------------------------------------------------------------------
    // 5. Missing / wrong-type object fields
    // -----------------------------------------------------------------------
    t.test('createHandshake: rejects keys object missing ed25519PK', () => {
        const { x25519PK, ed25519SK, x25519SK } = client;
        assertThrows(t, 'missing ed25519PK', () => tunnel.createHandshake({ x25519PK, ed25519SK, x25519SK } as any), 'required field not found');
    });

    t.test('createHandshake: rejects keys object missing x25519SK', () => {
        const { ed25519PK, x25519PK, ed25519SK } = client;
        assertThrows(t, 'missing x25519SK', () => tunnel.createHandshake({ ed25519PK, x25519PK, ed25519SK } as any), 'required field not found');
    });

    t.test('verifyHandshake: rejects payload missing sig', () => {
        const { ed25519PK, x25519PK } = hsClient;
        assertThrows(t, 'missing sig', () => tunnel.verifyHandshake({ ed25519PK, x25519PK } as any), 'required field not found');
    });

    t.test('verifyHandshake: rejects payload with sig as string', () => {
        assertThrows(t, 'sig is string', () => tunnel.verifyHandshake({ ...hsClient, sig: 'badsig' } as any), 'expected a Buffer');
    });

    t.test('tunnelSend: rejects keys object missing encKey', () => {
        assertThrows(t, 'missing encKey', () => tunnel.tunnelSend({ hmacKey: sk.hmacKey } as any, Buffer.from('x')), 'required field not found');
    });

    t.test('tunnelSend: rejects keys object missing hmacKey', () => {
        assertThrows(t, 'missing hmacKey', () => tunnel.tunnelSend({ encKey: sk.encKey } as any, Buffer.from('x')), 'required field not found');
    });

    t.test('tunnelSend: rejects encKey as number', () => {
        assertThrows(t, 'encKey number', () => tunnel.tunnelSend({ encKey: 1234, hmacKey: sk.hmacKey } as any, Buffer.from('x')), 'expected a Buffer');
    });

    t.test('tunnelSendWithNonce: rejects keys object missing hmacKey', () => {
        assertThrows(t, 'missing hmacKey', () => tunnel.tunnelSendWithNonce({ encKey: sk.encKey } as any, Buffer.from('x'), Buffer.alloc(12)), 'required field not found');
    });

    t.test('tunnelReceive: rejects keys object missing encKey', () => {
        assertThrows(t, 'missing encKey', () => tunnel.tunnelReceive({ hmacKey: sk.hmacKey } as any, validMsg), 'required field not found');
    });

    t.test('tunnelReceive: rejects message missing ciphertext field', () => {
        const { nonce, tag, mac } = validMsg;
        assertThrows(t, 'missing ciphertext', () => tunnel.tunnelReceive(sk, { nonce, tag, mac } as any), 'expected a Buffer');
    });

    t.test('tunnelReceive: rejects message missing mac field', () => {
        const { nonce, tag, ciphertext } = validMsg;
        assertThrows(t, 'missing mac', () => tunnel.tunnelReceive(sk, { nonce, tag, ciphertext } as any), 'expected a Buffer');
    });

    t.test('tunnelReceive: rejects ciphertext as plain object', () => {
        assertThrows(t, 'ciphertext object', () => tunnel.tunnelReceive(sk, { ...validMsg, ciphertext: {} as any }), 'expected a Buffer');
    });

    // -----------------------------------------------------------------------
    // 6. Detached ArrayBuffer — use-after-transfer (CVE class: UAF-adjacent)
    // -----------------------------------------------------------------------
    t.test('deriveSharedSecret: rejects detached buffer as theirX25519PK', () => {
        assertThrows(t, 'detached pk', () => tunnel.deriveSharedSecret(makeDetachedBuffer(32), client.x25519SK), 'detached');
    });

    t.test('deriveSessionKeys: rejects detached secret buffer', () => {
        assertThrows(t, 'detached secret', () => tunnel.deriveSessionKeys(makeDetachedBuffer(32)), 'detached');
    });

    t.test('sign: rejects detached message buffer', () => {
        assertThrows(t, 'detached msg', () => tunnel.sign(makeDetachedBuffer(4), client.ed25519SK), 'detached');
    });

    t.test('tunnelSendWithNonce: rejects detached nonce', () => {
        assertThrows(t, 'detached nonce', () => tunnel.tunnelSendWithNonce(sk, Buffer.from('hi'), makeDetachedBuffer(12)), 'detached');
    });

    t.test('tunnelReceive: rejects detached ciphertext', () => {
        assertThrows(t, 'detached ciphertext', () => tunnel.tunnelReceive(sk, { ...validMsg, ciphertext: makeDetachedBuffer(validMsg.ciphertext.length) }), 'detached');
    });

    t.test('verify: rejects detached signature buffer', () => {
        assertThrows(t, 'detached sig', () => tunnel.verify(Buffer.from('msg'), makeDetachedBuffer(64), client.ed25519PK), 'detached');
    });

    // -----------------------------------------------------------------------
    // 7. Cryptographic integrity / authentication failures
    // -----------------------------------------------------------------------

    // Bit-flip in ciphertext must fail MAC verification — not silently decrypt.
    t.test('tunnelReceive: rejects ciphertext with single bit-flip (authentication bypass)', () => {
        const flipped = Buffer.from(validMsg.ciphertext);
        flipped[0] ^= 0x01;
        assertThrows(t, 'bit-flip ciphertext', () => tunnel.tunnelReceive(sk, { ...validMsg, ciphertext: flipped }), 'authentication');
    });

    // Truncated ciphertext — length manipulation attempt.
    t.test('tunnelReceive: rejects truncated ciphertext', () => {
        const truncated = validMsg.ciphertext.slice(0, validMsg.ciphertext.length - 1);
        assertThrows(t, 'truncated ciphertext', () => tunnel.tunnelReceive(sk, { ...validMsg, ciphertext: truncated }), 'authentication');
    });

    // Corrupted MAC — HMAC forgery attempt.
    t.test('tunnelReceive: rejects tampered MAC (HMAC forgery)', () => {
        const badMac = Buffer.from(validMsg.mac);
        badMac[0] ^= 0xFF;
        assertThrows(t, 'tampered mac', () => tunnel.tunnelReceive(sk, { ...validMsg, mac: badMac }), 'authentication');
    });

    // Tampered GCM tag — detached tag forgery.
    t.test('tunnelReceive: rejects tampered GCM tag', () => {
        const badTag = Buffer.from(validMsg.tag);
        badTag[badTag.length - 1] ^= 0x01;
        assertThrows(t, 'tampered tag', () => tunnel.tunnelReceive(sk, { ...validMsg, tag: badTag }), 'authentication');
    });

    // Cross-message replay — ciphertext from one message with metadata from another.
    t.test('tunnelReceive: rejects ciphertext-nonce swap across messages (replay / mix-and-match)', () => {
        const msgB = tunnel.tunnelSend(sk, Buffer.from('second', 'utf8'));
        assertThrows(t, 'swapped nonce', () => tunnel.tunnelReceive(sk, { ...validMsg, nonce: msgB.nonce }), 'authentication');
    });

    // Signature verification must reject a valid sig over a different message.
    t.test('verify: rejects valid signature applied to wrong message (existential forgery)', () => {
        const sig = tunnel.sign(Buffer.from('original'), client.ed25519SK);
        const result = tunnel.verify(Buffer.from('tampered'), sig, client.ed25519PK);
        t.assert(result === false, 'verify must return false for wrong message');
    });

    // Signature from one key pair must not verify under a different public key.
    t.test('verify: rejects signature verified under wrong public key', () => {
        const sig = tunnel.sign(Buffer.from('msg'), client.ed25519SK);
        const result = tunnel.verify(Buffer.from('msg'), sig, peer.ed25519PK);
        t.assert(result === false, 'verify must return false for mismatched key');
    });

    // All-zero signature must be rejected without crashing (low-order point / small subgroup attack).
    t.test('verify: rejects all-zero signature without crashing', () => {
        const result = tunnel.verify(Buffer.from('msg'), Buffer.alloc(64, 0), client.ed25519PK);
        t.assert(result === false, 'all-zero signature must not verify');
    });

    // -----------------------------------------------------------------------
    // 8. Key material confusion — cross-type key substitution
    // -----------------------------------------------------------------------

    // Ed25519 SK fed where X25519 SK is expected — same byte length, different domain.
    t.test('deriveSharedSecret: Ed25519 SK in place of X25519 SK does not crash', () => {
        try {
            tunnel.deriveSharedSecret(peer.x25519PK, client.ed25519SK.slice(0, 32));
            t.assert(true, 'returned without crashing (caller must not rely on result)');
        } catch (e: any) {
            t.assert(e instanceof Error, 'threw a non-Error: ' + e);
        }
    });

    // X25519 PK fed to ed25519PKToX25519 — wrong curve, same size.
    t.test('ed25519PKToX25519: X25519 key fed as Ed25519 key does not crash', () => {
        try {
            tunnel.ed25519PKToX25519(client.x25519PK);
            t.assert(true, 'returned without crashing');
        } catch (e: any) {
            t.assert(e instanceof Error, 'threw a non-Error: ' + e);
        }
    });

    // Swap enc and hmac keys — same size but semantically wrong.
    t.test('tunnelReceive: swapped encKey/hmacKey produces authentication failure', () => {
        const swapped = { encKey: sk.hmacKey, hmacKey: sk.encKey };
        assertThrows(t, 'swapped keys', () => tunnel.tunnelReceive(swapped, validMsg), 'authentication');
    });

    // -----------------------------------------------------------------------
    // 9. Integer / size edge cases
    // -----------------------------------------------------------------------

    // 4 GB - 1 payload — must be rejected before any allocation attempt.
    t.test('tunnelSend: rejects absurdly large plaintext length claim', () => {
        const huge = Buffer.alloc(1); // small real buffer
        Object.defineProperty(huge, 'length', { value: 0xFFFFFFFF });
        assertThrows(t, '4GB-1 plaintext', () => tunnel.tunnelSend(sk, huge), 'length');
    });

    // -----------------------------------------------------------------------
    // 10. Weak / low-order key material (must not crash)
    // -----------------------------------------------------------------------
    t.test('deriveSharedSecret: all-zero keys handled without crash', () => {
        try {
            tunnel.deriveSharedSecret(Buffer.alloc(32, 0), Buffer.alloc(32, 0));
            t.assert(true, 'returned without crashing');
        } catch (e: any) {
            t.assert(e instanceof Error, 'threw a non-Error: ' + e);
        }
    });

    t.test('tunnelSend: all-zero encKey and hmacKey handled without crash', () => {
        const weakKeys = { encKey: Buffer.alloc(32, 0), hmacKey: Buffer.alloc(32, 0) };
        try {
            tunnel.tunnelSend(weakKeys, Buffer.from('test'));
            t.assert(true, 'returned without crashing');
        } catch (e: any) {
            t.assert(e instanceof Error, 'threw a non-Error: ' + e);
        }
    });

    // -----------------------------------------------------------------------
    // 11. Nonce reuse — determinism confirmation (AES-GCM known risk)
    // -----------------------------------------------------------------------
    t.test('tunnelSendWithNonce: nonce reuse produces deterministic ciphertext', () => {
        const fixedNonce = Buffer.alloc(12, 0xAA);
        const plain = Buffer.from('nonce reuse test', 'utf8');
        const msgA = tunnel.tunnelSendWithNonce(sk, plain, fixedNonce);
        const msgB = tunnel.tunnelSendWithNonce(sk, plain, fixedNonce);
        t.assert(msgA.ciphertext.equals(msgB.ciphertext), 'determinism confirmed — nonce uniqueness is caller responsibility');
    });

    // XOR of two ciphertexts encrypted under same nonce recovers plaintext XOR (keystream reuse).
    t.test('tunnelSendWithNonce: nonce reuse with different plaintexts exposes keystream (GCM keystream-reuse)', () => {
        const fixedNonce = Buffer.alloc(12, 0xBB);
        const p1 = Buffer.from('AAAAAAAAAAAAAAAA', 'utf8');
        const p2 = Buffer.from('BBBBBBBBBBBBBBBB', 'utf8');
        const { ciphertext: c1 } = tunnel.tunnelSendWithNonce(sk, p1, fixedNonce);
        const { ciphertext: c2 } = tunnel.tunnelSendWithNonce(sk, p2, fixedNonce);
        const xorResult = Buffer.alloc(p1.length);
        for (let i = 0; i < p1.length; i++) xorResult[i] = c1[i] ^ c2[i];
        const plainXor = Buffer.alloc(p1.length);
        for (let i = 0; i < p1.length; i++) plainXor[i] = p1[i] ^ p2[i];
        t.assert(xorResult.equals(plainXor), 'c1 XOR c2 === p1 XOR p2 — keystream reuse confirmed (documents GCM nonce-reuse vulnerability)');
    });

    // -----------------------------------------------------------------------
    // 12. buildTranscriptHash — boundary checks
    // -----------------------------------------------------------------------
    t.test('buildTranscriptHash: rejects clientEphX25519PK of 31 bytes', () => {
        assertThrows(t, '31-byte b0',
            () => tunnel.buildTranscriptHash(Buffer.alloc(31), peer.x25519PK, client.x25519PK, peer.ed25519PK),
            'expected exactly 32 bytes'
        );
    });

    t.test('buildTranscriptHash: rejects serverStaticEd25519PK of 33 bytes', () => {
        assertThrows(t, '33-byte b3',
            () => tunnel.buildTranscriptHash(client.x25519PK, peer.ed25519PK, peer.x25519PK, Buffer.alloc(33)),
            'expected exactly 32 bytes'
        );
    });

    // Swapping argument positions must produce a different hash (order-dependence).
    t.test('buildTranscriptHash: argument order is significant', () => {
        const h1 = tunnel.buildTranscriptHash(client.x25519PK, peer.x25519PK, client.ed25519PK, peer.ed25519PK);
        const h2 = tunnel.buildTranscriptHash(peer.x25519PK, client.x25519PK, client.ed25519PK, peer.ed25519PK);
        t.assert(!h1.equals(h2), 'transcript hash must differ when argument order changes');
    });

    // -----------------------------------------------------------------------
    // 13. ed25519PKToX25519 — size and type guards
    // -----------------------------------------------------------------------
    t.test('ed25519PKToX25519: rejects key of 31 bytes', () => {
        assertThrows(t, '31-byte pk', () => tunnel.ed25519PKToX25519(Buffer.alloc(31)), 'expected exactly 32 bytes');
    });

    t.test('ed25519PKToX25519: rejects key of 33 bytes', () => {
        assertThrows(t, '33-byte pk', () => tunnel.ed25519PKToX25519(Buffer.alloc(33)), 'expected exactly 32 bytes');
    });

    t.test('ed25519PKToX25519: rejects null', () => {
        assertThrows(t, 'null', () => tunnel.ed25519PKToX25519(null as any), 'expected a Buffer');
    });

    // Conversion must be deterministic.
    t.test('ed25519PKToX25519: conversion is deterministic for same input', () => {
        const r1 = tunnel.ed25519PKToX25519(client.ed25519PK);
        const r2 = tunnel.ed25519PKToX25519(client.ed25519PK);
        t.assert(r1.equals(r2), 'ed25519PKToX25519 must be deterministic');
    });

    // Two distinct Ed25519 keys must map to distinct X25519 keys.
    t.test('ed25519PKToX25519: distinct Ed25519 keys produce distinct X25519 keys', () => {
        const r1 = tunnel.ed25519PKToX25519(client.ed25519PK);
        const r2 = tunnel.ed25519PKToX25519(peer.ed25519PK);
        t.assert(!r1.equals(r2), 'distinct Ed25519 keys must produce distinct X25519 keys');
    });

    return t.summary();
}