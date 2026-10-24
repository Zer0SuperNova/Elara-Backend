// src/crypto/nativeProvider.ts
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const native = require('./module/build/bin/cryptomodule.node');

export interface Keys {
    ed25519PK: Buffer;
    x25519PK:  Buffer;
    ed25519SK: Buffer;
    x25519SK:  Buffer;
}

export interface HandshakePayload {
    ed25519PK: Buffer;
    x25519PK:  Buffer;
    sig:       Buffer;
}

export interface SessionKeys   { encKey: Buffer; hmacKey: Buffer; }
export interface TunnelMessage { nonce: Buffer; tag: Buffer; ciphertext: Buffer; mac: Buffer; }

// exported APIs from native module
export const tunnel = {
    generateKeys(): Keys                                              { return native.generateKeys(); },
    createHandshake(keys: Keys): HandshakePayload                    { return native.createHandshake(keys); },
    verifyHandshake(payload: HandshakePayload): boolean              { return native.verifyHandshake(payload); },
    deriveSharedSecret(theirPK: Buffer, ourSK: Buffer): Buffer|null  { return native.deriveSharedSecret(theirPK, ourSK); },
    deriveSessionKeys(secret: Buffer): SessionKeys                   { return native.deriveSessionKeys(secret); },
    sign(message: Buffer, ed25519SK: Buffer): Buffer                 { return native.sign(message, ed25519SK); },
    verify(message: Buffer, sig: Buffer, ed25519PK: Buffer): boolean { return native.verify(message, sig, ed25519PK); },
    tunnelSend(keys: SessionKeys, plaintext: Buffer): TunnelMessage       { return native.tunnelSend(keys, plaintext); },
    tunnelReceive(keys: SessionKeys, msg: TunnelMessage): Buffer|null     { return native.tunnelReceive(keys, msg); },
    ed25519PKToX25519(ed25519PK: Buffer): Buffer { return native.ed25519PKToX25519(ed25519PK); },
    deriveTripleSharedSecret(dh1: Buffer, dh2: Buffer, dh3: Buffer): Buffer { return native.deriveTripleSharedSecret(dh1, dh2, dh3); },
    buildTranscriptHash(clientEphPK: Buffer, clientStaticPK: Buffer, serverEphPK: Buffer, serverStaticPK: Buffer): Buffer {
        return native.buildTranscriptHash(clientEphPK, clientStaticPK, serverEphPK, serverStaticPK);
    },
    tunnelSendWithNonce(keys: SessionKeys, plaintext: Buffer, nonce: Buffer): TunnelMessage { return native.tunnelSendWithNonce(keys, plaintext, nonce); },
};