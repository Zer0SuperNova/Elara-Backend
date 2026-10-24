import { tunnel }     from '../../nativeProvider.js';
import { TestRunner } from '../runner.js';

export function run() {
    const t = new TestRunner('Tunnel');

    const clientOne = tunnel.generateKeys();
    const clientTwo = tunnel.generateKeys();
    const hsOne     = tunnel.createHandshake(clientOne);
    const hsTwo     = tunnel.createHandshake(clientTwo);
    const secretOne = tunnel.deriveSharedSecret(hsTwo.x25519PK, clientOne.x25519SK)!;
    const secretTwo = tunnel.deriveSharedSecret(hsOne.x25519PK, clientTwo.x25519SK)!;
    const keysOne   = tunnel.deriveSessionKeys(secretOne);
    const keysTwo   = tunnel.deriveSessionKeys(secretTwo);

    t.test('encrypt/decrypt roundtrip', () => {
        const plain     = Buffer.from('ping', 'utf8');
        const msg       = tunnel.tunnelSend(keysOne, plain);
        const decrypted = tunnel.tunnelReceive(keysTwo, msg);
        t.assert(decrypted !== null && decrypted.equals(plain), 'decrypted output does not match plaintext');
    });

    t.test('encrypt/decrypt large payload', () => {
        const plain     = Buffer.alloc(64_000, 0xAB);
        const msg       = tunnel.tunnelSend(keysOne, plain);
        const decrypted = tunnel.tunnelReceive(keysTwo, msg);
        t.assert(decrypted !== null && decrypted.equals(plain), 'large payload roundtrip failed');
    });

    t.test('ciphertext differs from plaintext', () => {
        const plain = Buffer.from('secret message', 'utf8');
        const msg   = tunnel.tunnelSend(keysOne, plain);
        t.assert(!msg.ciphertext.equals(plain), 'ciphertext should not equal plaintext');
    });

    t.test('nonce is unique per message', () => {
        const plain = Buffer.from('test', 'utf8');
        const msgA  = tunnel.tunnelSend(keysOne, plain);
        const msgB  = tunnel.tunnelSend(keysOne, plain);
        t.assert(!msgA.nonce.equals(msgB.nonce), 'nonces should be unique per message');
    });

    t.test('tampered ciphertext is rejected', () => {
        const plain    = Buffer.from('test', 'utf8');
        const msg      = tunnel.tunnelSend(keysOne, plain);
        const tampered = { ...msg, ciphertext: Buffer.from(msg.ciphertext) };
        tampered.ciphertext[0] ^= 0xFF;
        try {
            tunnel.tunnelReceive(keysTwo, tampered);
            t.assert(false, 'tampered ciphertext should have thrown');
        } catch (e) {
            t.assert(
                e instanceof Error && e.message.includes('decryption failed'),
                'unexpected error: ' + e
            );
        }
    });

    t.test('tampered tag is rejected', () => {
        const plain    = Buffer.from('test', 'utf8');
        const msg      = tunnel.tunnelSend(keysOne, plain);
        const tampered = { ...msg, tag: Buffer.from(msg.tag) };
        tampered.tag[0] ^= 0xFF;
        try {
            tunnel.tunnelReceive(keysTwo, tampered);
            t.assert(false, 'tampered tag should have thrown');
        } catch (e) {
            t.assert(
                e instanceof Error && e.message.includes('decryption failed'),
                'unexpected error: ' + e
            );
        }
    });

    t.test('tampered MAC is rejected', () => {
        const plain    = Buffer.from('test', 'utf8');
        const msg      = tunnel.tunnelSend(keysOne, plain);
        const tampered = { ...msg, mac: Buffer.from(msg.mac) };
        tampered.mac[0] ^= 0xFF;
        try {
            tunnel.tunnelReceive(keysTwo, tampered);
            t.assert(false, 'tampered MAC should have thrown');
        } catch (e) {
            t.assert(
                e instanceof Error && e.message.includes('decryption failed'),
                'unexpected error: ' + e
            );
        }
    });

    t.test('wrong keys cannot decrypt', () => {
        const plain       = Buffer.from('test', 'utf8');
        const msg         = tunnel.tunnelSend(keysOne, plain);
        const clientThree = tunnel.generateKeys();
        const hsThree     = tunnel.createHandshake(clientThree);
        const wrongSecret = tunnel.deriveSharedSecret(hsThree.x25519PK, clientOne.x25519SK)!;
        const wrongKeys   = tunnel.deriveSessionKeys(wrongSecret);
        try {
            tunnel.tunnelReceive(wrongKeys, msg);
            t.assert(false, 'wrong keys should have thrown');
        } catch (e) {
            t.assert(
                e instanceof Error && e.message.includes('decryption failed'),
                'unexpected error: ' + e
            );
        }
    });

    return t.summary();
}