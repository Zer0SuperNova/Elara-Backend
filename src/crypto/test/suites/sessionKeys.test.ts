import { tunnel }     from '../../nativeProvider.js';
import { TestRunner } from '../runner.js';

export function run() {
    const t = new TestRunner('Session Keys');

    const clientOne = tunnel.generateKeys();
    const clientTwo = tunnel.generateKeys();

    const hsOne = tunnel.createHandshake(clientOne);
    const hsTwo = tunnel.createHandshake(clientTwo);

    const secretOne = tunnel.deriveSharedSecret(hsTwo.x25519PK, clientOne.x25519SK)!;
    const secretTwo = tunnel.deriveSharedSecret(hsOne.x25519PK, clientTwo.x25519SK)!;

    const keysOne = tunnel.deriveSessionKeys(secretOne);
    const keysTwo = tunnel.deriveSessionKeys(secretTwo);

    t.test('encryption keys match across peers', () => {
        t.assert(keysOne.encKey.equals(keysTwo.encKey), 'encKey mismatch between peers');
    });

    t.test('HMAC keys match across peers', () => {
        t.assert(keysOne.hmacKey.equals(keysTwo.hmacKey), 'hmacKey mismatch between peers');
    });

    t.test('encKey and hmacKey are different', () => {
        t.assert(!keysOne.encKey.equals(keysOne.hmacKey), 'encKey and hmacKey should not be equal');
    });

    t.test('keys have correct length', () => {
        t.assert(keysOne.encKey.length  === 32, `encKey should be 32 bytes, got ${keysOne.encKey.length}`);
        t.assert(keysOne.hmacKey.length === 32, `hmacKey should be 32 bytes, got ${keysOne.hmacKey.length}`);
    });

    return t.summary();
}