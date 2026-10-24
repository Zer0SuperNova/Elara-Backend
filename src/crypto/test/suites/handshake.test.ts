import { tunnel }     from '../../nativeProvider.js';
import { TestRunner } from '../runner.js';

export function run() {
    const t = new TestRunner('Handshake');

    const clientOne = tunnel.generateKeys();
    const clientTwo = tunnel.generateKeys();

    const hsOne = tunnel.createHandshake(clientOne);
    const hsTwo = tunnel.createHandshake(clientTwo);

    t.test('clientOne handshake verifies', () => {
        t.assert(tunnel.verifyHandshake(hsOne), 'clientOne handshake failed verification');
    });

    t.test('clientTwo handshake verifies', () => {
        t.assert(tunnel.verifyHandshake(hsTwo), 'clientTwo handshake failed verification');
    });

    t.test('handshake with wrong key fails', () => {
        const tampered = { ...hsOne, ed25519PK: clientTwo.ed25519PK };
        t.assert(!tunnel.verifyHandshake(tampered), 'tampered handshake should not verify');
    });

    t.test('handshake payload has correct buffer sizes', () => {
        t.assert(hsOne.ed25519PK.length === 32, `ed25519PK should be 32 bytes, got ${hsOne.ed25519PK.length}`);
        t.assert(hsOne.x25519PK.length  === 32, `x25519PK should be 32 bytes, got ${hsOne.x25519PK.length}`);
        t.assert(hsOne.sig.length       === 64, `sig should be 64 bytes, got ${hsOne.sig.length}`);
    });

    return t.summary();
}