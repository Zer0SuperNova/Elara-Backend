import { tunnel }     from '../../nativeProvider.js';
import { TestRunner } from '../runner.js';

export function run() {
    const t = new TestRunner('Key Exchange');

    const clientOne = tunnel.generateKeys();
    const clientTwo = tunnel.generateKeys();

    const hsOne = tunnel.createHandshake(clientOne);
    const hsTwo = tunnel.createHandshake(clientTwo);

    const secretOne = tunnel.deriveSharedSecret(hsTwo.x25519PK, clientOne.x25519SK);
    const secretTwo = tunnel.deriveSharedSecret(hsOne.x25519PK, clientTwo.x25519SK);

    t.test('clientOne derives shared secret', () => {
        t.assert(secretOne !== null, 'deriveSharedSecret returned null for clientOne');
    });

    t.test('clientTwo derives shared secret', () => {
        t.assert(secretTwo !== null, 'deriveSharedSecret returned null for clientTwo');
    });

    t.test('shared secrets match (ECDH correctness)', () => {
        t.assert(
            secretOne !== null && secretTwo !== null && secretOne.equals(secretTwo),
            'shared secrets do not match'
        );
    });

    t.test('different key pairs produce different secrets', () => {
        const clientThree  = tunnel.generateKeys();
        const hsThree      = tunnel.createHandshake(clientThree);
        const secretOther  = tunnel.deriveSharedSecret(hsThree.x25519PK, clientOne.x25519SK);
        t.assert(
            secretOne !== null && secretOther !== null && !secretOne.equals(secretOther),
            'different key pairs should produce different secrets'
        );
    });

    return t.summary();
}