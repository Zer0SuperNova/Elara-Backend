import { tunnel }     from '../../nativeProvider.js';
import { TestRunner } from '../runner.js';

export function run() {
    const t = new TestRunner('Signing');

    const client = tunnel.generateKeys();
    const other  = tunnel.generateKeys();

    t.test('signature is 64 bytes', () => {
        const sig = tunnel.sign(Buffer.from('test', 'utf8'), client.ed25519SK);
        t.assert(sig.length === 64, `expected 64 bytes, got ${sig.length}`);
    });

    t.test('same message produces different signatures with different keys', () => {
        const msg  = Buffer.from('test', 'utf8');
        const sigA = tunnel.sign(msg, client.ed25519SK);
        const sigB = tunnel.sign(msg, other.ed25519SK);
        t.assert(!sigA.equals(sigB), 'different keys should produce different signatures');
    });

    t.test('different messages produce different signatures', () => {
        const sigA = tunnel.sign(Buffer.from('hello', 'utf8'), client.ed25519SK);
        const sigB = tunnel.sign(Buffer.from('world', 'utf8'), client.ed25519SK);
        t.assert(!sigA.equals(sigB), 'different messages should produce different signatures');
    });

    return t.summary();
}