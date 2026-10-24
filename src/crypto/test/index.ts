import { printResults } from './runner.js';
import * as handshake   from './suites/handshake.test.js';
import * as keyExchange from './suites/keyExchange.test.js';
import * as sessionKeys from './suites/sessionKeys.test.js';
import * as tunnel      from './suites/tunnel.test.js';
import * as signing     from './suites/signing.test.js';
import * as vuln        from './suites/vuln.test.js';

console.log('\n Crypto Tests');
console.log(`${'─'.repeat(50)}`);

const results = [
    handshake.run(),
    keyExchange.run(),
    sessionKeys.run(),
    tunnel.run(),
    signing.run(),
    vuln.run(),
];

printResults(results);