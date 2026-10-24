import { randomUUID, createHash, generateKeyPairSync, KeyObject } from 'node:crypto';
import db, { init } from '../src/database/mysql.js';

const DEFAULT_USERNAME = 'zer0';
const DEFAULT_PRODUCT = 'elara';

type JwkX = { x: string };
type JwkD = { d: string };

function b64urlToBuffer(b64url: string): Buffer {
  const base64 = b64url.replaceAll(/-/g, '+').replaceAll(/_/g, '/');
  const padLen = (4 - (base64.length % 4)) % 4;
  return Buffer.from(base64 + '='.repeat(padLen), 'base64');
}

const exportJwkX = (key: KeyObject): JwkX => key.export({ format: 'jwk' }) as JwkX;
const exportJwkD = (key: KeyObject): JwkD => key.export({ format: 'jwk' }) as JwkD;

async function main(): Promise<void> {
  const [username = DEFAULT_USERNAME, product = DEFAULT_PRODUCT] = process.argv.slice(2);

  const serverStaticPKHex = process.env.SERVER_STATIC_PUBLIC;
  const pskHex = process.env.PSK;
  if (!serverStaticPKHex || !pskHex) {
    console.error(
      `Missing core keys in .env (SERVER_STATIC_PUBLIC=${serverStaticPKHex}, PSK=${pskHex}). ` +
      `These are required to build a usable client config.`
    );
    process.exit(1);
  }


  const { publicKey: edPub, privateKey: edPriv } = generateKeyPairSync('ed25519');
  const edPk = b64urlToBuffer(exportJwkX(edPub).x);
  const edSk = Buffer.concat([b64urlToBuffer(exportJwkD(edPriv).d), edPk]);
  const edPkHex = edPk.toString('hex');
  const hash = createHash('sha256').update(edPk).digest('hex');

  await init();

  const buildId = randomUUID();
  await db.query(
    `INSERT INTO builds (id, hash, ed25519PK, zip_name, commit_sha, product, status, is_dev)
     VALUES (?, ?, ?, 'dev.zip', 'devsha', ?, 'active', TRUE)`,
    [buildId, hash, edPkHex, product]
  );
  console.log(`Created dev build ${buildId} (hash ${hash}).`);

  const user = await db.queryOne<{ id: string }>(
    'SELECT id FROM users WHERE username = ?',
    [username]
  );

  if (!user) {
    console.warn(
      `\nUser '${username}' not found — skipped user_builds binding. ` +
      `The handshake will work, but core login won't find a claimed build. ` +
      `Create the user (npm run create ${username} <password>) and re-run to bind it.`
    );
  } else {
    await db.query(
      `INSERT INTO user_builds (user_id, build_id, product_id, aes_key, status)
       VALUES (?, ?, ?, REPEAT('a', 64), 'active')`,
      [user.id, buildId, product]
    );
    console.log(`Bound build to user '${username}' (${user.id}) for product '${product}'.`);
  }

  console.log('\n// dev core client config');
  console.log(`cfg.serverStaticPKHex = "${serverStaticPKHex}";`);
  console.log(`cfg.pskHex = "${pskHex}";`);
  console.log(`cfg.Ed25519PKHex = "${edPkHex}";`);
  console.log(`cfg.Ed25519SKHex = "${edSk.toString('hex')}";`);
  console.log(`cfg.buildHashHex = "${hash}";`);

  process.exit(0);
}

main().catch((err) => {
  console.error('Failed to create dev core key:', err);
  process.exit(1);
});
