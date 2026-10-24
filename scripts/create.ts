/**
 * Creates a normal user account.
 *
 * Usage:
 *   npx tsx scripts/create.ts <username> <password>
 *
 * Inserts a new active user with role 'user'. If the username already exists,
 * the script aborts without touching the existing account — use
 * scripts/create-admin.ts if you intend to reset a password.
 */
import { randomUUID } from 'node:crypto';
import bcrypt from 'bcrypt';
import db, { init } from '../src/database/mysql.js';

const USERNAME_MIN = 3;
const USERNAME_MAX = 20;
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 72; // bcrypt truncates beyond 72 bytes
const USERNAME_REGEX = /^[a-zA-Z0-9äöüÄÖÜß\-.,@_]+$/;
const BCRYPT_COST = 12;

async function main(): Promise<void> {
    const [username, password] = process.argv.slice(2);

    if (!username || !password) {
        console.error('Usage: npx tsx scripts/create.ts <username> <password>');
        process.exit(1);
    }

    if (username.length < USERNAME_MIN || username.length > USERNAME_MAX || !USERNAME_REGEX.test(username)) {
        console.error(`Invalid username: must be ${USERNAME_MIN}-${USERNAME_MAX} chars and match ${USERNAME_REGEX}`);
        process.exit(1);
    }

    if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
        console.error(`Invalid password: must be ${PASSWORD_MIN}-${PASSWORD_MAX} characters`);
        process.exit(1);
    }

    await init();

    const existing = await db.queryOne<{ id: string }>(
        'SELECT id FROM users WHERE username = ?',
        [username]
    );

    if (existing) {
        console.error(`User '${username}' already exists (${existing.id}). Aborting.`);
        process.exit(1);
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

    const id = randomUUID();
    await db.query(
        "INSERT INTO users (id, username, password_hash, role, status) VALUES (?, ?, ?, 'user', 'active')",
        [id, username, passwordHash]
    );
    console.log(`Created user '${username}' (${id}).`);

    process.exit(0);
}

main().catch((err) => {
    console.error('Failed to create user:', err);
    process.exit(1);
});
