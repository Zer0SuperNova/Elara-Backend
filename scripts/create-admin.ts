/**
 * Creates (or promotes) an admin account.
 *
 * Usage:
 *   npx tsx scripts/create-admin.ts <username> <password>
 *
 * If the username already exists, its password is reset and its role is
 * upgraded to 'admin'. Otherwise a new active admin user is inserted.
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
        console.error('Usage: npx tsx scripts/create-admin.ts <username> <password>');
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

    const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

    const existing = await db.queryOne<{ id: string }>(
        'SELECT id FROM users WHERE username = ?',
        [username]
    );

    if (existing) {
        await db.query(
            "UPDATE users SET password_hash = ?, role = 'admin', is_legacy = false, status = 'active' WHERE id = ?",
            [passwordHash, existing.id]
        );
        console.log(`Updated existing user '${username}' (${existing.id}) -> admin, active, password reset.`);
    } else {
        const id = randomUUID();
        await db.query(
            "INSERT INTO users (id, username, password_hash, role, status) VALUES (?, ?, ?, 'admin', 'active')",
            [id, username, passwordHash]
        );
        console.log(`Created admin user '${username}' (${id}).`);
    }

    process.exit(0);
}

main().catch((err) => {
    console.error('Failed to create admin:', err);
    process.exit(1);
});
