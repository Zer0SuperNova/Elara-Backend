import { ResultSetHeader } from 'mysql2/promise';
import db from '../database/mysql.js';
import redis from '../database/redis.js';
import { createHash, randomBytes } from 'node:crypto';
import logger from '../handler/logger.js';
import bcrypt from 'bcrypt';
import {
    type DeviceIdentifier,
    type IdentifierType,
} from './devices.js';

/**
 * Represents a user in the system
 */
export interface User {
    id: string;
    username: string;
    password_hash: string;
    is_legacy: boolean;
    status: 'active' | 'suspended' | 'banned' | 'pending';
    status_reason: string | null;
    role: 'user' | 'admin';
    created_at: Date;
    updated_at: Date;
    last_login: Date | null;
    last_password_reset: Date | null;
    online_time: number;
    ip: string | null;
}

/**
 * Represents a user's hardware ID record
 */
export interface UserHwid {
    id: number;  
    user_id: string;
    hwid: string;
    device_name: string | null;
    created_at: Date;
    last_seen: Date | null;
}

const DEVICE_INFO_SCHEMA = {
    device_name:   'string',
    os:            'string',
    os_version:    'string',
    os_build:      'string',
    architecture:  'string',
    hostname:      'string',
    locale:        'string',
    timezone:      'string',
    cpu:           'string',
    gpu:           'string',
    cpu_cores:     'number',
    cpu_threads:   'number',
    gpu_vram_mb:   'number',
    ram_total_mb:  'number',

    motherboard_vendor: 'string', 
    motherboard_model:  'string', 
    motherboard_serial: 'string', 
    system_uuid:        'string', 
    cpu_socket:         'string', 
    cpu_l3_cache_mb:    'number', 

    ram_type:           'string', 
    ram_speed_mhz:      'number',
    ram_stick_count:    'number',
    ram_part_numbers:   'array',  

    disk_count:         'number', 
    disk_models:        'array',  
    disk_interfaces:    'array',  
    disk_serials:       'array', 

    monitor_models:     'array',
} as const;

const SESSION_TTL      = 60 * 60 * 24 * 90; 

const HWID_FIELDS = [
    'cpu',
    'gpu',
    'ram_total_mb',
    'hostname',
    'system_uuid',    
    'motherboard_serial',  
    'motherboard_model',
    'ram_speed_mhz'
] as const satisfies (keyof typeof DEVICE_INFO_SCHEMA)[];


type DeviceInfo = {
    [K in keyof typeof DEVICE_INFO_SCHEMA]?: typeof DEVICE_INFO_SCHEMA[K] extends 'string' ? string : number;
};

const USER_SELECT = 'SELECT id, username, password_hash, is_legacy, status, status_reason, role, created_at, updated_at, last_login, last_password_reset, ip FROM users';
const HWID_SELECT = 'SELECT id, user_id, hwid, device_name, created_at, last_seen FROM user_hwids';

/**
 * Retrieves all users from the database
 * @returns {Promise<User[]>} Array of all users
 */
export async function getAllUsers(): Promise<User[]> {
    return db.query<User[]>(USER_SELECT);
}

/**
 * Retrieves a user by their ID
 * @param {string} id - The user ID
 * @returns {Promise<User | null>} The user if found, null otherwise
 */
export async function getUserById(id: string): Promise<User | null> {
    return db.queryOne<User>(`${USER_SELECT} WHERE id = ?`, [id]);
}

/**
 * Retrieves a user by their username
 * @param {string} username - The username
 * @returns {Promise<User | null>} The user if found, null otherwise
 */
export async function getUserByUsername(username: string): Promise<User | null> {
    return db.queryOne<User>(`${USER_SELECT} WHERE username = ?`, [username]);
}

/**
 * Creates a new user
 * @param {string} id - The user ID
 * @param {string} username - The username
 * @param {string} passwordHash - The hashed password
 * @returns {Promise<void>}
 */
export async function createUser(id: string, username: string, passwordHash: string): Promise<void> {
    await db.query(
        'INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)',
        [id, username, passwordHash]
    );
}

/**
 * Upgrades a user's password hash and sets is_legacy to false
 * @param {string} id - The user ID
 * @param {string} passwordHash - The new hashed password
 * @returns {Promise<void>}
 */
export async function upgradePasswordHash(id: string, passwordHash: string): Promise<void> {
    await db.query(
        'UPDATE users SET password_hash = ?, is_legacy = false WHERE id = ?',
        [passwordHash, id]
    );
}

/**
 * Updates a user's status
 * @param {string} id - The user ID
 * @param {User['status']} status - The new status
 * @param {string} [reason] - Optional reason for the status change
 * @returns {Promise<void>}
 */
export async function updateUserStatus(id: string, status: User['status'], reason?: string): Promise<void> {
    await db.query(
        'UPDATE users SET status = ?, status_reason = ? WHERE id = ?',
        [status, reason ?? null, id]
    );
}

/**
 * Updates a user's last login timestamp
 * @param {string} id - The user ID
 * @returns {Promise<void>}
 */
export async function updateLastLogin(id: string): Promise<void> {
    await db.query('UPDATE users SET last_login = NOW() WHERE id = ?', [id]);
}

/**
 * Updates a user's last password reset timestamp
 * @param {string} id - The user ID
 * @returns {Promise<void>}
 */
export async function updateLastPasswordReset(id: string): Promise<void> {
    await db.query('UPDATE users SET last_password_reset = NOW() WHERE id = ?', [id]);
}

/**
 * Retrieves a specific hardware ID record for a user
 * @param {string} hwid - The hardware ID
 * @param {string} userId - The user ID
 * @returns {Promise<UserHwid | null>} The hardware ID record if found, null otherwise
 */
export async function getHwidByUserIdAndHwid(hwid: string, userId: string): Promise<UserHwid | null> {
    return db.queryOne<UserHwid>(
        `${HWID_SELECT} WHERE hwid = ? AND user_id = ?`,
        [hwid, userId]
    );
}

/**
 * Retrieves all hardware ID records for a user
 * @param {string} userId - The user ID
 * @returns {Promise<UserHwid[]>} Array of hardware ID records
 */
export async function getHwidsByUserId(userId: string): Promise<UserHwid[]> {
    return db.query<UserHwid[]>(`${HWID_SELECT} WHERE user_id = ?`, [userId]);
}

/**
 * Registers a new hardware ID for a user
 * @param {string} userId - The user ID
 * @param {string} hwid - The hardware ID
 * @param {string} [deviceName] - Optional device name
 * @returns {Promise<void>}
 */
export async function registerHwid(userId: string, hwid: string, deviceName?: string): Promise<void> {
    await db.query(
        'INSERT INTO user_hwids (user_id, hwid, device_name) VALUES (?, ?, ?)',
        [userId, hwid, deviceName ?? null]
    );
}

/**
 * Updates the last seen timestamp for a hardware ID record
 * @param {number} id - The hardware ID record ID
 * @returns {Promise<void>}
 */
export async function updateHwidLastSeen(id: number): Promise<void> {
    await db.query('UPDATE user_hwids SET last_seen = NOW() WHERE id = ?', [id]);
}

/**
 * Clears all registered HWIDs for a user, unlocking the account so the next
 * device to log in becomes the new bound device.
 * @param {string} userId - The user ID
 * @returns {Promise<number>} Number of HWID records removed
 */
export async function clearUserHwids(userId: string): Promise<number> {
    const result = await db.query<ResultSetHeader>(
        'DELETE FROM user_hwids WHERE user_id = ?',
        [userId]
    );
    return result?.affectedRows ?? 0;
}



/**
 * Adds online time to a user's total.
 * Called on each heartbeat with the elapsed seconds since the last beat.
 *
 * @param {string} id - The user ID
 * @param {number} seconds - Seconds to add to the user's total online time
 * @returns {Promise<void>}
 */
export async function addOnlineTime(id: string, seconds: number): Promise<void> {
    await db.query(
        'UPDATE users SET online_time = online_time + ? WHERE id = ?',
        [seconds, id]
    );
}


/**
 * Resolves the user id behind a raw session token via Redis, without going
 * through the auth middleware. Mirrors the lookup used by the heartbeat route
 * so callers can enforce "logged in" on auth:false routes.
 *
 * @param token - Raw session token from the request body.
 * @returns The owning user id, or null if the token is missing or unknown.
 */
export async function getUserIdBySessionToken(token: unknown): Promise<string | null> {
    if (typeof token !== 'string' || token.length === 0) return null;

    const tokenHash = createHash('sha256').update(token).digest('hex');
    const raw       = await redis.getClient().get(`session:token:${tokenHash}`);

    if (!raw) return null;
    try {
        return JSON.parse(raw).userId ?? null;
    } catch {
        return null;
    }
}

export async function isUserAdmin(userId: string): Promise<boolean> {
    const user = await getUserById(userId);
    return user?.role === 'admin';
}

export async function isUserAdminByUsername(username: string): Promise<boolean> {
    const user = await getUserByUsername(username);
    return user?.role === 'admin';
}

/**
 * Verifies a user's password and upgrades legacy hashes when needed.
 *
 * @param user - User record.
 * @param password - Plaintext password.
 * @returns True when the password is valid.
 */
export async function verifyPassword(user: User, password: string): Promise<boolean> {
    if (user.is_legacy) {
        const legacyHash = createHash('sha256').update(password).digest('hex');
        if (legacyHash !== user.password_hash) return false;

        const newHash = await bcrypt.hash(password, 12);
        await upgradePasswordHash(user.id, newHash);
        logger.info(`Upgraded legacy password hash for '${user.username}'`);
        return true;
    }

    return bcrypt.compare(password, user.password_hash);
}

/**
 * Ensures the current HWID is registered for the user.
 *
 * @param user - User record.
 * @param hwid - Generated hardware identifier.
 * @param deviceInfo - Parsed device info.
 */
export async function ensureHwidRegistered(user: User, hwid: string, deviceInfo: DeviceInfo): Promise<boolean> {

    const isAdmin = user.role === 'admin'; // TODO: change this to the const
    if (isAdmin) {
        logger.debug(`Skipping HWID lock for admin user '${user.username}'`);
        return true;
    }

    const known = await getHwidsByUserId(user.id);

    // Already bound to this exact device — allow and refresh last_seen.
    const match = known.find(h => h.hwid === hwid);
    if (match) {
        await updateHwidLastSeen(match.id);
        return true;
    }

    // Account is already locked to a different device — reject until the old
    // HWID is cleared via clearUserHwids (admin reset).
    if (known.length > 0) {
        logger.warn(`HWID lock: rejected new device for '${user.username}' (${user.id}); already bound to ${known.length} device(s)`);
        return false;
    }

    // First device ever seen for this account — bind it.
    await registerHwid(user.id, hwid, deviceInfo.device_name);
    logger.info(`HWID lock: bound first device for '${user.username}': ${hwid}`);
    return true;
}


/**
 * Validates and normalizes raw device info payload into a typed object.
 *
 * @param raw - Incoming device info payload.
 * @returns Parsed device info or null when invalid.
 */
export function parseDeviceInfo(raw: unknown): DeviceInfo | null {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;

    const input  = raw as Record<string, unknown>;
    const result: DeviceInfo = {};

    for (const [key, type] of Object.entries(DEVICE_INFO_SCHEMA)) {
        if (!(key in input)) continue;

        const value = input[key];
        if (!validateValue(type, value)) return null;

        (result as any)[key] = value;
    }

    return result;
}

/**
 * Generates a deterministic HWID from selected device fields.
 *
 * @param deviceInfo - Parsed device info.
 * @returns HWID hash or null when insufficient data is available.
 */
export function generateHwid(deviceInfo: DeviceInfo): string | null {
    const parts = HWID_FIELDS.map(key => deviceInfo[key]);
    if (parts.every(p => p === undefined)) return null;

    const raw = HWID_FIELDS
        .map(key => `${key}=${deviceInfo[key] ?? 'unknown'}`)
        .join('|');

    return createHash('sha256').update(raw).digest('hex');
}

/**
 * Returns the individual device fields behind the composite HWID, so a failed
 * match can be diffed to see which identifier changed. Mirrors
 * {@link generateHwid}'s field set; absent fields are reported as 'unknown'.
 *
 * @param deviceInfo - Parsed device info.
 * @returns A map of each HWID field to its string value.
 */
export function extractHwidComponents(deviceInfo: DeviceInfo): Record<string, string> {
    const components: Record<string, string> = {};
    for (const key of HWID_FIELDS) {
        const value = deviceInfo[key];
        components[key] = value === undefined ? 'unknown' : String(value);
    }
    return components;
}

/**
 * Hashes a token using SHA-256 and returns the hex digest.
 *
 * @param token - The input token string to hash.
 * @returns Hex-encoded SHA-256 hash of the token.
 */
function hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
}

const MAX_STRING_LEN = 256;

/**
 * Type guard that verifies a value is a finite number.
 *
 * @param v - Value to test.
 * @returns True when v is a finite number.
 */
function isFiniteNumber(v: unknown): v is number {
    return typeof v === 'number' && Number.isFinite(v);
}

/**
 * Type guard that verifies a value is a string and within the allowed length.
 *
 * @param v - Value to test.
 * @returns True when v is a string with length <= MAX_STRING_LEN.
 */
function isSafeString(v: unknown): v is string {
    return typeof v === 'string' && v.length <= MAX_STRING_LEN;
}

/**
 * Validates a value against a simple expected type descriptor.
 *
 * Supported types: 'string', 'number', 'array'.
 *
 * @param type - Expected type descriptor.
 * @param value - Value to validate.
 * @returns True when the value matches the descriptor.
 */
function validateValue(type: string, value: unknown): boolean {
    switch (type) {
        case 'string': return isSafeString(value);
        case 'number': return isFiniteNumber(value);
        case 'array':  return Array.isArray(value);
        default:       return false;
    }
}



interface SessionData {
    userId:      string;
    hwidHash:    string;
    createdAt:   number;
    lastSeenAt:  number;
    buildHash?:  string;
    deviceName?: string;
}

/**
 * Extracts the strong, hard-to-spoof hardware identifiers from device info.
 *
 * Only physically-bound serials are used (system UUID, motherboard serial,
 * disk serials) — soft fields like cpu/gpu name or hostname are deliberately
 * excluded, since they are low-entropy and trivially editable.
 *
 * @param deviceInfo - Parsed device info.
 * @returns The strong identifiers, each hashed with sha256.
 */
export function extractStrongIdentifiers(deviceInfo: DeviceInfo): DeviceIdentifier[] {
    const ids: DeviceIdentifier[] = [];

    const push = (type: IdentifierType, value: unknown) => {
        if (typeof value === 'string' && value.trim().length > 0) {
            ids.push({ type, valueHash: createHash('sha256').update(value).digest('hex') });
        }
    };

    push('system_uuid', deviceInfo.system_uuid);
    push('mb_serial',   deviceInfo.motherboard_serial);

    const disks = (deviceInfo as Record<string, unknown>).disk_serials;
    if (Array.isArray(disks)) {
        for (const serial of disks) push('disk_serial', serial);
    }

    return ids;
}

/**
 * Creates and persists a session token for the authenticated user.
 *
 * @param userId - User identifier.
 * @param hwid - Generated hardware identifier.
 * @param deviceInfo - Parsed device info.
 * @param buildHash - Optional client build hash.
 * @returns Raw session token.
 */
export async function createSessionToken(
    userId:     string,
    hwid:       string,
    deviceInfo: DeviceInfo,
    buildHash?: string,
): Promise<string> {
    const token      = randomBytes(32).toString('hex');
    const tokenHash  = hashToken(token);
    const client     = redis.getClient();

    const existingHash = await client.get(`session:user:${userId}`);
    const pipeline     = client.multi();

    if (existingHash) {
        pipeline.del(`session:token:${existingHash}`);
    }

    const session: SessionData = {
        userId,
        hwidHash:   hwid,
        createdAt:  Date.now(),
        lastSeenAt: Date.now(),
        buildHash,
        deviceName: deviceInfo.device_name,
    };

    pipeline.set(`session:token:${tokenHash}`, JSON.stringify(session), { EX: SESSION_TTL });
    pipeline.set(`session:user:${userId}`,      tokenHash,               { EX: SESSION_TTL });

    await pipeline.exec();

    return token;
}

/**
 * Invalidates a user's session token, removing both the token entry and the
 * `user → token` reverse lookup. Safe to call for an already-absent session.
 *
 * @param tokenHash - SHA-256 hash of the raw session token.
 * @param userId    - The user that owns the session.
 * @returns Resolves once both keys have been removed.
 */
export async function invalidateUserSession(tokenHash: string, userId: string): Promise<void> {
    const client   = redis.getClient();
    const pipeline = client.multi();
    pipeline.del(`session:token:${tokenHash}`);
    pipeline.del(`session:user:${userId}`);
    await pipeline.exec();
}


/**
 * Sets the country ISO code for a user.
 * @param userId - The user's ID.
 * @param countryIso - The country ISO code.
 */
export async function setCountryIsoForUser(userId: string, countryIso: string): Promise<void> {
    await db.query(
        'UPDATE users SET country_iso = ? WHERE id = ?',
        [countryIso, userId]
    );
}

/**
 * 
 * @param userId - userid
 * @param ip - the fuckin ip yuirrr
 */
export async function setIpForUser(userId: string, ip: string): Promise<void> {
    await db.query(
        'UPDATE users SET ip = ? WHERE id = ?',
        [ip, userId]
    );
}