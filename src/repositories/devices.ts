import { RowDataPacket, ResultSetHeader } from 'mysql2/promise';
import db from '../database/mysql.js';

/** Strong, hard-to-spoof hardware identifier types that can be banned. */
export type IdentifierType = 'system_uuid' | 'mb_serial' | 'disk_serial';

/** A single strong identifier: its type and the sha256 hex of the raw serial. */
export interface DeviceIdentifier {
    type:      IdentifierType;
    valueHash: string;
}

/**
 * Returns true if any of the given strong identifiers is present in hwid_bans.
 * Matches OR-wise: a single banned component is enough to reject the device.
 *
 * @param identifiers - Strong identifiers extracted from the client's device info.
 */
export async function isDeviceBanned(identifiers: DeviceIdentifier[]): Promise<boolean> {
    if (identifiers.length === 0) return false;

    const placeholders = identifiers.map(() => '(?, ?)').join(', ');
    const params       = identifiers.flatMap(i => [i.type, i.valueHash]);

    const row = await db.queryOne<RowDataPacket>(
        `SELECT 1 FROM hwid_bans WHERE (type, value_hash) IN (${placeholders}) LIMIT 1`,
        params,
    );

    return row !== null;
}

/**
 * Upserts a user's strong identifiers, bumping last_seen on rows that already exist.
 *
 * @param userId      - The user the identifiers belong to.
 * @param identifiers - Strong identifiers extracted from the client's device info.
 */
export async function recordDeviceIdentifiers(userId: string, identifiers: DeviceIdentifier[]): Promise<void> {
    if (identifiers.length === 0) return;

    const values = identifiers.map(() => '(?, ?, ?, NOW())').join(', ');
    const params = identifiers.flatMap(i => [userId, i.type, i.valueHash]);

    await db.query<ResultSetHeader>(
        `INSERT INTO device_identifiers (user_id, type, value_hash, last_seen)
         VALUES ${values}
         ON DUPLICATE KEY UPDATE last_seen = NOW()`,
        params,
    );
}

/**
 * Bans every strong identifier currently associated with a user by copying them
 * into hwid_bans. Existing bans are skipped (INSERT IGNORE on the unique key).
 *
 * @param userId   - The user whose devices should be banned.
 * @param reason   - Optional human-readable ban reason.
 * @param bannedBy - Optional admin user id who issued the ban.
 * @returns The number of identifiers newly banned.
 */
export async function banUserDevices(
    userId:   string,
    reason:   string | null,
    bannedBy: string | null,
): Promise<number> {
    const result = await db.query<ResultSetHeader>(
        `INSERT IGNORE INTO hwid_bans (type, value_hash, reason, banned_by)
         SELECT type, value_hash, ?, ? FROM device_identifiers WHERE user_id = ?`,
        [reason, bannedBy, userId],
    );

    return result?.affectedRows ?? 0;
}
