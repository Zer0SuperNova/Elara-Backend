import { RowDataPacket } from 'mysql2/promise';
import db from '../database/mysql.js';

/** A loader record from the `loaders` table. */
export interface Loader {
    id: string;
    hash: string;
    ed25519PK: string;
    status: 'active' | 'deactivated';
}

/** Retrieves a loader by hash, or null when none matches. */
export async function getLoaderByHash(hash: string): Promise<Loader | null> {
    return db.queryOne<Loader>(
        'SELECT id, hash, ed25519PK, status FROM loaders WHERE hash = ?',
        [hash]
    );
}

const loaderIdByHash = new Map<string, string>();

/** Resolves a loader's id from its hash (memoized), or '' when none matches. */
export async function getLoaderIdByHash(hash: string): Promise<string> {
    if (!hash) return '';

    const cached = loaderIdByHash.get(hash);
    if (cached) return cached;

    const row = await db.queryOne<RowDataPacket>('SELECT id FROM loaders WHERE hash = ? LIMIT 1', [hash]);
    if (row?.id) {
        loaderIdByHash.set(hash, row.id);
        return row.id;
    }
    return '';
}
