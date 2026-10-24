import { RowDataPacket, ResultSetHeader, PoolConnection } from 'mysql2/promise';
import db from '../database/mysql.js';

const BUILD_EXPIRY_DAYS = 14;
export const BUILD_EXPIRY_MS = BUILD_EXPIRY_DAYS * 24 * 60 * 60 * 1000;

/**
 * Represents a build record from the database.
 */
export interface Build extends RowDataPacket {
    /** Unique identifier for the build */
    id:         string;
    /** Unique hash of the build */
    hash:       string;
    /** Ed25519 public key */
    ed25519PK:  string;
    /** Name of the zip file */
    zip_name:   string;
    /** Commit SHA associated with the build */
    commit_sha: string;
    /** Product name or ID */
    product:    string;
    /** Status of the build */
    status:     'building' | 'inactive' | 'active' | 'banned' | 'tempbanned' | 'deactivated';
    /** Creation timestamp */
    created_at: Date;
    /** Last used timestamp, nullable */
    used_at:    Date | null;
    /** Indicates if this build is a development build */
    is_dev:    boolean;
}


/**
 * Represents a user_builds record from the database.
 */
export interface UserBuild extends RowDataPacket {
    /** Unique identifier for the user build */
    id:           string;
    /** User ID */
    user_id:      string;
    /** Build ID */
    build_id:     string;
    /** Product ID */
    product_id:   string;
    /** AES encryption key */
    aes_key:      string;
    /** Timestamp when claimed */
    claimed_at:   Date;
    /** Status of the user build */
    status:       'claimed' | 'active' | 'expired' | 'revoked';

     /** Indicates if this build is a development build */
    is_dev?:    boolean;
}



/**
 * Retrieves a build by its Ed25519 public key.
 * @param ed25519PK - The Ed25519 public key.
 * @returns The build if found, otherwise null.
 */
export async function getBuildByHash(hash: string): Promise<Build | null> {
    return db.queryOne<Build>('SELECT * FROM builds WHERE hash = ?', [hash]);
}


/**
 * Retrieves a build by its ID.
 * @param id - The ID of the build.
 * @returns The build if found, otherwise null.
 */
export async function getBuildById(id: string): Promise<Build | null> {
    return db.queryOne<Build>('SELECT * FROM builds WHERE id = ?', [id]);
}

const buildIdByHash = new Map<string, string>();

/** Resolves a build's id from its hash (memoized), or '' when none matches. */
export async function getBuildIdByHash(hash: string): Promise<string> {
    if (!hash) return '';

    const cached = buildIdByHash.get(hash);
    if (cached) return cached;

    const row = await db.queryOne<RowDataPacket>('SELECT id FROM builds WHERE hash = ? LIMIT 1', [hash]);
    if (row?.id) {
        buildIdByHash.set(hash, row.id);
        return row.id;
    }
    return '';
}

/**
 * Resolves a user's current build id from `user_builds`, newest claimed first.
 * Not memoized — a user's active build can change over time.
 *
 * @param userId - The user whose active build to look up.
 * @returns The build id, or '' when the user has no claimed/active build.
 */
export async function getActiveUserBuildId(userId: string): Promise<string> {
    if (!userId) return '';

    const row = await db.queryOne<RowDataPacket>(
        `SELECT build_id FROM user_builds
         WHERE user_id = ? AND status IN ('claimed', 'active')
         ORDER BY claimed_at DESC
         LIMIT 1`,
        [userId]
    );
    return row?.build_id ?? '';
}

/**
 * Resolves the owning user of a build from its hash, via `user_builds`.
 * Used as an analytics fallback when a crypto session isn't stamped with a user.
 * Not memoized — build ownership can change.
 *
 * @param buildHash - The build's hash.
 * @returns The owning user's id, or '' when none matches.
 */
export async function getUserIdByBuildHash(buildHash: string): Promise<string> {
    if (!buildHash) return '';

    const row = await db.queryOne<RowDataPacket>(
        `SELECT ub.user_id FROM user_builds ub
         INNER JOIN builds b ON b.id = ub.build_id
         WHERE b.hash = ? AND ub.status IN ('claimed', 'active')
         ORDER BY ub.claimed_at DESC
         LIMIT 1`,
        [buildHash]
    );
    return row?.user_id ?? '';
}



/**
 * Claims the oldest inactive build for a product, locking it for update.
 * @param product - The product name or ID.
 * @param conn - Optional MySQL connection.
 * @returns The claimed build if available, otherwise null.
 */
export async function claimInactiveBuild(product: string, conn?: PoolConnection): Promise<Build | null> {
    return db.queryOne<Build>(
        `SELECT * FROM builds 
         WHERE product = ? AND status = 'inactive' 
         ORDER BY created_at ASC
         LIMIT 1 FOR UPDATE SKIP LOCKED`,
        [product],
        conn
    );
}


/**
 * Marks a build as active and updates its used_at timestamp.
 * @param buildId - The ID of the build.
 * @param conn - Optional MySQL connection.
 */
export async function markBuildActive(buildId: string, conn?: PoolConnection): Promise<void> {
    await db.query<ResultSetHeader>(
        `UPDATE builds SET status = 'active', used_at = NOW() WHERE id = ?`,
        [buildId],
        conn
    );
}


/**
 * Deactivates a build by setting its status to 'deactivated'.
 * @param buildId - The ID of the build.
 * @param conn - Optional MySQL connection.
 */
export async function deactivateBuild(buildId: string, conn?: PoolConnection): Promise<void> {
    await db.query<ResultSetHeader>(
        `UPDATE builds SET status = 'deactivated' WHERE id = ?`,
        [buildId],
        conn
    );
}



/**
 * Gets the latest claimed or active user build for a product.
 * @param userId - The user ID.
 * @param productId - The product ID.
 * @param conn - Optional MySQL connection.
 * @returns The user build if found, otherwise null.
 */
export async function getUserBuildForProduct(userId: string, productId: string, conn?: PoolConnection): Promise<UserBuild | null> {
    return db.queryOne<UserBuild>(
        `SELECT ub.* FROM user_builds ub
         WHERE ub.user_id = ? AND ub.product_id = ?
         AND ub.status IN ('claimed', 'active')
         ORDER BY ub.claimed_at DESC
         LIMIT 1`,
        [userId, productId],
        conn
    );
}


/**
 * Gets a user's build by the build's hash.
 * @param userId - The user ID.
 * @param buildHash - The build hash.
 * @returns The user build if found, otherwise null.
 */
export async function getUserBuildByHash(userId: string, buildHash: string): Promise<UserBuild | null> {
    return db.queryOne<UserBuild>(
        `SELECT ub.* FROM user_builds ub
         INNER JOIN builds b ON b.id = ub.build_id
         WHERE ub.user_id = ? AND b.hash = ?
         AND ub.status IN ('claimed', 'active')
         LIMIT 1`,
        [userId, buildHash]
    );
}


/**
 * Creates a new user_builds record with status 'claimed'.
 * @param userId - The user ID.
 * @param buildId - The build ID.
 * @param productId - The product ID.
 * @param aesKey - The AES encryption key.
 * @param conn - Optional MySQL connection.
 */
export async function createUserBuild(
    userId:    string,
    buildId:   string,
    productId: string,
    aesKey:    string,
    conn?:     PoolConnection,
): Promise<void> {
    await db.query<ResultSetHeader>(
        `INSERT INTO user_builds (user_id, build_id, product_id, aes_key, status)
         VALUES (?, ?, ?, ?, 'claimed')`,
        [userId, buildId, productId, aesKey],
        conn
    );
}


/**
 * Revokes all claimed or active user builds for a user and product.
 * @param userId - The user ID.
 * @param productId - The product ID.
 * @param conn - Optional MySQL connection.
 * @returns The number of affected rows.
 */
export async function revokeExistingUserBuilds(userId: string, productId: string, conn?: PoolConnection): Promise<number> {
    const result = await db.query<ResultSetHeader>(
        `UPDATE user_builds 
         SET status = 'revoked'
         WHERE user_id = ? AND product_id = ? AND status IN ('claimed', 'active')`,
        [userId, productId],
        conn
    );

    return result?.affectedRows ?? 0;
}


/**
 * Activates a claimed user build by build hash.
 * @param userId - The user ID.
 * @param buildHash - The build hash.
 * @returns True if a row was updated, otherwise false.
 */
export async function activateUserBuild(userId: string, buildHash: string): Promise<boolean> {
    const result = await db.query<ResultSetHeader>(
        `UPDATE user_builds ub
         INNER JOIN builds b ON b.id = ub.build_id
         SET ub.status = 'active', ub.activated_at = NOW()
         WHERE ub.user_id = ? AND b.hash = ? AND ub.status = 'claimed'`,
        [userId, buildHash]
    );

    return (result?.affectedRows ?? 0) > 0;
}


/**
 * Expires a user build by setting its status to 'expired'.
 * @param userBuildId - The user_builds record ID.
 */
export async function expireUserBuild(userBuildId: string): Promise<void> {
    await db.query<ResultSetHeader>(
        `UPDATE user_builds SET status = 'expired' WHERE id = ?`,
        [userBuildId]
    );
}

export async function isBuildActive(buildId: string): Promise<boolean> {
    const build = await getBuildById(buildId);
    return build?.status === 'active';
}


/** * Checks if a user build has expired based on its claimed_at timestamp.
 * @param userBuild - The user build to check.
 * @returns True if the user build is expired, otherwise false.
 */
export async function isUserBuildExpired(userBuild: UserBuild): Promise<boolean> {
    if (userBuild.status === 'revoked' || userBuild.status === 'expired') return true;

    const isActiveBuild = await isBuildActive(userBuild.build_id);
    if (!isActiveBuild) return true;

    if (!userBuild.claimed_at) return false;
    const claimedAt = new Date(userBuild.claimed_at).getTime();
    return Date.now() > claimedAt + BUILD_EXPIRY_MS;
}

/**
* Bans a build by setting its status to 'banned'.
* @param buildId - The ID of the build.
* @param conn - Optional MySQL connection.
*/
export async function banBuild(buildId: string, conn?: PoolConnection): Promise<void> {
    await db.query<ResultSetHeader>(
        `UPDATE builds SET status = 'banned' WHERE id = ?`,
        [buildId],
        conn
    );
}
