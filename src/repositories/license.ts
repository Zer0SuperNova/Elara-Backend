import { ResultSetHeader } from 'mysql2';
import db from '../database/mysql.js';
import { getAllProducts } from './products.js';

/**
 * Represents a license in the system
 */
export interface License {
    id: string;
    license_key: string;
    account_id: string | null;
    product_id: string;
    duration: number;
    activated_at: Date | null;
    expires_at?: Date | null;
    status: 'inactive' | 'active' | 'revoked';
    status_reason: string | null;
    note: string | null;
    created_by: string | null;
    created_at: Date;
    updated_at: Date;
}

const LICENSE_SELECT = 'SELECT id, license_key, account_id, product_id, duration, activated_at, status, status_reason, note, created_by, created_at, updated_at FROM licenses';

function toDate(value: Date | string | null | undefined): Date | null {
    if (!value) return null;
    const date = value instanceof Date ? value : new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
}

function addMinutes(value: Date, minutes: number): Date {
    return new Date(value.getTime() + minutes * 60_000);
}

function activationDate(license: License): Date {
    return toDate(license.activated_at) ?? toDate(license.created_at) ?? new Date(0);
}

export function getMinutesRemainingUntil(expiresAt: Date | string | null): number | null {
    const expiry = toDate(expiresAt);
    if (!expiry) return null;
    return Math.max(0, Math.floor((expiry.getTime() - Date.now()) / 60_000));
}

export function buildEffectiveLicenses(licenses: License[]): License[] {
    const byProduct = new Map<string, License[]>();
    const now = new Date();

    for (const license of licenses) {
        if (license.status !== 'active' || Number(license.duration) <= 0) continue;
        const group = byProduct.get(license.product_id) ?? [];
        group.push(license);
        byProduct.set(license.product_id, group);
    }

    const effective: License[] = [];
    for (const group of byProduct.values()) {
        const ordered = group.sort((a, b) => {
            const byActivation = activationDate(a).getTime() - activationDate(b).getTime();
            return byActivation || a.id.localeCompare(b.id);
        });

        let cursor: Date | null = null;
        for (const license of ordered) {
            const startedAt = activationDate(license);
            const base = cursor && cursor > startedAt ? cursor : startedAt;
            cursor = addMinutes(base, Number(license.duration) || 0);
            if (cursor > now) {
                effective.push({ ...license, expires_at: cursor });
            }
        }
    }

    return effective;
}

export function hasEffectiveLicense(licenses: License[], productId: string): boolean {
    return buildEffectiveLicenses(licenses).some(l => l.product_id === productId);
}

export function getLatestEffectiveLicensesByProduct(licenses: License[]): License[] {
    const latest = new Map<string, License>();

    for (const license of buildEffectiveLicenses(licenses)) {
        const current = latest.get(license.product_id);
        const currentTime = current?.expires_at ? new Date(current.expires_at).getTime() : 0;
        const nextTime = license.expires_at ? new Date(license.expires_at).getTime() : 0;
        if (!current || nextTime > currentTime) {
            latest.set(license.product_id, license);
        }
    }

    return Array.from(latest.values());
}

/**
 * Retrieves all licenses from the database
 * @returns {Promise<License[]>} Array of all licenses
 */
export async function getAllLicenses(): Promise<License[]> {
    return db.query<License[]>(LICENSE_SELECT);
}

/**
 * Retrieves a license by its ID
 * @param {string} id - The license ID
 * @returns {Promise<License | null>} The license if found, null otherwise
 */
export async function getLicenseById(id: string): Promise<License | null> {
    return db.queryOne<License>(`${LICENSE_SELECT} WHERE id = ?`, [id]);
}

/**
 * Retrieves a license by its key
 * @param {string} licenseKey - The license key
 * @returns {Promise<License | null>} The license if found, null otherwise
 */
export async function getLicenseByKey(licenseKey: string): Promise<License | null> {
    return db.queryOne<License>(`${LICENSE_SELECT} WHERE license_key = ?`, [licenseKey]);
}

/**
 * Retrieves all licenses associated with an account
 * @param {string} accountId - The account ID
 * @returns {Promise<License[]>} Array of licenses
 */
export async function getLicensesByAccountId(accountId: string): Promise<License[]> {
    return db.query<License[]>(`${LICENSE_SELECT} WHERE account_id = ?`, [accountId]);
}

/**
 * Retrieves all licenses for a specific product
 * @param {string} productId - The product ID
 * @returns {Promise<License[]>} Array of licenses
 */
export async function getLicensesByProductId(productId: string): Promise<License[]> {
    return db.query<License[]>(`${LICENSE_SELECT} WHERE product_id = ?`, [productId]);
}

/**
 * Creates a new license
 * @param {string} licenseKey - The license key
 * @param {string} productId - The product ID
 * @param {number} duration - Duration in minutes
 * @param {string} [createdBy] - Optional admin user ID who generated the key
 * @param {string} [note] - Optional internal admin note
 * @returns {Promise<void>}
 */
export async function createLicense(licenseKey: string, productId: string, duration: number, createdBy?: string, note?: string): Promise<void> {
    await db.query(
        'INSERT INTO licenses (license_key, product_id, duration, created_by, note) VALUES (?, ?, ?, ?, ?)',
        [licenseKey, productId, duration, createdBy ?? null, note ?? null]
    );
}

/**
 * Activates a license for an account, setting activated_at and expires_at
 * @param {string} id - The license ID
 * @param {string} accountId - The account ID
 * @returns {Promise<void>}
 */
 export async function activateLicense(id: string, accountId: string): Promise<boolean> {
      return db.transaction(async (connection) => {
          const license = await db.queryOne<License>(
              `${LICENSE_SELECT} WHERE id = ? AND status = 'inactive' LIMIT 1 FOR UPDATE`,
              [id],
              connection,
          );

          if (!license) return false;

          await db.query(
              `SELECT id
                 FROM users
                WHERE id = ?
                LIMIT 1
                FOR UPDATE`,
              [accountId],
              connection,
          );

          const result = await db.query<ResultSetHeader>(
              `UPDATE licenses
                  SET account_id = ?,
                      status = 'active',
                      activated_at = NOW()
                WHERE id = ? AND status = 'inactive'`,
              [accountId, id],
              connection,
          );
          return (result?.affectedRows ?? 0) > 0;
      });
  }
  
/**
 * Updates a license's status
 * @param {string} id - The license ID
 * @param {License['status']} status - The new status
 * @param {string} [reason] - Optional reason for the status change
 * @returns {Promise<void>}
 */
export async function updateLicenseStatus(id: string, status: License['status'], reason?: string): Promise<void> {
    await db.query(
        'UPDATE licenses SET status = ?, status_reason = ? WHERE id = ?',
        [status, reason ?? null, id]
    );
}

/**
 * Revokes a license
 * @param {string} id - The license ID
 * @param {string} [reason] - Optional reason for revocation
 * @returns {Promise<void>}
 */
export async function revokeLicense(id: string, reason?: string): Promise<void> {
    return updateLicenseStatus(id, 'revoked', reason);
}

/**
 * Checks whether a license is expired
 * @param {License} license - The license object
 * @returns {boolean} True if expired
 */
export function isLicenseExpired(license: License): boolean {
    const activatedAt = toDate(license.activated_at);
    const expiresAt = activatedAt ? addMinutes(activatedAt, Number(license.duration) || 0) : null;

    if (!expiresAt) return false;
    return expiresAt < new Date();
}

export function getLatestExpiringLicense(licenses: License[], productId: string): License | null {
    return buildEffectiveLicenses(licenses)
        .filter(l => l.product_id === productId)
        .sort((a, b) => {
            const aTime = a.expires_at ? new Date(a.expires_at).getTime() : Number.MAX_SAFE_INTEGER;
            const bTime = b.expires_at ? new Date(b.expires_at).getTime() : Number.MAX_SAFE_INTEGER;
            return bTime - aTime;
        })[0] ?? null;
}


/**
 * Builds the licenses payload for the login response.
 * Admins get a synthetic, never-expiring entry per product (god mode);
 * everyone else gets their real active licenses.
 */
export async function buildLicensesPayload(userId: string, isAdmin: boolean) {
    const adminExpiry = new Date();
    adminExpiry.setFullYear(adminExpiry.getFullYear() + 20);

    if (isAdmin) {
        const adminMinutes = Math.floor((adminExpiry.getTime() - Date.now()) / 60_000);
        const products = await getAllProducts();
        return products.map(p => ({
            id:                `admin:${p.id}`,   // synthetic, no real license row
            product_id:        p.id,
            expires_at:        adminExpiry,
            minutes_remaining: adminMinutes,
        }));
    }

    const licenses = await getLicensesByAccountId(userId);
    return getLatestEffectiveLicensesByProduct(licenses)
        .map(l => ({
            id:                l.id,
            product_id:        l.product_id,
            expires_at:        l.expires_at,
            minutes_remaining: getMinutesRemainingUntil(l.expires_at ?? null),
        }));
}


/**
 * Builds the license -> API payload mapper.
 * Admins get a synthetic 20-year expiry so the client treats them as never expiring.
 */
export function makeLicenseMapper(isAdmin: boolean) {
    const adminExpiry = new Date();
    adminExpiry.setFullYear(adminExpiry.getFullYear() + 20);

    return (l: License) => {
        const expiresAt = isAdmin ? adminExpiry : (l.expires_at ?? null);
        return {
            id:                l.id,
            product_id:        l.product_id,
            expires_at:        expiresAt,
            minutes_remaining: isAdmin
                ? Math.max(0, Math.floor((adminExpiry.getTime() - Date.now()) / 60_000))
                : getMinutesRemainingUntil(expiresAt),
        };
    };
}
