import express from 'express';
import { errors, sendError } from '../../utils/errors.js';
import { getLatestEffectiveLicensesByProduct, getLicensesByAccountId, getMinutesRemainingUntil, License } from '../../repositories/license.js';
import { getUserById, setIpForUser } from '../../repositories/user.js';
import logger from '../../handler/logger.js';
import { PSK } from '../../types/psk.js';


const router = express.Router();

export const config = {
    auth:       true,
    encrypted:  true,
    allowedPsk: [PSK.LOADER, PSK.CORE],
};

/**
 * Calculates the remaining license time in minutes.
 *
 * @param license - License record.
 * @returns Remaining minutes or null if no expiry is available.
 */
export function getMinutesRemaining(license: License): number | null {
    return getMinutesRemainingUntil(license.expires_at ?? null);
}

/**
 * Resumes an existing session without re-authenticating with credentials.
 * Validates the token via the auth middleware, then returns fresh user
 * and license data. Used by the client on startup when a stored token exists.
 *
 * @route POST /api/v1/session
 * @access Protected
 */
router.post('/api/v1/session', async (req: express.Request, res: express.Response) => {
    const userId = req.userId as string;
    const ip = req.clientIp || 'unknown';

    try {
        const user = await getUserById(userId);
        if (!user) {
            logger.warn(`[Session] User '${userId}' not found`);
            return sendError(res, errors.NOT_FOUND, `User '${userId}' not found`);
        }

        let activeLicenses: License[] = [];
        try {
            const licenses = await getLicensesByAccountId(userId);
            activeLicenses = getLatestEffectiveLicensesByProduct(licenses);
        } catch (err) {
            logger.warn(`[Session] Failed to fetch licenses for '${userId}': ${err}`);
        }

        logger.debug(`[Session] Resumed session for user '${user.username}'`);

        // stamp ip
        await setIpForUser(user.id, ip);

        return res.json({
            user: {
                username: user.username,
                role:     user.role,
            },
            licenses: activeLicenses.map(l => ({
                id:                l.id,
                product_id:        l.product_id,
                expires_at:        l.expires_at,
                minutes_remaining: getMinutesRemainingUntil(l.expires_at ?? null),
            })),
        });

    } catch (err) {
        logger.error(`[Session] Failed for user '${userId}': ${err}`);
        return sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;
