import express from 'express';
import { errors, sendError } from '../../utils/errors.js';
import { getLatestEffectiveLicensesByProduct, getLicensesByAccountId, getMinutesRemainingUntil } from '../../repositories/license.js';
import logger from '../../handler/logger.js';
import { PSK } from '../../types/psk.js';
import { getUserPermissions, permissionsInclude } from '../../rbac/rbac.js';
import { Permission } from '../../rbac/permissions.js';

const router = express.Router();

export const config = {
    auth:      true,
    encrypted: true,
    allowedPsk: [PSK.LOADER, PSK.CORE]
};

/**
 * Returns all active licenses.
 * @route POST /api/v1/licenses
 * @access Protected
 */
router.post('/api/v1/licenses', async (req: express.Request, res: express.Response) => {
    try {
        const userId = req.userId as string;

        const [licenses, perms] = await Promise.all([
            getLicensesByAccountId(userId),
            getUserPermissions(userId),
        ]);
        const isAdmin = permissionsInclude(perms, Permission.Admin);

        const active = getLatestEffectiveLicensesByProduct(licenses);

        const adminExpiry = new Date();
        adminExpiry.setFullYear(adminExpiry.getFullYear() + 20);

        return res.json({
            licenses: active.map(l => {
                const expiresAt = isAdmin ? adminExpiry : (l.expires_at ?? null);
                return {
                    id:                l.id,
                    product_id:        l.product_id,
                    expires_at:        expiresAt,
                    minutes_remaining: getMinutesRemainingUntil(expiresAt),
                };
            }),
        });

    } catch (err) {
        logger.error(`[Licenses] Failed to fetch licenses for user '${req.userId}': ${err}`);
        return sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;
