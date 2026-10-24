import express from 'express';
import { errors, sendError } from '../../utils/errors.js';
import { getLatestExpiringLicense, getLicensesByAccountId } from '../../repositories/license.js';
import { getProductById } from '../../repositories/products.js';
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
 * Checks license via product id and returns a time. with active: false / true. Admins get a fake 20 year expiry for convenience.
 * @route POST /api/v1/license/check
 * @access Protected
 */
router.post('/api/v1/license/check', async (req: express.Request, res: express.Response) => {
    try {
        const userId = req.userId as string;

        const { product_id } = req.body;
        if (typeof product_id !== 'string' || product_id.trim().length === 0) {
            logger.warn(`[Licenses] Invalid product_id in license check request from user '${userId}'`);
            return sendError(res, errors.BAD_REQUEST, `Invalid product_id in license check request from user '${userId}'`);
        }

        // does product exist in database
        const product = await getProductById(product_id);
        if (!product) {
            logger.warn(`[Licenses] Product not found in license check request from user '${userId}'`);
            return sendError(res, errors.NOT_FOUND, `Product not found in license check request from user '${userId}'`);
        }


        // check if user has a valid license for the product
        const licenses = await getLicensesByAccountId(userId);
        const activeLicense = getLatestExpiringLicense(licenses, product_id);

        // check if user is admin
        const permissions = await getUserPermissions(userId);
        const isAdmin = permissionsInclude(permissions, Permission.Admin);

        // Admins get a synthetic 20-year expiry for convenience; everyone else gets their real license expiry.
        let expiresAt: Date | null = activeLicense?.expires_at ?? null;
        if (isAdmin) {
            expiresAt = new Date();
            expiresAt.setFullYear(expiresAt.getFullYear() + 20);
        }

        return res.json({
            active: Boolean(activeLicense) || isAdmin,
            expires_at: expiresAt ? expiresAt.toISOString() : null,
        });

    } catch (err) {
        logger.error(`[Licenses] Failed to fetch licenses for user '${req.userId}': ${err}`);
        return sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;
