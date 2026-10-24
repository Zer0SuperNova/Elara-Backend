import express from 'express';
import { errors, sendError } from '../../utils/errors.js';
import { getAllProducts, canAccessProductStatus } from '../../repositories/products.js';
import logger from '../../handler/logger.js';
import { PSK } from '../../types/psk.js';
import { getLicensesByAccountId, hasEffectiveLicense } from '../../repositories/license.js';
import { getUserPermissions, permissionsInclude } from '../../rbac/rbac.js';
import { Permission } from '../../rbac/permissions.js';
const router = express.Router();

export const config = {
    auth:      true,
    encrypted: true,
    allowedPsk: [PSK.LOADER, PSK.CORE]
};

/**
 * Checks if the user has permissions to use a specific product. (for a Heartbeat)
 * @route GET /api/v1/products
 * @access Protected
 */
router.post('/api/v1/product/check', async (req: express.Request, res: express.Response) => {
    try {
        const { productId } = req.body;
        const userId = req.userId as string;
        if (!productId) {
            logger.warn(`[Products] Missing productId in request body`);
            return sendError(res, errors.BAD_REQUEST, 'Missing productId in request body');
        }

        const perms    = await getUserPermissions(userId);
        const licenses = await getLicensesByAccountId(userId);
        const products = await getAllProducts();

        const product = products.find(p => p.id === productId);
        if (!product) {
            logger.warn(`[Products] Product with ID '${productId}' not found`);
            return sendError(res, errors.NOT_FOUND, `Product with ID '${productId}' not found`);
        }

        const isAdmin = permissionsInclude(perms, Permission.Admin);
        if (isAdmin) {
            return res.json({ access: true });
        }

        const hasLicense = hasEffectiveLicense(licenses, productId);
        const canUse = canAccessProductStatus(product.status, perms);


        return res.json({
            access: canUse && hasLicense,
        });

    } catch (err) {
        logger.error(`[Products] Failed to fetch products: ${err}`);
        return sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;
