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
 * Returns all active products.
 * @route GET /api/v1/products
 * @access Protected
 */
router.post('/api/v1/products', async (req: express.Request, res: express.Response) => {
    try {
        const perms    = await getUserPermissions(req.userId!);
        const isAdmin  = permissionsInclude(perms, Permission.Admin);

        const licenses = isAdmin ? [] : await getLicensesByAccountId(req.userId!);
        const products = await getAllProducts();

        const hasLicense = (productId: string) =>
            isAdmin ||
            hasEffectiveLicense(licenses, productId);

        return res.json({
            products: products.map(p => ({
                id:              p.id,
                family:          p.family,
                status:          p.status,
                name:            p.name,
                description:     p.description,
                loader_image_id: p.loader_image_id,
                executable_name: p.executable_name,
                can_use:  canAccessProductStatus(p.status, perms),
                licensed: hasLicense(p.id),
            })),
        });

    } catch (err) {
        logger.error(`[Products] Failed to fetch products: ${err}`);
        return sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;
