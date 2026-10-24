import express from 'express';
import { randomBytes } from 'node:crypto';
import { errors, sendError } from '../../utils/errors.js';
import logger from '../../handler/logger.js';
import redis from '../../database/redis.js';
import db from '../../database/mysql.js';
import {
    claimInactiveBuild,
    markBuildActive,
    createUserBuild,
    revokeExistingUserBuilds,
    deactivateBuild,
    getUserBuildForProduct,
} from '../../repositories/builds.js';
import { buildEffectiveLicenses, getLicensesByAccountId } from '../../repositories/license.js';
import { PSK } from '../../types/psk.js';
import { getProductsByFamily } from '../../repositories/products.js';
import { getUserPermissions, permissionsInclude } from '../../rbac/rbac.js';
import { Permission } from '../../rbac/permissions.js';

const router = express.Router();

const BUILD_REQUEST_LIMIT = 5;
const BUILD_REQUEST_WINDOW_SECONDS = 5 * 60;
const DOWNLOAD_TOKEN_TTL = 200;

export const config = {
    auth:       true,
    encrypted:  true,
    allowedPsk: [PSK.LOADER],
};

/**
 * Requests a build for the authenticated user.
 * Enforces a 10/day rate limit, checks license, revokes old builds,
 * claims a new one from the pool and returns an AES key + download token.
 *
 * @route POST /api/v1/build/request
 * @access Loader only
 */
router.post('/api/v1/build/request', async (req: express.Request, res: express.Response) => {
    const userId = req.userId as string;

    try {
        const { product_id } = req.body;

        if (typeof product_id !== 'string' || product_id.trim().length === 0) {
            logger.warn(`[Build/Request] Invalid product_id from user '${userId}'`);
            return sendError(res, errors.BAD_REQUEST, `Invalid product_id from user '${userId}'`);
        }

        // License check
        const [licenses, familyProducts] = await Promise.all([
            getLicensesByAccountId(userId),
            getProductsByFamily(product_id),
        ]);

        const familyProductIds = new Set(familyProducts.map(p => p.id));
        const hasLicense = buildEffectiveLicenses(licenses).some(l => familyProductIds.has(l.product_id));

        const isAdmin = await getUserPermissions(userId).then(perms => permissionsInclude(perms, Permission.Admin));
        if (!hasLicense && !isAdmin) {
            logger.warn(`[Build/Request] User '${userId}' has no active license for product '${product_id}'`);
            return sendError(res, errors.FORBIDDEN, `User '${userId}' has no active license for product '${product_id}'`);
        }


        const rateLimitKey = `user:${userId}:build_requests`;
        const redisClient = redis.getSessionClient();

        const newCount = await redisClient.incr(rateLimitKey);

        if (newCount === 1) {
            await redisClient.expire(rateLimitKey, BUILD_REQUEST_WINDOW_SECONDS);
        }

        if (newCount > BUILD_REQUEST_LIMIT) {
            logger.warn(`[Build/Request] User '${userId}' hit 5-minute build request limit`);
            return sendError(res, errors.RATE_LIMITED, `User '${userId}' hit 5-minute build request limit`);
        }

        const refundQuota = async (): Promise<void> => {
            try {
                await redisClient.decr(rateLimitKey);
            } catch (refundErr) {
                logger.warn(`[Build/Request] Failed to refund quota for user '${userId}': ${refundErr}`);
            }
        };

        // Ensure a build is available before opening a transaction
        const availableBuild = await claimInactiveBuild(product_id);
        if (!availableBuild) {
            logger.warn(`[Build/Request] No inactive builds available for product '${product_id}'`);
            await refundQuota();
            return sendError(res, errors.SERVICE_UNAVAILABLE, `No inactive builds available for product '${product_id}'`);
        }

        const aesKey = randomBytes(32).toString('hex');

        try {
            await db.transaction(async (conn) => {
                const existingUserBuild = await getUserBuildForProduct(userId, product_id, conn);
                if (existingUserBuild) {
                    await revokeExistingUserBuilds(userId, product_id, conn);
                    await deactivateBuild(existingUserBuild.build_id, conn);
                    logger.debug(`[Build/Request] Revoked previous build for user '${userId}' on product '${product_id}'`);
                }

                await markBuildActive(availableBuild.id, conn);
                await createUserBuild(userId, availableBuild.id, product_id, aesKey, conn);
            });
        } catch (txErr) {
            await refundQuota();
            throw txErr;
        }

        const downloadToken = randomBytes(32).toString('hex');
        await redisClient.setEx(`build:token:${downloadToken}`, DOWNLOAD_TOKEN_TTL, availableBuild.id);

        logger.info(`[Build/Request] User '${userId}' claimed build '${availableBuild.id}' for product '${product_id}'`);

        return res.json({
            download_token: downloadToken,
            build_hash:     availableBuild.hash,
            zip_name:       availableBuild.zip_name,
            aes_key:        aesKey,
        });

    } catch (err) {
        logger.error(`[Build/Request] Failed for user '${userId}': ${err}`);
        return sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;
