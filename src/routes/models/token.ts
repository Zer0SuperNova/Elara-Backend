import express from 'express';
import { randomUUID } from 'node:crypto';
import { errors, sendError } from '../../utils/errors.js';
import { getModelById } from '../../repositories/models.js';
import redis from '../../database/redis.js';
import logger from '../../handler/logger.js';
import { getLicensesByAccountId, hasEffectiveLicense } from '../../repositories/license.js';
import { getProductByModelId, canAccessProductStatus} from '../../repositories/products.js';
import { PSK } from '../../types/psk.js';
import { getUserPermissions, permissionsInclude } from '../../rbac/rbac.js';
import { Permission } from '../../rbac/permissions.js';

const router = express.Router();

/**
 * Time-to-live for issued model tokens in seconds.
 * @constant {number}
 */
const TOKEN_TTL_S = 30;

/**
 * Route configuration indicating whether authentication and encryption
 * are required for routes in this module.
 * @type {{auth: boolean, encrypted: boolean}}
 */
export const config = {
    auth: true,
    encrypted: true,
    allowedPsk: [PSK.CORE]
}

/**
 * POST /api/v1/model/token
 * Issue a short-lived token for a model given its ID.
 * The token is stored in Redis with a TTL and the response contains
 * the token and the model hash.
 *
 * Request body:
 * - id: string (model id)
 *
 * Response JSON:
 * - token: string
 * - hash: string
 *
 * @param {express.Request} req - Express request object
 * @param {express.Response} res - Express response object
 */
router.post('/api/v1/model/token', async (
    req: express.Request,
    res: express.Response,
) => {
    try {
        // Validate model ID (may be a model id or a product id)
        const requestedId = req.body.id;
        if (typeof requestedId !== 'string') {
            logger.debug(`[Model] Invalid model ID in token request: ${requestedId}`);
            sendError(res, errors.BAD_REQUEST, `Invalid model ID in token request: ${requestedId}`);
            return;
        }

        // getModelById resolves a product id to its model internally, so `model.id`
        // is the authoritative model id to issue the token and return the hash for.
        const model = await getModelById(requestedId);
        if (!model) {
            logger.warn(`[Model] Model not found: ${requestedId}`);
            sendError(res, errors.NOT_FOUND, `Model not found: ${requestedId}`);
            return;
        }

        const modelId = model.id;

        // Resolve product for this model
        const product = await getProductByModelId(modelId);
        if (!product) {
            logger.warn(`[Model] No active product found for model ${modelId}`);
            sendError(res, errors.INTERNAL, `No active product found for model ${modelId}`);
            return;
        }

        // check if product is beta ony and if user has beta access
        const userId = req.userId as string;
        if (!userId) {
            logger.warn(`[Model] Missing user ID in request for model token`);
            sendError(res, errors.UNAUTHORIZED, 'Missing user ID in request for model token');
            return;
        }


        const perms = await getUserPermissions(userId);
        if (!canAccessProductStatus(product.status, perms)) {
            logger.debug(`[Model] User ${userId} does not have access to product ${product.id} with status ${product.status}`);
            sendError(res, errors.FORBIDDEN, `User ${userId} does not have access to product ${product.id} (status ${product.status})`);
            return;
        }

        // Check if user has an active, non-expired license for this model
        const isUserAdmin = permissionsInclude(perms, Permission.Admin);

        if (!isUserAdmin) {
            const licenses = await getLicensesByAccountId(userId);
            const hasAccess = hasEffectiveLicense(licenses, product.id);

            if (!hasAccess) {
                logger.debug(`[Model] User ${userId} has no active license for model ${modelId}`);
                sendError(res, errors.FORBIDDEN, `User ${userId} has no active license for model ${modelId}`);
                return;
            }
        }

        // generate a UUID token and store it in Redis with TTL
        const token = randomUUID();
        await redis.getClient().setEx(`model:token:${token}`, TOKEN_TTL_S, modelId);

        logger.debug(`[Model] Token issued for model ${modelId}`);

        const hash = model.hash;
        if(!hash) {
            logger.error(`[Model] Missing hash for model ${modelId}`);
            sendError(res, errors.INTERNAL, `Missing hash for model ${modelId}`);
            return;
        }

        // Respond with the token and the model hash
        res.json({ 
            token: token,
            hash: model.hash.toLowerCase()
         });

    } catch (err) {
        logger.error(`[Model] Unexpected error: ${err}`);
        sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;
