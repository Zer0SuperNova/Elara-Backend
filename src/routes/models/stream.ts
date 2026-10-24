import express from 'express';
import { errors, sendBinaryError } from '../../utils/errors.js';
import { ensureModelChunked } from '../../master/chunker.js';
import redis from '../../database/redis.js';
import logger from '../../handler/logger.js';
import { PSK } from '../../types/psk.js';

const router = express.Router();

/**
 * Route configuration for model streaming.
 */
export const config = {
    auth: true,
    encrypted: true,
    allowedPsk: [PSK.CORE]
}

/**
 * Handles model stream requests.
 *
 * Validates the request token, resolves the model ID, and streams the model
 * to the client when authorized.
 */
router.post('/api/v1/model/stream', async (
    req: express.Request,
    res: express.Response,
) => {
    try {
        // Validate token
        const token = req.body.downloadToken;
        if (typeof token !== 'string') {
            sendBinaryError(res, errors.BAD_REQUEST, `Invalid token in model stream request: ${token}`);
            logger.debug(`Invalid token in model stream request: ${token}`);
            return;
        }

        // Atomically get and delete the token to prevent reuse
        const modelId = await redis.getClient().getDel(`model:token:${token}`);
        if (!modelId) {
            sendBinaryError(res, errors.UNAUTHORIZED, `Unauthorized token in model stream request: ${token}`);
            logger.debug(`Unauthorized token in model stream request: ${token}`);
            return;
        }

        // Ensure the model is cached
        const ready = await ensureModelChunked(modelId);
        if (!ready) {
            sendBinaryError(res, errors.NOT_FOUND, `Model not found for token in model stream request: ${token}`);
            logger.debug(`Model not found for token in model stream request: ${token}`);
            return;
        }

        // Stream the model to the client
        res.sendModelStream(modelId);

    } catch (err) {
        console.error(err);

        sendBinaryError(res, errors.INTERNAL, String(err));
    }
});

export default router;