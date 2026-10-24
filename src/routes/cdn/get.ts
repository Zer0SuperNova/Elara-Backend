import express from 'express';
import { errors, sendError } from '../../utils/errors.js';
import logger from '../../handler/logger.js';
import { ensureImageCached } from '../../master/imageLoader.js';
import { PSK } from '../../types/psk.js';
import { logAppEvent, analyticsContext } from '../../analytics/index.js';

const router = express.Router();

export const config = {
    auth:      false,
    encrypted: true,
    allowedPsk: [PSK.LOADER, PSK.CORE]
};

/**
 * Serves a cached asset from Redis by key.
 * @route GET /api/v1/cdn
 * @access Public
 */
router.post('/api/v1/cdn', async (req, res) => {
    const key = req.body.key;

    const logCdn = (action: string, status: number, extra: Record<string, unknown> = {}): void =>
        logAppEvent({
            category: 'cdn',
            action,
            target_id: typeof key === 'string' ? key : '',
            ...analyticsContext(req),
            meta: { status, ...extra },
        });

    try {
        if (typeof key !== 'string' || !key) {
            logCdn('rejected', 400, { reason: 'invalid_key' });
            return sendError(res, errors.BAD_REQUEST, `Invalid asset key: ${key}`);
        }

        // Serve from Redis
        const data = await ensureImageCached(key);

        if (!data) {
            logger.debug(`[CDN] Asset not found: ${key}`);
            logCdn('not_found', 404);
            return sendError(res, errors.NOT_FOUND, `Asset not found: ${key}`);
        }

        if (data.length < 1 * 1024 || data.length > 10 * 1024 * 1024) { // min 1 KB, max 10 MB
            logger.debug(`[CDN] Asset size out of range: ${key} (${data.length} bytes)`);
            logCdn('rejected', 400, { bytes: data.length, reason: 'size_out_of_range' });
            return sendError(res, errors.BAD_REQUEST, `Asset size out of range: ${key} (${data.length} bytes)`);
        }

        logger.debug(`[CDN] Serving asset: ${key} (${data.length} bytes)`);
        res.type('application/octet-stream');
        res.write(data);
        res.end();
        logCdn('served', 200, { bytes: data.length });

    } catch (err) {
        logger.error(`[CDN] Failed to serve asset '${key}': ${err}`);
        logCdn('error', 500);
        return sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;