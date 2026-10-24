import express from 'express';
import { createHash } from 'node:crypto';
import { errors, sendError } from '../../utils/errors.js';
import { getActive, getActiveTimeElapsed, refreshActive, deleteActive } from '../../session/store.js';
import { addOnlineTime } from '../../repositories/user.js';
import { getBuildByHash } from '../../repositories/builds.js';
import logger from '../../handler/logger.js';
import redis from '../../database/redis.js';
import { PSK } from '../../types/psk.js';

const router = express.Router();

export const config = {
    auth:       false,
    encrypted:  true,
    allowedPsk: [PSK.LOADER, PSK.CORE],
};

/**
 * Keeps the E2E session alive and tracks online time for authenticated users.
 *
 * For anonymous requests (no token), only the E2E session TTL is refreshed.
 * For authenticated requests, the elapsed time since the last heartbeat is
 * calculated from the session TTL and flushed to the database before refreshing.
 *
 * Returns 401 if the session has expired so the client knows to re-handshake.
 *
 * @route POST /api/v1/heartbeat
 * @access Public (E2E encrypted, no auth token required)
 */
router.post('/api/v1/heartbeat', async (req: express.Request, res: express.Response) => {
    const sessionId = req.header('X-Session');

    if (!sessionId) {
        logger.warn(`[Heartbeat] Missing session header`);
        return sendError(res, errors.BAD_REQUEST, 'Missing session header');
    }

    try {
        const delta = await getActiveTimeElapsed(sessionId);
        if (delta === null) {
            logger.warn(`[Heartbeat] Session expired — re-handshake required`);
            return sendError(res, errors.UNAUTHORIZED, 'Session expired — re-handshake required');
        }

        // reject if the CORE build this E2E session was made for has been deactivated: let the session die
        const session = await getActive(sessionId);
        if (session?.buildHash) {
            const build = await getBuildByHash(session.buildHash);
            if (build?.status === 'deactivated') {
                logger.warn(`[Heartbeat] Build '${build.id}' deactivated. letting session die`);
                await deleteActive(sessionId);
                return sendError(res, errors.UNAUTHORIZED, 'Build deactivation detected — session terminated');
            }
        }

        await refreshActive(sessionId);

        const token = req.body?.token;
        if (typeof token === 'string') {
            const tokenHash = createHash('sha256').update(token).digest('hex');
            const raw       = await redis.getClient().get(`session:token:${tokenHash}`);

            if (raw) {
                const { userId } = JSON.parse(raw);
                await addOnlineTime(userId, delta);
                logger.debug(`[Heartbeat] Tracked ${delta}s for user '${userId}'`);
            }
        } else {
            logger.debug(`[Heartbeat] Anonymous — E2E session refreshed only`);
        }

        return res.json({ success: true });

    } catch (err) {
        logger.error(`[Heartbeat] Failed: ${err}`);
        return sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;