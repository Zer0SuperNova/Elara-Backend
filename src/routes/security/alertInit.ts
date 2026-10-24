import express from 'express';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { errors, sendError } from '../../utils/errors.js';
import logger from '../../handler/logger.js';
import redis from '../../database/redis.js';
import { PSK } from '../../types/psk.js';
import { createSecurityAlert, failSecurityAlert } from '../../repositories/securityAlerts.js';
import { getUserIdBySessionToken } from '../../repositories/user.js';
import { analyticsContext, logAppEvent } from '../../analytics/index.js';

const router = express.Router();

export const config = {
    auth: false,
    encrypted: true,
    allowedPsk: [PSK.LOADER, PSK.CORE],
};

const TOKEN_TTL_SECONDS = 60;
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const MAX_PROCESSES = 1024;
const MAX_PROCESS_NAME_LENGTH = 260;
const MAX_PROCESS_CHARS = 128 * 1024;
const ALLOWED_IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp']);

function uploadTokenKey(token: string): string {
    return `security-alert:upload:${createHash('sha256').update(token).digest('hex')}`;
}

router.post('/api/v1/security/alert/init', async (req, res) => {
    let alertId = '';

    try {
        const title = typeof req.body?.title === 'string' ? req.body.title.trim() : '';
        const description = typeof req.body?.description === 'string' ? req.body.description.trim() : '';
        const contentType = req.body?.content_type;
        const imageSize = req.body?.image_size;
        const rawProcesses = req.body?.processes;
        const sessionId = req.header('X-Session');

        const processes = Array.isArray(rawProcesses)
            ? rawProcesses
                .map((value: unknown) => typeof value === 'string' ? value.trim() : value)
                .filter((value: unknown) =>
                    typeof value !== 'string' || !(value.startsWith('[') && value.endsWith(']')))
            : null;
        const processChars = processes?.reduce(
            (total: number, value: unknown) => total + (typeof value === 'string' ? value.length : 0),
            0,
        ) ?? 0;

        if (!title || title.length > 120 ||
            !description || description.length > 4000 ||
            !processes || processes.length > MAX_PROCESSES ||
            processes.some((value: unknown) =>
                typeof value !== 'string' || value.length === 0 || value.length > MAX_PROCESS_NAME_LENGTH) ||
            processChars > MAX_PROCESS_CHARS ||
            typeof contentType !== 'string' || !ALLOWED_IMAGE_TYPES.has(contentType) ||
            !Number.isInteger(imageSize) || imageSize < 1 || imageSize > MAX_IMAGE_BYTES ||
            !sessionId || !req.e2eSession || !req.pskType) {
            return sendError(res, errors.BAD_REQUEST);
        }

        alertId = randomUUID();
        const uploadToken = randomBytes(32).toString('hex');
        const userId = req.e2eSession.userId
            ?? await getUserIdBySessionToken(req.body?.token)
            ?? undefined;
        if (userId) req.userId = userId;

        await createSecurityAlert({
            id: alertId,
            title,
            description,
            processes: processes as string[],
            imageType: contentType,
            imageSize,
            userId,
            buildId: req.buildId,
            loaderId: req.loaderId,
            pskType: req.pskType,
        });

        await redis.getClient().set(
            uploadTokenKey(uploadToken),
            JSON.stringify({
                alertId,
                sessionId,
                pskType: req.pskType,
                contentType,
                imageSize,
            }),
            { EX: TOKEN_TTL_SECONDS },
        );

        logAppEvent({
            category: 'security',
            action: 'alert_initialized',
            target_id: alertId,
            ...analyticsContext(req),
            user_id: userId,
            meta: {
                content_type: contentType,
                image_size: imageSize,
                process_count: processes.length,
            },
        });

        return res.json({
            success: true,
            alert_id: alertId,
            upload_token: uploadToken,
            expires_in: TOKEN_TTL_SECONDS,
        });
    } catch (err) {
        if (alertId) {
            await failSecurityAlert(alertId, 'initialization_failed').catch(() => undefined);
        }
        logger.error(`[Security/Alert] Failed to initialize alert: ${err}`);
        return sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;
