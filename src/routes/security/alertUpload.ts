import express from 'express';
import { createHash } from 'node:crypto';
import { errors, sendError } from '../../utils/errors.js';
import logger from '../../handler/logger.js';
import redis from '../../database/redis.js';
import { PSK } from '../../types/psk.js';
import { completeSecurityAlert, failSecurityAlert } from '../../repositories/securityAlerts.js';
import { storeSecurityAlertImage } from '../../master/securityAlertStorage.js';
import { analyticsContext, logAppEvent } from '../../analytics/index.js';

const router = express.Router();

export const config = {
    auth: false,
    encrypted: true,
    bodyType: 'binary' as const,
    allowedPsk: [PSK.LOADER, PSK.CORE],
};

const MAX_IMAGE_BYTES = 5 * 1024 * 1024;

interface UploadGrant {
    alertId: string;
    sessionId: string;
    pskType: string;
    contentType: string;
    imageSize: number;
}

function tokenKey(token: string): string {
    return `security-alert:upload:${createHash('sha256').update(token).digest('hex')}`;
}

async function consumeGrant(token: string, sessionId: string, pskType: string): Promise<UploadGrant | null> {
    const script = `
        local value = redis.call('GET', KEYS[1])
        if not value then return false end
        local grant = cjson.decode(value)
        if grant.sessionId ~= ARGV[1] then return false end
        if grant.pskType ~= ARGV[2] then return false end
        redis.call('DEL', KEYS[1])
        return value
    `;

    const result = await redis.getClient().eval(script, {
        keys: [tokenKey(token)],
        arguments: [sessionId, pskType],
    });

    return typeof result === 'string' ? JSON.parse(result) as UploadGrant : null;
}

function detectImageType(image: Buffer): { contentType: string; extension: string } | null {
    if (image.length >= 8 &&
        image.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
        return { contentType: 'image/png', extension: 'png' };
    }

    if (image.length >= 3 && image[0] === 0xff && image[1] === 0xd8 && image[2] === 0xff) {
        return { contentType: 'image/jpeg', extension: 'jpg' };
    }

    if (image.length >= 12 &&
        image.subarray(0, 4).toString('ascii') === 'RIFF' &&
        image.subarray(8, 12).toString('ascii') === 'WEBP') {
        return { contentType: 'image/webp', extension: 'webp' };
    }

    return null;
}

router.post('/api/v1/security/alert/upload', async (req, res) => {
    const image = req.body;
    const token = req.header('X-Upload-Token');
    const sessionId = req.header('X-Session');

    // Prevent binary evidence from being serialized into analytics/error logs.
    req.body = {
        binary_upload: true,
        bytes: Buffer.isBuffer(image) ? image.length : 0,
    };

    if (!Buffer.isBuffer(image) || !token || !sessionId ||
        image.length < 1 || image.length > MAX_IMAGE_BYTES) {
        return sendError(res, errors.BAD_REQUEST);
    }

    let grant: UploadGrant | null = null;

    try {
        grant = await consumeGrant(token, sessionId, req.pskType ?? '');
        if (!grant) {
            return sendError(res, errors.UNAUTHORIZED);
        }

        if (image.length !== grant.imageSize) {
            await failSecurityAlert(grant.alertId, 'image_size_mismatch');
            return sendError(res, errors.BAD_REQUEST);
        }

        const detected = detectImageType(image);
        if (!detected || detected.contentType !== grant.contentType) {
            await failSecurityAlert(grant.alertId, 'invalid_image_type');
            return sendError(res, errors.BAD_REQUEST);
        }

        const sha256 = createHash('sha256').update(image).digest('hex');
        const date = new Date().toISOString().slice(0, 10).replaceAll('-', '/');
        const imageKey = `${date}/${grant.alertId}/screenshot.${detected.extension}`;

        await storeSecurityAlertImage(imageKey, image, detected.contentType, sha256);
        await completeSecurityAlert(
            grant.alertId,
            imageKey,
            detected.contentType,
            image.length,
            sha256,
        );

        logAppEvent({
            category: 'security',
            action: 'alert_uploaded',
            target_id: grant.alertId,
            ...analyticsContext(req),
            meta: {
                image_key: imageKey,
                image_size: image.length,
                image_sha256: sha256,
            },
        });

        return res.json({ success: true, alert_id: grant.alertId });
    } catch (err) {
        if (grant) {
            await failSecurityAlert(grant.alertId, 'upload_failed').catch(() => undefined);
        }
        logger.error(`[Security/Alert] Failed to upload alert image: ${err}`);
        return sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;
