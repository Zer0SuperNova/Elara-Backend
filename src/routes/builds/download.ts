import express from 'express';
import { GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { errors, sendBinaryError } from '../../utils/errors.js';
import logger from '../../handler/logger.js';
import redis from '../../database/redis.js';
import { getS3Client } from '../../database/s3.js';
import { getBuildById } from '../../repositories/builds.js';
import { PSK } from '../../types/psk.js';
import { logAppEvent, analyticsContext } from '../../analytics/index.js';

const router = express.Router();

const S3_BUCKET = 'builds';

export const config = {
    auth:       true,
    encrypted:  true,
    allowedPsk: [PSK.LOADER],
};

/**
 * Downloads a build zip from S3 and streams it encrypted to the client,
 * then deletes it from S3. Download token is single-use (getDel) with a 60s TTL.
 *
 * @route POST /api/v1/build/download
 * @access Loader only
 */
router.post('/api/v1/build/download', async (req: express.Request, res: express.Response) => {
    const userId = req.userId as string;

    try {
        const { download_token } = req.body;

        if (typeof download_token !== 'string') {
            logger.warn(`[Build/Download] Invalid token from user '${userId}'`);
            return sendBinaryError(res, errors.BAD_REQUEST, `Invalid token from user '${userId}'`);
        }

        const buildId = await redis.getClient().getDel(`build:token:${download_token}`);
        if (!buildId) {
            logger.warn(`[Build/Download] Invalid or expired token from user '${userId}'`);
            return sendBinaryError(res, errors.UNAUTHORIZED, `Invalid or expired token from user '${userId}'`);
        }

        const build = await getBuildById(buildId);
        if (!build) {
            logger.error(`[Build/Download] Build '${buildId}' not found for user '${userId}'`);
            return sendBinaryError(res, errors.NOT_FOUND, `Build '${buildId}' not found for user '${userId}'`);
        }

        const client = getS3Client();
        if (!client) {
            logger.error(`[Build/Download] S3 client not initialized`);
            return sendBinaryError(res, errors.INTERNAL, 'S3 client not initialized');
        }

        const s3Object = await client.send(new GetObjectCommand({
            Bucket: S3_BUCKET,
            Key:    build.zip_name,
        }));

        if (!s3Object.Body) {
            logger.error(`[Build/Download] S3 object body missing for '${build.zip_name}'`);
            return sendBinaryError(res, errors.NOT_FOUND, `S3 object body missing for '${build.zip_name}'`);
        }

        const payload = Buffer.concat(
            await Array.fromAsync(s3Object.Body as AsyncIterable<Uint8Array>)
        );

        logger.debug(`[Build/Download] Streaming '${build.zip_name}' (${payload.length} bytes) to user '${userId}'`);
        res.sendStream(payload);
        logger.info(`[Build/Download] Streamed '${build.zip_name}' to user '${userId}'`);
        logAppEvent({
            category: 'build',
            action: 'downloaded',
            ...analyticsContext(req),
            user_id: userId,
            target_id: buildId,
            build_id: buildId,
            meta: { zip_name: build.zip_name, bytes: payload.length },
        });

        try {
            await client.send(new DeleteObjectCommand({
                Bucket: S3_BUCKET,
                Key:    build.zip_name,
            }));
            logger.debug(`[Build/Download] Deleted '${build.zip_name}' from S3`);
        } catch (deleteErr) {
            logger.error(`[Build/Download] Failed to delete '${build.zip_name}' from S3: ${deleteErr}`);
        }

    } catch (err) {
        logger.error(`[Build/Download] Failed for user '${userId}': ${err}`);
        if (!res.headersSent) {
            sendBinaryError(res, errors.INTERNAL, String(err));
        }
    }
});

export default router;