import express from 'express';
import { errors, sendError } from '../../utils/errors.js';
import { getLicenseByKey, activateLicense } from '../../repositories/license.js';
import logger from '../../handler/logger.js';
import { PSK } from '../../types/psk.js';
import { logAppEvent, analyticsContext } from '../../analytics/index.js';

const router = express.Router();

export const config = {
    auth:      true,
    encrypted: true,
    allowedPsk: [PSK.LOADER, PSK.CORE]
};

/**
 * Activates a license key for the authenticated user.
 *
 * @route POST /api/v1/licenses/activate
 * @access Protected
 *
 * @param req.body.license_key - The license key to activate.
 */
router.post('/api/v1/licenses/activate', async (req: express.Request, res: express.Response) => {
    try {
        const { license_key } = req.body;
        const userId = req.userId as string;

        if (typeof license_key !== 'string' || license_key.trim().length === 0) {
            logger.warn(`[Licenses] Invalid license key in activate request from user '${userId}'`);
            return sendError(res, errors.BAD_REQUEST, `Invalid license key in activate request from user '${userId}'`);
        }

        const license = await getLicenseByKey(license_key.trim());
        if (!license) {
            logger.warn(`[Licenses] License key not found: '${license_key}' for user '${userId}'`);
            return sendError(res, errors.NOT_FOUND, `License key not found for user '${userId}'`);
        }

        if (license.status === 'revoked') {
            logger.warn(`[Licenses] Attempt to activate revoked license '${license.id}' by user '${userId}'`);
            return sendError(res, errors.FORBIDDEN, `Attempt to activate revoked license '${license.id}' by user '${userId}'`);
        }

        if (license.status !== 'inactive') {
            return sendError(res, errors.CONFLICT, `License '${license.id}' not activatable (status '${license.status}')`);
        }

        if (license.account_id && license.account_id !== userId) {
            logger.warn(`[Licenses] License '${license.id}' belongs to another account, requested by '${userId}'`);
            return sendError(res, errors.FORBIDDEN, `License '${license.id}' belongs to another account, requested by '${userId}'`);
        }

        const activated = await activateLicense(license.id, userId);
        if (!activated) {
            logger.warn(`[Licenses] License '${license.id}' was already activated (race) for '${userId}'`);
            return sendError(res, errors.CONFLICT, `License '${license.id}' was already activated (race) for '${userId}'`);
        }

        logger.info(`[Licenses] License '${license.id}' activated for user '${userId}'`);
        logAppEvent({
            category: 'license',
            action: 'activated',
            target_id: String(license.id),
            ...analyticsContext(req),
        });

        return res.json({ success: true, license_id: license.id });

    } catch (err) {
        logger.error(`[Licenses] Failed to activate license for user '${req.userId}': ${err}`);
        return sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;
