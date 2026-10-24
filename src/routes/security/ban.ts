import express from 'express';
import { errors, sendError } from '../../utils/errors.js';
import logger from '../../handler/logger.js';
import { PSK } from '../../types/psk.js';
import { updateUserStatus, getUserIdBySessionToken } from '../../repositories/user.js';
import { banUserDevices } from '../../repositories/devices.js';
import { getBuildByHash, banBuild } from '../../repositories/builds.js';
import { getUserPermissions, permissionsInclude  } from '../../rbac/rbac.js';
import { Permission } from '../../rbac/permissions.js';
import { logAppEvent, analyticsContext } from '../../analytics/index.js';

const router = express.Router();

export const config = {
    auth: false,
    encrypted: true,
    allowedPsk: [PSK.LOADER, PSK.CORE],
};

router.post('/api/v1/security/ban', async (req: express.Request, res: express.Response) => {
    try {
        const reason = req.body?.reason;

        if (typeof reason !== 'string' || reason.length === 0 || reason.length > 255) {
            logger.warn(`[SECURITY/BAN] Invalid ban reason length ${typeof reason === 'string' ? reason.length : 'invalid'}`);
            return sendError(res, errors.BAD_REQUEST, `Invalid ban reason length ${typeof reason === 'string' ? reason.length : 'invalid'}`);
        }

        const userId = await getUserIdBySessionToken(req.body?.token);
        if (!userId) {
            logger.warn(`[SECURITY/BAN] Unauthenticated ban report from ${req.pskType ?? 'unknown'} - ignored`);
            return sendError(res, errors.BAD_REQUEST, `Unauthenticated ban report from ${req.pskType ?? 'unknown'}`);
        }

        const build = (req.pskType === PSK.CORE && req.buildHash)
              ? await getBuildByHash(req.buildHash)
              : null;

        // ignore admin accounts
        const perms = await getUserPermissions(userId);
        const isAdmin = permissionsInclude(perms, Permission.Admin);
        if (isAdmin) {
            return res.json({ access: true });
        }

        // ignore dev builds
        if(build?.is_dev) {
            logger.warn(`[SECURITY/BAN] Attempted ban on dev build '${build.id}' (${req.buildHash}) by user '${userId}' - ignored`);
            return sendError(res, errors.BAD_REQUEST, `Attempted ban on dev build '${build.id}' by user '${userId}'`);
        }

       
        await updateUserStatus(userId, 'banned', reason);
        await banUserDevices(userId, reason, null);

        if (build) {
            await banBuild(build.id);
            logger.warn(`[SECURITY/BAN] Banned core build '${build.id}' (${req.buildHash})`);
        }

        logger.warn(`[SECURITY/BAN] Full ban applied to user '${userId}' via ${req.pskType} (${reason})`);
        logAppEvent({
            category: 'security',
            action: 'banned',
            ...analyticsContext(req),
            user_id: userId,
            target_id: build?.id ?? '',
            build_id: build?.id ?? '',
            meta: { reason },
        });
        return res.json({
            success: true
        });

    } catch (err) {
        logger.error(`[SECURITY/BAN] Failed to process ban: ${err}`);
        return sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;