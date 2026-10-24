import { Request, Response, NextFunction } from 'express';
import { logApiRequest, analyticsContext } from '../analytics/index.js';
import logger from '../handler/logger.js';

/**
 * Records a request-level analytics event once the response finishes.
 *
 * Reads request context (user, PSK, IP) at finish time, so fields populated by
 * later middleware are captured regardless of registration order. Fire-and-forget.
 *
 * @param req  - Express request object.
 * @param res  - Express response object.
 * @param next - Express next middleware function.
 */
export default function analyticsLogger(req: Request, res: Response, next: NextFunction): void {
    const start = process.hrtime.bigint();

    res.on('finish', () => {
        try {
            const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
            const ctx = analyticsContext(req);
            const authenticated = req.routeConfig?.auth === true || Boolean(req.session) || Boolean(req.userId);
            if (res.statusCode < 400 && authenticated && !ctx.user_id) {
                logger.error(
                    `[Analytics] ${req.method} ${req.path} finished ${res.statusCode} without a user_id — ` +
                    `authenticated request logged with empty identity (psk=${ctx.psk_type || 'none'})`,
                );
            }

            logApiRequest({
                method: req.method,
                route: req.path,
                status: res.statusCode,
                duration_ms: Math.round(durationMs),
                ...ctx,
            });
        } catch (err) {
            logger.warn(`[Analytics] access-log handler failed: ${err}`);
        }
    });

    next();
}
