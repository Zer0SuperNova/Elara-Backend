import { Request, Response, NextFunction } from 'express';
import { createHash } from 'node:crypto';
import { errors, sendError } from '../utils/errors.js';
import logger from '../handler/logger.js';
import redis from '../database/redis.js';
import { getUserById, invalidateUserSession } from '../repositories/user.js';

/**
 * Creates a SHA-256 hash for a session token.
 *
 * @param token - Raw session token.
 * @returns Hex-encoded SHA-256 hash of the token.
 */
function hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
}

/**
 * Authenticates incoming requests using a token stored in the request body.
 *
 * Skips authentication when the route config explicitly disables auth.
 * Enforces PSK access control after E2E URL rewriting has resolved the real route.
 * Validates the token against Redis, verifies the associated user is active,
 * and invalidates the session if the password was changed after it was created.
 *
 * @param req  - Express request object.
 * @param res  - Express response object.
 * @param next - Express next middleware function.
 * @returns A response when authentication fails, otherwise calls next().
 */
export default async function authMiddleware(
    req: Request,
    res: Response,
    next: NextFunction,
): Promise<void | Response> {

    // Re-enforce PSK access control here since pskGate checked against /hit,
    // but E2E has since rewritten the URL to the real action route.
    if (req.routeConfig?.allowedPsk && req.pskType && !req.routeConfig.allowedPsk.includes(req.pskType)) {
        logger.warn(`[Auth] "${req.pskType}" PSK is not permitted to access route ${req.originalUrl}`);
        return sendError(res, errors.FORBIDDEN);
    }

    if (req.routeConfig?.audience && req.routeConfig.audience !== req.pskType) {
        logger.warn(`[Auth] "${req.pskType}" PSK does not match required audience "${req.routeConfig.audience}" on ${req.originalUrl}`);
        return sendError(res, errors.FORBIDDEN);
    }

    if (req.routeConfig?.auth === false) return next();

    const token = req.body?.token;
    if (typeof token !== 'string') {
        logger.warn(`[Auth] Missing or invalid token in request to ${req.originalUrl}`);
        return sendError(res, errors.UNAUTHORIZED);
    }

    const tokenHash   = hashToken(token);
    const redisClient = redis.getClient();

    const rawSession = await redisClient.get(`session:token:${tokenHash}`);
    if (!rawSession) {
        logger.warn(`[Auth] Unknown or expired token on ${req.originalUrl}`);
        return sendError(res, errors.UNAUTHORIZED);
    }

    const session = JSON.parse(rawSession);

    const user = await getUserById(session.userId);
    if (!user) {
        logger.warn(`[Auth] User '${session.userId}' not found — invalidating session`);
        await invalidateUserSession(tokenHash, session.userId);
        return sendError(res, errors.UNAUTHORIZED);
    }

    // If the users password was reset after this session was created,
    // the session is stale invalidate it and force re-login.
    if (user.last_password_reset) {
        const passwordResetAt = new Date(user.last_password_reset).getTime();
        if (session.createdAt < passwordResetAt) {
            logger.warn(`[Auth] Session predates password reset for '${user.username}' — invalidating`);
            await invalidateUserSession(tokenHash, user.id);
            return sendError(res, errors.UNAUTHORIZED);
        }
    }

    // Banned or suspended accounts are rejected and their session cleaned up.
    if (user.status !== 'active') {
        logger.warn(`[Auth] ${user.status} account '${user.username}' attempted access — invalidating session`);
        await invalidateUserSession(tokenHash, user.id);
        return sendError(res, errors.FORBIDDEN);
    }

    req.userId  = session.userId;
    req.session = session;

    logger.debug(`[Auth] Authenticated user '${user.username}' on ${req.originalUrl}`);

    next();
}