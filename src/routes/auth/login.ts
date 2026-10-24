import express, { type Request, type Response } from 'express';
import { createHash } from 'node:crypto';
import { errors, sendError } from '../../utils/errors.js';
import logger from '../../handler/logger.js';
import redis from '../../database/redis.js';
import { getUserPermissions, permissionsInclude } from '../../rbac/rbac.js';
import { Permission } from '../../rbac/permissions.js';
import {
    getUserByUsername,
    updateLastLogin,
    getUserById,
    verifyPassword,
    ensureHwidRegistered,
    generateHwid,
    extractStrongIdentifiers,
    extractHwidComponents,
    createSessionToken,
    invalidateUserSession,
    parseDeviceInfo,
    setCountryIsoForUser,
    setIpForUser,
} from '../../repositories/user.js';
import { buildLicensesPayload } from '../../repositories/license.js';
import { PSK } from '../../types/psk.js';
import {
    activateUserBuild,
    deactivateBuild,
    expireUserBuild,
    getBuildByHash,
    getBuildIdByHash,
    getActiveUserBuildId,
    getUserBuildByHash,
    isUserBuildExpired,
} from '../../repositories/builds.js';
import { stampUserId, stampBuild } from '../../session/store.js';
import { isDeviceBanned, recordDeviceIdentifiers } from '../../repositories/devices.js';
import { logAuthEvent, analyticsContext, type AuthEventInput } from '../../analytics/index.js';

const USERNAME_MIN = 3;
const USERNAME_MAX = 20;
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 72;
const USERNAME_REGEX = /^[a-zA-Z0-9äöüÄÖÜß\-.,@_]+$/;
const COUNTRY_ISO_REGEX = /^[A-Z]{2}$/;

type AppUser = NonNullable<Awaited<ReturnType<typeof getUserById>>>;
type AppError = (typeof errors)[keyof typeof errors];
type DeviceInfoRaw = Parameters<typeof parseDeviceInfo>[0];

interface CredentialsLoginParams {
    username: string;
    password: string;
    deviceInfoRaw: DeviceInfoRaw;
    countryIso: string | undefined;
    buildHash: string | undefined;
}

const router = express.Router();

export const config = {
    auth: false,
    encrypted: true,
    allowedPsk: [PSK.LOADER, PSK.CORE],
};

function isValidCountryIso(iso: unknown): iso is string {
    return (
        typeof iso === 'string' &&
        COUNTRY_ISO_REGEX.test(iso) &&
        iso !== 'XX' &&
        iso !== 'T1'
    );
}

async function maybeSetCountry(userId: AppUser['id'], iso: string | undefined): Promise<void> {
    if (!isValidCountryIso(iso)) return;
    try {
        await setCountryIsoForUser(userId, iso);
    } catch (err) {
        logger.warn(`[Login] Failed to set country ISO for user=${userId}: ${err}`);
    }
}

/**
 * Request-scoped fields shared by every auth analytics event.
 *
 * Reuses {@link analyticsContext} for the common origin fields and drops
 * `user_id`, which each auth event sets itself (failures often have no user),
 * then adds the auth-only `session_id`.
 */
function authContext(
    req: Request,
): Pick<AuthEventInput, 'psk_type' | 'ip' | 'country' | 'build_id' | 'loader_id' | 'session_id'> {
    const ctx = analyticsContext(req);
    return {
        psk_type: ctx.psk_type,
        ip: ctx.ip,
        country: ctx.country,
        build_id: ctx.build_id,
        loader_id: ctx.loader_id,
        session_id: req.header('X-Session') ?? '',
    };
}

async function sendAuthSuccess(res: Response, user: AppUser, token: string): Promise<Response> {
    const isAdmin = permissionsInclude(await getUserPermissions(user.id), Permission.Admin);
    return res.json({
        token,
        user: { username: user.username, role: user.role },
        licenses: await buildLicensesPayload(user.id, isAdmin),
    });
}

function validateCredentialsRequest(
    username: unknown,
    password: unknown,
    deviceInfoRaw: unknown,
): boolean {
    if (typeof username !== 'string' || typeof password !== 'string' || typeof deviceInfoRaw !== 'object') {
        logger.warn('[Login] Invalid login request format');
        return false;
    }
    if (username.length < USERNAME_MIN || username.length > USERNAME_MAX || !USERNAME_REGEX.test(username)) {
        logger.warn(`[Login] Invalid username in login request: '${username}'`);
        return false;
    }
    if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
        logger.warn(`[Login] Invalid password length in login request for '${username}'`);
        return false;
    }
    return true;
}

async function resolveBuildActivation(userId: AppUser['id'], buildHash: string): Promise<AppError | null> {
    const userBuild = await getUserBuildByHash(userId, buildHash);
    if (!userBuild) {
        logger.warn(`[Login] No active build for hash '${buildHash}' user '${userId}'`);
        return errors.GONE;
    }

    const build = await getBuildByHash(buildHash);
    if (!build?.is_dev && (await isUserBuildExpired(userBuild))) {
        await expireUserBuild(userBuild.id);
        await deactivateBuild(userBuild.build_id);
        logger.info(`[Login] Build expired for user '${userId}' (activated ${userBuild.activated_at})`);
        return errors.GONE;
    }

    if (userBuild.status === 'claimed') {
        try {
            await activateUserBuild(userId, buildHash);
            logger.info(`[Login] Core build activated for user '${userId}' hash '${buildHash}'`);
        } catch (err) {
            logger.error(`[Login] Failed to activate build '${buildHash}' for '${userId}': ${err}`);
            return errors.INTERNAL;
        }
    }

    return null;
}

/**
 * Resolves the build id for a resume's analytics, with fallbacks.
 *
 * Prefers the id E2E derived from the crypto session, then the build hash stamped
 * on the auth-token session, then a direct DB lookup of the user's active build.
 *
 * @param req       - The resume request (carries the E2E-resolved build id).
 * @param buildHash - The build hash persisted on the auth-token session, if any.
 * @param userId    - The resuming user, used for the DB fallback.
 * @returns The resolved build id, or '' when the user has no build.
 */
async function resolveResumeBuildId(req: Request, buildHash: string | undefined, userId: string): Promise<string> {
    if (req.buildId) return req.buildId;

    if (buildHash) {
        const id = await getBuildIdByHash(buildHash);
        if (id) return id;
        logger.warn(`[Login] Resume: token-session buildHash '${buildHash}' resolved to no build for user '${userId}'`);
    }

    const fallbackId = await getActiveUserBuildId(userId);
    if (fallbackId) {
        logger.debug(`[Login] Resume: build id resolved via DB fallback for user '${userId}' → ${fallbackId}`);
    } else {
        logger.warn(`[Login] Resume: no active build found in DB for user '${userId}'`);
    }
    return fallbackId;
}

async function handleResume(req: Request, res: Response, token: string, countryIso: string | undefined): Promise<Response> {
    const ctx = authContext(req);
    const ip = req.clientIp || 'unknown';
    const tokenHash = createHash('sha256').update(token).digest('hex');
    logger.debug(`[Login] Resume path — tokenHash=${tokenHash.slice(0, 12)}…`);

    const rawSession = await redis.getClient().get(`session:token:${tokenHash}`);
    if (!rawSession) {
        logger.debug(`[Login] Resume failed — no session for tokenHash=${tokenHash.slice(0, 12)}…`);
        logAuthEvent({ ...ctx, event_type: 'resume_failed', outcome: 'failure', reason: 'unknown_session' });
        return sendError(res, errors.UNAUTHORIZED, 'Resume failed — no session for token');
    }

    const session = JSON.parse(rawSession);
    const user = await getUserById(session.userId);

    if (user?.status !== 'active') {
        logger.debug(`[Login] Resume rejected — user=${session.userId} status=${user?.status ?? 'not-found'}`);
        logAuthEvent({ ...ctx, event_type: 'resume_failed', outcome: 'failure', reason: 'inactive_account', user_id: session.userId });
        return sendError(res, errors.FORBIDDEN, `Resume rejected — user ${session.userId} status ${user?.status ?? 'not-found'}`);
    }

    if (user.last_password_reset) {
        const resetAt = new Date(user.last_password_reset).getTime();
        if (session.createdAt < resetAt) {
            logger.debug(`[Login] Resume rejected — session predates password reset for user=${user.id}`);
            try {
                await invalidateUserSession(tokenHash, user.id);
            } catch (err) {
                logger.warn(`[Login] Failed to delete stale session token for user=${user.id}: ${err}`);
            }
            logAuthEvent({ ...ctx, event_type: 'resume_failed', outcome: 'failure', reason: 'stale_session', user_id: user.id, username: user.username });
            return sendError(res, errors.UNAUTHORIZED, `Resume rejected — session predates password reset for user ${user.id}`);
        }
    }

    logger.info(`[Login] Session resumed for '${user.username}'`);
    await updateLastLogin(user.id);
    await maybeSetCountry(user.id, countryIso);
    await setIpForUser(user.id, ip);
    req.userId = user.id;

    const sessionId = req.header('X-Session');
    if (sessionId) {
        if (!(await stampUserId(sessionId, user.id))) {
            logger.warn(`[Login] Resume: could not stamp userId onto session '${sessionId}' for user '${user.id}' (session missing/expired)`);
        }
        if (session.buildHash && !(await stampBuild(sessionId, session.buildHash))) {
            logger.warn(`[Login] Resume: could not stamp build '${session.buildHash}' onto session '${sessionId}' for user '${user.id}'`);
        }
    } else {
        logger.warn(`[Login] Resume: no X-Session header for user '${user.id}' — crypto session not stamped`);
    }

    const buildId = await resolveResumeBuildId(req, session.buildHash, user.id);
    logAuthEvent({ ...ctx, event_type: 'session_resumed', outcome: 'success', user_id: user.id, username: user.username, build_id: buildId });
    return sendAuthSuccess(res, user, token);
}

async function handleCredentialsLogin(
    req: Request,
    res: Response,
    { username, password, deviceInfoRaw, countryIso, buildHash }: CredentialsLoginParams,
): Promise<Response> {
    const ctx = authContext(req);
    const ip = req.clientIp || 'unknown';

    const deviceInfo = parseDeviceInfo(deviceInfoRaw);
    if (!deviceInfo) {
        logger.warn(`[Login] Invalid device info in login request for '${username}'`);
        logAuthEvent({ ...ctx, event_type: 'login_failed', outcome: 'failure', reason: 'invalid_device', username });
        return sendError(res, errors.BAD_REQUEST, `Invalid device info in login request for '${username}'`);
    }

    const hwid = generateHwid(deviceInfo);
    if (!hwid) {
        logger.warn(`[Login] Failed to generate HWID for login attempt by '${username}'`);
        logAuthEvent({ ...ctx, event_type: 'login_failed', outcome: 'failure', reason: 'invalid_device', username });
        return sendError(res, errors.BAD_REQUEST, `Failed to generate HWID for '${username}'`);
    }

    const strongIds = extractStrongIdentifiers(deviceInfo);
    if (strongIds.length === 0) {
        logger.warn(`[Login] No strong hardware identifiers in login request for '${username}'`);
        logAuthEvent({ ...ctx, event_type: 'login_failed', outcome: 'failure', reason: 'invalid_device', username });
        return sendError(res, errors.BAD_REQUEST, `No strong hardware identifiers for '${username}'`);
    }


    const hwidComponents = extractHwidComponents(deviceInfo);

    const user = await getUserByUsername(username);
    if (!user) {
        logger.debug(`[Login] Attempt with unknown username: '${username}'`);
        logAuthEvent({ ...ctx, event_type: 'login_failed', outcome: 'failure', reason: 'unknown_user', username, hwid });
        return sendError(res, errors.UNAUTHORIZED, `Unknown username: '${username}'`);
    }

    if (user.status !== 'active') {
        logger.debug(`[Login] Attempt on ${user.status} account: '${username}'`);
        logAuthEvent({ ...ctx, event_type: 'login_failed', outcome: 'failure', reason: 'inactive_account', user_id: user.id, username, hwid });
        return sendError(res, errors.FORBIDDEN, `Attempt on ${user.status} account: '${username}'`);
    }

    if (!user.password_hash) {
        logger.warn(`[Login] User '${username}' (${user.id}) has no password hash`);
        logAuthEvent({ ...ctx, event_type: 'login_failed', outcome: 'failure', reason: 'no_password_hash', user_id: user.id, username, hwid });
        return sendError(res, errors.INTERNAL, 'User has no password hash');
    }

    if (!(await verifyPassword(user, password))) {
        logger.debug(`[Login] Failed password for '${username}'`);
        logAuthEvent({ ...ctx, event_type: 'login_failed', outcome: 'failure', reason: 'bad_password', user_id: user.id, username, hwid });
        return sendError(res, errors.UNAUTHORIZED, `Failed password for '${username}'`);
    }

    if (await isDeviceBanned(strongIds)) {
        logger.warn(`[Login] Banned device attempted login on '${username}' (${user.id})`);
        logAuthEvent({ ...ctx, event_type: 'login_failed', outcome: 'failure', reason: 'banned_device', user_id: user.id, username, hwid, meta: { hwid_components: hwidComponents } });
        return sendError(res, errors.UNAUTHORIZED, `Banned device attempted login on '${username}'`);
    }

    if (!(await ensureHwidRegistered(user, hwid, deviceInfo))) {
        logger.warn(`[Login] HWID lock hit for '${username}' (${user.id}) — unrecognized device rejected`);
        logAuthEvent({ ...ctx, event_type: 'login_failed', outcome: 'failure', reason: 'hwid_lock', user_id: user.id, username, hwid, meta: { hwid_components: hwidComponents } });
        return sendError(res, errors.FORBIDDEN, `HWID lock hit for '${username}' — unrecognized device`);
    }

    await recordDeviceIdentifiers(user.id, strongIds);
    await updateLastLogin(user.id);
    await setIpForUser(user.id, ip);

    if (req.pskType === PSK.CORE && buildHash) {
        const buildError = await resolveBuildActivation(user.id, buildHash);
        if (buildError) {
            logAuthEvent({ ...ctx, event_type: 'login_failed', outcome: 'failure', reason: 'build_error', user_id: user.id, username, hwid });
            return sendError(res, buildError, `Build activation failed for user '${user.id}'`);
        }
    }

    const token = await createSessionToken(user.id, hwid, deviceInfo, buildHash);
    logger.info(`[Login] User '${username}' logged in successfully`);

    req.userId = user.id;

    logAuthEvent({ ...ctx, event_type: 'login_success', outcome: 'success', user_id: user.id, username, hwid, meta: { hwid_components: hwidComponents } });

    const sessionId = req.header('X-Session');
    if (sessionId) {
        if (!(await stampUserId(sessionId, user.id))) {
            logger.warn(`[Login] Could not stamp userId onto session '${sessionId}' for user '${user.id}' (session missing/expired)`);
        }
        if (buildHash && !(await stampBuild(sessionId, buildHash))) {
            logger.warn(`[Login] Could not stamp build '${buildHash}' onto session '${sessionId}' for user '${user.id}' (session missing/expired)`);
        }
    } else {
        logger.warn(`[Login] No X-Session header on successful login for user '${user.id}' — session not stamped`);
    }

    await maybeSetCountry(user.id, countryIso);

    return sendAuthSuccess(res, user, token);
}

/**
 * Authenticates a user and returns a session token with active license info.
 *
 * @route POST /api/v1/login
 * @access Public
 */
router.post('/api/v1/login', async (req: Request, res: Response) => {
    const { username, password, device_info, token } = req.body;
    const countryIso = req.clientCountry;
    const buildHash = req.buildHash;
    const isResume = typeof token === 'string';

    logger.debug(
        `[Login] Request — psk=${req.pskType} buildHash=${buildHash ?? 'none'} ` +
        `mode=${isResume ? 'resume' : 'credentials'}`
    );

    try {
        if (isResume) {
            return await handleResume(req, res, token, countryIso);
        }

        if (!validateCredentialsRequest(username, password, device_info)) {
            return sendError(res, errors.BAD_REQUEST, 'Invalid login request payload');
        }

        return await handleCredentialsLogin(req, res, {
            username,
            password,
            deviceInfoRaw: device_info,
            countryIso,
            buildHash,
        });
    } catch (err) {
        logger.error(`[Login] Unexpected error (${isResume ? 'resume' : username}): ${err}`);
        return sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;