import { Request, Response, NextFunction } from 'express';
import { getRouteConfig } from '../handler/routeloader.js';
import { errors, sendError } from '../utils/errors.js';
import { getActive } from '../session/store.js';
import { tunnel } from '../crypto/nativeProvider.js';
import { ActionRoutes } from '../config/routes.js';
import { decodeFrame, encodeFrame } from '../utils/frame.js';
import { getModelChunkCount, getModelChunk } from '../master/chunker.js';
import { getBuildIdByHash, getUserIdByBuildHash } from '../repositories/builds.js';
import { getLoaderIdByHash } from '../repositories/loaders.js';
import logger from '../handler/logger.js';

/**
 * Resolves the active session from the `X-Session` request header.
 *
 * @param req - Incoming Express request.
 * @returns The active session, or `null` if the header is absent or the session is not found.
 */
async function resolveSession(req: Request) {
    const sessionId = req.header('X-Session');
    if (!sessionId) return null;
    return getActive(sessionId);
}

/**
 * Decodes and decrypts an incoming binary frame.
 *
 * @param buf     - Raw binary body from the client.
 * @param session - Active session holding the negotiated session keys.
 * @returns Decrypted plaintext buffer, or `null` if decryption fails.
 * @throws {Error} If the frame is structurally invalid.
 */
function decryptInbound(buf: Buffer, session: Awaited<ReturnType<typeof getActive>>) {
    const frame = decodeFrame(buf);
    return tunnel.tunnelReceive(session!.sessionKeys, frame);
}


/**
 * Rewrites `req.url` and `req.originalUrl` when the decrypted body contains
 * an `action` field, fanning out to the matching internal route via {@link ActionRoutes}.
 *
 * Must run after decryption since the action field is only visible in plaintext.
 * Route config is resolved before this runs so downstream middlewares are unaffected
 * by the URL rewrite.
 *
 * @param req - Express request with an already-parsed JSON body.
 * @returns `true` if routing succeeded or no action was present, `false` if the action is unknown.
 */
function applyActionRoute(req: Request): boolean {
    const action = req.body?.action;
    if (!action) return true;

    const actionRoute = ActionRoutes[action];
    if (!actionRoute) return false;

    req.url         = actionRoute;
    req.originalUrl = actionRoute;
    return true;
}


/**
 * Searches on redis for the chunks of the model and then streams it back to the client, encrypting each chunk with the session keys before sending.
 * @param id - The id of the model to stream, which is used to find the corresponding chunks in redis.
 * @param session - The active session containing the negotiated encryption keys.
 * @param res  - Express response object to write the encrypted chunks to.
 */
async function streamModelOutput(id: string, session: Awaited<ReturnType<typeof getActive>>, res: Response) {
    const totalChunks = await getModelChunkCount(id);
    if (!totalChunks) {
        sendError(res, errors.NOT_FOUND);
        return;
    }

    res.type('application/octet-stream');

    for (let i = 0; i < totalChunks; i++) {
        const chunk = await getModelChunk(id, i);
        if (!chunk) {
            logger.error(`[E2E] Missing chunk ${i} for model ${id}`);
            break;
        }

        res.write(chunk);
    }

    res.end();
}

async function stream(buf: Buffer, res: Response): Promise<void> {
    const totalChunks = Math.ceil(buf.length / CHUNK_SIZE);
    logger.debug(`[E2E] Streaming buffer (${buf.length} bytes) as ${totalChunks} chunk(s)`);

    res.type('application/octet-stream');

    for (let offset = 0; offset < buf.length; offset += CHUNK_SIZE) {
        res.write(buf.subarray(offset, offset + CHUNK_SIZE));
    }

    res.end();
}


/**
 * Maximum plaintext payload size per encrypted response frame.
 */
const CHUNK_SIZE = 64 * 1024; // 64 KB

/**
 * Patches the response object so all outbound data is encrypted with the
 * active session keys before being written to the socket.
 *
 * @param res     - Express response object to patch.
 * @param session - Active session containing the negotiated encryption keys.
 */
function patchResponseEncryption(res: Response, session: Awaited<ReturnType<typeof getActive>>) {
    const originalWrite = res.write.bind(res);
    const originalEnd   = res.end.bind(res);

    const encryptAndWriteChunk = (chunk: Buffer): boolean => {
        logger.debug(`[E2E] Encrypting chunk (${chunk.length} bytes)`);
        const encrypted = tunnel.tunnelSend(session!.sessionKeys, chunk);
        const packet    = encodeFrame(
            encrypted.nonce,
            encrypted.tag,
            encrypted.mac,
            encrypted.ciphertext,
        );
        logger.debug(`[E2E] Chunk encrypted → ${packet.length} bytes`);
        return originalWrite(packet);
    };

    res.write = (chunk: any): boolean => {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        return encryptAndWriteChunk(buf);
    };

    res.end = (): Response => {
        originalEnd();
        return res;
    };

    const sendEncrypted = (body: any): Response => {
        const plainBuf = Buffer.isBuffer(body)
            ? body
            : Buffer.from(JSON.stringify(body), 'utf8');

        const totalChunks = Math.ceil(plainBuf.length / CHUNK_SIZE);
        logger.debug(`[E2E] Sending ${plainBuf.length} bytes as ${totalChunks} chunk(s)`);

        res.type('application/octet-stream');

        for (let offset = 0; offset < plainBuf.length; offset += CHUNK_SIZE) {
            encryptAndWriteChunk(plainBuf.subarray(offset, offset + CHUNK_SIZE));
        }

        originalEnd();
        return res;
    };

    res.send = sendEncrypted;
    res.json = (body: any) => sendEncrypted(body);

    // custom method for ONLY model streaming
    res.sendModelStream = (id: string) => void streamModelOutput(id, session, res);
    res.sendStream = (bytes: Buffer) => void stream(bytes, res);
}


/**
 * E2E encryption middleware.
 *
 * Resolves and attaches the {@link RouteConfig} to `req.routeConfig` from the
 * original URL before any rerouting occurs, so all downstream middlewares can
 * read the correct config regardless of URL rewrites.
 *
 * For routes marked as `encrypted`, the middleware handles the full
 * cryptographic lifecycle per request:
 *
 * **Inbound**
 * 1. Validates that the body is a raw binary buffer.
 * 2. Resolves the active session via the `X-Session` header.
 * 3. Decodes and decrypts the binary frame using the session keys.
 * 4. Replaces `req.body` with the parsed plaintext JSON.
 * 5. Optionally rewrites the URL via the action route map.
 *
 * **Outbound**
 * 6. Patches `res.send` and `res.json` so every response is encrypted
 *    before it is written to the socket.
 *
 * @param req  - Express request object.
 * @param res  - Express response object.
 * @param next - Express next function.
 */
export default async function e2eMiddleware(
    req: Request,
    res: Response,
    next: NextFunction,
): Promise<void | Response> {

    const route = req.originalUrl.split('?')[0];

    // Resolve and attach config before any URL rewriting so downstream
    // middlewares always read the config of the real incoming route.
    req.routeConfig = getRouteConfig(route);
    logger.debug(`[E2E] routeConfig for ${route}: ${JSON.stringify(req.routeConfig)}`);

    if (req.routeConfig.encrypted === false) return next();

    logger.debug(`[E2E] Encrypted route: ${route}`);

    // Inbound processing
    const buf = req.body as Buffer;
    if (!Buffer.isBuffer(buf)) {
        logger.warn('[E2E] Expected binary body');
        return sendError(res, errors.BAD_REQUEST);
    }

    // Reject shared-memory-backed buffers to prevent potential security issues
    const session = await resolveSession(req);
    if (!session) {
        logger.warn('[E2E] Missing or inactive session');
        return sendError(res, errors.UNAUTHORIZED);
    }

    let plain: Buffer | null;
    try {
        plain = decryptInbound(buf, session);
    } catch {
        logger.warn('[E2E] Invalid frame');
        return sendError(res, errors.BAD_REQUEST);
    }

    // Decryption failure can occur due to tampering or if the client is out of sync with the server keys
    if (!plain) {
        logger.warn(`[E2E] Decrypt failed for session: ${req.header('X-Session')}`);
        return sendError(res, errors.UNAUTHORIZED);
    }

    if (req.routeConfig.bodyType === 'binary') {
        req.body = plain;
    } else {
        // Parse the decrypted plaintext as JSON and replace req.body.
        try {
            req.body = JSON.parse(plain.toString('utf8'));
        } catch {
            logger.warn('[E2E] Failed to parse decrypted body');
            return sendError(res, errors.BAD_REQUEST);
        }

        if (!applyActionRoute(req)) {
            logger.warn(`[E2E] Unknown action: ${req.body.action}`);
            return sendError(res, errors.BAD_REQUEST);
        }
    }

    // Re-attach config after potential URL rewrite
    req.routeConfig = getRouteConfig(req.url.split('?')[0]); 

    req.buildHash = session.buildHash;
    req.buildId = session.buildHash ? await getBuildIdByHash(session.buildHash) : '';
    req.loaderId = session.loaderHash ? await getLoaderIdByHash(session.loaderHash) : '';

    // Analytics fallback
    if (!session.userId && session.buildHash) {
        try {
            session.userId = await getUserIdByBuildHash(session.buildHash);
        } catch (err) {
            logger.warn(`[E2E] Failed to resolve user for build '${session.buildHash}': ${err}`);
        }
    }

    req.e2eSession = session;

    logger.debug(`[E2E] session userId=${session.userId ?? 'none'} buildHash=${session.buildHash ?? 'none'} loaderHash=${session.loaderHash ?? 'none'}`);
    logger.debug(`[E2E] Inbound processing complete for session ${req.header('X-Session')}, proceeding to route handler`);

    // Outbound processing
    patchResponseEncryption(res, session);

    return next();
}
