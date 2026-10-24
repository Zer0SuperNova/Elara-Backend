import express from 'express';
import { randomUUID } from 'node:crypto';
import { errors, sendError } from '../../utils/errors.js';
import { tunnel } from '../../crypto/nativeProvider.js';
import { setPending } from '../../session/store.js';
import logger from '../../handler/logger.js';
import { Build, getBuildByHash } from '../../repositories/builds.js';
import { getPskType } from '../../middlewares/pskGate.js';
import { getLoaderByHash } from '../../repositories/loaders.js';
import { PSK } from '../../types/psk.js';

const router = express.Router();

// config
export const config = {
    auth: false,
    encrypted: false,
    allowedPsk: [PSK.LOADER, PSK.CORE]
}

/**
 * Initializes the handshake process for secure session establishment.
 * 
 * Verifies the client's signature using their ed25519 public key, derives shared secrets
 * via X25519 Diffie-Hellman exchange, and creates a pending session with ephemeral keys.
 * 
 * @param {express.Request} req - Express request object
 * @param {string} req.body.hash - Client identity hash (64 character hex string): build hash for core, loader hash for loader
 * @param {string} req.body.sig - Client's ed25519 signature (128 character hex string)
 * @param {express.Response} res - Express response object
 * @returns {Object} JSON response with sessionId and serverX25519PK
 * @throws {Error} BAD_REQUEST if hash/sig are missing or invalid format
 * @throws {Error} UNAUTHORIZED if hash not found or signature verification fails
 * @throws {Error} INTERNAL if shared secret derivation fails
 */
router.post('/api/v1/handshake/init', async (req: express.Request, res: express.Response) => {
  try {
    const { hash, sig } = req.body;

    if(!hash || !sig) {
      logger.warn('[Handshake Init] Missing hash or signature');
      return sendError(res, errors.BAD_REQUEST, 'Missing hash or signature');
    }

    // type checks
    if (typeof hash !== 'string' || typeof sig !== 'string') {
      logger.warn('[Handshake Init] Invalid types for hash or signature');
      return sendError(res, errors.BAD_REQUEST, 'Invalid types for hash or signature');
    }

    // length checks
    if (hash.length !== 64 || sig.length !== 128) {
      logger.warn('[Handshake Init] Invalid length for hash or signature');
      return sendError(res, errors.BAD_REQUEST, 'Invalid length for hash or signature');
    }
    
    // Determine PSK type from request (loader or core) to fetch the correct client record
    const pskType = getPskType(req);

    // Fetch client record based on PSK type (loader or core) to get their ed25519 public key
    const clientRecord = pskType === PSK.LOADER
        ? await getLoaderByHash(hash)
        : await getBuildByHash(hash);

    // If no record found or ed25519PK is missing, reject the handshake
    if (!clientRecord) {
        logger.warn(`[Handshake Init] No ${pskType} record found for hash: ${hash}`);
        return sendError(res, errors.UNAUTHORIZED, `No ${pskType} record found for hash: ${hash}`);
    }

    // Attach the resolved identity so the request-level analytics logger records it
    // (handshake routes are unencrypted, so E2E never populates these).
    if (pskType === PSK.CORE) {
        req.buildHash = hash;
        req.buildId = clientRecord.id;
    } else {
        req.loaderId = clientRecord.id;
    }

    if (pskType === PSK.CORE) {
        const build = clientRecord as Build;

        if (build.status === 'banned' || build.status === 'tempbanned') {
            logger.warn(`[Handshake Init] Banned build attempted connection: ${hash}`);
            return sendError(res, errors.FORBIDDEN, `Banned build attempted connection: ${hash}`);
        }

        if (build.status !== 'active') {
            logger.warn(`[Handshake Init] Build not active (status: '${build.status}'): ${hash}`);
            return sendError(res, errors.UNAUTHORIZED, `Build not active (status '${build.status}'): ${hash}`);
        }
    }

    // Verify signature using client's ed25519 public key
    const ed25519PK = Buffer.from(clientRecord?.ed25519PK, 'hex');
    const valid = tunnel.verify(Buffer.from(hash, 'hex'), Buffer.from(sig, 'hex'), ed25519PK);
    if (!valid) {
      logger.warn('[Handshake Init] Signature verification failed');
      return sendError(res, errors.UNAUTHORIZED, 'Signature verification failed');
    }

    // Derive client's static X25519 public key from their ed25519 public key
    const x25519PK = tunnel.ed25519PKToX25519(ed25519PK);

    // Generate ephemeral keys for the Diffie-Hellman exchange
    const ephemeralKeys = tunnel.generateKeys();
    const sharedSecret = tunnel.deriveSharedSecret(x25519PK, ephemeralKeys.x25519SK);
    if (!sharedSecret) {
      logger.error('[Handshake Init] Failed to derive shared secret');
      return sendError(res, errors.INTERNAL, 'Failed to derive shared secret');
    }

    // get session keys from shared secret
    const sessionKeys = tunnel.deriveSessionKeys(sharedSecret);
    const sessionId = randomUUID();

    await setPending(sessionId, {
      preHandshakeKeys: sessionKeys,
      serverEphSK: ephemeralKeys.x25519SK,
      serverEphPK: ephemeralKeys.x25519PK,
      clientStaticX25519PK: x25519PK,
      dh1: sharedSecret,
      buildHash: pskType === PSK.CORE ? hash : undefined,
      loaderHash: pskType === PSK.LOADER ? hash : undefined,
      expiresAt: Date.now() + 30_000,
    });

    res.json({
      sessionId,
      serverX25519PK: ephemeralKeys.x25519PK.toString('hex'),
    });

  } catch (err) {
    logger.error(`[Handshake Init] Unexpected error: ${err}`);
    sendError(res, errors.INTERNAL, String(err));
  }
});

export default router;