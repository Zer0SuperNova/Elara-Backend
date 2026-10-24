import express from 'express';
import { errors, sendError } from '../../utils/errors.js';
import { getPending, setActive, deletePending } from '../../session/store.js';
import { getPskType } from '../../middlewares/pskGate.js';
import logger from '../../handler/logger.js';
import { SessionKeys, TunnelMessage, tunnel } from '../../crypto/nativeProvider.js';
import { PSK } from '../../types/psk.js';
import appConfig from '../../config/config.js';
import { getBuildIdByHash } from '../../repositories/builds.js';
import { getLoaderIdByHash } from '../../repositories/loaders.js';

const router = express.Router();

export const config = {
    auth: false,
    encrypted: false,
    allowedPsk: [PSK.LOADER, PSK.CORE]
}

router.post('/api/v1/handshake/finalize', async (req, res) => {
  try {
    const { sessionId, nonce, tag, ciphertext, mac } = req.body;

    if (!sessionId || !nonce || !tag || !ciphertext || !mac) {
      logger.warn('[Finalize] Missing required fields');
      return sendError(res, errors.BAD_REQUEST, 'Missing required fields');
    }

    if (typeof sessionId !== 'string' || typeof nonce !== 'string' || typeof tag !== 'string' || typeof ciphertext !== 'string' || typeof mac !== 'string') {
      logger.warn('[Finalize] Invalid field types');
      return sendError(res, errors.BAD_REQUEST, 'Invalid field types');
    }

    if (nonce.length !== 24 || tag.length !== 32 || mac.length !== 64) {
      logger.warn('[Finalize] Invalid field lengths');
      return sendError(res, errors.BAD_REQUEST, 'Invalid field lengths');
    }

    const session = await getPending(sessionId);
    if (!session) {
      logger.warn(`[Finalize] Pending session not found: ${sessionId}`);
      return sendError(res, errors.UNAUTHORIZED, `Pending session not found: ${sessionId}`);
    }

    // Attach the resolved identity so the request-level analytics logger records it
    // (handshake routes are unencrypted, so E2E never populates these).
    req.buildHash = session.buildHash;
    req.buildId = session.buildHash ? await getBuildIdByHash(session.buildHash) : '';
    req.loaderId = session.loaderHash ? await getLoaderIdByHash(session.loaderHash) : '';

    const keys: SessionKeys = {
      encKey: Buffer.isBuffer(session.preHandshakeKeys.encKey)
        ? session.preHandshakeKeys.encKey
        : Buffer.from(session.preHandshakeKeys.encKey),
      hmacKey: Buffer.isBuffer(session.preHandshakeKeys.hmacKey)
        ? session.preHandshakeKeys.hmacKey
        : Buffer.from(session.preHandshakeKeys.hmacKey)
    };

    const message: TunnelMessage = {
      nonce: Buffer.from(nonce, 'hex'),
      tag: Buffer.from(tag, 'hex'),
      ciphertext: Buffer.from(ciphertext, 'hex'),
      mac: Buffer.from(mac, 'hex')
    };

    const decrypted = tunnel.tunnelReceive(keys, message);
    if (!decrypted) {
      logger.warn(`[Finalize] Failed to decrypt tunnel message for session: ${sessionId}`);
      return sendError(res, errors.UNAUTHORIZED, `Failed to decrypt tunnel message for session: ${sessionId}`);
    }

    const payload = JSON.parse(decrypted.toString());
    const clientEphPK = Buffer.from(payload.clientEphX25519PK, 'hex');
    const clientTranscript = Buffer.from(payload.transcript, 'hex');

    const identity = appConfig.serverKeys.static[getPskType(req)];
    const srvSK = identity.secret;
    const srvPK = identity.public;

    if (!srvSK || !srvPK) {
      logger.error('[Finalize] Server static keys are missing');
      return sendError(res, errors.INTERNAL, 'Server static keys are missing');
    }

    const srvSKBuf = Buffer.from(srvSK, 'hex');
    const srvPKBuf = Buffer.from(srvPK, 'hex');

    const dh2 = tunnel.deriveSharedSecret(clientEphPK, srvSKBuf);
    const dh3 = tunnel.deriveSharedSecret(clientEphPK, session.serverEphSK);
    if (!dh2 || !dh3) {
      logger.error('[Finalize] Failed to derive DH secrets');
      return sendError(res, errors.INTERNAL, 'Failed to derive DH secrets');
    }

    const finalSecret = tunnel.deriveTripleSharedSecret(session.dh1, dh2, dh3);
    const realSessionKeys = tunnel.deriveSessionKeys(finalSecret);

    const expectedTranscript = tunnel.buildTranscriptHash(
      clientEphPK,
      session.clientStaticX25519PK,
      session.serverEphPK,
      srvPKBuf
    );

    if (!expectedTranscript.equals(clientTranscript)) {
      logger.warn(`[Finalize] Transcript mismatch for session: ${sessionId}`);
      await deletePending(sessionId);
      return sendError(res, errors.UNAUTHORIZED, `Transcript mismatch for session: ${sessionId}`);
    }

    await setActive(sessionId, {
      sessionId,
      sessionKeys: realSessionKeys,
      buildHash: session.buildHash,
      loaderHash: session.loaderHash,
      activeSince: Date.now()
    });

    await deletePending(sessionId);
    res.json({ status: "success" });

  } catch (err) {
    logger.error(`[Finalize] Error: ${err}`);
    sendError(res, errors.INTERNAL, String(err));
  }
});

export default router;