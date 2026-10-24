import express from 'express';
import { errors, sendError } from '../../utils/errors.js';
import logger from '../../handler/logger.js';
import { PSK } from '../../types/psk.js';
const router = express.Router();

export const config = {
    auth: true,
    encrypted: true,
    allowedPsk: [PSK.CORE, PSK.LOADER]
}

router.post('/api/v1/echo', async (req, res) => {
    const { message } = req.body;

    logger.debug(`Received echo request with message: ${message}`);

    if (!message || typeof message !== 'string') {
        logger.warn(`Invalid message in echo request: ${message}`);
        return sendError(res, errors.BAD_REQUEST, `Invalid message in echo request: ${message}`);
    }

    if (message.length < 1 || message.length > 10) {
        logger.warn(`Message length invalid in echo request: ${message.length}`);
        return sendError(res, errors.BAD_REQUEST, `Message length invalid in echo request: ${message.length}`);
    }

    res.json({ message });
});


export default router;