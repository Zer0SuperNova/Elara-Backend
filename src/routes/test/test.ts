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

router.post('/api/v1/test', async (req, res) => {
    const { message } = req.body;

    logger.debug(`Received test request with message: ${message}`);

    if (!message || typeof message !== 'string')
    {
        logger.warn(`Invalid message in test request: ${message}`);
        return sendError(res, errors.BAD_REQUEST, `Invalid message in test request: ${message}`);
    }

    if (message.length < 1 || message.length > 10)
    {
        logger.warn(`Message length invalid in test request: ${message.length}`);
        return sendError(res, errors.BAD_REQUEST, `Message length invalid in test request: ${message.length}`);
    }

    res.json({ message });
});

export default router;