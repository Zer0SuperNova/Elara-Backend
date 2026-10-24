import express from 'express';
import { errors, sendError } from '../../utils/errors.js';

const router = express.Router();

export const config = {
    auth: false,
    encrypted: false
}
router.get('/api/v1/ping', async (
    req: express.Request, 
    res: express.Response, 
) => {
    try {
        res.json({
            success: true,
            message: "pong"
        });
        
    } catch (err) {
        console.error(err);
        sendError(res, errors.INTERNAL, String(err));
    }
});

export default router;
