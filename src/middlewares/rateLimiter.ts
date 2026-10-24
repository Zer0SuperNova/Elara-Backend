import { rateLimit, ipKeyGenerator } from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import redis from '../database/redis.js';

export function createRateLimiter() {
    return rateLimit({
        windowMs: 60 * 1000,
		max: 200,
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: (req) => {
            const cfIp = req.headers['cf-connecting-ip'];
            if (typeof cfIp === 'string' && cfIp) {
                return ipKeyGenerator(cfIp);
            }
            if (!req.ip) throw new Error('Could not determine client IP');
            return ipKeyGenerator(req.ip);
        },
        skip: () => false,
        validate: { ip: false },
        store: new RedisStore({
            sendCommand: (...args: string[]) => redis.getClient().sendCommand(args),
        }),
    });
}