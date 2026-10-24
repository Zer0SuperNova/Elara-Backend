import { Request, Response, NextFunction } from 'express';

/**
 * Middleware to extract client information (IP and country) from request headers.
 *
 * Populates `req.clientIp` and `req.clientCountry` for downstream middleware and handlers.
 *
 * @param req  - Express request object.
 * @param next - Express next middleware function.
 */
export default function clientInfo(req: Request, _res: Response, next: NextFunction): void {
    req.clientIp = req.header('cf-connecting-ip') ?? req.socket.remoteAddress ?? '';
    req.clientCountry = req.header('CF-IPCountry') ?? '';
    next();
}
