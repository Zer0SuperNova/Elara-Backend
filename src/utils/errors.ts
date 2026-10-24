import type { Response } from 'express';
import { logServerIssue } from '../analytics/index.js';

export const errors = {
    // Auth
    UNAUTHORIZED:        { status: 401, error: 'Unauthorized', error_code: 'UNAUTHORIZED' },
    FORBIDDEN:           { status: 403, error: 'Forbidden', error_code: 'FORBIDDEN' },

    // Routing
    INVALID_ROUTE:       { status: 400, error: 'Invalid route', error_code: 'INVALID_ROUTE' },
    NOT_FOUND:           { status: 404, error: 'Not found', error_code: 'NOT_FOUND' },

    // Rate limiting
    RATE_LIMITED:        { status: 429, error: 'Too many requests', error_code: 'RATE_LIMITED' },

    // General
    BAD_REQUEST:         { status: 400, error: 'Bad request', error_code: 'BAD_REQUEST' },
    INTERNAL:            { status: 500, error: 'Internal server error', error_code: 'INTERNAL_ERROR' },
    INVALID_FIELD_LENGTH: { status: 400, error: 'Invalid field length', error_code: 'INVALID_FIELD_LENGTH' },
    CONFLICT:             { status: 409, error: 'Conflict', error_code: 'CONFLICT' },
    GONE:                 { status: 410, error: 'Gone', error_code: 'GONE' },
    SERVICE_UNAVAILABLE: { status: 503, error: 'Service unavailable', error_code: 'SERVICE_UNAVAILABLE' },

    // special errors
    NO_BUILDS_AVAILABLE: { status: 503, error: 'No builds available', error_code: 'NO_BUILDS_AVAILABLE' },
} as const;

type AppError = typeof errors[keyof typeof errors];

/**
 * Records a failed response to the `server_issues` table. Pulls request context
 * off `res.req` (Express's back-reference), so every call site logs without
 * passing `req`. Never throws — `logServerIssue` swallows its own failures.
 *
 * @param res          - The response being errored out.
 * @param error        - The error descriptor being sent.
 * @param responseBody - What the client receives back, for the response column.
 * @param detail       - Optional richer message (e.g. an exception) for the `message` column.
 */
function recordIssue(res: Response, error: AppError, responseBody: unknown, detail?: string): void {
    const req = res.req;
    logServerIssue({
        method:        req?.method,
        route:         req?.path ?? req?.originalUrl ?? '',
        status:        error.status,
        error_code:    error.error_code,
        message:       detail ?? error.error,
        user_id:       req?.userId,
        psk_type:      req?.pskType ? String(req.pskType) : undefined,
        ip:            req?.clientIp ?? req?.ip,
        request_body:  req?.body,
        response_body: responseBody,
    });
}

export function sendError(res: Response, error: AppError, detail?: string) {
    const body = { error: error.error, error_code: error.error_code };
    recordIssue(res, error, body, detail);
    return res.status(error.status).json(body);
}

export function sendBinaryError(res: Response, error: AppError, detail?: string) {
    recordIssue(res, error, undefined, detail);
    return res.status(error.status).end();
}