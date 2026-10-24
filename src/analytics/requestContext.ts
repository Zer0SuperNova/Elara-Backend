/**
 * Shared request-context extraction for analytics events.
 *
 * Every event type carries the same identity/origin fields. Resolving them in
 * one place keeps the rules consistent across call sites (a route that only
 * reads `req.e2eSession?.userId` and a middleware that reads `req.userId` would
 * otherwise log different user ids for the same request).
 */

import type { Request } from 'express';
import logger from '../handler/logger.js';

export interface AnalyticsContext {
  user_id: string;
  psk_type: string;
  ip: string;
  country: string;
  build_id: string;
  loader_id: string;
}

const EMPTY_CONTEXT: AnalyticsContext = {
  user_id:   '',
  psk_type:  '',
  ip:        '',
  country:   '',
  build_id:  '',
  loader_id: '',
};

/**
 * Derives the shared analytics fields from the request.
 *
 * An empty string means the value is genuinely absent for this request, not a
 * dropped field: an unauthenticated CDN fetch has no `user_id`, and a loader
 * session carries `loader_id` but no `build_id`. ClickHouse stores `''` for
 * these rather than NULL.
 *
 * `userId` is preferred over the session copy so authenticated routes and the
 * access-log middleware resolve identity identically. The session copy
 * (`e2eSession.userId`) is itself MySQL-backed: E2E resolves the build's owner
 * for unstamped core sessions, so this fallback isn't limited to stamped sessions.
 * Never throws — on any failure it logs and returns an empty context.
 *
 * @param req - The incoming request, after the identity/session middlewares have run.
 * @returns The shared analytics fields, each coalesced to `''` when absent.
 */
export function analyticsContext(req: Request): AnalyticsContext {
  try {
    return {
      user_id:   req.userId ?? req.e2eSession?.userId ?? '',
      psk_type:  req.pskType ? String(req.pskType) : '',
      ip:        req.clientIp ?? '',
      country:   req.clientCountry ?? '',
      build_id:  req.buildId ?? '',
      loader_id: req.loaderId ?? '',
    };
  } catch (err) {
    logger.warn(`[Analytics] Failed to build request context: ${err}`);
    return { ...EMPTY_CONTEXT };
  }
}
