import crypto from "node:crypto";
import type { Request, Response, NextFunction } from "express";
import config from "../config/config.js";
import { errors, sendError } from '../utils/errors.js';
import { Routes } from '../config/routes.js';
import logger from "../handler/logger.js";
import type { PskType } from "../types/psk.js";
import { getRouteConfig } from "../handler/routeloader.js";
import redis from "../database/redis.js";

const PSK_REGISTRY = {
  core:   config.serverKeys.static.core.psk,
  loader: config.serverKeys.static.loader.psk,
} as const;

for (const [name, value] of Object.entries(PSK_REGISTRY)) {
  if (!value) throw new Error(`Missing PSK in config: ${name}`);
}

const PSKs = Object.fromEntries(
  Object.entries(PSK_REGISTRY).map(([k, v]) => [k, Buffer.from(v!, "hex")])
) as Record<PskType, Buffer>;

/**
 * Returns the PSK type used to authenticate the current request.
 * @throws {Error} If `pskGate` has not run or did not authenticate the request.
 */
export function getPskType(req: Request): PskType {
  if (!req.pskType) throw new Error("pskGate middleware has not run or did not authenticate this request");
  return req.pskType;
}

/**
 * Computes the HMAC-SHA256 of `data` using the given `key`.
 * @param {Buffer} key - The secret key for HMAC computation
 * @param {Buffer} data - The data to be hashed
 * @returns {string} The hex-encoded HMAC-SHA256 digest
 */
function hmac(key: Buffer, data: Buffer) {
  return crypto.createHmac("sha256", key).update(data).digest("hex");
}

/**
 * Returns true if `v` is a hex string of exactly `len` characters.
 */
const isHex = (v: string, len: number) =>
  new RegExp(`^[0-9a-f]{${len}}$`, "i").test(v);

/**
 * Tries every registered PSK against `token` and returns the matching key name,
 * or `null` if none match.
 */
function resolveToken(data: Buffer, token: string): PskType | null {
  for (const [name, key] of Object.entries(PSKs) as [PskType, Buffer][]) {
    const expected = hmac(key, data);
    if (
      expected.length === token.length &&
      crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(token))
    ) {
      return name;
    }
  }
  return null;
}

/**
 * Validates PSK headers against all registered keys and forwards the request
 * to the mapped route. Sets `req.pskType` so downstream middleware can tell
 * which key authenticated the request.
 *
 * Performs nonce replay detection via Redis to prevent request replay attacks.
 *
 * Genuinely public routes (registered with `encrypted: false` and no `allowedPsk`,
 * e.g. the health check) carry no PSK handshake, so they're let through untouched —
 * the gate would otherwise 400 a plain request that has no PSK headers. The explicit
 * `encrypted === false` check distinguishes them from the encrypted entry point
 * (`/hit`), which is unregistered and resolves to an empty config.
 *
 * @see {@link getPskType} for reading the resolved key in subsequent middleware.
 */
export default async function pskGate(req: Request, res: Response, next: NextFunction) {
  const incomingConfig = getRouteConfig(req.path);
  if (incomingConfig.encrypted === false && !incomingConfig.allowedPsk) {
    return next();
  }

  const routeId = req.header("X-R");
  const nonce   = req.header("X-N");
  const token   = req.header("X-T");

  if (!routeId || !nonce || !token)            return sendError(res, errors.BAD_REQUEST);
  if (!isHex(nonce, 32) || !isHex(token, 64)) return sendError(res, errors.BAD_REQUEST);

  const data = Buffer.from(
    `${routeId}|${nonce}|${req.method}|${req.path}`,
    "utf8"
  );

  const matchedKey = resolveToken(data, token);
  if (!matchedKey) {
    logger.warn(`PSK Gate: Failed to authenticate request for route ID ${routeId}`);

    const computed = Object.fromEntries(
      Object.entries(PSKs).map(([k, v]) => [k, hmac(v, data)])
    ) as Record<PskType, string>;

    logger.debug(`PSK Gate: Auth failure breakdown for route ID ${routeId}:`);
    logger.debug(`  signed string : "${data.toString("utf8")}"`);
    logger.debug(`  routeId (X-R) : ${routeId}`);
    logger.debug(`  nonce   (X-N) : ${nonce} (len ${nonce.length})`);
    logger.debug(`  method        : ${req.method}`);
    logger.debug(`  req.path      : ${req.path}`);
    logger.debug(`  originalUrl   : ${req.originalUrl}`);
    logger.debug(`  received token: ${token} (len ${token.length})`);
    for (const [name, expected] of Object.entries(computed)) {
      logger.debug(
        `  expected[${name}]: ${expected} (len ${expected.length}) match=${expected === token}`
      );
    }
    return sendError(res, errors.UNAUTHORIZED);
  }

  const target = Routes[routeId];
  if (!target) {
    logger.warn(`PSK Gate: No route mapping found for ID ${routeId}`);
    return sendError(res, errors.NOT_FOUND);
  }

  const routeConfig = getRouteConfig(target);
  if (routeConfig.allowedPsk && !routeConfig.allowedPsk.includes(matchedKey)) {
    logger.warn(`PSK Gate: "${matchedKey}" PSK is not permitted to access route ${target}`);
    return sendError(res, errors.FORBIDDEN);
  }

  const alreadySeen = await redis.getClient().set(`psk:nonce:${nonce}`, '1', { NX: true, EX: 60 });
  if (!alreadySeen) {
    logger.warn(`PSK Gate: Nonce replay detected for route ${target}`);
    return sendError(res, errors.UNAUTHORIZED);
  }

  req.pskType     = matchedKey;
  req.url         = target;
  req.originalUrl = target;

  logger.debug(`PSK Gate: Route ID ${routeId} validated via "${matchedKey}" PSK, forwarding to ${target}`);

  return next();
}