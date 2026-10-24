import redis from '../database/redis.js';
import type { SessionKeys } from '../crypto/nativeProvider.js';

/**
 * Represents an active cryptographic session.
 */
export interface ActiveSession {
  sessionId:   string;
  sessionKeys: SessionKeys;
  buildHash?:  string;
  loaderHash?: string;
  activeSince: number;
  userId?:     string;
}

/**
 * Represents a pending cryptographic handshake.
 */
export interface PendingHandshake {
  preHandshakeKeys:     SessionKeys;
  serverEphSK:          Buffer;
  serverEphPK:          Buffer;
  clientStaticX25519PK: Buffer;
  dh1:                  Buffer;
  buildHash?:           string;
  loaderHash?:          string;
  expiresAt:            number;
}

const PENDING_TTL = 60;
const ACTIVE_TTL  = 240;

const toHex   = (b: Buffer) => b.toString('hex');
const fromHex = (s: string) => Buffer.from(s, 'hex');

function serializeKeys(keys: SessionKeys) {
  return {
    encKey:  Buffer.isBuffer(keys.encKey)  ? keys.encKey.toString('hex')  : Buffer.from(keys.encKey).toString('hex'),
    hmacKey: Buffer.isBuffer(keys.hmacKey) ? keys.hmacKey.toString('hex') : Buffer.from(keys.hmacKey).toString('hex'),
  };
}

function deserializeKeys(obj: any): SessionKeys {
  return {
    encKey:  Buffer.from(obj.encKey,  'hex'),
    hmacKey: Buffer.from(obj.hmacKey, 'hex'),
  };
}

function serializePending(p: PendingHandshake) {
  return {
    ...p,
    preHandshakeKeys:     serializeKeys(p.preHandshakeKeys),
    serverEphSK:          toHex(p.serverEphSK),
    serverEphPK:          toHex(p.serverEphPK),
    clientStaticX25519PK: toHex(p.clientStaticX25519PK),
    dh1:                  toHex(p.dh1),
  };
}

function deserializePending(obj: any): PendingHandshake {
  return {
    ...obj,
    preHandshakeKeys:     deserializeKeys(obj.preHandshakeKeys),
    serverEphSK:          fromHex(obj.serverEphSK),
    serverEphPK:          fromHex(obj.serverEphPK),
    clientStaticX25519PK: fromHex(obj.clientStaticX25519PK),
    dh1:                  fromHex(obj.dh1),
  };
}

const KEY_PENDING = (id: string) => `encryption:pending:${id}`;
const KEY_ACTIVE  = (id: string) => `encryption:active:${id}`;

export async function setPending(sessionId: string, pending: PendingHandshake) {
  await redis.getClient().set(KEY_PENDING(sessionId), JSON.stringify(serializePending(pending)), { EX: PENDING_TTL });
}

export async function getPending(sessionId: string): Promise<PendingHandshake | null> {
  const raw = await redis.getClient().get(KEY_PENDING(sessionId));
  return raw ? deserializePending(JSON.parse(raw)) : null;
}

export async function deletePending(sessionId: string) {
  await redis.getClient().del(KEY_PENDING(sessionId));
}

export async function setActive(sessionId: string, session: ActiveSession) {
  await redis.getClient().set(KEY_ACTIVE(sessionId), JSON.stringify({
    ...session,
    sessionKeys: serializeKeys(session.sessionKeys),
  }), { EX: ACTIVE_TTL });
}

export async function getActive(sessionId: string): Promise<ActiveSession | null> {
  const raw = await redis.getClient().get(KEY_ACTIVE(sessionId));
  if (!raw) return null;
  const parsed = JSON.parse(raw);
  return {
    ...parsed,
    sessionKeys: deserializeKeys(parsed.sessionKeys),
  };
}

export async function deleteActive(sessionId: string) {
  await redis.getClient().del(KEY_ACTIVE(sessionId));
}

/**
 * Refreshes the TTL of an active session.
 * @returns True if refreshed, false if the session no longer exists.
 */
export async function refreshActive(sessionId: string): Promise<boolean> {
  const result = await redis.getClient().expire(KEY_ACTIVE(sessionId), ACTIVE_TTL);
  return result === 1;
}

/**
 * Stamps a userId onto an existing active session without touching the keys or TTL.
 * Called after login once the userId is known.
 * @returns True if updated, false if the session no longer exists.
 */
export async function stampUserId(sessionId: string, userId: string): Promise<boolean> {
  const client = redis.getClient();
  const raw    = await client.get(KEY_ACTIVE(sessionId));
  if (!raw) return false;

  const parsed  = JSON.parse(raw);
  parsed.userId = userId;

  const ttl = await client.ttl(KEY_ACTIVE(sessionId));
  if (ttl <= 0) return false;

  await client.set(KEY_ACTIVE(sessionId), JSON.stringify(parsed), { EX: ttl });
  return true;
}

/**
 * Stamps a buildHash onto an existing active session without touching the keys or TTL.
 * Mirrors {@link stampUserId}; called after login once the build is known, so later
 * requests on the same session (and analytics) carry the build even if the handshake
 * didn't establish one.
 *
 * @param sessionId - The active session to update.
 * @param buildHash - The build hash to associate with the session.
 * @returns True if updated, false if the session no longer exists or has expired.
 */
export async function stampBuild(sessionId: string, buildHash: string): Promise<boolean> {
  const client = redis.getClient();
  const raw    = await client.get(KEY_ACTIVE(sessionId));
  if (!raw) return false;

  const parsed     = JSON.parse(raw);
  parsed.buildHash = buildHash;

  const ttl = await client.ttl(KEY_ACTIVE(sessionId));
  if (ttl <= 0) return false;

  await client.set(KEY_ACTIVE(sessionId), JSON.stringify(parsed), { EX: ttl });
  return true;
}

/**
 * Returns the number of seconds elapsed since the session was activated, or `null` if the session doesn't exist or has expired.
 * Used for session analytics and tracking user activity duration.
 * Note that this is not perfectly accurate due to the nature of TTL and potential clock drift, but should be sufficient for general tracking purposes.
 * @param sessionId - The ID of the session to check.
 * @returns The number of seconds since activation, or `null` if the session is invalid.
 */
export async function getActiveTimeElapsed(sessionId: string): Promise<number | null> {
    const remaining = await redis.getClient().ttl(KEY_ACTIVE(sessionId));
    if (remaining < 0) return null; 
    return ACTIVE_TTL - remaining;
}