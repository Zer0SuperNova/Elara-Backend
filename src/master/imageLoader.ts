import {
  GetObjectCommand,
  type GetObjectCommandOutput,
} from '@aws-sdk/client-s3';
import { createHash, randomUUID } from 'node:crypto';
import { getS3Client } from '../database/s3.js';
import redis from '../database/redis.js';
import logger from '../handler/logger.js';

const BUCKET = 'loadercdn';
const REDIS_PREFIX = 'loadermedia:';
const HASH_PREFIX = 'loadermedia:hash:';

// Lazy-cache coordination.
const LOCK_TTL_MS = 30_000;
const WAIT_TIMEOUT_MS = 30_000;
const WAIT_POLL_MS = 100;

function hashBuffer(buf: Buffer): string {
  return createHash('md5').update(buf).digest('hex');
}

async function streamToBuffer(stream: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const chunks: Buffer[] = [];

  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  return Buffer.concat(chunks);
}

/** Reads a cached asset from Redis as a Buffer, or null if absent. */
async function readCached(key: string): Promise<Buffer | null> {
  return (await redis.getBufferClient().get(`${REDIS_PREFIX}${key}`)) as Buffer | null;
}

/** Downloads an asset from the CDN bucket, or null if it isn't present. */
async function downloadAsset(key: string): Promise<Buffer | null> {
  const s3 = getS3Client();
  if (!s3) {
    logger.error('[ImageLoader] S3 client not initialized.');
    return null;
  }

  try {
    const res: GetObjectCommandOutput = await s3.send(
      new GetObjectCommand({ Bucket: BUCKET, Key: key }),
    );
    if (!res.Body) return null;
    return await streamToBuffer(res.Body as AsyncIterable<Uint8Array>);
  } catch (err) {
    // Missing object (NoSuchKey) or any fetch error -> treat as unavailable.
    logger.debug(`[ImageLoader] Asset ${key} not available in S3: ${err}`);
    return null;
  }
}

/** Waits until an asset appears in Redis (cached by whichever request holds the lock). */
async function waitForCached(key: string, timeoutMs: number): Promise<Buffer | null> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const data = await readCached(key);
    if (data) return data;
    await new Promise((resolve) => setTimeout(resolve, WAIT_POLL_MS));
  }
  return null;
}

/**
 * Returns an asset's bytes, lazily fetching it from S3 and caching it in Redis
 * (binary + md5 hash) on a cache miss. A Redis lock dedupes concurrent misses so
 * the asset is fetched + cached only once.
 *
 * @param key - The asset key (also the S3 object key).
 * @returns The asset bytes, or null if it exists in neither Redis nor S3.
 */
export async function ensureImageCached(key: string): Promise<Buffer | null> {
  const cached = await readCached(key);
  if (cached) return cached;

  const client = redis.getClient();
  const lockKey = `cdnlock:${key}`;
  const lockToken = randomUUID();
  const gotLock = await client.set(lockKey, lockToken, { NX: true, PX: LOCK_TTL_MS });

  if (!gotLock) {
    // Another request is already fetching this asset — wait instead of downloading twice.
    return waitForCached(key, WAIT_TIMEOUT_MS);
  }

  try {
    // Re-check: another worker may have cached it between the first check and the lock.
    const again = await readCached(key);
    if (again) return again;

    const data = await downloadAsset(key);
    if (!data) return null;

    await client.set(`${REDIS_PREFIX}${key}`, data);
    await client.set(`${HASH_PREFIX}${key}`, hashBuffer(data));
    logger.debug(`[ImageLoader] Cached ${key} (${data.length} bytes) on demand`);
    return data;
  } catch (err) {
    logger.error(`[ImageLoader] Failed to lazily cache ${key}: ${err}`);
    return null;
  } finally {
    // Release the lock only if we still own it.
    if ((await client.get(lockKey)) === lockToken) {
      await client.del(lockKey);
    }
  }
}
