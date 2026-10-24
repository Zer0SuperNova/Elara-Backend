import { GetObjectCommand, type GetObjectCommandOutput } from '@aws-sdk/client-s3';
import { randomUUID } from 'node:crypto';
import logger from '../handler/logger.js';
import redis from '../database/redis.js';
import { getS3Client } from '../database/s3.js';

const BUCKET = 'models';
const CHUNK_SIZE = 1024 * 1024; // 1MB

const LOCK_TTL_MS = 60_000;
const WAIT_TIMEOUT_MS = 60_000;
const WAIT_POLL_MS = 100;

async function streamToBuffer(stream: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const chunks: Buffer[] = [];

  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  return Buffer.concat(chunks);
}

/**
 * Checks whether a model has already been chunked and cached in Redis.
 * Uses the metadata key as a single source of truth — if it exists, all chunks are present.
 *
 * @param modelId - Unique identifier of the model to check.
 * @returns True if the model is already cached in Redis.
 */
async function isModelCached(modelId: string): Promise<boolean> {
  const total = await redis.getClient().get(`model:${modelId}:chunks`);
  return total !== null;
}

/**
 * Splits a model buffer into fixed-size chunks and stores each chunk in Redis as binary.
 * Also writes a metadata key `model:<id>:chunks` containing the total chunk count.
 *
 * @param modelId - Unique identifier of the model.
 * @param modelData - Raw binary buffer of the full model file.
 */
/**
 * Removes every chunk + metadata key for a model, including orphaned chunks
 * left by a previously interrupted chunking (which have no count key). Scans by
 * key pattern so it catches chunks regardless of how many were written.
 *
 * @param modelId - Unique identifier of the model.
 */
async function clearModelChunks(modelId: string): Promise<void> {
  const client = redis.getClient();

  for await (const batch of client.scanIterator({ MATCH: `model:${modelId}:chunk:*`, COUNT: 100 })) {
    if (batch.length) await client.del(batch);
  }

  await client.del(`model:${modelId}:chunks`);
}

async function chunkModel(modelId: string, modelData: Buffer): Promise<void> {
  const client = redis.getClient();
  const totalChunks = Math.ceil(modelData.length / CHUNK_SIZE);

  // Clear any stale/partial chunks first so a re-chunk can never leave ghosts behind.
  await clearModelChunks(modelId);

  logger.debug(`[Chunker] Chunking model ${modelId} -> ${totalChunks} chunk(s)`);

  for (let i = 0; i < totalChunks; i++) {
    const chunk = modelData.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
    await client.set(`model:${modelId}:chunk:${i}`, chunk);
  }

  await client.set(`model:${modelId}:chunks`, String(totalChunks));
  logger.debug(`[Chunker] Model ${modelId} stored (${totalChunks} chunk(s))`);
}

/**
 * Retrieves a single chunk from Redis as a Buffer.
 *
 * @param modelId - Unique identifier of the model.
 * @param index - Chunk index to retrieve.
 * @returns The chunk as a Buffer, or null if not found.
 */
export async function getModelChunk(modelId: string, index: number): Promise<Buffer | null> {
  const client = redis.getBufferClient();
  return (await client.get(`model:${modelId}:chunk:${index}`)) as Buffer | null;
}

/**
 * Retrieves the total number of chunks stored for a model.
 *
 * @param modelId - Unique identifier of the model.
 * @returns The total chunk count, or null if the model is not cached.
 */
export async function getModelChunkCount(modelId: string): Promise<number | null> {
  const total = await redis.getClient().get(`model:${modelId}:chunks`);
  return total ? Number(total) : null;
}

/**
 * Downloads a model's file from S3, or returns null if it isn't present.
 *
 * @param modelId - Unique identifier of the model.
 */
async function downloadModel(modelId: string): Promise<Buffer | null> {
  const s3 = getS3Client();
  if (!s3) {
    logger.error('[Chunker] S3 client not initialized.');
    return null;
  }

  try {
    const res: GetObjectCommandOutput = await s3.send(
      new GetObjectCommand({ Bucket: BUCKET, Key: `${modelId}.onnx` }),
    );
    if (!res.Body) return null;
    return await streamToBuffer(res.Body as AsyncIterable<Uint8Array>);
  } catch (err) {
    logger.debug(`[Chunker] Model ${modelId} not available in S3: ${err}`);
    return null;
  }
}

/**
 * Waits until a model's chunks appear in Redis (written by whichever worker
 * holds the lock), up to a timeout.
 *
 * @param modelId - Unique identifier of the model.
 * @param timeoutMs - Maximum time to wait.
 */
async function waitForChunks(modelId: string, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await isModelCached(modelId)) return true;
    await new Promise((resolve) => setTimeout(resolve, WAIT_POLL_MS));
  }
  return false;
}

/**
 * Ensures a model is chunked into Redis, lazily downloading and chunking it from
 * S3 on a cache miss. A Redis lock guarantees that concurrent requests for the
 * same uncached model trigger only a single download + chunk; the rest wait for
 * it to finish and then serve from cache.
 *
 * @param modelId - Unique identifier of the model.
 * @returns True if the model is cached and ready to stream, false if unavailable.
 */
export async function ensureModelChunked(modelId: string): Promise<boolean> {
  if (await isModelCached(modelId)) return true;

  const client = redis.getClient();
  const lockKey = `model:${modelId}:lock`;
  const lockToken = randomUUID();
  const gotLock = await client.set(lockKey, lockToken, { NX: true, PX: LOCK_TTL_MS });

  if (!gotLock) {
    return waitForChunks(modelId, WAIT_TIMEOUT_MS);
  }

  try {
    if (await isModelCached(modelId)) return true;

    const data = await downloadModel(modelId);
    if (!data) return false;

    await chunkModel(modelId, data);
    return true;
  } catch (err) {
    logger.error(`[Chunker] Failed to lazily chunk model ${modelId}: ${err}`);
    return false;
  } finally {
    if ((await client.get(lockKey)) === lockToken) {
      await client.del(lockKey);
    }
  }
}