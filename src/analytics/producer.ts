import redis from '../database/redis.js';
import logger from '../handler/logger.js';
import identity from '../cluster/identity.js';
import type { AnalyticsTable } from './types.js';

// Redis Stream key all analytics events are appended to.
export const ANALYTICS_STREAM = 'analytics:events';

// Approximate cap on stream length
const STREAM_MAXLEN = 1_000_000;

/**
 * Appends a single record to the analytics stream.
 *
 * The record is serialized into a `payload` field; `table` tells the consumer
 * which ClickHouse table to target. `event_time` is epoch milliseconds; the
 * consumer formats it into a `DateTime64(3)` datetime string before insert.
 *
 * @param table  - Target ClickHouse table the consumer should route this row to.
 * @param record - The event fields to serialize; `event_time` and `node_id` are
 *                  stamped here if not already present.
 * @returns Resolves once the entry has been appended to the stream.
 */
async function push(table: AnalyticsTable, record: Record<string, unknown>): Promise<void> {
  let payload: string;
  try {
    payload = JSON.stringify({
      ...record,
      event_time: record.event_time ?? Date.now(),
      node_id: identity.nodeId,
    });
  } catch (err) {
    logger.warn(`[Analytics] Failed to serialize '${table}' event — dropping: ${err}`);
    return;
  }

  await redis.getClient().xAdd(
    ANALYTICS_STREAM,
    '*',
    { table, payload },
    { TRIM: { strategy: 'MAXLEN', strategyModifier: '~', threshold: STREAM_MAXLEN } },
  );
}

/**
 * Fire-and-forget enqueue of an analytics event; errors are logged, never thrown.
 * Guards both the synchronous path (e.g. a disconnected Redis client throwing on
 * access) and the async append, so a logging failure can never reach the caller.
 *
 * @param table  - Target ClickHouse table the consumer should route this row to.
 * @param record - The event fields to enqueue.
 */
export function emit(table: AnalyticsTable, record: Record<string, unknown>): void {
  void push(table, record).catch((err: unknown) => {
    logger.warn(`[Analytics] Failed to enqueue '${table}' event: ${err}`);
  });
}
