/**
 * Master-side analytics consumer.
 *
 * Drains the Redis Stream that producers append to and flushes batches into
 * ClickHouse. Runs only on the elected master via {@link start} / {@link stop}.
 *
 * Delivery is at-least-once: entries are read through a consumer group and only
 * acknowledged (and deleted) after their ClickHouse insert succeeds. A failed
 * insert leaves them pending for retry, and {@link claimStale} reclaims entries
 * stranded by a master that died mid-batch.
 */

import redis from '../database/redis.js';
import logger from '../handler/logger.js';
import identity from '../cluster/identity.js';
import { getClickhouseClient, isClickhouseConnected } from '../database/clickhouse.js';
import { ANALYTICS_STREAM } from './producer.js';
import type { AnalyticsTable } from './types.js';

const GROUP = 'ch-writers';
const CONSUMER = identity.nodeId;

const BATCH_COUNT = 2000;
const IDLE_MS = 1000;
const ERROR_BACKOFF_MS = 5000;
const MIN_IDLE_MS = 60_000;

const KNOWN_TABLES = new Set<AnalyticsTable>(['auth_events', 'app_events', 'api_requests', 'server_issues']);

type StreamEntry = { id: string; message: Record<string, string> };

const dateTimeFormatter = new Intl.DateTimeFormat('en-GB', {
  timeZone: 'Europe/Berlin',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
});

/**
 * Converts epoch milliseconds to a `YYYY-MM-DD HH:MM:SS.mmm` string in
 * Europe/Berlin, which a `DateTime64(3, 'Europe/Berlin')` column parses
 * unambiguously. The millisecond fraction is timezone-independent.
 *
 * @param ms - Epoch milliseconds.
 * @returns The formatted `YYYY-MM-DD HH:MM:SS.mmm` datetime string.
 */
function toClickHouseDateTime(ms: number): string {
  const parts = dateTimeFormatter.formatToParts(new Date(ms));
  const get = (type: Intl.DateTimeFormatPartTypes): string =>
    parts.find((p) => p.type === type)?.value ?? '00';
  const millis = String(((ms % 1000) + 1000) % 1000).padStart(3, '0');
  return `${get('year')}-${get('month')}-${get('day')} ${get('hour')}:${get('minute')}:${get('second')}.${millis}`;
}

let running = false;
let looping = false;
let timer: NodeJS.Timeout | null = null;

/**
 * Narrows an arbitrary string to a known analytics table.
 *
 * @param table - The candidate table name from a stream entry.
 * @returns True if the name is one of the known ClickHouse tables.
 */
function isKnownTable(table: string): table is AnalyticsTable {
  return KNOWN_TABLES.has(table as AnalyticsTable);
}

/**
 * Parses a stream payload into a ClickHouse row, converting `event_time` from
 * epoch milliseconds to a `YYYY-MM-DD HH:MM:SS.mmm` string.
 *
 * @param payload - The JSON payload string from a stream entry.
 * @returns The parsed row, or null when the JSON is unparseable.
 */
function toRow(payload: string): Record<string, unknown> | null {
  try {
    const obj = JSON.parse(payload) as Record<string, unknown>;
    if (typeof obj.event_time === 'number' && Number.isFinite(obj.event_time)) {
      obj.event_time = toClickHouseDateTime(obj.event_time);
    } else {
      delete obj.event_time;
    }
    return obj;
  } catch {
    return null;
  }
}

/**
 * Creates the consumer group if it doesn't already exist.
 *
 * @returns Resolves once the group exists; a `BUSYGROUP` error is swallowed.
 * @throws Re-throws any group-creation error other than `BUSYGROUP`.
 */
async function ensureGroup(): Promise<void> {
  try {
    await redis.getClient().xGroupCreate(ANALYTICS_STREAM, GROUP, '$', { MKSTREAM: true });
    logger.debug(`[Analytics] created consumer group '${GROUP}'`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (!msg.includes('BUSYGROUP')) throw err;
  }
}

/**
 * Inserts a batch of entries into ClickHouse and acknowledges what succeeded.
 * Poison entries (unknown table / unparseable) are acknowledged and dropped so
 * they don't block the stream; entries whose insert fails are left pending.
 *
 * @param entries - The stream entries to insert, grouped by target table.
 * @returns The number of entries handled.
 */
async function processEntries(entries: StreamEntry[]): Promise<number> {
  if (entries.length === 0) return 0;

  const ackIds: string[] = [];
  const byTable = new Map<AnalyticsTable, { ids: string[]; rows: Record<string, unknown>[] }>();

  for (const { id, message } of entries) {
    const table = message?.table;
    const payload = message?.payload;

    if (!table || !isKnownTable(table) || typeof payload !== 'string') {
      logger.warn(`[Analytics] dropping malformed entry ${id} (table=${table})`);
      ackIds.push(id);
      continue;
    }

    const row = toRow(payload);
    if (!row) {
      logger.warn(`[Analytics] dropping unparseable entry ${id}`);
      ackIds.push(id);
      continue;
    }

    const bucket = byTable.get(table) ?? { ids: [], rows: [] };
    bucket.ids.push(id);
    bucket.rows.push(row);
    byTable.set(table, bucket);
  }

  for (const [table, { ids, rows }] of byTable) {
    try {
      await getClickhouseClient().insert({ table, values: rows, format: 'JSONEachRow' });
      ackIds.push(...ids);
    } catch (err) {
      logger.error(`[Analytics] insert into '${table}' failed (${rows.length} rows, will retry): ${err}`);
    }
  }

  if (ackIds.length > 0) {
    try {
      const client = redis.getClient();
      await client.xAck(ANALYTICS_STREAM, GROUP, ackIds);
      await client.xDel(ANALYTICS_STREAM, ackIds);
    } catch (err) {
      // Rows are already inserted; a failed ack just means they redeliver and the
      // (idempotent at-least-once) insert repeats. Log and move on, don't throw.
      logger.error(`[Analytics] failed to ack/del ${ackIds.length} entries (will redeliver): ${err}`);
    }
  }

  return entries.length;
}

/**
 * Reads and processes new (never-delivered) entries from the stream.
 *
 * @returns The number of entries handled in this read.
 */
async function readNew(): Promise<number> {
  const res = await redis.getClient().xReadGroup(
    GROUP,
    CONSUMER,
    { key: ANALYTICS_STREAM, id: '>' },
    { COUNT: BATCH_COUNT },
  );

  const entries = res?.[0]?.messages as StreamEntry[] | undefined;
  return processEntries(entries ?? []);
}

/**
 * Reclaims and processes entries stranded by a previous (dead) master.
 *
 * @returns The number of reclaimed entries handled in this pass.
 */
async function claimStale(): Promise<number> {
  const res = await redis.getClient().xAutoClaim(
    ANALYTICS_STREAM,
    GROUP,
    CONSUMER,
    MIN_IDLE_MS,
    '0',
    { COUNT: BATCH_COUNT },
  );

  const entries = (res?.messages ?? []).filter((m): m is StreamEntry => m != null);
  return processEntries(entries);
}

/**
 * Schedules the next loop iteration, unless the consumer has stopped.
 *
 * @param delay - Milliseconds to wait before the next iteration.
 */
function schedule(delay: number): void {
  if (!running) return;
  timer = setTimeout(() => void loop(), delay);
  timer.unref?.();
}

/**
 * One drain iteration: reclaims stale entries, reads new ones, then reschedules
 * itself immediately while batches are full or after an idle delay otherwise.
 *
 * @returns Resolves once the iteration completes and the next is scheduled.
 */
async function loop(): Promise<void> {
  if (!running || looping) return;
  looping = true;

  try {
    const claimed = await claimStale();
    const fresh = await readNew();
    const handled = claimed + fresh;
    schedule(handled >= BATCH_COUNT ? 0 : IDLE_MS);
  } catch (err) {
    logger.error(`[Analytics] consumer loop error: ${err}`);

    // The group can vanish if Redis was unreachable at start or the stream was
    // trimmed away. Recreate it (idempotent) so the consumer self-heals.
    if (err instanceof Error && err.message.includes('NOGROUP')) {
      await ensureGroup().catch((e) => logger.error(`[Analytics] group re-create failed: ${e}`));
    }

    schedule(ERROR_BACKOFF_MS);
  } finally {
    looping = false;
  }
}

/**
 * Starts the consumer. Idempotent; intended to run only on the master. Never
 * throws — if the group can't be created yet (Redis down), it starts anyway and
 * the loop recreates it on the first `NOGROUP`.
 *
 * @returns Resolves once startup is scheduled.
 */
export async function start(): Promise<void> {
  if (running) return;

  if (!isClickhouseConnected()) {
    logger.warn('[Analytics] consumer starting while ClickHouse is disconnected — inserts will retry until it recovers');
  }

  try {
    await ensureGroup();
  } catch (err) {
    logger.error(`[Analytics] could not create consumer group at start — loop will retry: ${err}`);
  }

  running = true;
  logger.info('[Analytics] stream consumer started');
  schedule(0);
}

/**
 * Stops the consumer. Idempotent; called on master step-down and shutdown.
 */
export function stop(): void {
  if (!running && !timer) return;
  running = false;
  if (timer) {
    clearTimeout(timer);
    timer = null;
  }
  logger.info('[Analytics] stream consumer stopped');
}
