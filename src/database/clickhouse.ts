import config from '../config/config.js';
import { ClickHouseClient, createClient } from '@clickhouse/client';
import logger from '../handler/logger.js';

/**
 * Lifecycle states for the singleton ClickHouse connection.
 *
 * @remarks
 * Tracking explicit state allows callers and health checks to distinguish
 * "not initialized yet" from "tried and failed" rather than only seeing a
 * `null` client.
 */
export enum ClickHouseConnectionState {
  /** No initialization has been attempted. */
  Idle = 'idle',
  /** An initialization attempt is currently in progress. */
  Connecting = 'connecting',
  /** A live, verified connection is available. */
  Connected = 'connected',
  /** The connection was intentionally closed. */
  Disconnected = 'disconnected',
  /** Initialization ran but failed after exhausting all retries. */
  Failed = 'failed',
}

/**
 * Error thrown for all ClickHouse connectivity failures.
 *
 * @remarks
 * Using a dedicated error type lets callers distinguish connectivity
 * problems from other runtime errors via `instanceof` and inspect the
 * originating error through {@link ClickHouseConnectionError.cause}.
 */
export class ClickHouseConnectionError extends Error {
  /** The underlying error or value that triggered this failure, if any. */
  public readonly cause?: unknown;

  /**
   * @param message - A human-readable description of the failure.
   * @param cause - The underlying error or value that caused the failure.
   */
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'ClickHouseConnectionError';
    this.cause = cause;
  }
}

/**
 * Tuning options for {@link initClickhouse}.
 */
export interface InitOptions {
  /**
   * Maximum number of connection attempts before giving up.
   *
   * @defaultValue 5
   */
  maxRetries?: number;

  /**
   * Base delay, in milliseconds, used to seed the exponential backoff.
   *
   * @defaultValue 500
   */
  retryBaseDelayMs?: number;

  /**
   * Upper bound, in milliseconds, on any single backoff delay.
   *
   * @defaultValue 10_000
   */
  retryMaxDelayMs?: number;

  /**
   * Timeout, in milliseconds, applied to each connectivity ping.
   *
   * @defaultValue 5_000
   */
  pingTimeoutMs?: number;
}

/**
 * The active client instance, or `null` when no live connection exists.
 * @internal
 */
let client: ClickHouseClient | null = null;

/**
 * The current connection lifecycle state.
 * @internal
 */
let state: ClickHouseConnectionState = ClickHouseConnectionState.Idle;

/**
 * The in-flight initialization promise, shared across concurrent callers
 * to prevent opening multiple connections to the same server.
 * @internal
 */
let initPromise: Promise<ClickHouseClient> | null = null;

/**
 * Validates that the required ClickHouse configuration is present.
 *
 * @remarks
 * `url` and `database` are treated as required. `username` and `password`
 * are intentionally not validated because the default ClickHouse user may
 * have no password.
 *
 * @throws {@link ClickHouseConnectionError} If configuration is missing or
 * required fields are absent.
 */
function validateConfig(): void {
  const ch = config?.db?.clickhouse;
  const missing: string[] = [];

  if (!ch) {
    throw new ClickHouseConnectionError('config.db.clickhouse is not defined');
  }
  if (!ch.url) missing.push('url');
  if (!ch.database) missing.push('database');

  if (missing.length > 0) {
    throw new ClickHouseConnectionError(
      `Missing ClickHouse configuration: ${missing.join(', ')}`,
    );
  }
}

/**
 * Resolves after the given delay without keeping the event loop alive.
 *
 * @param ms - The delay duration in milliseconds.
 * @returns A promise that resolves once the delay has elapsed.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    (timer as unknown as { unref?: () => void }).unref?.();
  });
}

/**
 * Computes an exponential backoff delay with full jitter.
 *
 * @param attempt - The zero-based attempt index.
 * @param base - The base delay in milliseconds.
 * @param max - The maximum delay in milliseconds.
 * @returns A jittered delay in milliseconds, never exceeding `max`.
 */
function backoffDelay(attempt: number, base: number, max: number): number {
  const exponential = Math.min(max, base * 2 ** attempt);
  return Math.round(Math.random() * exponential);
}

/**
 * Pings the server, enforcing a hard timeout per attempt.
 *
 * @remarks
 * The client's `ping()` resolves to a result object rather than throwing,
 * so both an unsuccessful result and a timeout are normalized into a
 * thrown {@link ClickHouseConnectionError}.
 *
 * @param candidate - The client to probe.
 * @param timeoutMs - The maximum time to wait for the ping, in milliseconds.
 * @throws {@link ClickHouseConnectionError} If the ping fails or times out.
 */
async function pingWithTimeout(
  candidate: ClickHouseClient,
  timeoutMs: number,
): Promise<void> {
  const timeout = new Promise<never>((_, reject) => {
    const timer = setTimeout(() => {
      reject(new ClickHouseConnectionError(`Ping timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    (timer as unknown as { unref?: () => void }).unref?.();
  });

  const result = await Promise.race([candidate.ping(), timeout]);
  if (!result.success) {
    throw new ClickHouseConnectionError('ClickHouse ping failed', result.error);
  }
}

/**
 * Creates and verifies a client, retrying with exponential backoff.
 *
 * @remarks
 * Each attempt creates a fresh client and verifies it with a ping before
 * being returned. A failed candidate is closed before the next attempt to
 * avoid leaking sockets.
 *
 * @param options - Retry and timeout tuning options.
 * @returns A live, verified client.
 * @throws {@link ClickHouseConnectionError} If every attempt fails.
 */
async function connectWithRetry(options: InitOptions): Promise<ClickHouseClient> {
  const {
    maxRetries = 5,
    retryBaseDelayMs = 500,
    retryMaxDelayMs = 10_000,
    pingTimeoutMs = 5_000,
  } = options;

  validateConfig();

  let lastError: unknown;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    let candidate: ClickHouseClient | null = null;
    try {
      candidate = createClient({
        url: config.db.clickhouse.url,
        username: config.db.clickhouse.username,
        password: config.db.clickhouse.password,
        database: config.db.clickhouse.database,
      });

      await pingWithTimeout(candidate, pingTimeoutMs);
      return candidate;
    } catch (error) {
      lastError = error;

      if (candidate) {
        await candidate.close().catch(() => {
          /* Ignore close errors raised while cleaning up a failed candidate. */
        });
      }

      const message = error instanceof Error ? error.message : String(error);
      logger.warn(`[clickhouse] attempt ${attempt}/${maxRetries} failed: ${message}`);

      if (attempt < maxRetries) {
        const delay = backoffDelay(attempt - 1, retryBaseDelayMs, retryMaxDelayMs);
        logger.warn(`[clickhouse] retrying in ${delay}ms`);
        await sleep(delay);
      }
    }
  }

  throw new ClickHouseConnectionError(
    `Failed to connect to ClickHouse after ${maxRetries} attempt(s)`,
    lastError,
  );
}

/**
 * Initializes the ClickHouse client and verifies connectivity before
 * resolving.
 *
 * @remarks
 * This function is idempotent. Concurrent calls share a single in-flight
 * connection attempt, and once a connection is established subsequent calls
 * resolve immediately with the cached client. After a failure the in-flight
 * reference is cleared so a later call can retry.
 *
 * Call and await this once during application startup.
 *
 * @param options - Retry and timeout tuning options.
 * @returns A promise resolving to a live, verified client.
 * @throws {@link ClickHouseConnectionError} If initialization fails after
 * all retries.
 *
 * @example
 * ```ts
 * await initClickhouse({ maxRetries: 3 });
 * ```
 */
export function initClickhouse(options: InitOptions = {}): Promise<ClickHouseClient> {
  if (client && state === ClickHouseConnectionState.Connected) {
    return Promise.resolve(client);
  }
  if (initPromise) {
    return initPromise;
  }

  state = ClickHouseConnectionState.Connecting;

  const pending = connectWithRetry(options)
    .then((connected) => {
      client = connected;
      state = ClickHouseConnectionState.Connected;
      logger.info('[clickhouse] connected successfully');
      return connected;
    })
    .catch((error: unknown) => {
      client = null;
      state = ClickHouseConnectionState.Failed;
      throw error instanceof ClickHouseConnectionError
        ? error
        : new ClickHouseConnectionError('Failed to initialize ClickHouse client', error);
    })
    .finally(() => {
      initPromise = null;
    });

  initPromise = pending;
  return pending;
}

/**
 * Returns the live client, throwing if no verified connection exists.
 *
 * @remarks
 * Intended for use in request handlers and repositories where
 * {@link initClickhouse} has already completed during startup.
 *
 * @returns The connected client.
 * @throws {@link ClickHouseConnectionError} If the client is not connected.
 */
export function getClickhouseClient(): ClickHouseClient {
  if (!client || state !== ClickHouseConnectionState.Connected) {
    throw new ClickHouseConnectionError(
      `ClickHouse client is not available (state: ${state}). ` +
        'Call and await initClickhouse() during application startup.',
    );
  }
  return client;
}

/**
 * Returns the current connection lifecycle state.
 *
 * @returns The current {@link ClickHouseConnectionState}.
 */
export function getConnectionState(): ClickHouseConnectionState {
  return state;
}

/**
 * Reports whether a live, verified connection is currently available.
 *
 * @returns `true` if connected, otherwise `false`.
 */
export function isClickhouseConnected(): boolean {
  return state === ClickHouseConnectionState.Connected && client !== null;
}

/**
 * Performs an active liveness probe against the current connection.
 *
 * @remarks
 * Safe to wire into a readiness or liveness endpoint; it returns `false`
 * rather than throwing on failure.
 *
 * @param timeoutMs - The ping timeout in milliseconds.
 * @returns `true` if the server responds successfully, otherwise `false`.
 */
export async function clickhouseHealthCheck(timeoutMs = 5_000): Promise<boolean> {
  if (!client) return false;
  try {
    await pingWithTimeout(client, timeoutMs);
    return true;
  } catch {
    return false;
  }
}

/**
 * Gracefully closes the active connection and resets internal state.
 *
 * @remarks
 * Wire this into your process shutdown handlers to release resources
 * cleanly. Close errors are logged but not rethrown.
 *
 * @returns A promise that resolves once shutdown is complete.
 *
 */
export async function closeClickhouse(): Promise<void> {
  const current = client;
  client = null;
  initPromise = null;
  state = ClickHouseConnectionState.Disconnected;

  if (current) {
    try {
        await current.close();
        logger.info('[clickhouse] connection closed');
    } catch (error) {
        console.error('[clickhouse] error while closing connection:', error);
        logger.error('[clickhouse] error while closing connection:' + error);
    }
  }
}