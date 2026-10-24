import { emit } from './producer.js';
import logger from '../handler/logger.js';
import type {
  AnalyticsTable,
  AppEventInput,
  ApiRequestInput,
  AuthEventInput,
  ClientDiagnosticsInput,
  ServerIssueInput,
} from './types.js';

// body cap
const MAX_BODY_CHARS = 16_000;

/**
 * Serializes a free-form meta object into the `meta` JSON column string.
 *
 * @param meta - Optional extras to serialize.
 * @returns The JSON string, or `'{}'` when absent, empty, or unserializable.
 */
function serializeMeta(meta?: Record<string, unknown>): string {
  if (!meta || Object.keys(meta).length === 0) return '{}';
  try {
    return JSON.stringify(meta);
  } catch {
    return '{}';
  }
}

/**
 * Serializes a req/res body into its `String` column, truncating oversized
 * payloads. Strings pass through as-is; everything else is JSON-encoded.
 *
 * @param body - The body to serialize (object, array, string, or absent).
 * @returns The serialized body, or `'{}'` when absent or unserializable.
 */
function serializeBody(body: unknown): string {
  if (body === undefined || body === null) return '{}';
  let str: string;
  try {
    str = typeof body === 'string' ? body : JSON.stringify(body);
  } catch {
    return '{}';
  }
  if (str.length > MAX_BODY_CHARS) str = `${str.slice(0, MAX_BODY_CHARS)}…[truncated]`;
  return str;
}

/**
 * Builds the row for an event and enqueues it, swallowing any failure so a
 * logging call can never throw into the caller's request path.
 *
 * @param table - Target ClickHouse table.
 * @param build - Builds the row lazily, so a throw while shaping it is caught here.
 */
function record(table: AnalyticsTable, build: () => Record<string, unknown>): void {
  try {
    emit(table, build());
  } catch (err) {
    logger.warn(`[Analytics] Failed to record '${table}' event: ${err}`);
  }
}

/**
 * Records an authentication lifecycle event to the `auth_events` table.
 *
 * @param event - The auth event fields; absent optional fields default to `''`.
 */
export function logAuthEvent(event: AuthEventInput): void {
  record('auth_events', () => ({
    event_type: event.event_type,
    outcome: event.outcome,
    reason: event.reason ?? '',
    user_id: event.user_id ?? '',
    username: event.username ?? '',
    psk_type: event.psk_type ?? '',
    ip: event.ip ?? '',
    country: event.country ?? '',
    hwid: event.hwid ?? '',
    build_id: event.build_id ?? '',
    loader_id: event.loader_id ?? '',
    session_id: event.session_id ?? '',
    meta: serializeMeta(event.meta),
  }));
}

/**
 * Records a generic event (license, build, ban, …) to `app_events`.
 *
 * @param event - The app event fields; absent optional fields default to `''`.
 */
export function logAppEvent(event: AppEventInput): void {
  record('app_events', () => ({
    category: event.category,
    action: event.action,
    user_id: event.user_id ?? '',
    target_id: event.target_id ?? '',
    psk_type: event.psk_type ?? '',
    ip: event.ip ?? '',
    country: event.country ?? '',
    build_id: event.build_id ?? '',
    loader_id: event.loader_id ?? '',
    meta: serializeMeta(event.meta),
  }));
}

/**
 * Records a request-level access-log event to the `api_requests` table.
 *
 * @param event - The request event fields; absent optional fields default to `''`.
 */
export function logApiRequest(event: ApiRequestInput): void {
  record('api_requests', () => ({
    method: event.method,
    route: event.route,
    status: event.status,
    duration_ms: event.duration_ms,
    user_id: event.user_id ?? '',
    psk_type: event.psk_type ?? '',
    ip: event.ip ?? '',
    country: event.country ?? '',
    build_id: event.build_id ?? '',
    loader_id: event.loader_id ?? '',
  }));
}

/**
 * Records a client-side diagnostic / watchdog report to `client_diagnostics`.
 *
 * @param event - The diagnostic fields; absent optional fields default to `''`.
 */
export function logClientDiagnostics(event: ClientDiagnosticsInput): void {
  record('client_diagnostics', () => ({
    event_type: event.event_type,
    severity: event.severity ?? '',
    message: event.message ?? '',
    error_code: event.error_code ?? '',
    user_id: event.user_id ?? '',
    username: event.username ?? '',
    session_id: event.session_id ?? '',
    psk_type: event.psk_type ?? '',
    build_id: event.build_id ?? '',
    loader_id: event.loader_id ?? '',
    ip: event.ip ?? '',
    country: event.country ?? '',
    meta: serializeMeta(event.meta),
  }));
}

/**
 * Records a server-side failure (any non-2xx response) to `server_issues`,
 * including the request and response bodies for debugging.
 *
 * @param event - The issue fields; absent optional fields default to `''`/`'{}'`.
 */
export function logServerIssue(event: ServerIssueInput): void {
  record('server_issues', () => ({
    method: event.method ?? '',
    route: event.route,
    status: event.status,
    error_code: event.error_code ?? '',
    message: event.message ?? '',
    user_id: event.user_id ?? '',
    psk_type: event.psk_type ?? '',
    ip: event.ip ?? '',
    request_body: serializeBody(event.request_body),
    response_body: serializeBody(event.response_body),
  }));
}
