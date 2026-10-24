import config from '../config/config.js';

/**
 * Error thrown when one or more required configuration values are missing.
 *
 * @remarks
 * The {@link ConfigValidationError.missingKeys} property lists every absent
 * value so the whole set of problems can be surfaced at once, rather than
 * failing on the first missing key.
 */
export class ConfigValidationError extends Error {
  /** The dotted paths of every configuration value found to be missing. */
  public readonly missingKeys: readonly string[];

  /**
   * @param missingKeys - The dotted paths of the missing configuration values.
   */
  constructor(missingKeys: readonly string[]) {
    super(`Missing required configuration: ${missingKeys.join(', ')}`);
    this.name = 'ConfigValidationError';
    this.missingKeys = missingKeys;
  }
}

/**
 * Options controlling how configuration validation traverses and treats
 * values.
 */
export interface ConfigCheckOptions {
  /**
   * Whether empty strings should be treated as missing.
   *
   * @remarks
   * Environment variables that are set but blank resolve to an empty string,
   * which is rarely a valid value, so this defaults to `true`.
   *
   * @defaultValue true
   */
  treatEmptyStringAsMissing?: boolean;

  /**
   * Dotted paths to exclude from validation.
   *
   * @remarks
   * Because every leaf in the configuration is discovered dynamically, use
   * this to opt specific values out of the check (for example, ones that are
   * genuinely optional).
   *
   * @defaultValue []
   */
  ignoreKeys?: readonly string[];
}

/**
 * A configuration value paired with the dotted path identifying its source.
 * @internal
 */
type ConfigEntry = readonly [path: string, value: unknown];

/**
 * Recursively flattens a configuration object into `[path, value]` tuples.
 *
 * @remarks
 * Plain objects are traversed; every other value (string, number, boolean,
 * array, `null`, or `undefined`) is treated as a leaf. This discovers all
 * configuration values dynamically, so no manual list of keys is maintained.
 *
 * @param value - The current value being flattened.
 * @param prefix - The accumulated dotted path leading to `value`.
 * @returns The flattened leaf entries.
 * @internal
 */
function flattenConfig(value: unknown, prefix = ''): ConfigEntry[] {
  const isPlainObject =
    value !== null && typeof value === 'object' && !Array.isArray(value);

  if (isPlainObject) {
    return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) =>
      flattenConfig(child, prefix ? `${prefix}.${key}` : key),
    );
  }

  return [[prefix, value]];
}

/**
 * Determines whether a single configuration value should count as missing.
 *
 * @remarks
 * Only `undefined`, `null`, and (optionally) blank strings are considered
 * missing. Valid falsy values such as `false` and `0` are preserved.
 *
 * @param value - The value to inspect.
 * @param treatEmptyStringAsMissing - Whether a blank string is missing.
 * @returns `true` if the value is considered missing.
 * @internal
 */
function isMissing(value: unknown, treatEmptyStringAsMissing: boolean): boolean {
  if (value === undefined || value === null) return true;
  if (treatEmptyStringAsMissing && typeof value === 'string' && value.trim() === '') {
    return true;
  }
  return false;
}

/**
 * Returns the dotted paths of every configuration value that is missing.
 *
 * @remarks
 * All values are discovered dynamically by walking the imported
 * configuration object, so newly added keys are validated automatically.
 *
 * @param options - Validation options.
 * @returns An array of dotted paths; empty when all values are present.
 *
 * @example
 * ```ts
 * const missing = getMissingConfigKeys();
 * if (missing.length > 0) {
 *   console.error('Missing config:', missing);
 * }
 * ```
 */
export function getMissingConfigKeys(options: ConfigCheckOptions = {}): string[] {
  const { treatEmptyStringAsMissing = true, ignoreKeys = [] } = options;
  const ignored = new Set(ignoreKeys);

  return flattenConfig(config)
    .filter(([path]) => !ignored.has(path))
    .filter(([, value]) => isMissing(value, treatEmptyStringAsMissing))
    .map(([path]) => path);
}

/**
 * Reports whether all required configuration values are present.
 *
 * @param options - Validation options.
 * @returns `true` if nothing is missing, otherwise `false`.
 */
export function isConfigValid(options: ConfigCheckOptions = {}): boolean {
  return getMissingConfigKeys(options).length === 0;
}

/**
 * Asserts that all required configuration values are present.
 *
 * @remarks
 * Call this once during application startup, before any subsystem that
 * depends on the configuration is initialized.
 *
 * @param options - Validation options.
 * @throws {@link ConfigValidationError} If any required value is missing.
 *
 * @example
 * ```ts
 * import { assertConfigValid } from './configCheck.js';
 *
 * assertConfigValid();
 * ```
 */
export function assertConfigValid(options: ConfigCheckOptions = {}): void {
  const missing = getMissingConfigKeys(options);
  if (missing.length > 0) {
    throw new ConfigValidationError(missing);
  }
}

/**
 * Validates the configuration and terminates the process if anything is
 * missing.
 *
 * @remarks
 * This is a convenience for entry points that prefer a logged message and a
 * non-zero exit code over an unhandled exception. Use {@link assertConfigValid}
 * instead when the caller should handle the error.
 *
 * @param options - Validation options.
 */
export function validateConfig(options: ConfigCheckOptions = {}): void {
  const missing = getMissingConfigKeys(options);
  if (missing.length > 0) {
    console.error(
      `[config] missing ${missing.length} required value(s):\n` +
        missing.map((key) => `  - ${key}`).join('\n'),
    );
    process.exit(1);
  }
  console.log('[config] all required values are present');
}