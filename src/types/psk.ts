/**
 * All registered PSK identities.
 * Add a new literal here when a new key is introduced in `config.serverKeys.static`.
 */
export type PskType = "core" | "loader";

/**
 * Convenience constants so downstream middleware never hardcodes a raw string.
 *
 * @example
 * if (getPskType(req) === PSK.LOADER) { ... }
 */
export const PSK = {
  CORE:   "core",
  LOADER: "loader",
} as const satisfies Record<string, PskType>;