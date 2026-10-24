import { Router, Express } from 'express';
import message from './logger.js';
import fs from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import { PskType, PSK } from '../types/psk.js';


const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);


/**
 * Route-level configuration exported by route modules.
 */
export interface RouteConfig {
    /** When `true`, the route requires E2E encryption. Defaults to `false` (public). */
    encrypted?: boolean;
    /** Plaintext shape expected after E2E decryption. Defaults to JSON. */
    bodyType?: 'json' | 'binary';
    /** When `true`, the route requires a valid authenticated session. */
    auth?: boolean;
    // When set, restricts access to the specified audience, which is validated in the auth middleware.
    audience?: 'loader' | 'core';
    // When set, restricts access to requests authenticated with the specified PSK(s), which is validated in the pskGate middleware.
    allowedPsk?: PskType[];

}

/** Stores the resolved config for every registered route path. */
const registry = new Map<string, RouteConfig>();

/** Regex-based fallback for parameterised routes: pattern -> config. */
const regexRegistry: Array<{ pattern: RegExp; config: RouteConfig }> = [];


/** Default values for route configs, applied when a property is not explicitly set. */
const ROUTE_DEFAULTS: Partial<RouteConfig> = {};

/**
 * Returns the {@link RouteConfig} for the given path, or an empty object
 * if the path is not registered (treat as fully public / no requirements).
 *
 * @param path - Request path with the query string already stripped.
 */
export function getRouteConfig(path: string): RouteConfig {
    const config =
        registry.get(path) ??
        regexRegistry.find(({ pattern }) => pattern.test(path))?.config ??
        {};

    return { ...ROUTE_DEFAULTS, ...config };
}


/**
 * Stores a route's config in the appropriate registry collection.
 *
 * @param routePath - The route path string.
 * @param regexp    - Compiled route regex, used for parameterised paths.
 * @param config    - The resolved config to associate with the route.
 */
function registerRoute(
    routePath: string,
    regexp: RegExp | undefined,
    config: RouteConfig,
): void {
    if (routePath.includes(':')) {
        if (regexp) regexRegistry.push({ pattern: regexp, config });
    } else {
        registry.set(routePath, config);
    }
}

/**
 * Walks a router's stack and stores each route's config in the registry.
 *
 * @param router - The Express router to inspect.
 * @param config - The config to associate with every route in this router.
 */
function extractRoutes(router: Router, config: RouteConfig): void {
    const stack = (router as any).stack;
    if (!stack) return;

    for (const layer of stack) {
        if (!layer.route) continue;
        registerRoute(
            layer.route.path,
            layer.route.regexp ?? layer.regexp,
            config,
        );
    }
}


/**
 * Imports a single route module and registers its router with the app.
 *
 * @param app        - The Express application.
 * @param itemPath   - Absolute path to the route module.
 * @param fileName   - Module filename, used for logging.
 * @param folderName - Parent folder name, used for logging.
 */
async function loadRoute(
    app: Express,
    itemPath: string,
    fileName: string,
    folderName: string,
): Promise<void> {
    const mod    = await import(pathToFileURL(itemPath).href);
    const router: Router      = mod.default;
    const config: RouteConfig = mod.config ?? {};

    if (!router || typeof router !== 'function') {
        message.err(`Invalid router exported from ${fileName}`);
        return;
    }

    extractRoutes(router, config);
    app.use(router);

    const prefix       = folderName    ? `[${folderName}] ` : '';
    const encryptedTag = config.encrypted ? '[ENCRYPTED] '  : '';
    const authTag      = config.auth      ? '[AUTH] '       : '';
    const pskTag       = config.allowedPsk?.length ? `[PSK:${config.allowedPsk.join(',')}] ` : '';
    message.notify(`${encryptedTag}${authTag}${pskTag}${prefix}Loaded ${fileName}`);
}

/**
 * Recursively loads all route modules from a directory.
 *
 * @param app        - The Express application.
 * @param routesPath - Directory to scan.
 * @param folderName - Accumulated folder path, used for logging.
 */
async function loadRoutes(
    app: Express,
    routesPath: string,
    folderName = '',
): Promise<void> {
    if (!fs.existsSync(routesPath)) {
        message.err(`Routes directory not found: ${routesPath}`);
        return;
    }

    for (const item of fs.readdirSync(routesPath)) {
        const itemPath = path.join(routesPath, item);
        const stat     = fs.statSync(itemPath);

        if (stat.isDirectory()) {
            await loadRoutes(app, itemPath, folderName ? `${folderName}/${item}` : item);
        } else if (stat.isFile() && /\.(ts|js)$/.test(item)) {
            try {
                await loadRoute(app, itemPath, item, folderName);
            } catch (err: any) {
                message.err(`Failed to load route ${item}: ${err.message}`);
            }
        }
    }
}


/**
 * Loads all route modules from the default routes directory.
 *
 * @param app - The Express application.
 */
function load(app: Express): Promise<void> {
    const routesPath = path.join(__dirname, '../routes');
    return loadRoutes(app, routesPath).catch(err => {
        message.err(`Route loader failed: ${err.message}`);
        throw err;
    });
}

export default { load };
