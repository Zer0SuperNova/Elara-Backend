import './utils/shutdown.js';

// core
import express, { Express } from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';

// handlers
import config from './config/config.js';
import {validateConfig} from './utils/configCheck.js';
import logger from './handler/logger.js';
import routeloader from './handler/routeloader.js';

// databases
import redis from './database/redis.js';
import { init as initMysql } from './database/mysql.js';
import { initS3Client } from './database/s3.js';
import { initClickhouse } from './database/clickhouse.js';

// middlewares
import E2EMiddleware from './middlewares/E2E.js';
import pskGate from './middlewares/pskGate.js';
import { createRateLimiter } from './middlewares/rateLimiter.js';
import authMiddleware from './middlewares/auth.js';
import analyticsLogger from './middlewares/analyticsLogger.js';
import clientInfo from './middlewares/clientInfo.js';

// cluster
import election from './cluster/election.js';

// set timezone for consistent timestamps in logs and databases
process.env.TZ = 'Europe/Berlin';

/**
 * Creates and configures the Express application with middleware.
 * @returns {Express} Configured Express application instance
 */
function createApp(): Express {
    const app = express();

    app.disable('x-powered-by');
    app.set('trust proxy', 1);
    app.options('*path', cors());
    app.use(cors({ origin: ['*'] }));
    app.use(express.json());
    app.use(bodyParser.urlencoded({ extended: true }));
    app.use(express.raw({ type: '*/*', limit: '10mb' }));

    // Custom middlewares
    app.use(clientInfo);
    app.use(analyticsLogger);
    app.use(createRateLimiter());
    app.use(pskGate);
    app.use(E2EMiddleware);
    app.use(authMiddleware);

    return app;
}


/**
 * Initializes all required databases and bootstrap data.
 * Exits the process if Redis cannot be reached.
 * @returns {Promise<void>} Resolves when database initialization completes.
 */
async function initDatabases(): Promise<void> {
    logger.notify('Initializing databases...');

    const [redisClient] = await Promise.all([
        redis.init(),
        initMysql(),
        initS3Client(),
        initClickhouse(),
    ]);

    if (!redisClient) {
        logger.critical('[Redis] Failed to connect after 3 attempts. Aborting startup.');
        process.exit(1);
    }

    logger.notify('Databases initialized\n');
}

/**
 * Ensures the application is running on a supported operating system.
 * Exits the process if the current platform is unsupported.
 * @returns {Promise<void>} Resolves when the OS check passes.
 */
async function operatingSystemCheck(): Promise<void> {
    const supportedOS = ['linux', 'darwin'];
    const currentOS = process.platform;

    if (!supportedOS.includes(currentOS)) {
        logger.critical(`Unsupported operating system: ${currentOS}. Supported OS: ${supportedOS.join(', ')}`);
        process.exit(1);
    }

    logger.debug(`Operating system check passed: ${currentOS}`);
}


/**
 * Loads routes and starts the HTTP server.
 * Exits the process if API endpoint configuration is missing.
 * @param {Express} app - Configured Express application instance.
 * @returns {Promise<void>} Resolves when the server has started listening.
 */
async function startServer(app: Express): Promise<void> {
    const port = Number(config.endpoints.api.port);
    const hostname = config.endpoints.api.hostname;

    if (!port || !hostname) {
        logger.critical('API endpoint configuration is missing');
        process.exit(1);
    }

    await routeloader.load(app);

    app.listen(port, hostname, () => {
        logger.success(`[API] Listening on ${hostname}:${port}`);
    });
}


// Main startup sequence
try {

    // Validate config before doing anything else
    validateConfig();
    

    await operatingSystemCheck();
    await initDatabases();

    await election.start();

    const app = createApp();
    await startServer(app);

} catch (error) {
    logger.critical(`Startup error: ${error}`);
    process.exit(1);
}