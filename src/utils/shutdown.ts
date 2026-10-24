import logger from '../handler/logger.js';
import redis from '../database/redis.js';
import * as analyticsConsumer from '../analytics/consumer.js';
import { closeClickhouse } from '../database/clickhouse.js';

/**
 * Performs a graceful application shutdown.
 * Disconnects Redis when connected, logs the shutdown sequence,
 * and exits the process.
 *
 * @param signal - The signal or event name that triggered the shutdown.
 * @returns Resolves just before the process exits.
 */
async function shutdown(signal: string): Promise<void> {
    logger.notify(`[App] Received ${signal}, shutting down...`);

    try {
        analyticsConsumer.stop();
        await closeClickhouse();

        if (await redis.isConnected()) {
            logger.notify('[Redis] Disconnecting...');
            await redis.disconnect();
        }
    } catch (err) {
        logger.critical(`[App] Error during shutdown: ${err}`);
    }

    logger.success('[App] Shutdown complete');
    process.exit(0);
}

// Handle interrupt signals from the process.
process.on('SIGINT', () =>
    shutdown('SIGINT')
);

// Handle termination signals from the process.
process.on('SIGTERM', () =>
    shutdown('SIGTERM')
);

// Log uncaught exceptions and trigger shutdown.
process.on('uncaughtException', (err) => {
    logger.critical(`[App] Uncaught Exception: ${err.message}`);
    logger.critical(err.stack || 'No stack trace available');
    shutdown('uncaughtException');
});

// Log unhandled promise rejections and trigger shutdown.
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise);
    logger.critical(`[App] Unhandled Rejection, reason: ${reason}`);
    shutdown('unhandledRejection');
});