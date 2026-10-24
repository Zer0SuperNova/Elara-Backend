import { createClient, RedisClientType, RESP_TYPES } from 'redis';
import logger from '../handler/logger.js';
import config from '../config/config.js';

let client: RedisClientType;
let bufferClient: ReturnType<typeof client.withTypeMapping>;
let sessionClient: RedisClientType;

const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 3000;

/**
 * Waits for a specified number of milliseconds.
 * @param {number} ms - The number of milliseconds to wait
 * @returns {Promise<void>} A promise that resolves after the delay
 */
function wait(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Gets the session client.
 * @returns {RedisClientType} The session client
 * @throws {Error} If the session client has not been initialized
 */
function getSessionClient(): RedisClientType {
	if (!sessionClient) throw new Error("[Redis] Session client not initialized. Call init() first.");
	return sessionClient;
}

/**
 * Initializes a Redis client with retry logic.
 * Attempts to connect to Redis with automatic retries on failure.
 * @returns {Promise<RedisClientType | null>} The connected Redis client or null if all connection attempts fail
 */
async function init(): Promise<RedisClientType | null> {
    const host: string = config.db.redis.host || 'localhost';
    const port: number = Number(config.db.redis.port) || 6379;

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        try {
            client = createClient({
                socket: { host, port },
                username: config.db.redis.username,
                password: config.db.redis.password
            });

            client.on('error', (err: Error) => {
                logger.error("[Redis] Runtime error: " + err);
            });

            await client.connect();
            bufferClient = client.withTypeMapping({ [RESP_TYPES.BLOB_STRING]: Buffer });
            sessionClient = client.duplicate();
            await sessionClient.connect();
            await sessionClient.select(0);
            logger.info("[Redis] Connected to redis");
            return client;
        } catch (error) {
            logger.error(`[Redis] Connection attempt ${attempt}/${MAX_RETRIES} failed: ${error}`);

            if (attempt < MAX_RETRIES) {
                logger.info(`[Redis] Retrying in ${RETRY_DELAY_MS / 1000}s...`);
                await wait(RETRY_DELAY_MS);
            }
            else
            {
                logger.critical("[Redis] All connection attempts failed. Please check your Redis server and configuration.");
            }
        }
    }

    return null;
}

/**
 * Gets the initialized Redis client.
 * @returns {RedisClientType} The connected Redis client
 * @throws {Error} If the client has not been initialized
 */
function getClient(): RedisClientType {
    if (!client) throw new Error("[Redis] Client not initialized. Call init() first.");
    return client;
}

/**
 * Gets the buffer-mapped Redis client for binary data operations.
 * @returns The buffer client
 * @throws {Error} If the client has not been initialized
 */
function getBufferClient(): ReturnType<typeof client.withTypeMapping> {
    if (!bufferClient) throw new Error("[Redis] Buffer client not initialized. Call init() first.");
    return bufferClient;
}

/**
 * Disconnects the Redis client.
 * @returns {Promise<void>} A promise that resolves when disconnection is complete
 */
async function disconnect(): Promise<void> {
	if (sessionClient?.isOpen) {
		await sessionClient.quit();
	}

	if (client?.isOpen) {
		await client.quit();
		logger.info("[Redis] Disconnected");
	}
}

/**
 * Checks if the Redis client is currently connected.
 * @returns {Promise<boolean>} True if the client is connected, false otherwise
 */
async function isConnected(): Promise<boolean> {
    return client?.isOpen || false;
}

export default {
	init,
	getClient,
	getBufferClient,
	getSessionClient,
	disconnect,
	isConnected
};