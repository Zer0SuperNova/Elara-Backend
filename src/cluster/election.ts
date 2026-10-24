import redis from '../database/redis.js';
import logger from '../handler/logger.js';
import identity from './identity.js';
import * as analyticsConsumer from '../analytics/consumer.js';

const MASTER_KEY = 'cluster:master:lock';
const MASTER_TTL_MS = 10_000;

const RENEW_SCRIPT = `
  if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("PEXPIRE", KEYS[1], ARGV[2])
  else
    return 0
  end
`;

/**
 * Attempts to acquire the master lock for the given node.
 *
 * @param nodeId - Unique identifier for the current node.
 * @returns True when the lock was acquired successfully.
 */
async function tryAcquireLock(nodeId: string): Promise<boolean> {
    const client = redis.getClient();
    const result = await client.set(MASTER_KEY, nodeId, { NX: true, PX: MASTER_TTL_MS });
    return result === 'OK';
}

/**
 * Renews the master lock if it is still owned by the given node.
 *
 * @param nodeId - Unique identifier for the current node.
 * @returns True when the lock was renewed successfully.
 */
async function renewLock(nodeId: string): Promise<boolean> {
    const client = redis.getClient();
    const result = await client.eval(RENEW_SCRIPT, {
        keys: [MASTER_KEY],
        arguments: [nodeId, String(MASTER_TTL_MS)]
    });
    return result === 1;
}

// master loop
const HEARTBEAT_INTERVAL_MS = 3_000;
let _isMaster = false;

/**
 * Runs the master heartbeat loop for the given node.
 *
 * @param nodeId - Unique identifier for the current node.
 */
async function masterLoop(nodeId: string): Promise<void> {
    _isMaster = true;
    logger.info(`[${nodeId}] Became master`);

    // Models and images are no longer preloaded here — both are cached lazily on
    // first request (see ensureModelChunked / ensureImageCached) and written
    // through by the admin panel on upload.
    await analyticsConsumer.start();

    const interval = setInterval(async () => {
        try {
            const renewed = await renewLock(nodeId);
            if (!renewed) {
                _isMaster = false;
                logger.warn(`[${nodeId}] Lost master lock — stepping down`);
                analyticsConsumer.stop();
                clearInterval(interval);
                await electionLoop(nodeId);
            }
        } catch (err) {
            console.error(err);
            logger.error(`[${nodeId}] Heartbeat error`);
        }
    }, HEARTBEAT_INTERVAL_MS);
}

/**
 * Runs a single election cycle and retries until the node becomes master.
 *
 * @param nodeId - Unique identifier for the current node.
 */
async function electionLoop(nodeId: string): Promise<void> {
    const won = await tryAcquireLock(nodeId);

    if (won) {
        await masterLoop(nodeId);
    } else {
        setTimeout(() => electionLoop(nodeId), MASTER_TTL_MS);
    }
}

/**
 * Starts the master election process for the given node.
 *
 * @param nodeId - Unique identifier for the current node.
 */
async function startElection(nodeId: string): Promise<void> {
    await electionLoop(nodeId);
}

/**
 * Initializes the election process by determining the node identity and starting the election loop.
 */
async function start()
{
    const nodeId = identity.nodeId;
    if(!nodeId) {
        logger.critical('Failed to determine node identity. Aborting election.');
        return;
    }

    // Start the election loop
    await startElection(nodeId);
}

export default {
    start,
    isMaster: () => _isMaster
};