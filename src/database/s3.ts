import { S3Client } from '@aws-sdk/client-s3';
import { NodeHttpHandler } from '@smithy/node-http-handler';
import message from '../handler/logger.js';
import config from '../config/config.js';

let _s3Client: S3Client | null = null;

/**
 * Retrieves the S3 client instance.
 * @returns {S3Client | null}
 */
function getS3Client(): S3Client | null {
  return _s3Client;
}

/**
 * Parses a config/env value into a boolean safely.
 * Accepts: true, 1, yes, on
 */
function parseBoolean(value: unknown, defaultValue = false): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value === 1;
  if (typeof value !== 'string') return defaultValue;

  switch (value.trim().toLowerCase()) {
    case 'true':
    case '1':
    case 'yes':
    case 'on':
      return true;
    case 'false':
    case '0':
    case 'no':
    case 'off':
      return false;
    default:
      return defaultValue;
  }
}

/**
 * Initializes the S3 client using the official AWS SDK v3.
 * @async
 * @returns {Promise<S3Client | null>}
 */
async function initS3Client(): Promise<S3Client | null> {
  try {
    const host = String(config.db.s3.host ?? '').trim();
    const port = Number(config.db.s3.port);
    const accessKeyId = String(config.db.s3.accessKey ?? '').trim();
    const secretAccessKey = String(config.db.s3.secretKey ?? '').trim();
    const useSSL = parseBoolean(config.db.s3.useSSL, false);

    if (!host || Number.isNaN(port) || port <= 0 || !accessKeyId || !secretAccessKey) {
      message.critical('[S3] Missing or invalid S3 configuration variables. Please check your .env file.');
      return null;
    }

    const protocol = useSSL ? 'https' : 'http';
    const endpoint = `${protocol}://${host}:${port}`;

    _s3Client = new S3Client({
      endpoint,
      region: 'us-east-1',
      credentials: {
        accessKeyId,
        secretAccessKey,
      },
      forcePathStyle: true,
      requestHandler: new NodeHttpHandler({
        connectionTimeout: 3000,
        socketTimeout: 5000,
      }),
    });

    message.success('[S3] client initialized successfully.');
    return _s3Client;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    message.critical(`[S3] Error initializing S3 client: ${errorMessage}`);
    return null;
  }
}

export { getS3Client, initS3Client };