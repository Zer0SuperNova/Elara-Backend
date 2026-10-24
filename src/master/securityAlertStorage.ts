import {
    CreateBucketCommand,
    HeadBucketCommand,
    PutObjectCommand,
} from '@aws-sdk/client-s3';
import { getS3Client } from '../database/s3.js';

export const SECURITY_ALERT_BUCKET = 'security-alerts';

let bucketReady: Promise<void> | null = null;

async function ensureBucket(): Promise<void> {
    const client = getS3Client();
    if (!client) throw new Error('S3 client is not initialized');

    try {
        await client.send(new HeadBucketCommand({ Bucket: SECURITY_ALERT_BUCKET }));
    } catch {
        await client.send(new CreateBucketCommand({ Bucket: SECURITY_ALERT_BUCKET }));
    }
}

function ensureBucketOnce(): Promise<void> {
    bucketReady ??= ensureBucket().catch((err) => {
        bucketReady = null;
        throw err;
    });
    return bucketReady;
}

export async function storeSecurityAlertImage(
    key: string,
    image: Buffer,
    contentType: string,
    sha256: string,
): Promise<void> {
    const client = getS3Client();
    if (!client) throw new Error('S3 client is not initialized');

    await ensureBucketOnce();
    await client.send(new PutObjectCommand({
        Bucket: SECURITY_ALERT_BUCKET,
        Key: key,
        Body: image,
        ContentLength: image.length,
        ContentType: contentType,
        Metadata: { sha256 },
    }));
}
