import db from '../database/mysql.js';

export interface CreateSecurityAlertInput {
    id: string;
    title: string;
    description: string;
    processes: string[];
    imageType: string;
    imageSize: number;
    userId?: string;
    buildId?: string;
    loaderId?: string;
    pskType: string;
}

export async function createSecurityAlert(input: CreateSecurityAlertInput): Promise<void> {
    await db.query(
        `INSERT INTO security_alerts
            (id, title, description, processes, status, image_type, image_size, user_id, build_id, loader_id, psk_type)
         VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)`,
        [
            input.id,
            input.title,
            input.description,
            JSON.stringify(input.processes),
            input.imageType,
            input.imageSize,
            input.userId ?? null,
            input.buildId ?? null,
            input.loaderId ?? null,
            input.pskType,
        ],
    );
}

export async function completeSecurityAlert(
    id: string,
    imageKey: string,
    imageType: string,
    imageSize: number,
    imageSha256: string,
): Promise<void> {
    await db.query(
        `UPDATE security_alerts
         SET status = 'completed',
             image_key = ?,
             image_type = ?,
             image_size = ?,
             image_sha256 = ?,
             failure_reason = NULL,
             completed_at = NOW()
         WHERE id = ? AND status = 'pending'`,
        [imageKey, imageType, imageSize, imageSha256, id],
    );
}

export async function failSecurityAlert(id: string, reason: string): Promise<void> {
    await db.query(
        `UPDATE security_alerts
         SET status = 'failed', failure_reason = ?
         WHERE id = ? AND status = 'pending'`,
        [reason.slice(0, 255), id],
    );
}
