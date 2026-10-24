import db from '../database/mysql.js';

/** Wildcard permission id. A role granted this holds every permission. */
export const WILDCARD = '*';

/**
* Resolves the effective permission ids granted to a user via their single role.
* @param userId - The user id.
* @returns Permission ids (may include '*'); empty if the user has no grants.
*/
export async function getUserPermissions(userId: string): Promise<string[]> {
    const rows = await db.query<{ permission_id: string }[]>(
        `SELECT rp.permission_id
        FROM users u
        JOIN role_permissions rp ON rp.role_name = u.role
        WHERE u.id = ?`,
        [userId],
    );
    return rows.map(r => r.permission_id);
}

/**
* Resolves the permission ids granted to a role.
* @param roleName - The role name.
* @returns Permission ids (may include '*').
*/
export async function getRolePermissions(roleName: string): Promise<string[]> {
    const rows = await db.query<{ permission_id: string }[]>(
        `SELECT permission_id FROM role_permissions WHERE role_name = ?`,
        [roleName],
    );
    return rows.map(r => r.permission_id);
}


export async function userHasPermission(userId: string, permission: string): Promise<boolean> {
    const perms = await getUserPermissions(userId);
    return permissionsInclude(perms, permission);
}

/**
* Checks an already-resolved permission set (avoids a DB hit when you've
* already fetched permissions via getUserPermissions).
* @param permissions - Resolved permission ids for a user.
* @param permission  - The permission id to check for.
* @returns True if the set contains the permission or '*'.
*/
export function permissionsInclude(permissions: string[], permission: string): boolean {
    return permissions.includes(WILDCARD) || permissions.includes(permission);
}