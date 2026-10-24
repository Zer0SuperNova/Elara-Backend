import db from '../database/mysql.js';
  import { Permission } from '../rbac/permissions.js';
import { permissionsInclude } from '../rbac/rbac.js';
import { getModelIdByProductId } from './models.js';

export interface Product {
    id: string;
    family: string;
    name: string;
    description: string | null;
    model_id: string | null;
    status: 'Active' | 'Beta Only' | 'Under Supervision' | 'Updating' | 'Offline';
    created_at: Date;
    updated_at: Date;
    loader_image_id: string | null;
    executable_name: string;
}

const PRODUCT_SELECT = 'SELECT id, family, name, description, model_id, status, created_at, updated_at, loader_image_id, executable_name FROM products';
/**
 * Retrieves a product by its ID.
 * @param {string} id - The product ID
 * @returns {Promise<Product | null>} The product object or null if not found
 */
export async function getProductById(id: string): Promise<Product | null> {
    return db.queryOne<Product>(`${PRODUCT_SELECT} WHERE id = ?`, [id]);
}

/**
* Retrieves the product linked to a model ID, regardless of status.
* Access is enforced by the caller (status gate + license).
* @param {string} modelId - The model ID
* @returns {Promise<Product | null>} The product, or null if none is linked
*/
export async function getProductByModelId(modelId: string): Promise<Product | null> {
    return db.queryOne<Product>(
        `${PRODUCT_SELECT} WHERE model_id = ? LIMIT 1`,
        [modelId]
    );
}


/**
 * Retrieves all products from the database.
 * @returns {Promise<Product[]>} Array of all products
 */
export async function getAllProducts(): Promise<Product[]> {
    return db.query<Product[]>(PRODUCT_SELECT);
}

/**
 * Retrieves all active products from the database.
 * @returns {Promise<Product[]>} Array of active products
 */
export async function getActiveProducts(): Promise<Product[]> {
    return db.query<Product[]>(`${PRODUCT_SELECT} WHERE status = 'active'`);
}

export async function getProductsByFamily(family: string): Promise<Product[]> {
    return db.query<Product[]>(
        `${PRODUCT_SELECT} WHERE family = ?`,
        [family]
    );
}

/**
* Products visible to a caller given their resolved permissions:
* active products for everyone, plus Beta Only for beta/wildcard holders.
* @param permissions - Resolved permission ids for the user.
*/
export async function getProductsVisibleTo(permissions: string[]): Promise<Product[]> {
   const canBeta =
       permissions.includes(Permission.Wildcard) ||
       permissions.includes(Permission.AccessBeta);

    return db.query<Product[]>(
        canBeta
            ? `${PRODUCT_SELECT} WHERE status IN ('active', 'Beta Only')`
            : `${PRODUCT_SELECT} WHERE status = 'active'`,
    );
}

/**
* Whether a user with these permissions may use a product of this status.
* Used for the can_use UX hint (list) AND enforcement (model token).
*/
export function canAccessProductStatus(status: Product['status'], perms: string[]): boolean {
    if (permissionsInclude(perms, Permission.Admin)) return true;

    switch (status) {
        case 'Active':    return true;
        case 'Beta Only': return permissionsInclude(perms, Permission.AccessBeta);
        default:          return false;
    }
}

