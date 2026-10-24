import db from '../database/mysql.js';

/**
 * Represents a model entity from the `models` table.
 */
export interface Model {
    /** Unique identifier of the model. */
    id: string;
    /** Full display name of the game. */
    name: string;
    /** Short/abbreviated name of the game. */
    short_name: string;
    /** Hash of the model. */
    hash: string;
}

/**
 * Retrieves all models from the database.
 *
 * @returns A promise that resolves to an array of models.
 */
export async function getAllModels(): Promise<Model[]> {
    return db.query<Model[]>(
        'SELECT id, name, short_name, hash FROM models'
    );
}


/**
 * Retrieves a single model by its identifier.
 *
 * @param id - The model's unique identifier.
 * @returns A promise that resolves to the model, or null if not found.
 */
export async function getModelById(id: string): Promise<Model | null> {
    const isProductid = await getModelIdByProductId(id);
    if (isProductid) {
        id = isProductid;
    }
    
    return db.queryOne<Model>(
        'SELECT id, name, short_name, hash FROM models WHERE id = ?',
        [id]
    );
}


/**
 * Retrieves the model identifier for a given product.
 *
 * @param productId - The product's unique identifier.
 * @returns A promise that resolves to the model ID, or null if not found.
 */
export async function getModelIdByProductId(productId: string): Promise<string | null> {
    const result = await db.queryOne<{ model_id: string }>(
        'SELECT model_id FROM products WHERE id = ?',
        [productId]
    );
    return result ? result.model_id : null;
}