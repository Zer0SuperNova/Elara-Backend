import mysql, { Pool, PoolConnection} from 'mysql2/promise';
import config from '../config/config.js';
import message from '../handler/logger.js';

let db: Pool | undefined;

/**
 * Initializes the MySQL database connection pool
 * @returns {Promise<Pool>} The initialized connection pool
 * @throws {Error} If connection to MySQL fails
 */
async function init(): Promise<Pool> {
  db = mysql.createPool({
    connectionLimit: 10,
    host: config.db.mysql.host,
    user: config.db.mysql.user,
    password: config.db.mysql.password,
    database: config.db.mysql.dbname,
    waitForConnections: true,
  });

  try {
    const connection = await db.getConnection();
    connection.release();
    message.success("[MySQL] Connected to mysql");
    return db;
  } catch (err) {
    message.err(`[MySQL] Error connecting to mysql: ${err}`);
    throw err;
  }
}

interface TransactionHandler {
  query: PoolConnection['query'];
  rollback: () => Promise<void>;
  commit: () => Promise<void>;
}

export { init };

export default {
  getConnection: (): Promise<PoolConnection> => {
    if (!db) throw new Error('Database not initialized. Call init() first.');
    return db.getConnection();
  },
  queryOne: async <T = any>(sql: string, params?: any, connection?: PoolConnection): Promise<T | null> => {
      if (!db) throw new Error('Database not initialized. Call init() first.');

      const executor = connection ?? db;
      const [rows] = await executor.query(sql, params);
      return ((rows as T[])[0]) ?? null;
  },

  query: async <T = any>(sql: string, params?: any, connection?: PoolConnection): Promise<T> => {
      if (!db) throw new Error('Database not initialized. Call init() first.');

      const executor = connection ?? db;
      const [rows] = await executor.query(sql, params);
      return rows as T;
  },
  transaction: async <T>(fn: (connection: PoolConnection) => Promise<T>): Promise<T> => {
      if (!db) throw new Error('Database not initialized');

      const connection = await db.getConnection();
      try {
          await connection.beginTransaction();
          const result = await fn(connection);
          await connection.commit();
          return result;
      } catch (error) {
          await connection.rollback();
          throw error;
      } finally {
          connection.release();
      }
  },
};