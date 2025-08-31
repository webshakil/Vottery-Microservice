import pkg from 'pg';
const { Pool } = pkg;

let pool = null;

const createConnection = async () => {
    if (pool) {
        return pool;
    }

    try {
        pool = new Pool({
            user: process.env.DB_USER || 'your_db_user',
            host: process.env.DB_HOST || 'localhost',
            database: process.env.DB_NAME || 'vottery',
            password: process.env.DB_PASSWORD || 'your_password',
            port: process.env.DB_PORT || 5432,
            ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
            max: 20,
            idleTimeoutMillis: 30000,
            connectionTimeoutMillis: 2000,
        });

        // Test connection
        const client = await pool.connect();
        await client.query('SELECT NOW()');
        client.release();
        
        return pool;
    } catch (error) {
        console.error('Database connection failed:', error);
        throw error;
    }
};

const query = async (text, params) => {
    const client = await pool.connect();
    try {
        const result = await client.query(text, params);
        return result;
    } finally {
        client.release();
    }
};

export { createConnection, query };