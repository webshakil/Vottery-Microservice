
// import pkg from 'pg';
// const { Pool } = pkg;

// // const pool = new Pool({
// //   host: process.env.DB_HOST || 'localhost',
// //   port: process.env.DB_PORT || 5432,
// //   database: process.env.DB_NAME || 'vottery_db',
// //   user: process.env.DB_USER || 'postgres',
// //   password: process.env.DB_PASSWORD || 'password',
// //   ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
// //   max: 20,
// //   idleTimeoutMillis: 30000,
// //   connectionTimeoutMillis: 2000,
// // });
// const pool = new Pool({
//    host: process.env.DB_HOST,   // remove this
//   port: process.env.DB_PORT || 5432,
//   database: process.env.DB_NAME || 'vottery_db',
//   user: process.env.DB_USER || 'postgres',
//   password: process.env.DB_PASSWORD || 'password',
// });
// export const db = {
//   query: (text, params) => pool.query(text, params),
//   getClient: () => pool.connect()
// };

// // Test database connection
// pool.connect()
//   .then(client => {
//     console.log('✅ Connected to PostgreSQL database');
//     client.release();
//   })
//   .catch(err => {
//     console.error('❌ Database connection error:', err.message);
//   });


import pkg from 'pg';
import dotenv from 'dotenv';
import { logger } from '../utils/logger.js';

dotenv.config();
const { Pool } = pkg;

const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'sngine_db',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'password',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
};

const pool = new Pool(dbConfig);

pool.on('error', (err) => {
  logger.error('Unexpected error on idle client:', err);
  process.exit(-1);
});

// Test connection
pool.connect((err, client, release) => {
  if (err) {
    logger.error('Error acquiring client:', err.stack);
  } else {
    logger.info('Database connected successfully');
    release();
  }
});

export const db = {
  query: (text, params) => pool.query(text, params),
  getClient: () => pool.connect()
};
