import { Sequelize } from 'sequelize';
import dotenv from 'dotenv';
import logger from '../utils/logger.js';

dotenv.config();

const config = {
  database: process.env.DATABASE_NAME || 'vottery_db',
  username: process.env.DATABASE_USER || 'vottery_user',
  password: process.env.DATABASE_PASSWORD || 'vottery_password',
  host: process.env.DATABASE_HOST || 'localhost',
  port: process.env.DATABASE_PORT || 5432,
  dialect: 'postgres',
  logging: process.env.NODE_ENV === 'development' ? (sql) => logger.debug(sql) : false,
  pool: {
    max: parseInt(process.env.DATABASE_POOL_MAX) || 20,
    min: parseInt(process.env.DATABASE_POOL_MIN) || 5,
    acquire: parseInt(process.env.DATABASE_POOL_ACQUIRE) || 30000,
    idle: parseInt(process.env.DATABASE_POOL_IDLE) || 10000,
  },
  dialectOptions: {
    ssl: process.env.DATABASE_SSL === 'true' ? {
      require: true,
      rejectUnauthorized: false
    } : false,
    connectTimeout: 30000,
  },
  define: {
    timestamps: true,
    underscored: true,
    paranoid: false, // We'll handle soft deletes manually where needed
    charset: 'utf8mb4',
    collate: 'utf8mb4_unicode_ci',
  },
  retry: {
    max: 3,
    match: [
      /ETIMEDOUT/,
      /EHOSTUNREACH/,
      /ECONNRESET/,
      /ECONNREFUSED/,
      /ETIMEDOUT/,
      /ESOCKETTIMEDOUT/,
      /EHOSTUNREACH/,
      /EPIPE/,
      /EAI_AGAIN/,
      /SequelizeConnectionError/,
      /SequelizeConnectionRefusedError/,
      /SequelizeHostNotFoundError/,
      /SequelizeHostNotReachableError/,
      /SequelizeInvalidConnectionError/,
      /SequelizeConnectionTimedOutError/
    ]
  }
};

// Create Sequelize instance
const sequelize = new Sequelize(
  process.env.DATABASE_URL || 
  `postgres://${config.username}:${config.password}@${config.host}:${config.port}/${config.database}`,
  config
);

// Test database connection
const testConnection = async () => {
  try {
    await sequelize.authenticate();
    logger.info('✅ Database connection has been established successfully');
    
    // Log connection details (without sensitive info)
    logger.info(`📊 Connected to PostgreSQL database: ${config.database} on ${config.host}:${config.port}`);
    
    return true;
  } catch (error) {
    logger.error('❌ Unable to connect to the database:', error.message);
    throw error;
  }
};

// Graceful shutdown
const closeConnection = async () => {
  try {
    await sequelize.close();
    logger.info('📴 Database connection closed successfully');
  } catch (error) {
    logger.error('❌ Error closing database connection:', error.message);
    throw error;
  }
};

// Handle process termination
process.on('SIGINT', async () => {
  logger.info('🛑 Received SIGINT signal, closing database connection...');
  await closeConnection();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('🛑 Received SIGTERM signal, closing database connection...');
  await closeConnection();
  process.exit(0);
});

// Export sequelize instance and utilities
export { sequelize, testConnection, closeConnection };
export default sequelize;