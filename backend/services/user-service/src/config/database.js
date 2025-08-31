import { Sequelize } from 'sequelize';
import logger from '../utils/logger.js';

const databaseConfig = {
  development: {
    username: process.env.DATABASE_USER || process.env.DB_USER || 'postgres',
    password: process.env.DATABASE_PASSWORD || process.env.DB_PASSWORD || 'password',
    database: process.env.DATABASE_NAME || process.env.DB_NAME || 'vottery_dev',
    host: process.env.DATABASE_HOST || process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DATABASE_PORT) || parseInt(process.env.DB_PORT) || 5432,
    dialect: 'postgres',
    logging: (msg) => logger.debug(msg),
    pool: {
      max: parseInt(process.env.DATABASE_POOL_MAX) || 5,
      min: parseInt(process.env.DATABASE_POOL_MIN) || 0,
      acquire: parseInt(process.env.DATABASE_POOL_ACQUIRE) || 30000,
      idle: parseInt(process.env.DATABASE_POOL_IDLE) || 10000
    },
    define: {
      timestamps: true,
      underscored: true,
      freezeTableName: true
    }
  },
     
  production: {
    username: process.env.DATABASE_USER || process.env.DB_USER,
    password: process.env.DATABASE_PASSWORD || process.env.DB_PASSWORD,
    database: process.env.DATABASE_NAME || process.env.DB_NAME,
    host: process.env.DATABASE_HOST || process.env.DB_HOST,
    port: parseInt(process.env.DATABASE_PORT) || parseInt(process.env.DB_PORT) || 5432,
    dialect: 'postgres',
    logging: false,
    pool: {
      max: parseInt(process.env.DATABASE_POOL_MAX) || 20,
      min: parseInt(process.env.DATABASE_POOL_MIN) || 5,
      acquire: parseInt(process.env.DATABASE_POOL_ACQUIRE) || 60000,
      idle: parseInt(process.env.DATABASE_POOL_IDLE) || 10000
    },
    define: {
      timestamps: true,
      underscored: true,
      freezeTableName: true
    },
    dialectOptions: {
      ssl: (process.env.DATABASE_SSL || process.env.DB_SSL) === 'true' ? {
        require: true,
        rejectUnauthorized: false
      } : false
    }
  },
     
  test: {
    username: process.env.DATABASE_USER || process.env.DB_USER || 'postgres',
    password: process.env.DATABASE_PASSWORD || process.env.DB_PASSWORD || 'password',
    database: process.env.DATABASE_NAME || process.env.DB_NAME || 'vottery_test',
    host: process.env.DATABASE_HOST || process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DATABASE_PORT) || parseInt(process.env.DB_PORT) || 5432,
    dialect: 'postgres',
    logging: false,
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    },
    define: {
      timestamps: true,
      underscored: true,
      freezeTableName: true
    }
  }
};

const environment = process.env.NODE_ENV || 'development';
const config = databaseConfig[environment];

const sequelize = new Sequelize(
  config.database,
  config.username,
  config.password,
  config
);

// Test database connection
const testConnection = async () => {
  try {
    await sequelize.authenticate();
    logger.info(`Database connection established successfully for ${environment} environment`);
    logger.info(`Connected to: ${config.database} on ${config.host}:${config.port}`);
  } catch (error) {
    logger.error('Unable to connect to database:', error);
    logger.error('Database config:', {
      host: config.host,
      port: config.port,
      database: config.database,
      username: config.username
    });
    process.exit(1);
  }
};

// Initialize connection test if not in test environment
if (process.env.NODE_ENV !== 'test') {
  testConnection();
}

export { sequelize };
export default databaseConfig;
// import { Sequelize } from 'sequelize';
// import logger  from '../utils/logger.js';

// const databaseConfig = {
//   development: {
//     username: process.env.DB_USER || 'postgres',
//     password: process.env.DB_PASSWORD || 'password',
//     database: process.env.DB_NAME || 'vottery_dev',
//     host: process.env.DB_HOST || 'localhost',
//     port: process.env.DB_PORT || 5432,
//     dialect: 'postgres',
//     logging: (msg) => logger.debug(msg),
//     pool: {
//       max: 5,
//       min: 0,
//       acquire: 30000,
//       idle: 10000
//     },
//     define: {
//       timestamps: true,
//       underscored: true,
//       freezeTableName: true
//     }
//   },
  
//   production: {
//     username: process.env.DB_USER,
//     password: process.env.DB_PASSWORD,
//     database: process.env.DB_NAME,
//     host: process.env.DB_HOST,
//     port: process.env.DB_PORT || 5432,
//     dialect: 'postgres',
//     logging: false,
//     pool: {
//       max: 20,
//       min: 5,
//       acquire: 60000,
//       idle: 10000
//     },
//     define: {
//       timestamps: true,
//       underscored: true,
//       freezeTableName: true
//     },
//     dialectOptions: {
//       ssl: process.env.DB_SSL === 'true' ? {
//         require: true,
//         rejectUnauthorized: false
//       } : false
//     }
//   },
  
//   test: {
//     username: process.env.DB_USER || 'postgres',
//     password: process.env.DB_PASSWORD || 'password',
//     database: process.env.DB_NAME || 'vottery_test',
//     host: process.env.DB_HOST || 'localhost',
//     port: process.env.DB_PORT || 5432,
//     dialect: 'postgres',
//     logging: false,
//     pool: {
//       max: 5,
//       min: 0,
//       acquire: 30000,
//       idle: 10000
//     },
//     define: {
//       timestamps: true,
//       underscored: true,
//       freezeTableName: true
//     }
//   }
// };

// const environment = process.env.NODE_ENV || 'development';
// const config = databaseConfig[environment];

// const sequelize = new Sequelize(
//   config.database,
//   config.username,
//   config.password,
//   config
// );

// // Test database connection
// const testConnection = async () => {
//   try {
//     await sequelize.authenticate();
//     logger.info('Database connection established successfully');
//   } catch (error) {
//     logger.error('Unable to connect to database:', error);
//     process.exit(1);
//   }
// };

// // Initialize connection test
// if (process.env.NODE_ENV !== 'test') {
//   testConnection();
// }

// export { sequelize };
// export default databaseConfig;