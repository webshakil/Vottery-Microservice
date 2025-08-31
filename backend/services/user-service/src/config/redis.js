import Redis from 'ioredis';
//import { logger } from '../utils/logger.js';
import logger from '../utils/logger.js';

const redisConfig = {
  development: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    db: process.env.REDIS_DB || 0,
    password: process.env.REDIS_PASSWORD,
    retryDelayOnFailover: 100,
    enableReadyCheck: false,
    maxRetriesPerRequest: null,
  },
  
  production: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    db: process.env.REDIS_DB || 0,
    password: process.env.REDIS_PASSWORD,
    retryDelayOnFailover: 100,
    enableReadyCheck: false,
    maxRetriesPerRequest: null,
    tls: process.env.REDIS_TLS === 'true' ? {} : null,
  },
  
  test: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6380,
    db: process.env.REDIS_DB || 1,
    password: process.env.REDIS_PASSWORD,
  }
};

const environment = process.env.NODE_ENV || 'development';
const config = redisConfig[environment];

let redis;

try {
  redis = new Redis(config);
  
  redis.on('connect', () => {
    logger.info('Redis connected successfully');
  });
  
  redis.on('error', (err) => {
    logger.error('Redis connection error:', err);
  });
  
  redis.on('close', () => {
    logger.warn('Redis connection closed');
  });
  
} catch (error) {
  logger.error('Failed to initialize Redis:', error);
}

export default redis;