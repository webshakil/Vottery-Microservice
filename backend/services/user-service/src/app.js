import express from 'express';
import cors from 'cors';
import events from 'events';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import dotenv from 'dotenv';

// Import utilities
import logger from './utils/logger.js';
import { testConnection } from './database/connection.js';
import errorHandler from './middleware/errorHandler.js';
import securityMiddleware from './middleware/security.js';
import rateLimitingMiddleware from './middleware/rateLimiting.js';
import { auditLog } from './middleware/auditLog.js';

// Import routes
import routes from './routes/index.js';

// Import models for database sync
import './models/index.js';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3003;
const HOST = process.env.HOST || 'localhost';

// Store server instance for graceful shutdown
let serverInstance = null;

// Trust proxy for accurate IP addresses
app.set('trust proxy', 1);

// Add request timing middleware
app.use((req, res, next) => {
  req.startTime = Date.now();
  next();
});

// Security headers with Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// CORS Configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = (process.env.CORS_ORIGIN || 'http://localhost:3000').split(',');
    
    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV === 'development') {
      callback(null, true);
    } else {
      logger.warn(`CORS blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: (process.env.CORS_METHODS || 'GET,HEAD,PUT,PATCH,POST,DELETE').split(','),
  credentials: process.env.CORS_CREDENTIALS === 'true',
  optionsSuccessStatus: 200, // Some legacy browsers choke on 204
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));

events.EventEmitter.defaultMaxListeners = 20; 

// Compression middleware
app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  }
}));

// Body parsing middleware
app.use(express.json({ 
  limit: '10mb',
  strict: true,
  type: 'application/json'
}));
app.use(express.urlencoded({ 
  extended: true, 
  limit: '10mb',
  parameterLimit: 1000
}));

// Cookie parser
app.use(cookieParser(process.env.SESSION_SECRET));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: parseInt(process.env.SESSION_MAX_AGE) || 86400000, // 24 hours
    sameSite: 'strict'
  },
  name: 'vottery.session'
}));

// Global rate limiting
const globalRateLimit = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 1000,
  message: {
    error: 'Too many requests from this IP, please try again later.',
    code: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: process.env.RATE_LIMIT_SKIP_SUCCESSFUL_REQUESTS === 'true',
  skipFailedRequests: process.env.RATE_LIMIT_SKIP_FAILED_REQUESTS === 'true',
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.url,
      method: req.method
    });
    
    res.status(429).json({
      success: false,
      error: 'Rate limit exceeded',
      message: 'Too many requests from this IP, please try again later.',
      retryAfter: Math.round(req.rateLimit.resetTime / 1000)
    });
  }
});

// Speed limiting (progressive delay)
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 100, // Allow 100 requests per windowMs without delay
  delayMs: 500, // Add 500ms delay per request after delayAfter
  maxDelayMs: 20000, // Maximum delay of 20 seconds
  skipFailedRequests: true,
  skipSuccessfulRequests: false
});

app.use(globalRateLimit);
app.use(speedLimiter);

// Custom security middleware - apply specific functions
app.use(securityMiddleware.sanitizeInput);
app.use(securityMiddleware.preventXSS);
app.use(securityMiddleware.preventSQLInjection);

// Rate limiting middleware (more specific limits)
app.use(rateLimitingMiddleware);

// Request logging middleware
app.use((req, res, next) => {
  const originalSend = res.send;
  
  res.send = function(data) {
    const responseTime = Date.now() - req.startTime;
    logger.request(req, res, responseTime);
    originalSend.call(this, data);
  };
  
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Vottery User Service is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: process.env.npm_package_version || '1.0.0'
  });
});

// API routes
app.use('/api/v1', routes);

// 404 handler
app.use('*', (req, res) => {
  logger.warn(`404 Not Found: ${req.method} ${req.originalUrl}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  res.status(404).json({
    success: false,
    error: 'Not Found',
    message: `The requested endpoint ${req.method} ${req.originalUrl} was not found`,
    timestamp: new Date().toISOString()
  });
});

// Global error handler
app.use(errorHandler);

// Graceful shutdown
const gracefulShutdown = (signal) => {
  return (code) => {
    logger.info(`Received ${signal}, shutting down gracefully...`);
    
    if (serverInstance) {
      serverInstance.close(() => {
        logger.info('HTTP server closed');
        
        // Close database connections
        import('./database/connection.js').then(({ closeConnection }) => {
          closeConnection().then(() => {
            logger.info('Graceful shutdown completed');
            process.exit(0);
          }).catch((error) => {
            logger.error('Error during graceful shutdown:', error);
            process.exit(1);
          });
        }).catch(() => {
          logger.info('Database connection cleanup skipped');
          process.exit(0);
        });
      });
      
      // Force close server after 30 seconds
      setTimeout(() => {
        logger.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
      }, 30000);
    } else {
      process.exit(0);
    }
  };
};

// Handle process termination
process.on('SIGTERM', gracefulShutdown('SIGTERM'));
process.on('SIGINT', gracefulShutdown('SIGINT'));

// Handle uncaught exceptions and promise rejections
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Start server
const startServer = async () => {
  try {
    // Verify required environment variables
    const requiredEnvVars = ['SESSION_SECRET'];
    const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

    if (missingEnvVars.length > 0) {
      logger.error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
      process.exit(1);
    }

    // Test database connection
    await testConnection();
    
    // Start HTTP server
    const server = app.listen(PORT, HOST, () => {
      logger.info(`Vottery User Service started successfully`);
      logger.info(`Server running on ${HOST}:${PORT}`);
      logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`Database: Connected and ready`);
      logger.info(`Security: All middleware active`);
      
      if (process.env.NODE_ENV === 'development') {
        logger.info(`API Documentation: http://${HOST}:${PORT}/health`);
        logger.info(`Available endpoints:`);
        logger.info(`   • Health Check: GET /health`);
        logger.info(`   • User API: /api/v1/users`);
        logger.info(`   • Profile API: /api/v1/profile`);
        logger.info(`   • Organization API: /api/v1/organizations`);
        logger.info(`   • Security API: /api/v1/security`);
      }
    });

    // Enable keep-alive
    server.keepAliveTimeout = 65000;
    server.headersTimeout = 66000;
    
    // Store server instance for graceful shutdown
    serverInstance = server;
    
    return server;
    
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
startServer().catch((error) => {
  logger.error('Failed to start server:', error);
  process.exit(1);
});

export default app;
// import express from 'express';
// import cors from 'cors';
// import events from 'events';
// import helmet from 'helmet';
// import compression from 'compression';
// import cookieParser from 'cookie-parser';
// import session from 'express-session';
// import rateLimit from 'express-rate-limit';
// import slowDown from 'express-slow-down';
// import dotenv from 'dotenv';

// // Import utilities
// import logger from './utils/logger.js';
// import { testConnection } from './database/connection.js';
// import errorHandler from './middleware/errorHandler.js';
// import securityMiddleware from './middleware/security.js';
// import rateLimitingMiddleware from './middleware/rateLimiting.js';
// //import auditLogMiddleware from './middleware/auditLog.js';
// import { auditLog } from './middleware/auditLog.js';

// // Import routes
// import routes from './routes/index.js';

// // Import models for database sync
// import './models/index.js';

// // Load environment variables
// dotenv.config();

// const app = express();
// const PORT = process.env.PORT || 3003;
// const HOST = process.env.HOST || 'localhost';

// // Trust proxy for accurate IP addresses
// app.set('trust proxy', 1);

// // Add request timing middleware
// app.use((req, res, next) => {
//   req.startTime = Date.now();
//   next();
// });

// // Security headers with Helmet
// app.use(helmet({
//   contentSecurityPolicy: {
//     directives: {
//       defaultSrc: ["'self'"],
//       scriptSrc: ["'self'", "'unsafe-inline'"],
//       styleSrc: ["'self'", "'unsafe-inline'"],
//       imgSrc: ["'self'", "data:", "https:"],
//       connectSrc: ["'self'"],
//       fontSrc: ["'self'"],
//       objectSrc: ["'none'"],
//       mediaSrc: ["'self'"],
//       frameSrc: ["'none'"],
//     },
//   },
//   crossOriginEmbedderPolicy: false,
//   hsts: {
//     maxAge: 31536000,
//     includeSubDomains: true,
//     preload: true
//   }
// }));

// // CORS Configuration
// const corsOptions = {
//   origin: function (origin, callback) {
//     const allowedOrigins = (process.env.CORS_ORIGIN || 'http://localhost:3000').split(',');
    
//     // Allow requests with no origin (mobile apps, etc.)
//     if (!origin) return callback(null, true);
    
//     if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV === 'development') {
//       callback(null, true);
//     } else {
//       logger.warn(`CORS blocked origin: ${origin}`);
//       callback(new Error('Not allowed by CORS'));
//     }
//   },
//   methods: (process.env.CORS_METHODS || 'GET,HEAD,PUT,PATCH,POST,DELETE').split(','),
//   credentials: process.env.CORS_CREDENTIALS === 'true',
//   optionsSuccessStatus: 200, // Some legacy browsers choke on 204
//   maxAge: 86400 // 24 hours
// };

// app.use(cors(corsOptions));

// events.EventEmitter.defaultMaxListeners = 20; 

// // Compression middleware
// app.use(compression({
//   level: 6,
//   threshold: 1024,
//   filter: (req, res) => {
//     if (req.headers['x-no-compression']) {
//       return false;
//     }
//     return compression.filter(req, res);
//   }
// }));

// // Body parsing middleware
// app.use(express.json({ 
//   limit: '10mb',
//   strict: true,
//   type: 'application/json'
// }));
// app.use(express.urlencoded({ 
//   extended: true, 
//   limit: '10mb',
//   parameterLimit: 1000
// }));

// // Cookie parser
// app.use(cookieParser(process.env.SESSION_SECRET));

// // Session configuration
// app.use(session({
//   secret: process.env.SESSION_SECRET || 'your-session-secret-key',
//   resave: false,
//   saveUninitialized: false,
//   cookie: {
//     secure: process.env.NODE_ENV === 'production',
//     httpOnly: true,
//     maxAge: parseInt(process.env.SESSION_MAX_AGE) || 86400000, // 24 hours
//     sameSite: 'strict'
//   },
//   name: 'vottery.session'
// }));

// // Global rate limiting
// const globalRateLimit = rateLimit({
//   windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
//   max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 1000,
//   message: {
//     error: 'Too many requests from this IP, please try again later.',
//     code: 'RATE_LIMIT_EXCEEDED'
//   },
//   standardHeaders: true,
//   legacyHeaders: false,
//   skipSuccessfulRequests: process.env.RATE_LIMIT_SKIP_SUCCESSFUL_REQUESTS === 'true',
//   skipFailedRequests: process.env.RATE_LIMIT_SKIP_FAILED_REQUESTS === 'true',
//   handler: (req, res) => {
//     logger.warn(`Rate limit exceeded for IP: ${req.ip}`, {
//       ip: req.ip,
//       userAgent: req.get('User-Agent'),
//       url: req.url,
//       method: req.method
//     });
    
//     res.status(429).json({
//       success: false,
//       error: 'Rate limit exceeded',
//       message: 'Too many requests from this IP, please try again later.',
//       retryAfter: Math.round(req.rateLimit.resetTime / 1000)
//     });
//   }
// });

// // Speed limiting (progressive delay)
// const speedLimiter = slowDown({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   delayAfter: 100, // Allow 100 requests per windowMs without delay
//   delayMs: 500, // Add 500ms delay per request after delayAfter
//   maxDelayMs: 20000, // Maximum delay of 20 seconds
//   skipFailedRequests: true,
//   skipSuccessfulRequests: false
// });

// app.use(globalRateLimit);
// app.use(speedLimiter);

// // Custom security middleware
// app.use(securityMiddleware);

// // Rate limiting middleware (more specific limits)
// app.use(rateLimitingMiddleware);

// // Audit logging middleware
// //app.use(auditLogMiddleware);
// app.use(auditLog.logActivity);

// // Request logging middleware
// app.use((req, res, next) => {
//   const originalSend = res.send;
  
//   res.send = function(data) {
//     const responseTime = Date.now() - req.startTime;
//     logger.request(req, res, responseTime);
//     originalSend.call(this, data);
//   };
  
//   next();
// });

// // Health check endpoint
// app.get('/health', (req, res) => {
//   res.status(200).json({
//     success: true,
//     message: 'Vottery User Service is running',
//     timestamp: new Date().toISOString(),
//     uptime: process.uptime(),
//     memory: process.memoryUsage(),
//     version: process.env.npm_package_version || '1.0.0'
//   });
// });

// // API routes
// app.use('/api/v1', routes);

// // 404 handler
// app.use('*', (req, res) => {
//   logger.warn(`404 Not Found: ${req.method} ${req.originalUrl}`, {
//     ip: req.ip,
//     userAgent: req.get('User-Agent')
//   });
  
//   res.status(404).json({
//     success: false,
//     error: 'Not Found',
//     message: `The requested endpoint ${req.method} ${req.originalUrl} was not found`,
//     timestamp: new Date().toISOString()
//   });
// });

// // Global error handler
// app.use(errorHandler);

// // Graceful shutdown
// const gracefulShutdown = (signal) => {
//   return (code) => {
//     logger.info(`🛑 Received ${signal}, shutting down gracefully...`);
    
//     server.close(() => {
//       logger.info('📴 HTTP server closed');
      
//       // Close database connections
//       import('./database/connection.js').then(({ closeConnection }) => {
//         closeConnection().then(() => {
//           logger.info('✅ Graceful shutdown completed');
//           process.exit(0);
//         }).catch((error) => {
//           logger.error('❌ Error during graceful shutdown:', error);
//           process.exit(1);
//         });
//       });
//     });
    
//     // Force close server after 30 seconds
//     setTimeout(() => {
//       logger.error('⚠️ Could not close connections in time, forcefully shutting down');
//       process.exit(1);
//     }, 30000);
//   };
// };

// // Handle process termination
// process.on('SIGTERM', gracefulShutdown('SIGTERM'));
// process.on('SIGINT', gracefulShutdown('SIGINT'));

// // Handle uncaught exceptions and promise rejections
// process.on('uncaughtException', (error) => {
//   logger.error('💥 Uncaught Exception:', error);
//   process.exit(1);
// });

// process.on('unhandledRejection', (reason, promise) => {
//   logger.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
//   process.exit(1);
// });

// // Start server
// const startServer = async () => {
//   try {
//     // Test database connection
//     await testConnection();
    
//     // Start HTTP server
//     const server = app.listen(PORT, HOST, () => {
//       logger.info(`🚀 Vottery User Service started successfully`);
//       logger.info(`📍 Server running on ${HOST}:${PORT}`);
//       logger.info(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
//       logger.info(`📊 Database: Connected and ready`);
//       logger.info(`🔒 Security: All middleware active`);
      
//       if (process.env.NODE_ENV === 'development') {
//         logger.info(`📖 API Documentation: http://${HOST}:${PORT}/health`);
//         logger.info(`🔍 Available endpoints:`);
//         logger.info(`   • Health Check: GET /health`);
//         logger.info(`   • User API: /api/v1/users`);
//         logger.info(`   • Profile API: /api/v1/profile`);
//         logger.info(`   • Organization API: /api/v1/organizations`);
//         logger.info(`   • Security API: /api/v1/security`);
//       }
//     });

//     // Enable keep-alive
//     server.keepAliveTimeout = 65000;
//     server.headersTimeout = 66000;
    
//     // Make server available for graceful shutdown
//     global.server = server;
    
//     return server;
    
//   } catch (error) {
//     logger.error('💥 Failed to start server:', error);
//     process.exit(1);
//   }
// };

// // Start the server
// const server = startServer();

// export default app;