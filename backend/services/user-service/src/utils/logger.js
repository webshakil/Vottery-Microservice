import winston from 'winston';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Define log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Define colors for each level
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'blue',
};

// Add colors to winston
winston.addColors(colors);

// Define log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }), // keeps stack traces for errors
  winston.format.json(),
  winston.format.prettyPrint()
);

// Define console format for development
const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.colorize({ all: true }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    if (Object.keys(meta).length > 0) {
      msg += ` ${JSON.stringify(meta, null, 2)}`;
    }
    return msg;
  })
);

// Define transports
const transports = [
  new winston.transports.Console({
    level: process.env.NODE_ENV === 'production' ? 'warn' : 'debug',
    format: process.env.NODE_ENV === 'production' ? logFormat : consoleFormat,
    handleExceptions: true,
    handleRejections: true,
  }),
];

// File transports for production
if (process.env.NODE_ENV === 'production' || process.env.LOG_FILE_PATH) {
  const logDir = process.env.LOG_FILE_PATH
    ? path.dirname(process.env.LOG_FILE_PATH)
    : path.join(__dirname, '../../logs');

  const logFilename = process.env.LOG_FILE_PATH
    ? path.basename(process.env.LOG_FILE_PATH)
    : 'vottery-user-service.log';

  transports.push(
    new winston.transports.File({
      filename: path.join(logDir, logFilename),
      level: process.env.LOG_LEVEL || 'info',
      format: logFormat,
      maxsize: 10 * 1024 * 1024,
      maxFiles: 5,
      tailable: true,
      handleExceptions: true,
      handleRejections: true,
    })
  );

  transports.push(
    new winston.transports.File({
      filename: path.join(logDir, 'error.log'),
      level: 'error',
      format: logFormat,
      maxsize: 10 * 1024 * 1024,
      maxFiles: 5,
      tailable: true,
      handleExceptions: true,
      handleRejections: true,
    })
  );

  transports.push(
    new winston.transports.File({
      filename: path.join(logDir, 'audit.log'),
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      maxsize: 10 * 1024 * 1024,
      maxFiles: 10,
      tailable: true,
    })
  );
}

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  levels,
  format: logFormat,
  defaultMeta: {
    service: 'vottery-user-service',
    version: process.env.npm_package_version || '1.0.0',
  },
  transports,
  exitOnError: false,
});

// Custom logging methods
logger.security = (message, meta = {}) => {
  logger.info(message, {
    ...meta,
    type: 'SECURITY_EVENT',
    timestamp: new Date().toISOString(),
  });
};

logger.audit = (message, meta = {}) => {
  logger.info(message, {
    ...meta,
    type: 'AUDIT_EVENT',
    timestamp: new Date().toISOString(),
  });
};

logger.performance = (message, meta = {}) => {
  logger.info(message, {
    ...meta,
    type: 'PERFORMANCE_EVENT',
    timestamp: new Date().toISOString(),
  });
};

// HTTP request logging helper
logger.request = (req, res, responseTime) => {
  const logData = {
    method: req.method,
    url: req.url,
    statusCode: res.statusCode,
    responseTime: `${responseTime}ms`,
    userAgent: req.get('User-Agent'),
    ip: req.ip || req.connection.remoteAddress,
    userId: req.user?.id || 'anonymous',
    type: 'HTTP_REQUEST',
  };

  if (res.statusCode >= 400) {
    logger.warn(`${req.method} ${req.url} ${res.statusCode} - ${responseTime}ms`, logData);
  } else {
    logger.http(`${req.method} ${req.url} ${res.statusCode} - ${responseTime}ms`, logData);
  }
};

// Handle uncaught exceptions and unhandled promise rejections
logger.exceptions.handle(
  new winston.transports.Console({ format: consoleFormat })
);

logger.rejections.handle(
  new winston.transports.Console({ format: consoleFormat })
);

export default logger;

// import winston from 'winston';
// import path from 'path';
// import { fileURLToPath } from 'url';

// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);

// // Define log levels
// const levels = {
//   error: 0,
//   warn: 1,
//   info: 2,
//   http: 3,
//   debug: 4,
// };

// // Define colors for each level
// const colors = {
//   error: 'red',
//   warn: 'yellow',
//   info: 'green',
//   http: 'magenta',
//   debug: 'blue',
// };

// // Add colors to winston
// winston.addColors(colors);

// // Define log format
// const logFormat = winston.format.combine(
//   winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
//   winston.format.errors({ stack: true }),
//   winston.format.json(),
//   winston.format.prettyPrint()
// );

// // Define console format for development
// const consoleFormat = winston.format.combine(
//   winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
//   winston.format.colorize({ all: true }),
//   winston.format.printf(({ timestamp, level, message, ...meta }) => {
//     let msg = `${timestamp} [${level}]: ${message}`;
    
//     // Add metadata if present
//     if (Object.keys(meta).length > 0) {
//       msg += ` ${JSON.stringify(meta, null, 2)}`;
//     }
    
//     return msg;
//   })
// );

// // Define transports
// const transports = [
//   // Console transport for development
//   new winston.transports.Console({
//     level: process.env.NODE_ENV === 'production' ? 'warn' : 'debug',
//     format: process.env.NODE_ENV === 'production' ? logFormat : consoleFormat,
//     handleExceptions: true,
//     handleRejections: true,
//   }),
// ];

// // Add file transports for production
// if (process.env.NODE_ENV === 'production' || process.env.LOG_FILE_PATH) {
//   const logDir = process.env.LOG_FILE_PATH 
//     ? path.dirname(process.env.LOG_FILE_PATH) 
//     : path.join(__dirname, '../../logs');
  
//   const logFilename = process.env.LOG_FILE_PATH 
//     ? path.basename(process.env.LOG_FILE_PATH)
//     : 'vottery-user-service.log';

//   // General log file
//   transports.push(
//     new winston.transports.File({
//       filename: path.join(logDir, logFilename),
//       level: process.env.LOG_LEVEL || 'info',
//       format: logFormat,
//       maxsize: 10 * 1024 * 1024, // 10MB
//       maxFiles: 5,
//       tailable: true,
//       handleExceptions: true,
//       handleRejections: true,
//     })
//   );

//   // Error log file
//   transports.push(
//     new winston.transports.File({
//       filename: path.join(logDir, 'error.log'),
//       level: 'error',
//       format: logFormat,
//       maxsize: 10 * 1024 * 1024, // 10MB
//       maxFiles: 5,
//       tailable: true,
//       handleExceptions: true,
//       handleRejections: true,
//     })
//   );

//   // Audit log file for security events
//   transports.push(
//     new winston.transports.File({
//       filename: path.join(logDir, 'audit.log'),
//       level: 'info',
//       format: winston.format.combine(
//         winston.format.timestamp(),
//         winston.format.json()
//       ),
//       maxsize: 10 * 1024 * 1024, // 10MB
//       maxFiles: 10, // Keep more audit logs
//       tailable: true,
//     })
//   );
// }

// // Create logger instance
// const logger = winston.createLogger({
//   level: process.env.LOG_LEVEL || 'info',
//   levels,
//   format: logFormat,
//   defaultMeta: { 
//     service: 'vottery-user-service',
//     version: process.env.npm_package_version || '1.0.0'
//   },
//   transports,
//   exitOnError: false,
// });

// // Add custom logging methods
// logger.security = (message, meta = {}) => {
//   logger.info(message, { 
//     ...meta, 
//     type: 'SECURITY_EVENT',
//     timestamp: new Date().toISOString()
//   });
// };

// logger.audit = (message, meta = {}) => {
//   logger.info(message, { 
//     ...meta, 
//     type: 'AUDIT_EVENT',
//     timestamp: new Date().toISOString()
//   });
// };

// logger.performance = (message, meta = {}) => {
//   logger.info(message, { 
//     ...meta, 
//     type: 'PERFORMANCE_EVENT',
//     timestamp: new Date().toISOString()
//   });
// };

// // Add request logging helper
// logger.request = (req, res, responseTime) => {
//   const logData = {
//     method: req.method,
//     url: req.url,
//     statusCode: res.statusCode,
//     responseTime: `${responseTime}ms`,
//     userAgent: req.get('User-Agent'),
//     ip: req.ip || req.connection.remoteAddress,
//     userId: req.user?.id || 'anonymous',
//     type: 'HTTP_REQUEST'
//   };

//   if (res.statusCode >= 400) {
//     logger.warn(`${req.method} ${req.url} ${res.statusCode} - ${responseTime}ms`, logData);
//   } else {
//     logger.http(`${req.method} ${req.url} ${res.statusCode} - ${responseTime}ms`, logData);
//   }
// };

// // Error logging helper
// logger.error = winston.format.errors({ stack: true })(logger.error);

// // Handle uncaught exceptions and unhandled promise rejections
// logger.exceptions.handle(
//   new winston.transports.Console({
//     format: consoleFormat
//   })
// );

// logger.rejections.handle(
//   new winston.transports.Console({
//     format: consoleFormat
//   })
// );

// export default logger;