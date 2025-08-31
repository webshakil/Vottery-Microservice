// middleware/errorHandler.js
import auditService from '../services/auditService.js';
import logger from '../utils/logger.js';
import { ResponseBuilder, AppError } from '../utils/response.js';
import { HTTP_STATUS, MESSAGES } from '../utils/constants.js';

/**
 * Global error handling middleware
 * @param {Error} error 
 * @param {object} req 
 * @param {object} res 
 * @param {function} next 
 */
export const errorHandler = (error, req, res, next) => {
  let statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR;
  let message = MESSAGES.ERROR.INTERNAL_ERROR;
  let errors = [];
  let meta = {};

  // Log the error details
  logger.error('Error occurred:', {
    message: error.message,
    stack: error.stack,
    url: req.originalUrl,
    method: req.method,
    userId: req.user?.id,
    ip: req.ip
  });

  // Log security event for audit trail
  if (req.user?.id) {
    auditService.logSecurityEvent(
      req.user.id,
      'error_occurred',
      'medium',
      `Error in ${req.method} ${req.originalUrl}: ${error.message}`,
      {
        errorName: error.name,
        statusCode: error.statusCode || statusCode,
        stack: error.stack
      },
      req.ip
    );
  }

  // Handle different error types
  if (error instanceof AppError) {
    // Custom application errors
    statusCode = error.statusCode;
    message = error.message;
    meta.errorCode = error.code;
    meta.timestamp = error.timestamp;
    if (error.details) {
      errors = Array.isArray(error.details) ? error.details : [error.details];
    }
  } else if (error.name === 'ValidationError') {
    // Sequelize validation errors
    statusCode = HTTP_STATUS.UNPROCESSABLE_ENTITY;
    message = MESSAGES.ERROR.VALIDATION_FAILED;
    errors = error.errors?.map(err => ({
      field: err.path,
      message: err.message,
      value: err.value
    })) || [];
  } else if (error.name === 'SequelizeUniqueConstraintError') {
    // Sequelize unique constraint errors
    statusCode = HTTP_STATUS.CONFLICT;
    message = MESSAGES.ERROR.CONFLICT;
    errors = error.errors?.map(err => ({
      field: err.path,
      message: `${err.path} already exists`,
      value: err.value
    })) || [];
  } else if (error.name === 'SequelizeDatabaseError') {
    // Database errors
    statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR;
    message = 'Database operation failed';
    logger.error('Database error:', error);
  } else if (error.name === 'JsonWebTokenError') {
    // JWT errors
    statusCode = HTTP_STATUS.UNAUTHORIZED;
    message = MESSAGES.ERROR.UNAUTHORIZED;
  } else if (error.name === 'TokenExpiredError') {
    // Expired token errors
    statusCode = HTTP_STATUS.UNAUTHORIZED;
    message = MESSAGES.ERROR.TOKEN_EXPIRED;
  } else if (error.name === 'SyntaxError' && error.status === 400) {
    // JSON parsing errors
    statusCode = HTTP_STATUS.BAD_REQUEST;
    message = 'Invalid JSON format';
  } else if (error.code === 'ENOENT') {
    // File not found errors
    statusCode = HTTP_STATUS.NOT_FOUND;
    message = 'File not found';
  } else if (error.code === 'ECONNREFUSED') {
    // Connection refused errors
    statusCode = HTTP_STATUS.SERVICE_UNAVAILABLE;
    message = MESSAGES.ERROR.SERVICE_UNAVAILABLE;
  }

  // Add request context to meta
  meta = {
    ...meta,
    requestId: req.id || `req-${Date.now()}`,
    path: req.originalUrl,
    method: req.method,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  };

  // Send error response
  return ResponseBuilder.error(res, message, statusCode, errors, meta);
};

/**
 * Handle 404 errors for unmatched routes
 * @param {object} req 
 * @param {object} res 
 * @param {function} next 
 */
export const notFoundHandler = (req, res, next) => {
  const message = `Route ${req.method} ${req.originalUrl} not found`;
  
  // Log the 404 attempt
  logger.warn('404 Error:', {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  return ResponseBuilder.notFound(res, message, {
    path: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString()
  });
};

/**
 * Async error wrapper for route handlers
 * @param {function} fn 
 * @returns {function}
 */
export const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

/**
 * Handle unhandled promise rejections
 */
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Promise Rejection:', {
    reason: reason.message || reason,
    stack: reason.stack,
    promise
  });
  
  // Graceful shutdown
  process.exit(1);
});

/**
 * Handle uncaught exceptions
 */
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', {
    message: error.message,
    stack: error.stack
  });
  
  // Graceful shutdown
  process.exit(1);
});

export default errorHandler;
// //import { auditService } from '../services/auditService.js';
// import auditService from '../services/auditService.js';
// import { errorResponse } from '../utils/response.js';
// import { ResponseBuilder } from '../utils/response.js';
// //import { redisClient } from '../config/redis.js';

// /**
//  * Error Handler Middleware
//  * Comprehensive error handling, logging, and recovery
//  */

// /**
//  * Main error handler - should be last middleware
//  */
// export const errorHandler = async (err, req, res, next) => {
//   try {
//     // Generate error ID for tracking
//     const errorId = generateErrorId();
    
//     // Determine error type and details
//     const errorInfo = analyzeError(err);
    
//     // Log error with full context
//     await logError(err, req, errorId, errorInfo);
    
//     // Send appropriate response
//     const response = formatErrorResponse(err, errorId, errorInfo);
    
//     // Set security headers for error responses
//     setSecurityHeaders(res, errorInfo);
    
//     // Update error metrics
//     await updateErrorMetrics(errorInfo, req);
    
//     return res.status(errorInfo.statusCode).json(response);

//   } catch (handlerError) {
//     console.error('Error handler failed:', handlerError);
    
//     // Fallback error response
//     return res.status(500).json({
//       success: false,
//       message: 'Internal server error',
//       errorId: 'handler-failure',
//       timestamp: new Date().toISOString()
//     });
//   }
// };

// /**
//  * Async error wrapper for route handlers
//  */
// export const asyncHandler = (fn) => {
//   return (req, res, next) => {
//     Promise.resolve(fn(req, res, next)).catch(next);
//   };
// };

// /**
//  * Validation error handler
//  */
// export const validationErrorHandler = (err, req, res, next) => {
//   if (err.name === 'ValidationError' || err.isJoi || err.name === 'SequelizeValidationError') {
//     const errorId = generateErrorId();
    
//     const validationErrors = extractValidationErrors(err);
    
//     // Log validation error
//     auditService.log(req.user?.id || null, 'VALIDATION_ERROR', 'error', null, {
//       errorId,
//       errors: validationErrors,
//       path: req.originalUrl,
//       method: req.method,
//       body: sanitizeForErrorLog(req.body),
//       ip: req.ip
//     }, req);

//     return res.status(400).json({
//       success: false,
//       message: 'Validation failed',
//       errors: validationErrors,
//       errorId,
//       timestamp: new Date().toISOString()
//     });
//   }
  
//   next(err);
// };

// /**
//  * Database error handler
//  */
// export const databaseErrorHandler = (err, req, res, next) => {
//   if (err.name === 'SequelizeError' || err.name?.startsWith('Sequelize')) {
//     const errorId = generateErrorId();
    
//     // Log database error with sanitized details
//     auditService.log(req.user?.id || null, 'DATABASE_ERROR', 'error', null, {
//       errorId,
//       errorType: err.name,
//       message: err.message,
//       path: req.originalUrl,
//       method: req.method,
//       sql: err.sql ? '[REDACTED]' : undefined, // Don't log actual SQL
//       table: err.table,
//       constraint: err.constraint,
//       ip: req.ip
//     }, req);

//     // Map specific database errors
//     const statusCode = mapDatabaseErrorCode(err);
//     const message = mapDatabaseErrorMessage(err);

//     return res.status(statusCode).json({
//       success: false,
//       message,
//       errorId,
//       timestamp: new Date().toISOString()
//     });
//   }
  
//   next(err);
// };

// /**
//  * Authentication error handler
//  */
// export const authenticationErrorHandler = (err, req, res, next) => {
//   if (err.name === 'JsonWebTokenError' || 
//       err.name === 'TokenExpiredError' || 
//       err.name === 'NotBeforeError' ||
//       err.message?.includes('authentication') ||
//       err.message?.includes('unauthorized')) {
    
//     const errorId = generateErrorId();
    
//     // Log authentication error
//     auditService.log(req.user?.id || null, 'AUTHENTICATION_ERROR', 'error', null, {
//       errorId,
//       errorType: err.name,
//       message: err.message,
//       path: req.originalUrl,
//       method: req.method,
//       token: req.headers.authorization ? '[REDACTED]' : 'none',
//       ip: req.ip,
//       userAgent: req.headers['user-agent']
//     }, req);

//     // Clear any existing auth cookies
//     res.clearCookie('access_token');
//     res.clearCookie('refresh_token');

//     return res.status(401).json({
//       success: false,
//       message: 'Authentication failed',
//       error: 'AUTHENTICATION_REQUIRED',
//       errorId,
//       timestamp: new Date().toISOString()
//     });
//   }
  
//   next(err);
// };

// /**
//  * Authorization error handler
//  */
// export const authorizationErrorHandler = (err, req, res, next) => {
//   if (err.message?.includes('authorization') || 
//       err.message?.includes('permission') ||
//       err.message?.includes('access denied')) {
    
//     const errorId = generateErrorId();
    
//     // Log authorization error
//     auditService.log(req.user?.id || null, 'AUTHORIZATION_ERROR', 'error', null, {
//       errorId,
//       message: err.message,
//       path: req.originalUrl,
//       method: req.method,
//       userId: req.user?.id,
//       requiredPermission: err.requiredPermission,
//       userRoles: req.userRoles?.map(r => r.name),
//       ip: req.ip
//     }, req);

//     return res.status(403).json({
//       success: false,
//       message: 'Access denied',
//       error: 'INSUFFICIENT_PERMISSIONS',
//       errorId,
//       timestamp: new Date().toISOString()
//     });
//   }
  
//   next(err);
// };

// /**
//  * Rate limit error handler
//  */
// export const rateLimitErrorHandler = (err, req, res, next) => {
//   if (err.type === 'RATE_LIMIT_ERROR' || err.message?.includes('rate limit')) {
//     const errorId = generateErrorId();
    
//     // Log rate limit error
//     auditService.log(req.user?.id || null, 'RATE_LIMIT_ERROR', 'error', null, {
//       errorId,
//       path: req.originalUrl,
//       method: req.method,
//       ip: req.ip,
//       limit: err.limit,
//       current: err.current,
//       resetTime: err.resetTime
//     }, req);

//     return res.status(429).json({
//       success: false,
//       message: 'Rate limit exceeded',
//       error: 'RATE_LIMIT_EXCEEDED',
//       errorId,
//       retryAfter: err.resetTime,
//       timestamp: new Date().toISOString()
//     });
//   }
  
//   next(err);
// };

// /**
//  * Payment error handler
//  */
// export const paymentErrorHandler = (err, req, res, next) => {
//   if (err.type?.includes('Stripe') || 
//       err.type?.includes('Paddle') ||
//       err.message?.includes('payment') ||
//       err.message?.includes('billing')) {
    
//     const errorId = generateErrorId();
    
//     // Log payment error (sanitized for PCI compliance)
//     auditService.log(req.user?.id || null, 'PAYMENT_ERROR', 'error', null, {
//       errorId,
//       errorType: err.type,
//       errorCode: err.code,
//       message: err.message,
//       path: req.originalUrl,
//       method: req.method,
//       paymentMethod: '[REDACTED]',
//       amount: err.amount,
//       currency: err.currency,
//       ip: req.ip,
//       pciCompliant: true
//     }, req);

//     const statusCode = mapPaymentErrorCode(err);
//     const message = mapPaymentErrorMessage(err);

//     return res.status(statusCode).json({
//       success: false,
//       message,
//       error: 'PAYMENT_ERROR',
//       errorId,
//       code: err.code,
//       timestamp: new Date().toISOString()
//     });
//   }
  
//   next(err);
// };

// /**
//  * File upload error handler
//  */
// export const fileUploadErrorHandler = (err, req, res, next) => {
//   if (err.code === 'LIMIT_FILE_SIZE' || 
//       err.code === 'LIMIT_UNEXPECTED_FILE' ||
//       err.message?.includes('file') ||
//       err.message?.includes('upload')) {
    
//     const errorId = generateErrorId();
    
//     // Log file upload error
//     auditService.log(req.user?.id || null, 'FILE_UPLOAD_ERROR', 'error', null, {
//       errorId,
//       errorCode: err.code,
//       message: err.message,
//       path: req.originalUrl,
//       fileSize: err.fileSize,
//       fileName: err.fileName,
//       mimeType: err.mimeType,
//       ip: req.ip
//     }, req);

//     const message = mapFileUploadErrorMessage(err);

//     return res.status(400).json({
//       success: false,
//       message,
//       error: 'FILE_UPLOAD_ERROR',
//       errorId,
//       timestamp: new Date().toISOString()
//     });
//   }
  
//   next(err);
// };

// /**
//  * Not found handler (404)
//  */
// export const notFoundHandler = (req, res) => {
//   const errorId = generateErrorId();
  
//   // Log 404 errors for security monitoring
//   auditService.log(req.user?.id || null, 'RESOURCE_NOT_FOUND', 'error', null, {
//     errorId,
//     path: req.originalUrl,
//     method: req.method,
//     referrer: req.headers.referer,
//     ip: req.ip,
//     userAgent: req.headers['user-agent']
//   }, req);

//   return res.status(404).json({
//     success: false,
//     message: 'Resource not found',
//     error: 'NOT_FOUND',
//     errorId,
//     timestamp: new Date().toISOString()
//   });
// };

// /**
//  * Unhandled promise rejection handler
//  */
// export const unhandledRejectionHandler = (reason, promise) => {
//   console.error('Unhandled Promise Rejection:', reason);
  
//   // Log unhandled rejection
//   auditService.log(null, 'UNHANDLED_PROMISE_REJECTION', 'error', null, {
//     reason: reason?.message || reason,
//     stack: reason?.stack,
//     promise: promise.toString(),
//     timestamp: new Date().toISOString()
//   });

//   // Don't exit the process in production, but log for monitoring
//   if (process.env.NODE_ENV !== 'production') {
//     process.exit(1);
//   }
// };

// /**
//  * Uncaught exception handler
//  */
// export const uncaughtExceptionHandler = (error) => {
//   console.error('Uncaught Exception:', error);
  
//   // Log uncaught exception
//   auditService.log(null, 'UNCAUGHT_EXCEPTION', 'error', null, {
//     message: error.message,
//     stack: error.stack,
//     timestamp: new Date().toISOString()
//   });

//   // Graceful shutdown
//   process.exit(1);
// };

// // Helper Functions

// /**
//  * Generate unique error ID
//  */
// function generateErrorId() {
//   return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
// }

// /**
//  * Analyze error to determine type and severity
//  */
// function analyzeError(err) {
//   const errorInfo = {
//     type: 'UNKNOWN_ERROR',
//     severity: 'MEDIUM',
//     statusCode: 500,
//     category: 'SERVER_ERROR',
//     isOperational: false
//   };

//   // Authentication/Authorization errors
//   if (err.name === 'JsonWebTokenError' || err.message?.includes('authentication')) {
//     errorInfo.type = 'AUTHENTICATION_ERROR';
//     errorInfo.severity = 'HIGH';
//     errorInfo.statusCode = 401;
//     errorInfo.category = 'CLIENT_ERROR';
//     errorInfo.isOperational = true;
//   }
  
//   // Validation errors
//   else if (err.name === 'ValidationError' || err.isJoi) {
//     errorInfo.type = 'VALIDATION_ERROR';
//     errorInfo.severity = 'LOW';
//     errorInfo.statusCode = 400;
//     errorInfo.category = 'CLIENT_ERROR';
//     errorInfo.isOperational = true;
//   }
  
//   // Database errors
//   else if (err.name?.startsWith('Sequelize')) {
//     errorInfo.type = 'DATABASE_ERROR';
//     errorInfo.severity = 'HIGH';
//     errorInfo.statusCode = mapDatabaseErrorCode(err);
//     errorInfo.category = 'SERVER_ERROR';
//     errorInfo.isOperational = err.name === 'SequelizeValidationError';
//   }
  
//   // Payment errors
//   else if (err.type?.includes('Stripe') || err.type?.includes('Paddle')) {
//     errorInfo.type = 'PAYMENT_ERROR';
//     errorInfo.severity = 'HIGH';
//     errorInfo.statusCode = mapPaymentErrorCode(err);
//     errorInfo.category = 'INTEGRATION_ERROR';
//     errorInfo.isOperational = true;
//   }
  
//   // Rate limit errors
//   else if (err.type === 'RATE_LIMIT_ERROR') {
//     errorInfo.type = 'RATE_LIMIT_ERROR';
//     errorInfo.severity = 'MEDIUM';
//     errorInfo.statusCode = 429;
//     errorInfo.category = 'CLIENT_ERROR';
//     errorInfo.isOperational = true;
//   }

//   return errorInfo;
// }

// /**
//  * Log error with full context
//  */
// async function logError(err, req, errorId, errorInfo) {
//   try {
//     const logData = {
//       errorId,
//       message: err.message,
//       stack: process.env.NODE_ENV === 'production' ? '[REDACTED]' : err.stack,
//       type: errorInfo.type,
//       severity: errorInfo.severity,
//       category: errorInfo.category,
//       statusCode: errorInfo.statusCode,
//       isOperational: errorInfo.isOperational,
//       path: req?.originalUrl,
//       method: req?.method,
//       userId: req?.user?.id,
//       ip: req?.ip,
//       userAgent: req?.headers?.['user-agent'],
//       body: sanitizeForErrorLog(req?.body),
//       query: req?.query,
//       params: req?.params,
//       headers: sanitizeHeaders(req?.headers),
//       timestamp: new Date().toISOString(),
//       nodeVersion: process.version,
//       environment: process.env.NODE_ENV
//     };

//     await auditService.log(req?.user?.id || null, 'APPLICATION_ERROR', 'error', null, logData, req);

//   } catch (logError) {
//     console.error('Error logging failed:', logError);
//   }
// }

// /**
//  * Format error response based on environment
//  */
// function formatErrorResponse(err, errorId, errorInfo) {
//   const baseResponse = {
//     success: false,
//     error: errorInfo.type,
//     errorId,
//     timestamp: new Date().toISOString()
//   };

//   if (process.env.NODE_ENV === 'production') {
//     // Production - minimal error details
//     baseResponse.message = getProductionErrorMessage(errorInfo.type);
//   } else {
//     // Development - detailed error information
//     baseResponse.message = err.message;
//     baseResponse.stack = err.stack;
//     baseResponse.details = {
//       type: errorInfo.type,
//       severity: errorInfo.severity,
//       category: errorInfo.category,
//       isOperational: errorInfo.isOperational
//     };
//   }

//   return baseResponse;
// }

// /**
//  * Set security headers for error responses
//  */
// function setSecurityHeaders(res, errorInfo) {
//   res.set('X-Content-Type-Options', 'nosniff');
//   res.set('X-Frame-Options', 'DENY');
//   res.set('X-XSS-Protection', '1; mode=block');
  
//   // Don't cache error responses
//   res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
//   res.set('Pragma', 'no-cache');
//   res.set('Expires', '0');
  
//   // Add error classification header for monitoring
//   res.set('X-Error-Category', errorInfo.category);
//   res.set('X-Error-Severity', errorInfo.severity);
// }

// /**
//  * Update error metrics for monitoring
//  */
// // async function updateErrorMetrics(errorInfo, req) {
// //   try {
// //     const hour = Math.floor(Date.now() / (60 * 60 * 1000));
// //     const metricsKey = `error_metrics:${hour}`;
    
// //     // Increment error counters
// //     await redisClient.hincrby(metricsKey, 'total_errors', 1);
// //     await redisClient.hincrby(metricsKey, `type:${errorInfo.type}`, 1);
// //     await redisClient.hincrby(metricsKey, `severity:${errorInfo.severity}`, 1);
// //     await redisClient.hincrby(metricsKey, `status:${errorInfo.statusCode}`, 1);
// //     await redisClient.hincrby(metricsKey, `endpoint:${req?.originalUrl || 'unknown'}`, 1);
    
// //     // Set expiration for hourly metrics
// //     await redisClient.expire(metricsKey, 24 * 60 * 60); // Keep for 24 hours

// //     // Track error patterns for alerting
// //     if (errorInfo.severity === 'HIGH') {
// //       await redisClient.incr('high_severity_errors:count');
// //       await redisClient.expire('high_severity_errors:count', 300); // 5 minutes
// //     }

// //   } catch (metricsError) {
// //     console.error('Error metrics update failed:', metricsError);
// //   }
// // }

// /**
//  * Extract validation errors from different validation libraries
//  */
// function extractValidationErrors(err) {
//   const errors = [];

//   // Joi validation errors
//   if (err.isJoi && err.details) {
//     return err.details.map(detail => ({
//       field: detail.path.join('.'),
//       message: detail.message,
//       value: detail.context?.value
//     }));
//   }

//   // Sequelize validation errors
//   if (err.name === 'SequelizeValidationError' && err.errors) {
//     return err.errors.map(error => ({
//       field: error.path,
//       message: error.message,
//       value: error.value,
//       type: error.validatorKey
//     }));
//   }

//   // Express-validator errors
//   if (err.array && typeof err.array === 'function') {
//     return err.array().map(error => ({
//       field: error.param,
//       message: error.msg,
//       value: error.value,
//       location: error.location
//     }));
//   }

//   // Generic validation error
//   if (err.name === 'ValidationError') {
//     return [{
//       field: 'general',
//       message: err.message
//     }];
//   }

//   return errors;
// }

// /**
//  * Map database errors to HTTP status codes
//  */
// function mapDatabaseErrorCode(err) {
//   const errorMappings = {
//     'SequelizeUniqueConstraintError': 409,
//     'SequelizeForeignKeyConstraintError': 400,
//     'SequelizeValidationError': 400,
//     'SequelizeConnectionError': 503,
//     'SequelizeTimeoutError': 408,
//     'SequelizeDatabaseError': 500,
//     'SequelizeConnectionRefusedError': 503,
//     'SequelizeHostNotFoundError': 503,
//     'SequelizeHostNotReachableError': 503,
//     'SequelizeInvalidConnectionError': 503,
//     'SequelizeConnectionTimedOutError': 408
//   };

//   return errorMappings[err.name] || 500;
// }

// /**
//  * Map database errors to user-friendly messages
//  */
// function mapDatabaseErrorMessage(err) {
//   const messageMappings = {
//     'SequelizeUniqueConstraintError': 'A record with this information already exists',
//     'SequelizeForeignKeyConstraintError': 'Referenced record does not exist',
//     'SequelizeValidationError': 'Data validation failed',
//     'SequelizeConnectionError': 'Database connection failed',
//     'SequelizeTimeoutError': 'Database operation timed out',
//     'SequelizeDatabaseError': 'Database operation failed'
//   };

//   return messageMappings[err.name] || 'Database error occurred';
// }

// /**
//  * Map payment errors to HTTP status codes
//  */
// function mapPaymentErrorCode(err) {
//   const stripeCodeMappings = {
//     'card_declined': 402,
//     'insufficient_funds': 402,
//     'invalid_cvc': 400,
//     'invalid_expiry_month': 400,
//     'invalid_expiry_year': 400,
//     'invalid_number': 400,
//     'expired_card': 400,
//     'incorrect_cvc': 400,
//     'processing_error': 502,
//     'rate_limit': 429
//   };

//   if (err.code && stripeCodeMappings[err.code]) {
//     return stripeCodeMappings[err.code];
//   }

//   if (err.type === 'StripeCardError') return 402;
//   if (err.type === 'StripeRateLimitError') return 429;
//   if (err.type === 'StripeInvalidRequestError') return 400;
//   if (err.type === 'StripeAPIError') return 502;
//   if (err.type === 'StripeConnectionError') return 503;
//   if (err.type === 'StripeAuthenticationError') return 401;

//   return 500;
// }

// /**
//  * Map payment errors to user-friendly messages
//  */
// function mapPaymentErrorMessage(err) {
//   const messageMappings = {
//     'card_declined': 'Your card was declined',
//     'insufficient_funds': 'Insufficient funds',
//     'invalid_cvc': 'Invalid security code',
//     'invalid_expiry_month': 'Invalid expiry month',
//     'invalid_expiry_year': 'Invalid expiry year',
//     'invalid_number': 'Invalid card number',
//     'expired_card': 'Your card has expired',
//     'incorrect_cvc': 'Incorrect security code',
//     'processing_error': 'Payment processing error',
//     'rate_limit': 'Too many payment requests'
//   };

//   if (err.code && messageMappings[err.code]) {
//     return messageMappings[err.code];
//   }

//   if (err.type === 'StripeCardError') return 'Card payment failed';
//   if (err.type === 'StripeRateLimitError') return 'Too many requests, please try again';
//   if (err.type === 'StripeInvalidRequestError') return 'Invalid payment request';
//   if (err.type === 'StripeAPIError') return 'Payment service unavailable';
//   if (err.type === 'StripeConnectionError') return 'Payment service connection failed';
//   if (err.type === 'StripeAuthenticationError') return 'Payment authentication failed';

//   return 'Payment processing failed';
// }

// /**
//  * Map file upload errors to user-friendly messages
//  */
// function mapFileUploadErrorMessage(err) {
//   const messageMappings = {
//     'LIMIT_FILE_SIZE': 'File size too large',
//     'LIMIT_FILE_COUNT': 'Too many files uploaded',
//     'LIMIT_FIELD_KEY': 'Field name too long',
//     'LIMIT_FIELD_VALUE': 'Field value too long',
//     'LIMIT_FIELD_COUNT': 'Too many fields',
//     'LIMIT_UNEXPECTED_FILE': 'Unexpected file field',
//     'MISSING_FIELD_NAME': 'Missing field name',
//     'INVALID_FILE_TYPE': 'Invalid file type'
//   };

//   return messageMappings[err.code] || 'File upload failed';
// }

// /**
//  * Get production-safe error messages
//  */
// function getProductionErrorMessage(errorType) {
//   const productionMessages = {
//     'AUTHENTICATION_ERROR': 'Authentication required',
//     'AUTHORIZATION_ERROR': 'Access denied',
//     'VALIDATION_ERROR': 'Invalid input provided',
//     'DATABASE_ERROR': 'Data operation failed',
//     'PAYMENT_ERROR': 'Payment processing failed',
//     'RATE_LIMIT_ERROR': 'Too many requests',
//     'FILE_UPLOAD_ERROR': 'File upload failed',
//     'INTEGRATION_ERROR': 'External service unavailable',
//     'NETWORK_ERROR': 'Network connection failed'
//   };

//   return productionMessages[errorType] || 'An error occurred';
// }

// /**
//  * Sanitize request body for error logging
//  */
// function sanitizeForErrorLog(body) {
//   if (!body || typeof body !== 'object') {
//     return body;
//   }

//   const sensitiveFields = [
//     'password', 'token', 'key', 'secret', 'authorization',
//     'credit_card', 'ssn', 'bank_account', 'biometric_data',
//     'private_key', 'api_key', 'refresh_token', 'access_token'
//   ];

//   const sanitized = Array.isArray(body) ? [...body] : { ...body };

//   for (const [key, value] of Object.entries(sanitized)) {
//     const lowerKey = key.toLowerCase();
    
//     if (sensitiveFields.some(field => lowerKey.includes(field))) {
//       sanitized[key] = '[REDACTED]';
//     } else if (typeof value === 'object' && value !== null) {
//       sanitized[key] = sanitizeForErrorLog(value);
//     }
//   }

//   return sanitized;
// }

// /**
//  * Sanitize headers for error logging
//  */
// function sanitizeHeaders(headers) {
//   if (!headers || typeof headers !== 'object') {
//     return headers;
//   }

//   const sensitiveHeaders = [
//     'authorization', 'cookie', 'x-api-key', 'x-auth-token',
//     'x-access-token', 'x-refresh-token', 'x-mfa-token'
//   ];

//   const sanitized = { ...headers };

//   for (const header of sensitiveHeaders) {
//     if (sanitized[header]) {
//       sanitized[header] = '[REDACTED]';
//     }
//   }

//   return sanitized;
// }

// /**
//  * Health check for error handler
//  */
// export const errorHandlerHealth = () => {
//   return {
//     status: 'healthy',
//     timestamp: new Date().toISOString(),
//     handlers: [
//       'errorHandler',
//       'validationErrorHandler',
//       'databaseErrorHandler',
//       'authenticationErrorHandler',
//       'authorizationErrorHandler',
//       'rateLimitErrorHandler',
//       'paymentErrorHandler',
//       'fileUploadErrorHandler'
//     ]
//   };
// };

// /**
//  * Configure process-level error handlers
//  */
// export const configureProcessErrorHandlers = () => {
//   process.on('unhandledRejection', unhandledRejectionHandler);
//   process.on('uncaughtException', uncaughtExceptionHandler);
  
//   // Graceful shutdown on SIGTERM
//   process.on('SIGTERM', () => {
//     console.log('SIGTERM received, shutting down gracefully');
//     process.exit(0);
//   });
  
//   // Graceful shutdown on SIGINT
//   process.on('SIGINT', () => {
//     console.log('SIGINT received, shutting down gracefully');
//     process.exit(0);
//   });
// };
// // import logger from '../utils/logger.js';
// // import { ValidationError } from 'sequelize';

// // // Custom error classes
// // export class AppError extends Error {
// //   constructor(message, statusCode, code = null, isOperational = true) {
// //     super(message);
// //     this.statusCode = statusCode;
// //     this.code = code;
// //     this.isOperational = isOperational;
// //     this.timestamp = new Date().toISOString();
    
// //     Error.captureStackTrace(this, this.constructor);
// //   }
// // }

// // export class ValidationAppError extends AppError {
// //   constructor(message, errors = []) {
// //     super(message, 400, 'VALIDATION_ERROR');
// //     this.errors = errors;
// //   }
// // }

// // export class AuthenticationError extends AppError {
// //   constructor(message = 'Authentication failed') {
// //     super(message, 401, 'AUTHENTICATION_ERROR');
// //   }
// // }

// // export class AuthorizationError extends AppError {
// //   constructor(message = 'Access denied') {
// //     super(message, 403, 'AUTHORIZATION_ERROR');
// //   }
// // }

// // export class NotFoundError extends AppError {
// //   constructor(message = 'Resource not found') {
// //     super(message, 404, 'NOT_FOUND');
// //   }
// // }

// // export class ConflictError extends AppError {
// //   constructor(message = 'Resource already exists') {
// //     super(message, 409, 'CONFLICT');
// //   }
// // }

// // export class RateLimitError extends AppError {
// //   constructor(message = 'Rate limit exceeded') {
// //     super(message, 429, 'RATE_LIMIT_EXCEEDED');
// //   }
// // }

// // export class DatabaseError extends AppError {
// //   constructor(message = 'Database operation failed') {
// //     super(message, 500, 'DATABASE_ERROR');
// //   }
// // }

// // export class EncryptionError extends AppError {
// //   constructor(message = 'Encryption/Decryption failed') {
// //     super(message, 500, 'ENCRYPTION_ERROR');
// //   }
// // }

// // // Handle different types of errors
// // const handleSequelizeError = (error) => {
// //   if (error instanceof ValidationError) {
// //     const errors = error.errors.map(err => ({
// //       field: err.path,
// //       message: err.message,
// //       value: err.value
// //     }));
    
// //     return new ValidationAppError('Validation failed', errors);
// //   }
  
// //   // Handle unique constraint violations
// //   if (error.name === 'SequelizeUniqueConstraintError') {
// //     const field = error.errors?.[0]?.path || 'field';
// //     return new ConflictError(`${field} already exists`);
// //   }
  
// //   // Handle foreign key constraint violations
// //   if (error.name === 'SequelizeForeignKeyConstraintError') {
// //     return new ValidationAppError('Invalid reference to related resource');
// //   }
  
// //   // Handle connection errors
// //   if (error.name === 'SequelizeConnectionError') {
// //     return new DatabaseError('Database connection failed');
// //   }
  
// //   // Handle timeout errors
// //   if (error.name === 'SequelizeTimeoutError') {
// //     return new DatabaseError('Database operation timed out');
// //   }
  
// //   return new DatabaseError(error.message || 'Database error occurred');
// // };

// // const handleJWTError = (error) => {
// //   if (error.name === 'JsonWebTokenError') {
// //     return new AuthenticationError('Invalid token');
// //   }
  
// //   if (error.name === 'TokenExpiredError') {
// //     return new AuthenticationError('Token expired');
// //   }
  
// //   if (error.name === 'NotBeforeError') {
// //     return new AuthenticationError('Token not active');
// //   }
  
// //   return new AuthenticationError('Token validation failed');
// // };

// // const handleMulterError = (error) => {
// //   if (error.code === 'LIMIT_FILE_SIZE') {
// //     return new ValidationAppError('File size too large');
// //   }
  
// //   if (error.code === 'LIMIT_FILE_COUNT') {
// //     return new ValidationAppError('Too many files');
// //   }
  
// //   if (error.code === 'LIMIT_UNEXPECTED_FILE') {
// //     return new ValidationAppError('Unexpected file field');
// //   }
  
// //   return new ValidationAppError(`File upload error: ${error.message}`);
// // };

// // // Send error response in development
// // const sendErrorDev = (err, req, res) => {
// //   // Log full error details in development
// //   logger.error('Development Error:', {
// //     error: err,
// //     stack: err.stack,
// //     url: req.url,
// //     method: req.method,
// //     ip: req.ip,
// //     userAgent: req.get('User-Agent'),
// //     user: req.user?.id || 'anonymous'
// //   });

// //   res.status(err.statusCode || 500).json({
// //     success: false,
// //     error: err.message,
// //     code: err.code,
// //     statusCode: err.statusCode,
// //     timestamp: err.timestamp || new Date().toISOString(),
// //     stack: err.stack,
// //     errors: err.errors || undefined,
// //     path: req.path,
// //     method: req.method
// //   });
// // };

// // // Send error response in production
// // const sendErrorProd = (err, req, res) => {
// //   // Operational errors - safe to send to client
// //   if (err.isOperational) {
// //     logger.error('Operational Error:', {
// //       message: err.message,
// //       code: err.code,
// //       statusCode: err.statusCode,
// //       url: req.url,
// //       method: req.method,
// //       ip: req.ip,
// //       user: req.user?.id || 'anonymous'
// //     });

// //     res.status(err.statusCode || 500).json({
// //       success: false,
// //       error: err.message,
// //       code: err.code,
// //       timestamp: err.timestamp || new Date().toISOString(),
// //       errors: err.errors || undefined
// //     });
// //   } else {
// //     // Programming or system errors - don't leak details
// //     logger.error('System Error:', {
// //       error: err,
// //       stack: err.stack,
// //       url: req.url,
// //       method: req.method,
// //       ip: req.ip,
// //       userAgent: req.get('User-Agent'),
// //       user: req.user?.id || 'anonymous'
// //     });

// //     res.status(500).json({
// //       success: false,
// //       error: 'Something went wrong',
// //       code: 'INTERNAL_SERVER_ERROR',
// //       timestamp: new Date().toISOString()
// //     });
// //   }
// // };

// // // Main error handler middleware
// // const errorHandler = (err, req, res, next) => {
// //   // Make sure error has statusCode
// //   err.statusCode = err.statusCode || 500;
// //   err.status = err.status || 'error';

// //   // Handle different error types
// //   if (err.name?.includes('Sequelize')) {
// //     err = handleSequelizeError(err);
// //   } else if (err.name?.includes('JsonWebToken') || err.name?.includes('Token')) {
// //     err = handleJWTError(err);
// //   } else if (err.name === 'MulterError') {
// //     err = handleMulterError(err);
// //   } else if (err.type === 'entity.parse.failed') {
// //     err = new ValidationAppError('Invalid JSON in request body');
// //   } else if (err.code === 'EBADCSRFTOKEN') {
// //     err = new ValidationAppError('Invalid CSRF token');
// //   }

// //   // Send error response
// //   if (process.env.NODE_ENV === 'development') {
// //     sendErrorDev(err, req, res);
// //   } else {
// //     sendErrorProd(err, req, res);
// //   }
// // };

// // // Async error wrapper for route handlers
// // export const asyncHandler = (fn) => {
// //   return (req, res, next) => {
// //     Promise.resolve(fn(req, res, next)).catch(next);
// //   };
// // };

// // // Create error with status code
// // export const createError = (message, statusCode, code = null) => {
// //   return new AppError(message, statusCode, code);
// // };

// // export default errorHandler;