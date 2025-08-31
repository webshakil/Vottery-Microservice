
import logger from '../utils/logger.js';
import { HTTP_STATUS, MESSAGES, SERVICE_CONFIG } from './constants.js';
import { body, param, query, validationResult } from 'express-validator';

/**
 * Standard API response structure
 */
export class APIResponse {
  constructor(success = true, message = '', data = null, meta = {}) {
    this.success = success;
    this.message = message;
    this.data = data;
    this.meta = {
      timestamp: new Date().toISOString(),
      service: SERVICE_CONFIG.NAME,
      version: SERVICE_CONFIG.VERSION,
      ...meta
    };
  }

  toJSON() {
    return {
      success: this.success,
      message: this.message,
      data: this.data,
      meta: this.meta
    };
  }
}

/**
 * Paginated response structure
 */
export class PaginatedResponse extends APIResponse {
  constructor(data = [], pagination = {}, message = MESSAGES.SUCCESS.RETRIEVED, meta = {}) {
    super(true, message, data, meta);

    this.meta.pagination = {
      currentPage: pagination.currentPage || 1,
      totalPages: pagination.totalPages || 1,
      totalItems: pagination.totalItems || data.length,
      itemsPerPage: pagination.itemsPerPage || data.length,
      hasNextPage: pagination.hasNextPage || false,
      hasPreviousPage: pagination.hasPreviousPage || false,
      ...pagination
    };
  }
}

/**
 * Error response structure
 */
export class ErrorResponse extends APIResponse {
  constructor(message = MESSAGES.ERROR.INTERNAL_ERROR, errors = [], statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, meta = {}) {
    super(false, message, null, meta);

    this.errors = Array.isArray(errors) ? errors : [errors];
    this.statusCode = statusCode;
    this.meta.errorId = this.generateErrorId();
    this.meta.statusCode = statusCode;
  }

  generateErrorId() {
    return `${SERVICE_CONFIG.NAME}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  toJSON() {
    return {
      success: this.success,
      message: this.message,
      data: this.data,
      errors: this.errors,
      meta: this.meta
    };
  }
}

/**
 * Response builder utility class
 */
export class ResponseBuilder {
  static success(res, data = null, message = MESSAGES.SUCCESS.OPERATION_COMPLETED, statusCode = HTTP_STATUS.OK, meta = {}) {
    const response = new APIResponse(true, message, data, meta);

    logger.debug('Sending success response', {
      statusCode,
      message,
      hasData: data !== null,
      meta
    });

    return res.status(statusCode).json(response.toJSON());
  }

  static created(res, data, message = MESSAGES.SUCCESS.CREATED, meta = {}) {
    return this.success(res, data, message, HTTP_STATUS.CREATED, meta);
  }

  static updated(res, data, message = MESSAGES.SUCCESS.UPDATED, meta = {}) {
    return this.success(res, data, message, HTTP_STATUS.OK, meta);
  }

  static deleted(res, message = MESSAGES.SUCCESS.DELETED, meta = {}) {
    return this.success(res, null, message, HTTP_STATUS.NO_CONTENT, meta);
  }

  static paginated(res, data, pagination, message = MESSAGES.SUCCESS.RETRIEVED, meta = {}) {
    const response = new PaginatedResponse(data, pagination, message, meta);

    logger.debug('Sending paginated response', {
      itemCount: data.length,
      pagination: response.meta.pagination
    });

    return res.status(HTTP_STATUS.OK).json(response.toJSON());
  }

  static error(res, message = MESSAGES.ERROR.INTERNAL_ERROR, statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, errors = [], meta = {}) {
    const response = new ErrorResponse(message, errors, statusCode, meta);

    logger.error('Sending error response', {
      statusCode,
      message,
      errorId: response.meta.errorId,
      errorCount: response.errors.length
    });

    return res.status(statusCode).json(response.toJSON());
  }

  static validationError(res, errors, message = MESSAGES.ERROR.VALIDATION_FAILED, meta = {}) {
    return this.error(res, message, HTTP_STATUS.UNPROCESSABLE_ENTITY, errors, meta);
  }

  static unauthorized(res, message = MESSAGES.ERROR.UNAUTHORIZED, meta = {}) {
    return this.error(res, message, HTTP_STATUS.UNAUTHORIZED, [], meta);
  }

  static forbidden(res, message = MESSAGES.ERROR.FORBIDDEN, meta = {}) {
    return this.error(res, message, HTTP_STATUS.FORBIDDEN, [], meta);
  }

  static notFound(res, message = MESSAGES.ERROR.NOT_FOUND, meta = {}) {
    return this.error(res, message, HTTP_STATUS.NOT_FOUND, [], meta);
  }

  static conflict(res, message = MESSAGES.ERROR.CONFLICT, meta = {}) {
    return this.error(res, message, HTTP_STATUS.CONFLICT, [], meta);
  }

  static rateLimited(res, message = MESSAGES.ERROR.RATE_LIMIT_EXCEEDED, meta = {}) {
    return this.error(res, message, HTTP_STATUS.TOO_MANY_REQUESTS, [], meta);
  }

  static internalError(res, message = MESSAGES.ERROR.INTERNAL_ERROR, error = null, meta = {}) {
    if (error instanceof Error) {
      logger.error('Internal server error', { error: error.message, stack: error.stack }, error);
    }

    return this.error(res, message, HTTP_STATUS.INTERNAL_SERVER_ERROR, [], meta);
  }

  static serviceUnavailable(res, message = MESSAGES.ERROR.SERVICE_UNAVAILABLE, meta = {}) {
    return this.error(res, message, HTTP_STATUS.SERVICE_UNAVAILABLE, [], meta);
  }
}

/**
 * Response wrapper middleware
 */
export const responseWrapper = (req, res, next) => {
  res.success = (data, message, meta) => ResponseBuilder.success(res, data, message, HTTP_STATUS.OK, meta);
  res.created = (data, message, meta) => ResponseBuilder.created(res, data, message, meta);
  res.updated = (data, message, meta) => ResponseBuilder.updated(res, data, message, meta);
  res.deleted = (message, meta) => ResponseBuilder.deleted(res, message, meta);
  res.paginated = (data, pagination, message, meta) => ResponseBuilder.paginated(res, data, pagination, message, meta);

  res.error = (message, statusCode, errors, meta) => ResponseBuilder.error(res, message, statusCode, errors, meta);
  res.validationError = (errors, message, meta) => ResponseBuilder.validationError(res, errors, message, meta);
  res.unauthorized = (message, meta) => ResponseBuilder.unauthorized(res, message, meta);
  res.forbidden = (message, meta) => ResponseBuilder.forbidden(res, message, meta);
  res.notFound = (message, meta) => ResponseBuilder.notFound(res, message, meta);
  res.conflict = (message, meta) => ResponseBuilder.conflict(res, message, meta);
  res.rateLimited = (message, meta) => ResponseBuilder.rateLimited(res, message, meta);
  res.internalError = (message, error, meta) => ResponseBuilder.internalError(res, message, error, meta);
  res.serviceUnavailable = (message, meta) => ResponseBuilder.serviceUnavailable(res, message, meta);

  next();
};

/**
 * Format validation errors
 */
export const formatValidationErrors = (validationErrors) => {
  if (!Array.isArray(validationErrors)) {
    return [{ field: 'unknown', message: 'Invalid validation error format' }];
  }

  return validationErrors.map(error => ({
    field: error.field || error.path || 'unknown',
    message: error.message || 'Validation failed',
    code: error.code || 'VALIDATION_ERROR',
    value: error.value || null
  }));
};

/**
 * Calculate pagination metadata
 */
export const calculatePagination = (totalItems, currentPage = 1, itemsPerPage = 20) => {
  const totalPages = Math.ceil(totalItems / itemsPerPage);
  const hasNextPage = currentPage < totalPages;
  const hasPreviousPage = currentPage > 1;

  return {
    currentPage,
    totalPages,
    totalItems,
    itemsPerPage,
    hasNextPage,
    hasPreviousPage,
    nextPage: hasNextPage ? currentPage + 1 : null,
    previousPage: hasPreviousPage ? currentPage - 1 : null,
    startItem: ((currentPage - 1) * itemsPerPage) + 1,
    endItem: Math.min(currentPage * itemsPerPage, totalItems)
  };
};

/**
 * Handle async route errors
 */
export const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Success response with timing
 */
export const successWithTiming = (res, data, startTime, message = MESSAGES.SUCCESS.RETRIEVED) => {
  const duration = Date.now() - startTime;
  return ResponseBuilder.success(res, data, message, HTTP_STATUS.OK, {
    processingTime: `${duration}ms`
  });
};

/**
 * Success response with cache
 */
export const successWithCache = (res, data, maxAge = 300, message = MESSAGES.SUCCESS.RETRIEVED) => {
  res.set({
    'Cache-Control': `public, max-age=${maxAge}`,
    'ETag': `"${Date.now()}"`,
    'Last-Modified': new Date().toUTCString()
  });

  return ResponseBuilder.success(res, data, message);
};

/**
 * Health check response
 */
export const healthResponse = (res, healthData = {}) => {
  const defaultHealth = {
    status: 'healthy',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    timestamp: new Date().toISOString()
  };

  return ResponseBuilder.success(res, { ...defaultHealth, ...healthData }, 'Service is healthy');
};

/**
 * Validation middleware
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }
  next();
};

export const validation = {
  checkUsername: [
    param('username').isLength({ min: 3, max: 30 }).isAlphanumeric(),
    handleValidationErrors
  ],
  checkEmail: [
    param('email').isEmail(),
    handleValidationErrors
  ],
  updateUser: [
    body('firstName').optional().isLength({ min: 1, max: 50 }),
    body('lastName').optional().isLength({ min: 1, max: 50 }),
    body('email').optional().isEmail(),
    handleValidationErrors
  ],
  changePassword: [
    body('currentPassword').isLength({ min: 1 }),
    body('newPassword').isLength({ min: 8, max: 128 }),
    handleValidationErrors
  ],
  toggle2FA: [
    body('enabled').isBoolean(),
    handleValidationErrors
  ],
  pagination: [
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 100 }),
    handleValidationErrors
  ],
  validateObjectId: [
    param('userId').optional().isMongoId(),
    param('sessionId').optional().isMongoId(),
    handleValidationErrors
  ],
  userFilters: [
    query('status').optional().isIn(['active', 'suspended', 'deleted']),
    query('role').optional().isString(),
    handleValidationErrors
  ],
  adminUpdateUser: [
    body('status').optional().isIn(['active', 'suspended']),
    body('role').optional().isString(),
    handleValidationErrors
  ],
  userSuspension: [
    body('suspended').isBoolean(),
    body('reason').optional().isString(),
    handleValidationErrors
  ],
  dateRange: [
    query('startDate').optional().isISO8601(),
    query('endDate').optional().isISO8601(),
    handleValidationErrors
  ],
  exportOptions: [
    query('format').optional().isIn(['csv', 'json', 'xlsx']),
    handleValidationErrors
  ],
  bulkUserIds: [
    body('userIds').isArray({ min: 1 }),
    body('userIds.*').isMongoId(),
    handleValidationErrors
  ],
  searchQuery: [
    query('q').isLength({ min: 1, max: 100 }),
    handleValidationErrors
  ],
  advancedFilters: [
    body('filters').isObject(),
    handleValidationErrors
  ]
};

// Default export
export default ResponseBuilder;






// // import logger from '../utils/logger.js';
// // import { HTTP_STATUS, MESSAGES, SERVICE_CONFIG } from './constants.js';
// // //import logger from './logger.js';

// // /**
// //  * Standard API response structure
// //  */
// // export class APIResponse {
// //   constructor(success = true, message = '', data = null, meta = {}) {
// //     this.success = success;
// //     this.message = message;
// //     this.data = data;
// //     this.meta = {
// //       timestamp: new Date().toISOString(),
// //       service: SERVICE_CONFIG.NAME,
// //       version: SERVICE_CONFIG.VERSION,
// //       ...meta
// //     };
// //   }

// //   /**
// //    * Convert response to JSON
// //    * @returns {object} JSON representation
// //    */
// //   toJSON() {
// //     return {
// //       success: this.success,
// //       message: this.message,
// //       data: this.data,
// //       meta: this.meta
// //     };
// //   }
// // }

// // /**
// //  * Paginated response structure
// //  */
// // export class PaginatedResponse extends APIResponse {
// //   constructor(data = [], pagination = {}, message = MESSAGES.SUCCESS.RETRIEVED, meta = {}) {
// //     super(true, message, data, meta);
    
// //     this.meta.pagination = {
// //       currentPage: pagination.currentPage || 1,
// //       totalPages: pagination.totalPages || 1,
// //       totalItems: pagination.totalItems || data.length,
// //       itemsPerPage: pagination.itemsPerPage || data.length,
// //       hasNextPage: pagination.hasNextPage || false,
// //       hasPreviousPage: pagination.hasPreviousPage || false,
// //       ...pagination
// //     };
// //   }
// // }

// // /**
// //  * Error response structure
// //  */
// // export class ErrorResponse extends APIResponse {
// //   constructor(message = MESSAGES.ERROR.INTERNAL_ERROR, errors = [], statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, meta = {}) {
// //     super(false, message, null, meta);
    
// //     this.errors = Array.isArray(errors) ? errors : [errors];
// //     this.statusCode = statusCode;
    
// //     // Add error tracking information
// //     this.meta.errorId = this.generateErrorId();
// //     this.meta.statusCode = statusCode;
// //   }

// //   /**
// //    * Generate unique error ID for tracking
// //    * @returns {string} Error ID
// //    */
// //   generateErrorId() {
// //     return `${SERVICE_CONFIG.NAME}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
// //   }

// //   /**
// //    * Convert to JSON (exclude statusCode from response body)
// //    * @returns {object} JSON representation
// //    */
// //   toJSON() {
// //     return {
// //       success: this.success,
// //       message: this.message,
// //       data: this.data,
// //       errors: this.errors,
// //       meta: this.meta
// //     };
// //   }
// // }

// // /**
// //  * Response builder utility class
// //  */
// // export class ResponseBuilder {
// //   /**
// //    * Send successful response
// //    * @param {object} res - Express response object
// //    * @param {*} data - Response data
// //    * @param {string} message - Success message
// //    * @param {number} statusCode - HTTP status code
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static success(res, data = null, message = MESSAGES.SUCCESS.OPERATION_COMPLETED, statusCode = HTTP_STATUS.OK, meta = {}) {
// //     const response = new APIResponse(true, message, data, meta);
    
// //     logger.debug('Sending success response', {
// //       statusCode,
// //       message,
// //       hasData: data !== null,
// //       meta
// //     });

// //     return res.status(statusCode).json(response.toJSON());
// //   }

// //   static created(res, data, message = MESSAGES.SUCCESS.CREATED, meta = {}) {
// //     return this.success(res, data, message, HTTP_STATUS.CREATED, meta);
// //   }

// //   static updated(res, data, message = MESSAGES.SUCCESS.UPDATED, meta = {}) {
// //     return this.success(res, data, message, HTTP_STATUS.OK, meta);
// //   }

// //   static deleted(res, message = MESSAGES.SUCCESS.DELETED, meta = {}) {
// //     return this.success(res, null, message, HTTP_STATUS.NO_CONTENT, meta);
// //   }

// //   static paginated(res, data, pagination, message = MESSAGES.SUCCESS.RETRIEVED, meta = {}) {
// //     const response = new PaginatedResponse(data, pagination, message, meta);
    
// //     logger.debug('Sending paginated response', {
// //       itemCount: data.length,
// //       pagination: response.meta.pagination
// //     });

// //     return res.status(HTTP_STATUS.OK).json(response.toJSON());
// //   }

// //   static error(res, message = MESSAGES.ERROR.INTERNAL_ERROR, statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, errors = [], meta = {}) {
// //     const response = new ErrorResponse(message, errors, statusCode, meta);
    
// //     logger.error('Sending error response', {
// //       statusCode,
// //       message,
// //       errorId: response.meta.errorId,
// //       errorCount: response.errors.length
// //     });

// //     return res.status(statusCode).json(response.toJSON());
// //   }

// //   static validationError(res, errors, message = MESSAGES.ERROR.VALIDATION_FAILED, meta = {}) {
// //     return this.error(res, message, HTTP_STATUS.UNPROCESSABLE_ENTITY, errors, meta);
// //   }

// //   static unauthorized(res, message = MESSAGES.ERROR.UNAUTHORIZED, meta = {}) {
// //     return this.error(res, message, HTTP_STATUS.UNAUTHORIZED, [], meta);
// //   }

// //   static forbidden(res, message = MESSAGES.ERROR.FORBIDDEN, meta = {}) {
// //     return this.error(res, message, HTTP_STATUS.FORBIDDEN, [], meta);
// //   }

// //   static notFound(res, message = MESSAGES.ERROR.NOT_FOUND, meta = {}) {
// //     return this.error(res, message, HTTP_STATUS.NOT_FOUND, [], meta);
// //   }

// //   static conflict(res, message = MESSAGES.ERROR.CONFLICT, meta = {}) {
// //     return this.error(res, message, HTTP_STATUS.CONFLICT, [], meta);
// //   }

// //   static rateLimited(res, message = MESSAGES.ERROR.RATE_LIMIT_EXCEEDED, meta = {}) {
// //     return this.error(res, message, HTTP_STATUS.TOO_MANY_REQUESTS, [], meta);
// //   }

// //   static internalError(res, message = MESSAGES.ERROR.INTERNAL_ERROR, error = null, meta = {}) {
// //     if (error instanceof Error) {
// //       logger.error('Internal server error', { error: error.message, stack: error.stack }, error);
// //     }

// //     return this.error(res, message, HTTP_STATUS.INTERNAL_SERVER_ERROR, [], meta);
// //   }

// //   static serviceUnavailable(res, message = MESSAGES.ERROR.SERVICE_UNAVAILABLE, meta = {}) {
// //     return this.error(res, message, HTTP_STATUS.SERVICE_UNAVAILABLE, [], meta);
// //   }
// // }

// // /**
// //  * Response wrapper middleware
// //  */
// // export const responseWrapper = (req, res, next) => {
// //   res.success = (data, message, meta) => ResponseBuilder.success(res, data, message, HTTP_STATUS.OK, meta);
// //   res.created = (data, message, meta) => ResponseBuilder.created(res, data, message, meta);
// //   res.updated = (data, message, meta) => ResponseBuilder.updated(res, data, message, meta);
// //   res.deleted = (message, meta) => ResponseBuilder.deleted(res, message, meta);
// //   res.paginated = (data, pagination, message, meta) => ResponseBuilder.paginated(res, data, pagination, message, meta);

// //   res.error = (message, statusCode, errors, meta) => ResponseBuilder.error(res, message, statusCode, errors, meta);
// //   res.validationError = (errors, message, meta) => ResponseBuilder.validationError(res, errors, message, meta);
// //   res.unauthorized = (message, meta) => ResponseBuilder.unauthorized(res, message, meta);
// //   res.forbidden = (message, meta) => ResponseBuilder.forbidden(res, message, meta);
// //   res.notFound = (message, meta) => ResponseBuilder.notFound(res, message, meta);
// //   res.conflict = (message, meta) => ResponseBuilder.conflict(res, message, meta);
// //   res.rateLimited = (message, meta) => ResponseBuilder.rateLimited(res, message, meta);
// //   res.internalError = (message, error, meta) => ResponseBuilder.internalError(res, message, error, meta);
// //   res.serviceUnavailable = (message, meta) => ResponseBuilder.serviceUnavailable(res, message, meta);

// //   next();
// // };

// // /**
// //  * Format validation errors
// //  */
// // export const formatValidationErrors = (validationErrors) => {
// //   if (!Array.isArray(validationErrors)) {
// //     return [{ field: 'unknown', message: 'Invalid validation error format' }];
// //   }

// //   return validationErrors.map(error => ({
// //     field: error.field || error.path || 'unknown',
// //     message: error.message || 'Validation failed',
// //     code: error.code || 'VALIDATION_ERROR',
// //     value: error.value || null
// //   }));
// // };

// // /**
// //  * Calculate pagination metadata
// //  */
// // export const calculatePagination = (totalItems, currentPage = 1, itemsPerPage = 20) => {
// //   const totalPages = Math.ceil(totalItems / itemsPerPage);
// //   const hasNextPage = currentPage < totalPages;
// //   const hasPreviousPage = currentPage > 1;
  
// //   return {
// //     currentPage,
// //     totalPages,
// //     totalItems,
// //     itemsPerPage,
// //     hasNextPage,
// //     hasPreviousPage,
// //     nextPage: hasNextPage ? currentPage + 1 : null,
// //     previousPage: hasPreviousPage ? currentPage - 1 : null,
// //     startItem: ((currentPage - 1) * itemsPerPage) + 1,
// //     endItem: Math.min(currentPage * itemsPerPage, totalItems)
// //   };
// // };

// // /**
// //  * Handle async route errors
// //  */
// // export const asyncHandler = (fn) => {
// //   return (req, res, next) => {
// //     Promise.resolve(fn(req, res, next)).catch(next);
// //   };
// // };

// // /**
// //  * Success response with timing
// //  */
// // export const successWithTiming = (res, data, startTime, message = MESSAGES.SUCCESS.RETRIEVED) => {
// //   const duration = Date.now() - startTime;
// //   return ResponseBuilder.success(res, data, message, HTTP_STATUS.OK, {
// //     processingTime: `${duration}ms`
// //   });
// // };

// // /**
// //  * Success response with cache
// //  */
// // export const successWithCache = (res, data, maxAge = 300, message = MESSAGES.SUCCESS.RETRIEVED) => {
// //   res.set({
// //     'Cache-Control': `public, max-age=${maxAge}`,
// //     'ETag': `"${Date.now()}"`,
// //     'Last-Modified': new Date().toUTCString()
// //   });
  
// //   return ResponseBuilder.success(res, data, message);
// // };

// // /**
// //  * Health check response
// //  */
// // export const healthResponse = (res, healthData = {}) => {
// //   const defaultHealth = {
// //     status: 'healthy',
// //     uptime: process.uptime(),
// //     memory: process.memoryUsage(),
// //     timestamp: new Date().toISOString()
// //   };

// //   return ResponseBuilder.success(res, { ...defaultHealth, ...healthData }, 'Service is healthy');
// // };

// // // Default export
// // export default ResponseBuilder;

// // // Named exports
// // export {

 






  
// // };

// // import { HTTP_STATUS, MESSAGES, SERVICE_CONFIG } from './constants.js';
// // import logger from './logger.js';

// // /**
// //  * Standard API response structure
// //  */
// // export class APIResponse {
// //   constructor(success = true, message = '', data = null, meta = {}) {
// //     this.success = success;
// //     this.message = message;
// //     this.data = data;
// //     this.meta = {
// //       timestamp: new Date().toISOString(),
// //       service: SERVICE_CONFIG.NAME,
// //       version: SERVICE_CONFIG.VERSION,
// //       ...meta
// //     };
// //   }

// //   /**
// //    * Convert response to JSON
// //    * @returns {object} JSON representation
// //    */
// //   toJSON() {
// //     return {
// //       success: this.success,
// //       message: this.message,
// //       data: this.data,
// //       meta: this.meta
// //     };
// //   }
// // }

// // /**
// //  * Paginated response structure
// //  */
// // export class PaginatedResponse extends APIResponse {
// //   constructor(data = [], pagination = {}, message = MESSAGES.SUCCESS.RETRIEVED, meta = {}) {
// //     super(true, message, data, meta);
    
// //     this.meta.pagination = {
// //       currentPage: pagination.currentPage || 1,
// //       totalPages: pagination.totalPages || 1,
// //       totalItems: pagination.totalItems || data.length,
// //       itemsPerPage: pagination.itemsPerPage || data.length,
// //       hasNextPage: pagination.hasNextPage || false,
// //       hasPreviousPage: pagination.hasPreviousPage || false,
// //       ...pagination
// //     };
// //   }
// // }

// // /**
// //  * Error response structure
// //  */
// // export class ErrorResponse extends APIResponse {
// //   constructor(message = MESSAGES.ERROR.INTERNAL_ERROR, errors = [], statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, meta = {}) {
// //     super(false, message, null, meta);
    
// //     this.errors = Array.isArray(errors) ? errors : [errors];
// //     this.statusCode = statusCode;
    
// //     // Add error tracking information
// //     this.meta.errorId = this.generateErrorId();
// //     this.meta.statusCode = statusCode;
// //   }

// //   /**
// //    * Generate unique error ID for tracking
// //    * @returns {string} Error ID
// //    */
// //   generateErrorId() {
// //     return `${SERVICE_CONFIG.NAME}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
// //   }

// //   /**
// //    * Convert to JSON (exclude statusCode from response body)
// //    * @returns {object} JSON representation
// //    */
// //   toJSON() {
// //     return {
// //       success: this.success,
// //       message: this.message,
// //       data: this.data,
// //       errors: this.errors,
// //       meta: this.meta
// //     };
// //   }
// // }

// // /**
// //  * Response builder utility class
// //  */
// // export class ResponseBuilder {
// //   /**
// //    * Send successful response
// //    * @param {object} res - Express response object
// //    * @param {*} data - Response data
// //    * @param {string} message - Success message
// //    * @param {number} statusCode - HTTP status code
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static success(res, data = null, message = MESSAGES.SUCCESS.OPERATION_COMPLETED, statusCode = HTTP_STATUS.OK, meta = {}) {
// //     const response = new APIResponse(true, message, data, meta);
    
// //     logger.debug('Sending success response', {
// //       statusCode,
// //       message,
// //       hasData: data !== null,
// //       meta
// //     });

// //     return res.status(statusCode).json(response.toJSON());
// //   }

// //   /**
// //    * Send created response
// //    * @param {object} res - Express response object
// //    * @param {*} data - Created resource data
// //    * @param {string} message - Success message
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static created(res, data, message = MESSAGES.SUCCESS.CREATED, meta = {}) {
// //     return this.success(res, data, message, HTTP_STATUS.CREATED, meta);
// //   }

// //   /**
// //    * Send updated response
// //    * @param {object} res - Express response object
// //    * @param {*} data - Updated resource data
// //    * @param {string} message - Success message
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static updated(res, data, message = MESSAGES.SUCCESS.UPDATED, meta = {}) {
// //     return this.success(res, data, message, HTTP_STATUS.OK, meta);
// //   }

// //   /**
// //    * Send deleted response
// //    * @param {object} res - Express response object
// //    * @param {string} message - Success message
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static deleted(res, message = MESSAGES.SUCCESS.DELETED, meta = {}) {
// //     return this.success(res, null, message, HTTP_STATUS.NO_CONTENT, meta);
// //   }

// //   /**
// //    * Send paginated response
// //    * @param {object} res - Express response object
// //    * @param {Array} data - Array of items
// //    * @param {object} pagination - Pagination metadata
// //    * @param {string} message - Success message
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static paginated(res, data, pagination, message = MESSAGES.SUCCESS.RETRIEVED, meta = {}) {
// //     const response = new PaginatedResponse(data, pagination, message, meta);
    
// //     logger.debug('Sending paginated response', {
// //       itemCount: data.length,
// //       pagination: response.meta.pagination
// //     });

// //     return res.status(HTTP_STATUS.OK).json(response.toJSON());
// //   }

// //   /**
// //    * Send error response
// //    * @param {object} res - Express response object
// //    * @param {string} message - Error message
// //    * @param {number} statusCode - HTTP status code
// //    * @param {Array} errors - Validation errors
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static error(res, message = MESSAGES.ERROR.INTERNAL_ERROR, statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, errors = [], meta = {}) {
// //     const response = new ErrorResponse(message, errors, statusCode, meta);
    
// //     logger.error('Sending error response', {
// //       statusCode,
// //       message,
// //       errorId: response.meta.errorId,
// //       errorCount: response.errors.length
// //     });

// //     return res.status(statusCode).json(response.toJSON());
// //   }

// //   /**
// //    * Send validation error response
// //    * @param {object} res - Express response object
// //    * @param {Array} errors - Validation errors
// //    * @param {string} message - Error message
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static validationError(res, errors, message = MESSAGES.ERROR.VALIDATION_FAILED, meta = {}) {
// //     return this.error(res, message, HTTP_STATUS.UNPROCESSABLE_ENTITY, errors, meta);
// //   }

// //   /**
// //    * Send unauthorized response
// //    * @param {object} res - Express response object
// //    * @param {string} message - Error message
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static unauthorized(res, message = MESSAGES.ERROR.UNAUTHORIZED, meta = {}) {
// //     return this.error(res, message, HTTP_STATUS.UNAUTHORIZED, [], meta);
// //   }

// //   /**
// //    * Send forbidden response
// //    * @param {object} res - Express response object
// //    * @param {string} message - Error message
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static forbidden(res, message = MESSAGES.ERROR.FORBIDDEN, meta = {}) {
// //     return this.error(res, message, HTTP_STATUS.FORBIDDEN, [], meta);
// //   }

// //   /**
// //    * Send not found response
// //    * @param {object} res - Express response object
// //    * @param {string} message - Error message
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static notFound(res, message = MESSAGES.ERROR.NOT_FOUND, meta = {}) {
// //     return this.error(res, message, HTTP_STATUS.NOT_FOUND, [], meta);
// //   }

// //   /**
// //    * Send conflict response
// //    * @param {object} res - Express response object
// //    * @param {string} message - Error message
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static conflict(res, message = MESSAGES.ERROR.CONFLICT, meta = {}) {
// //     return this.error(res, message, HTTP_STATUS.CONFLICT, [], meta);
// //   }

// //   /**
// //    * Send rate limit exceeded response
// //    * @param {object} res - Express response object
// //    * @param {string} message - Error message
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static rateLimited(res, message = MESSAGES.ERROR.RATE_LIMIT_EXCEEDED, meta = {}) {
// //     return this.error(res, message, HTTP_STATUS.TOO_MANY_REQUESTS, [], meta);
// //   }

// //   /**
// //    * Send internal server error response
// //    * @param {object} res - Express response object
// //    * @param {string} message - Error message
// //    * @param {Error} error - Error object
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static internalError(res, message = MESSAGES.ERROR.INTERNAL_ERROR, error = null, meta = {}) {
// //     // Log the actual error for debugging
// //     if (error instanceof Error) {
// //       logger.error('Internal server error', { error: error.message, stack: error.stack }, error);
// //     }

// //     return this.error(res, message, HTTP_STATUS.INTERNAL_SERVER_ERROR, [], meta);
// //   }

// //   /**
// //    * Send service unavailable response
// //    * @param {object} res - Express response object
// //    * @param {string} message - Error message
// //    * @param {object} meta - Additional metadata
// //    * @returns {object} Express response
// //    */
// //   static serviceUnavailable(res, message = MESSAGES.ERROR.SERVICE_UNAVAILABLE, meta = {}) {
// //     return this.error(res, message, HTTP_STATUS.SERVICE_UNAVAILABLE, [], meta);
// //   }
// // }

// // /**
// //  * Response wrapper middleware
// //  * Adds response helper methods to Express response object
// //  */
// // export const responseWrapper = (req, res, next) => {
// //   // Add success response methods
// //   res.success = (data, message, meta) => ResponseBuilder.success(res, data, message, HTTP_STATUS.OK, meta);
// //   res.created = (data, message, meta) => ResponseBuilder.created(res, data, message, meta);
// //   res.updated = (data, message, meta) => ResponseBuilder.updated(res, data, message, meta);
// //   res.deleted = (message, meta) => ResponseBuilder.deleted(res, message, meta);
// //   res.paginated = (data, pagination, message, meta) => ResponseBuilder.paginated(res, data, pagination, message, meta);

// //   // Add error response methods
// //   res.error = (message, statusCode, errors, meta) => ResponseBuilder.error(res, message, statusCode, errors, meta);
// //   res.validationError = (errors, message, meta) => ResponseBuilder.validationError(res, errors, message, meta);
// //   res.unauthorized = (message, meta) => ResponseBuilder.unauthorized(res, message, meta);
// //   res.forbidden = (message, meta) => ResponseBuilder.forbidden(res, message, meta);
// //   res.notFound = (message, meta) => ResponseBuilder.notFound(res, message, meta);
// //   res.conflict = (message, meta) => ResponseBuilder.conflict(res, message, meta);
// //   res.rateLimited = (message, meta) => ResponseBuilder.rateLimited(res, message, meta);
// //   res.internalError = (message, error, meta) => ResponseBuilder.internalError(res, message, error, meta);
// //   res.serviceUnavailable = (message, meta) => ResponseBuilder.serviceUnavailable(res, message, meta);

// //   next();
// // };

// // /**
// //  * Format validation errors for response
// //  * @param {Array} validationErrors - Array of validation error objects
// //  * @returns {Array} Formatted error array
// //  */
// // export const formatValidationErrors = (validationErrors) => {
// //   if (!Array.isArray(validationErrors)) {
// //     return [{ field: 'unknown', message: 'Invalid validation error format' }];
// //   }

// //   return validationErrors.map(error => ({
// //     field: error.field || error.path || 'unknown',
// //     message: error.message || 'Validation failed',
// //     code: error.code || 'VALIDATION_ERROR',
// //     value: error.value || null
// //   }));
// // };

// // /**
// //  * Calculate pagination metadata
// //  * @param {number} totalItems - Total number of items
// //  * @param {number} currentPage - Current page number
// //  * @param {number} itemsPerPage - Items per page
// //  * @returns {object} Pagination metadata
// //  */
// // export const calculatePagination = (totalItems, currentPage = 1, itemsPerPage = 20) => {
// //   const totalPages = Math.ceil(totalItems / itemsPerPage);
// //   const hasNextPage = currentPage < totalPages;
// //   const hasPreviousPage = currentPage > 1;
  
// //   return {
// //     currentPage,
// //     totalPages,
// //     totalItems,
// //     itemsPerPage,
// //     hasNextPage,
// //     hasPreviousPage,
// //     nextPage: hasNextPage ? currentPage + 1 : null,
// //     previousPage: hasPreviousPage ? currentPage - 1 : null,
// //     startItem: ((currentPage - 1) * itemsPerPage) + 1,
// //     endItem: Math.min(currentPage * itemsPerPage, totalItems)
// //   };
// // };

// // /**
// //  * Handle async route errors
// //  * @param {Function} fn - Async route handler
// //  * @returns {Function} Wrapped route handler
// //  */
// // export const asyncHandler = (fn) => {
// //   return (req, res, next) => {
// //     Promise.resolve(fn(req, res, next)).catch(next);
// //   };
// // };

// // /**
// //  * Create success response with timing
// //  * @param {object} res - Express response object
// //  * @param {*} data - Response data
// //  * @param {number} startTime - Request start time
// //  * @param {string} message - Success message
// //  * @returns {object} Express response
// //  */
// // export const successWithTiming = (res, data, startTime, message = MESSAGES.SUCCESS.RETRIEVED) => {
// //   const duration = Date.now() - startTime;
// //   return ResponseBuilder.success(res, data, message, HTTP_STATUS.OK, {
// //     processingTime: `${duration}ms`
// //   });
// // };

// // /**
// //  * Create response with cache headers
// //  * @param {object} res - Express response object
// //  * @param {*} data - Response data
// //  * @param {number} maxAge - Cache max age in seconds
// //  * @param {string} message - Success message
// //  * @returns {object} Express response
// //  */
// // export const successWithCache = (res, data, maxAge = 300, message = MESSAGES.SUCCESS.RETRIEVED) => {
// //   res.set({
// //     'Cache-Control': `public, max-age=${maxAge}`,
// //     'ETag': `"${Date.now()}"`,
// //     'Last-Modified': new Date().toUTCString()
// //   });
  
// //   return ResponseBuilder.success(res, data, message);
// // };

// // /**
// //  * Health check response
// //  * @param {object} res - Express response object
// //  * @param {object} healthData - Health check data
// //  * @returns {object} Express response
// //  */
// // export const healthResponse = (res, healthData = {}) => {
// //   const defaultHealth = {
// //     status: 'healthy',
// //     uptime: process.uptime(),
// //     memory: process.memoryUsage(),
// //     timestamp: new Date().toISOString()
// //   };

// //   return ResponseBuilder.success(res, { ...defaultHealth, ...healthData }, 'Service is healthy');
// // };

// // // Export all utilities
// // export default ResponseBuilder;

// // export {
// //   APIResponse,
// //   PaginatedResponse,
// //   ErrorResponse,

// //   responseWrapper,
// //   formatValidationErrors,
// //   calculatePagination,
// //   asyncHandler,
// //   successWithTiming,
// //   successWithCache,
// //   healthResponse
// // };
// // import Joi from 'joi';
// // import DOMPurify from 'isomorphic-dompurify';
// // import { errorResponse } from '../utils/response.js';
// // import { auditService } from '../services/auditService.js';

// // /**
// //  * Validation Middleware
// //  * Handles input validation, sanitization, and security checks
// //  */

// // /**
// //  * Generic validation middleware using Joi schemas
// //  * @param {object} schema - Joi validation schema
// //  * @param {string} source - Where to validate (body, query, params)
// //  */
// // export const validate = (schema, source = 'body') => {
// //   return async (req, res, next) => {
// //     try {
// //       const dataToValidate = req[source];
      
// //       const { error, value } = schema.validate(dataToValidate, {
// //         abortEarly: false,
// //         stripUnknown: true,
// //         convert: true
// //       });

// //       if (error) {
// //         const errorMessages = error.details.map(detail => ({
// //           field: detail.path.join('.'),
// //           message: detail.message,
// //           value: detail.context?.value
// //         }));

// //         // Log validation failures for security monitoring
// //         await auditService.log(req.user?.id || null, 'VALIDATION_FAILED', 'security', null, {
// //           endpoint: req.originalUrl,
// //           source,
// //           errors: errorMessages,
// //           userAgent: req.headers['user-agent']
// //         }, req);

// //         return errorResponse(res, 'Validation failed', 400, { 
// //           errors: errorMessages 
// //         });
// //       }

// //       // Replace original data with validated/sanitized data
// //       req[source] = value;
// //       next();

// //     } catch (error) {
// //       console.error('Validation middleware error:', error);
// //       return errorResponse(res, 'Validation processing failed', 500);
// //     }
// //   };
// // };

// // /**
// //  * Sanitize input data to prevent XSS and injection attacks
// //  */
// // export const sanitizeInput = (req, res, next) => {
// //   try {
// //     // Sanitize request body
// //     if (req.body && typeof req.body === 'object') {
// //       req.body = sanitizeObject(req.body);
// //     }

// //     // Sanitize query parameters
// //     if (req.query && typeof req.query === 'object') {
// //       req.query = sanitizeObject(req.query);
// //     }

// //     // Sanitize URL parameters
// //     if (req.params && typeof req.params === 'object') {
// //       req.params = sanitizeObject(req.params);
// //     }

// //     next();

// //   } catch (error) {
// //     console.error('Input sanitization error:', error);
// //     return errorResponse(res, 'Input sanitization failed', 500);
// //   }
// // };

// // /**
// //  * Validate file uploads
// //  * @param {object} options - Upload validation options
// //  */
// // export const validateFileUpload = (options = {}) => {
// //   const {
// //     maxSize = 5 * 1024 * 1024, // 5MB default
// //     allowedTypes = ['image/jpeg', 'image/png', 'image/gif'],
// //     maxFiles = 1,
// //     required = false
// //   } = options;

// //   return async (req, res, next) => {
// //     try {
// //       const files = req.files || [];

// //       if (required && files.length === 0) {
// //         return errorResponse(res, 'File upload is required', 400);
// //       }

// //       if (files.length > maxFiles) {
// //         return errorResponse(res, `Maximum ${maxFiles} files allowed`, 400);
// //       }

// //       for (const file of files) {
// //         // Check file size
// //         if (file.size > maxSize) {
// //           return errorResponse(res, `File size must be less than ${maxSize / (1024 * 1024)}MB`, 400);
// //         }

// //         // Check file type
// //         if (!allowedTypes.includes(file.mimetype)) {
// //           return errorResponse(res, `File type ${file.mimetype} not allowed`, 400);
// //         }

// //         // Check for malicious file extensions
// //         const dangerousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.jar'];
// //         const fileExtension = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
        
// //         if (dangerousExtensions.includes(fileExtension)) {
// //           await auditService.log(req.user?.id || null, 'MALICIOUS_FILE_UPLOAD_ATTEMPT', 'security', null, {
// //             filename: file.originalname,
// //             mimetype: file.mimetype,
// //             size: file.size,
// //             ip: req.ip
// //           }, req);
          
// //           return errorResponse(res, 'File type not allowed for security reasons', 400);
// //         }
// //       }

// //       next();

// //     } catch (error) {
// //       console.error('File validation error:', error);
// //       return errorResponse(res, 'File validation failed', 500);
// //     }
// //   };
// // };

// // /**
// //  * Rate limiting validation
// //  * @param {string} action - Action type for rate limiting
// //  */
// // export const validateRateLimit = (action) => {
// //   return async (req, res, next) => {
// //     try {
// //       const key = `rate_limit:${action}:${req.user?.id || req.ip}`;
// //       const limit = getRateLimitForAction(action);
      
// //       // This would integrate with your rate limiting service
// //       const currentCount = await checkRateLimit(key, limit);
      
// //       if (currentCount > limit.max) {
// //         await auditService.log(req.user?.id || null, 'RATE_LIMIT_EXCEEDED', 'security', null, {
// //           action,
// //           limit: limit.max,
// //           window: limit.window,
// //           currentCount,
// //           ip: req.ip
// //         }, req);
        
// //         return errorResponse(res, `Rate limit exceeded for ${action}`, 429, {
// //           retryAfter: limit.window
// //         });
// //       }

// //       next();

// //     } catch (error) {
// //       console.error('Rate limit validation error:', error);
// //       next(); // Don't block on rate limit errors
// //     }
// //   };
// // };

// // /**
// //  * Password strength validation
// //  */
// // export const validatePasswordStrength = (req, res, next) => {
// //   const { password } = req.body;
  
// //   if (!password) {
// //     return next(); // Skip if no password provided
// //   }

// //   const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  
// //   if (!passwordRegex.test(password)) {
// //     return errorResponse(res, 'Password must be at least 8 characters with uppercase, lowercase, number, and special character', 400);
// //   }

// //   // Check against common passwords
// //   if (isCommonPassword(password)) {
// //     return errorResponse(res, 'Password is too common. Please choose a stronger password', 400);
// //   }

// //   next();
// // };

// // /**
// //  * Email validation and verification
// //  */
// // export const validateEmail = (req, res, next) => {
// //   const { email } = req.body;
  
// //   if (!email) {
// //     return next();
// //   }

// //   const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// //   if (!emailRegex.test(email)) {
// //     return errorResponse(res, 'Invalid email format', 400);
// //   }

// //   // Check for disposable email domains
// //   if (isDisposableEmail(email)) {
// //     return errorResponse(res, 'Disposable email addresses are not allowed', 400);
// //   }

// //   next();
// // };

// // /**
// //  * SQL injection detection
// //  */
// // export const detectSQLInjection = (req, res, next) => {
// //   try {
// //     const sqlPatterns = [
// //       /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)/i,
// //       /(\b(or|and)\b\s+\d+\s*=\s*\d+)/i,
// //       /(['"])\s*;\s*\w+/i,
// //       /\b(script|javascript|vbscript)\b/i
// //     ];

// //     const checkForSQL = (obj, path = '') => {
// //       for (const [key, value] of Object.entries(obj)) {
// //         const currentPath = path ? `${path}.${key}` : key;
        
// //         if (typeof value === 'string') {
// //           for (const pattern of sqlPatterns) {
// //             if (pattern.test(value)) {
// //               return { found: true, path: currentPath, value, pattern: pattern.toString() };
// //             }
// //           }
// //         } else if (typeof value === 'object' && value !== null) {
// //           const result = checkForSQL(value, currentPath);
// //           if (result.found) return result;
// //         }
// //       }
// //       return { found: false };
// //     };

// //     // Check body, query, and params
// //     const sources = ['body', 'query', 'params'];
// //     for (const source of sources) {
// //       if (req[source] && typeof req[source] === 'object') {
// //         const result = checkForSQL(req[source]);
// //         if (result.found) {
// //           // Log SQL injection attempt
// //           await auditService.log(req.user?.id || null, 'SQL_INJECTION_ATTEMPT', 'security', null, {
// //             source,
// //             path: result.path,
// //             pattern: result.pattern,
// //             value: result.value,
// //             ip: req.ip,
// //             userAgent: req.headers['user-agent']
// //           }, req);
          
// //           return errorResponse(res, 'Invalid input detected', 400);
// //         }
// //       }
// //     }

// //     next();

// //   } catch (error) {
// //     console.error('SQL injection detection error:', error);
// //     next(); // Don't block on detection errors
// //   }
// // };

// // /**
// //  * XSS detection and prevention
// //  */
// // export const detectXSS = (req, res, next) => {
// //   try {
// //     const xssPatterns = [
// //       /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
// //       /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
// //       /javascript:/gi,
// //       /on\w+\s*=/gi,
// //       /<\s*\w+\s+on\w+/gi
// //     ];

// //     const checkForXSS = (obj, path = '') => {
// //       for (const [key, value] of Object.entries(obj)) {
// //         const currentPath = path ? `${path}.${key}` : key;
        
// //         if (typeof value === 'string') {
// //           for (const pattern of xssPatterns) {
// //             if (pattern.test(value)) {
// //               return { found: true, path: currentPath, value, pattern: pattern.toString() };
// //             }
// //           }
// //         } else if (typeof value === 'object' && value !== null) {
// //           const result = checkForXSS(value, currentPath);
// //           if (result.found) return result;
// //         }
// //       }
// //       return { found: false };
// //     };

// //     // Check all input sources
// //     const sources = ['body', 'query', 'params'];
// //     for (const source of sources) {
// //       if (req[source] && typeof req[source] === 'object') {
// //         const result = checkForXSS(req[source]);
// //         if (result.found) {
// //           // Log XSS attempt
// //           await auditService.log(req.user?.id || null, 'XSS_ATTEMPT', 'security', null, {
// //             source,
// //             path: result.path,
// //             pattern: result.pattern,
// //             value: result.value,
// //             ip: req.ip,
// //             userAgent: req.headers['user-agent']
// //           }, req);
          
// //           return errorResponse(res, 'Invalid input detected', 400);
// //         }
// //       }
// //     }

// //     next();

// //   } catch (error) {
// //     console.error('XSS detection error:', error);
// //     next(); // Don't block on detection errors
// //   }
// // };

// // // Validation Schemas for common operations

// // export const userValidationSchemas = {
// //   register: Joi.object({
// //     email: Joi.string().email().required(),
// //     password: Joi.string().min(8).required(),
// //     username: Joi.string().alphanum().min(3).max(30).required(),
// //     first_name: Joi.string().min(1).max(50).optional(),
// //     last_name: Joi.string().min(1).max(50).optional(),
// //     terms_accepted: Joi.boolean().valid(true).required()
// //   }),

// //   login: Joi.object({
// //     email: Joi.string().email().required(),
// //     password: Joi.string().required(),
// //     remember_me: Joi.boolean().optional()
// //   }),

// //   updateProfile: Joi.object({
// //     first_name: Joi.string().min(1).max(50).optional(),
// //     last_name: Joi.string().min(1).max(50).optional(),
// //     username: Joi.string().alphanum().min(3).max(30).optional(),
// //     bio: Joi.string().max(500).optional(),
// //     avatar_url: Joi.string().uri().optional(),
// //     preferences: Joi.object().optional()
// //   }),

// //   changePassword: Joi.object({
// //     current_password: Joi.string().required(),
// //     new_password: Joi.string().min(8).required(),
// //     confirm_password: Joi.string().valid(Joi.ref('new_password')).required()
// //   })
// // };

// // export const roleValidationSchemas = {
// //   createRole: Joi.object({
// //     name: Joi.string().min(2).max(50).required(),
// //     category: Joi.string().valid('admin', 'user').required(),
// //     level: Joi.number().integer().min(1).max(100).required(),
// //     permissions: Joi.array().items(Joi.string()).min(1).required(),
// //     description: Joi.string().max(255).optional()
// //   }),

// //   assignRole: Joi.object({
// //     userId: Joi.number().integer().positive().required(),
// //     expiresAt: Joi.date().greater('now').optional()
// //   })
// // };

// // export const subscriptionValidationSchemas = {
// //   createSubscription: Joi.object({
// //     plan_type: Joi.string().valid('pay_as_you_go', 'monthly', '3_month', '6_month', 'yearly').required(),
// //     payment_method: Joi.string().required(),
// //     auto_renew: Joi.boolean().default(false)
// //   }),

// //   updateSubscription: Joi.object({
// //     auto_renew: Joi.boolean().optional(),
// //     plan_type: Joi.string().valid('pay_as_you_go', 'monthly', '3_month', '6_month', 'yearly').optional()
// //   })
// // };

// // // Helper Functions

// // /**
// //  * Sanitize object recursively
// //  */
// // function sanitizeObject(obj) {
// //   if (typeof obj !== 'object' || obj === null) {
// //     return typeof obj === 'string' ? DOMPurify.sanitize(obj) : obj;
// //   }

// //   if (Array.isArray(obj)) {
// //     return obj.map(item => sanitizeObject(item));
// //   }

// //   const sanitized = {};
// //   for (const [key, value] of Object.entries(obj)) {
// //     sanitized[key] = sanitizeObject(value);
// //   }
  
// //   return sanitized;
// // }

// // /**
// //  * Get rate limit configuration for specific action
// //  */
// // function getRateLimitForAction(action) {
// //   const limits = {
// //     login: { max: 5, window: 900 }, // 5 attempts per 15 minutes
// //     register: { max: 3, window: 3600 }, // 3 attempts per hour
// //     password_reset: { max: 3, window: 3600 }, // 3 attempts per hour
// //     api_general: { max: 100, window: 3600 }, // 100 requests per hour
// //     upload: { max: 10, window: 3600 } // 10 uploads per hour
// //   };

// //   return limits[action] || limits.api_general;
// // }

// // /**
// //  * Check current rate limit count
// //  */
// // async function checkRateLimit(key, limit) {
// //   // This would integrate with Redis or similar
// //   // Placeholder implementation
// //   return 0;
// // }

// // /**
// //  * Check if password is commonly used
// //  */
// // function isCommonPassword(password) {
// //   const commonPasswords = [
// //     'password', '123456', '12345678', 'qwerty', 'abc123',
// //     'password123', 'admin', 'letmein', 'welcome', 'monkey'
// //   ];
  
// //   return commonPasswords.includes(password.toLowerCase());
// // }

// // /**
// //  * Check if email domain is disposable
// //  */
// // function isDisposableEmail(email) {
// //   const disposableDomains = [
// //     '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
// //     'mailinator.com', 'throwaway.email'
// //   ];
  
// //   const domain = email.split('@')[1]?.toLowerCase();
// //   return disposableDomains.includes(domain);
// // }