//both codes are same just to solve the error 
import { HTTP_STATUS, MESSAGES, SERVICE_CONFIG } from './constants.js';
import logger from './logger.js';

/**
 * Custom Application Error class for handling errors throughout the application
 */
export class AppError extends Error {
  constructor(message, statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, code = 'APP_ERROR', details = null) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.isOperational = true;
    this.timestamp = new Date().toISOString();
    
    // Capture stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      statusCode: this.statusCode,
      code: this.code,
      details: this.details,
      timestamp: this.timestamp,
      stack: this.stack
    };
  }
}

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

export class ResponseBuilder {
  static success(res, data = null, message = MESSAGES.SUCCESS.OPERATION_COMPLETED, statusCode = HTTP_STATUS.OK, meta = {}) {
    const response = new APIResponse(true, message, data, meta);
    logger.debug('Sending success response', { statusCode, message, hasData: data !== null, meta });
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
    logger.debug('Sending paginated response', { itemCount: data.length, pagination: response.meta.pagination });
    return res.status(HTTP_STATUS.OK).json(response.toJSON());
  }

  static error(res, message = MESSAGES.ERROR.INTERNAL_ERROR, statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, errors = [], meta = {}) {
    const response = new ErrorResponse(message, errors, statusCode, meta);
    logger.error('Sending error response', { statusCode, message, errorId: response.meta.errorId, errorCount: response.errors.length });
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

  // Handle AppError instances
  static fromAppError(res, appError, meta = {}) {
    if (!(appError instanceof AppError)) {
      return this.internalError(res, 'An unexpected error occurred', appError, meta);
    }
    
    const errorDetails = appError.details ? [appError.details] : [];
    return this.error(res, appError.message, appError.statusCode, errorDetails, {
      ...meta,
      errorCode: appError.code,
      timestamp: appError.timestamp
    });
  }
}

// Helper functions for backward compatibility
export const successResponse = (res, data, message = MESSAGES.SUCCESS.OPERATION_COMPLETED, statusCode = HTTP_STATUS.OK, meta = {}) => {
  return ResponseBuilder.success(res, data, message, statusCode, meta);
};

export const errorResponse = (res, message, statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, errors = [], meta = {}) => {
  return ResponseBuilder.error(res, message, statusCode, errors, meta);
};

// Middleware
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
  res.fromAppError = (appError, meta) => ResponseBuilder.fromAppError(res, appError, meta);

  next();
};

// Error handling utilities
export const formatValidationErrors = (validationErrors) => {
  if (!Array.isArray(validationErrors)) return [{ field: 'unknown', message: 'Invalid validation error format' }];
  return validationErrors.map(error => ({
    field: error.field || error.path || 'unknown',
    message: error.message || 'Validation failed',
    code: error.code || 'VALIDATION_ERROR',
    value: error.value || null
  }));
};

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

export const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

export const successWithTiming = (res, data, startTime, message = MESSAGES.SUCCESS.RETRIEVED) => {
  const duration = Date.now() - startTime;
  return ResponseBuilder.success(res, data, message, HTTP_STATUS.OK, { processingTime: `${duration}ms` });
};

export const successWithCache = (res, data, maxAge = 300, message = MESSAGES.SUCCESS.RETRIEVED) => {
  res.set({
    'Cache-Control': `public, max-age=${maxAge}`,
    'ETag': `"${Date.now()}"`,
    'Last-Modified': new Date().toUTCString()
  });
  return ResponseBuilder.success(res, data, message);
};

export const healthResponse = (res, healthData = {}) => {
  const defaultHealth = {
    status: 'healthy',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    timestamp: new Date().toISOString()
  };
  return ResponseBuilder.success(res, { ...defaultHealth, ...healthData }, 'Service is healthy');
};

// Predefined AppError subclasses for common scenarios
export class ValidationError extends AppError {
  constructor(message, details = null) {
    super(message, HTTP_STATUS.UNPROCESSIBLE_ENTITY, 'VALIDATION_ERROR', details);
  }
}

export class AuthenticationError extends AppError {
  constructor(message = 'Authentication failed') {
    super(message, HTTP_STATUS.UNAUTHORIZED, 'AUTHENTICATION_ERROR');
  }
}

export class AuthorizationError extends AppError {
  constructor(message = 'Access denied') {
    super(message, HTTP_STATUS.FORBIDDEN, 'AUTHORIZATION_ERROR');
  }
}

export class NotFoundError extends AppError {
  constructor(resource = 'Resource') {
    super(`${resource} not found`, HTTP_STATUS.NOT_FOUND, 'NOT_FOUND_ERROR');
  }
}

export class ConflictError extends AppError {
  constructor(message = 'Resource conflict') {
    super(message, HTTP_STATUS.CONFLICT, 'CONFLICT_ERROR');
  }
}

export class RateLimitError extends AppError {
  constructor(message = 'Rate limit exceeded') {
    super(message, HTTP_STATUS.TOO_MANY_REQUESTS, 'RATE_LIMIT_ERROR');
  }
}

export class ServiceUnavailableError extends AppError {
  constructor(message = 'Service temporarily unavailable') {
    super(message, HTTP_STATUS.SERVICE_UNAVAILABLE, 'SERVICE_UNAVAILABLE_ERROR');
  }
}


// Default export
export default ResponseBuilder;
// //both codes are same just to solve the error 
// import { HTTP_STATUS, MESSAGES, SERVICE_CONFIG } from './constants.js';
// import logger from './logger.js';

// /**
//  * Custom Application Error class for handling errors throughout the application
//  */
// export class AppError extends Error {
//   constructor(message, statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, code = 'APP_ERROR', details = null) {
//     super(message);
//     this.name = this.constructor.name;
//     this.statusCode = statusCode;
//     this.code = code;
//     this.details = details;
//     this.isOperational = true;
//     this.timestamp = new Date().toISOString();
    
//     // Capture stack trace
//     if (Error.captureStackTrace) {
//       Error.captureStackTrace(this, this.constructor);
//     }
//   }

//   toJSON() {
//     return {
//       name: this.name,
//       message: this.message,
//       statusCode: this.statusCode,
//       code: this.code,
//       details: this.details,
//       timestamp: this.timestamp,
//       stack: this.stack
//     };
//   }
// }

// /**
//  * Standard API response structure
//  */
// export class APIResponse {
//   constructor(success = true, message = '', data = null, meta = {}) {
//     this.success = success;
//     this.message = message;
//     this.data = data;
//     this.meta = {
//       timestamp: new Date().toISOString(),
//       service: SERVICE_CONFIG.NAME,
//       version: SERVICE_CONFIG.VERSION,
//       ...meta
//     };
//   }

//   toJSON() {
//     return {
//       success: this.success,
//       message: this.message,
//       data: this.data,
//       meta: this.meta
//     };
//   }
// }

// export class PaginatedResponse extends APIResponse {
//   constructor(data = [], pagination = {}, message = MESSAGES.SUCCESS.RETRIEVED, meta = {}) {
//     super(true, message, data, meta);
//     this.meta.pagination = {
//       currentPage: pagination.currentPage || 1,
//       totalPages: pagination.totalPages || 1,
//       totalItems: pagination.totalItems || data.length,
//       itemsPerPage: pagination.itemsPerPage || data.length,
//       hasNextPage: pagination.hasNextPage || false,
//       hasPreviousPage: pagination.hasPreviousPage || false,
//       ...pagination
//     };
//   }
// }

// export class ErrorResponse extends APIResponse {
//   constructor(message = MESSAGES.ERROR.INTERNAL_ERROR, errors = [], statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, meta = {}) {
//     super(false, message, null, meta);
//     this.errors = Array.isArray(errors) ? errors : [errors];
//     this.statusCode = statusCode;
//     this.meta.errorId = this.generateErrorId();
//     this.meta.statusCode = statusCode;
//   }

//   generateErrorId() {
//     return `${SERVICE_CONFIG.NAME}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
//   }

//   toJSON() {
//     return {
//       success: this.success,
//       message: this.message,
//       data: this.data,
//       errors: this.errors,
//       meta: this.meta
//     };
//   }
// }

// export class ResponseBuilder {
//   static success(res, data = null, message = MESSAGES.SUCCESS.OPERATION_COMPLETED, statusCode = HTTP_STATUS.OK, meta = {}) {
//     const response = new APIResponse(true, message, data, meta);
//     logger.debug('Sending success response', { statusCode, message, hasData: data !== null, meta });
//     return res.status(statusCode).json(response.toJSON());
//   }

//   static created(res, data, message = MESSAGES.SUCCESS.CREATED, meta = {}) {
//     return this.success(res, data, message, HTTP_STATUS.CREATED, meta);
//   }

//   static updated(res, data, message = MESSAGES.SUCCESS.UPDATED, meta = {}) {
//     return this.success(res, data, message, HTTP_STATUS.OK, meta);
//   }

//   static deleted(res, message = MESSAGES.SUCCESS.DELETED, meta = {}) {
//     return this.success(res, null, message, HTTP_STATUS.NO_CONTENT, meta);
//   }

//   static paginated(res, data, pagination, message = MESSAGES.SUCCESS.RETRIEVED, meta = {}) {
//     const response = new PaginatedResponse(data, pagination, message, meta);
//     logger.debug('Sending paginated response', { itemCount: data.length, pagination: response.meta.pagination });
//     return res.status(HTTP_STATUS.OK).json(response.toJSON());
//   }

//   static error(res, message = MESSAGES.ERROR.INTERNAL_ERROR, statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, errors = [], meta = {}) {
//     const response = new ErrorResponse(message, errors, statusCode, meta);
//     logger.error('Sending error response', { statusCode, message, errorId: response.meta.errorId, errorCount: response.errors.length });
//     return res.status(statusCode).json(response.toJSON());
//   }

//   static validationError(res, errors, message = MESSAGES.ERROR.VALIDATION_FAILED, meta = {}) {
//     return this.error(res, message, HTTP_STATUS.UNPROCESSABLE_ENTITY, errors, meta);
//   }

//   static unauthorized(res, message = MESSAGES.ERROR.UNAUTHORIZED, meta = {}) {
//     return this.error(res, message, HTTP_STATUS.UNAUTHORIZED, [], meta);
//   }

//   static forbidden(res, message = MESSAGES.ERROR.FORBIDDEN, meta = {}) {
//     return this.error(res, message, HTTP_STATUS.FORBIDDEN, [], meta);
//   }

//   static notFound(res, message = MESSAGES.ERROR.NOT_FOUND, meta = {}) {
//     return this.error(res, message, HTTP_STATUS.NOT_FOUND, [], meta);
//   }

//   static conflict(res, message = MESSAGES.ERROR.CONFLICT, meta = {}) {
//     return this.error(res, message, HTTP_STATUS.CONFLICT, [], meta);
//   }

//   static rateLimited(res, message = MESSAGES.ERROR.RATE_LIMIT_EXCEEDED, meta = {}) {
//     return this.error(res, message, HTTP_STATUS.TOO_MANY_REQUESTS, [], meta);
//   }

//   static internalError(res, message = MESSAGES.ERROR.INTERNAL_ERROR, error = null, meta = {}) {
//     if (error instanceof Error) {
//       logger.error('Internal server error', { error: error.message, stack: error.stack }, error);
//     }
//     return this.error(res, message, HTTP_STATUS.INTERNAL_SERVER_ERROR, [], meta);
//   }

//   static serviceUnavailable(res, message = MESSAGES.ERROR.SERVICE_UNAVAILABLE, meta = {}) {
//     return this.error(res, message, HTTP_STATUS.SERVICE_UNAVAILABLE, [], meta);
//   }

//   // Handle AppError instances
//   static fromAppError(res, appError, meta = {}) {
//     if (!(appError instanceof AppError)) {
//       return this.internalError(res, 'An unexpected error occurred', appError, meta);
//     }
    
//     const errorDetails = appError.details ? [appError.details] : [];
//     return this.error(res, appError.message, appError.statusCode, errorDetails, {
//       ...meta,
//       errorCode: appError.code,
//       timestamp: appError.timestamp
//     });
//   }
// }

// // Middleware
// export const responseWrapper = (req, res, next) => {
//   res.success = (data, message, meta) => ResponseBuilder.success(res, data, message, HTTP_STATUS.OK, meta);
//   res.created = (data, message, meta) => ResponseBuilder.created(res, data, message, meta);
//   res.updated = (data, message, meta) => ResponseBuilder.updated(res, data, message, meta);
//   res.deleted = (message, meta) => ResponseBuilder.deleted(res, message, meta);
//   res.paginated = (data, pagination, message, meta) => ResponseBuilder.paginated(res, data, pagination, message, meta);

//   res.error = (message, statusCode, errors, meta) => ResponseBuilder.error(res, message, statusCode, errors, meta);
//   res.validationError = (errors, message, meta) => ResponseBuilder.validationError(res, errors, message, meta);
//   res.unauthorized = (message, meta) => ResponseBuilder.unauthorized(res, message, meta);
//   res.forbidden = (message, meta) => ResponseBuilder.forbidden(res, message, meta);
//   res.notFound = (message, meta) => ResponseBuilder.notFound(res, message, meta);
//   res.conflict = (message, meta) => ResponseBuilder.conflict(res, message, meta);
//   res.rateLimited = (message, meta) => ResponseBuilder.rateLimited(res, message, meta);
//   res.internalError = (message, error, meta) => ResponseBuilder.internalError(res, message, error, meta);
//   res.serviceUnavailable = (message, meta) => ResponseBuilder.serviceUnavailable(res, message, meta);
//   res.fromAppError = (appError, meta) => ResponseBuilder.fromAppError(res, appError, meta);

//   next();
// };

// // Error handling utilities
// export const formatValidationErrors = (validationErrors) => {
//   if (!Array.isArray(validationErrors)) return [{ field: 'unknown', message: 'Invalid validation error format' }];
//   return validationErrors.map(error => ({
//     field: error.field || error.path || 'unknown',
//     message: error.message || 'Validation failed',
//     code: error.code || 'VALIDATION_ERROR',
//     value: error.value || null
//   }));
// };

// export const calculatePagination = (totalItems, currentPage = 1, itemsPerPage = 20) => {
//   const totalPages = Math.ceil(totalItems / itemsPerPage);
//   const hasNextPage = currentPage < totalPages;
//   const hasPreviousPage = currentPage > 1;
//   return {
//     currentPage,
//     totalPages,
//     totalItems,
//     itemsPerPage,
//     hasNextPage,
//     hasPreviousPage,
//     nextPage: hasNextPage ? currentPage + 1 : null,
//     previousPage: hasPreviousPage ? currentPage - 1 : null,
//     startItem: ((currentPage - 1) * itemsPerPage) + 1,
//     endItem: Math.min(currentPage * itemsPerPage, totalItems)
//   };
// };

// export const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// export const successWithTiming = (res, data, startTime, message = MESSAGES.SUCCESS.RETRIEVED) => {
//   const duration = Date.now() - startTime;
//   return ResponseBuilder.success(res, data, message, HTTP_STATUS.OK, { processingTime: `${duration}ms` });
// };

// export const successWithCache = (res, data, maxAge = 300, message = MESSAGES.SUCCESS.RETRIEVED) => {
//   res.set({
//     'Cache-Control': `public, max-age=${maxAge}`,
//     'ETag': `"${Date.now()}"`,
//     'Last-Modified': new Date().toUTCString()
//   });
//   return ResponseBuilder.success(res, data, message);
// };

// export const healthResponse = (res, healthData = {}) => {
//   const defaultHealth = {
//     status: 'healthy',
//     uptime: process.uptime(),
//     memory: process.memoryUsage(),
//     timestamp: new Date().toISOString()
//   };
//   return ResponseBuilder.success(res, { ...defaultHealth, ...healthData }, 'Service is healthy');
// };

// // Predefined AppError subclasses for common scenarios
// export class ValidationError extends AppError {
//   constructor(message, details = null) {
//     super(message, HTTP_STATUS.UNPROCESSABLE_ENTITY, 'VALIDATION_ERROR', details);
//   }
// }

// export class AuthenticationError extends AppError {
//   constructor(message = 'Authentication failed') {
//     super(message, HTTP_STATUS.UNAUTHORIZED, 'AUTHENTICATION_ERROR');
//   }
// }

// export class AuthorizationError extends AppError {
//   constructor(message = 'Access denied') {
//     super(message, HTTP_STATUS.FORBIDDEN, 'AUTHORIZATION_ERROR');
//   }
// }

// export class NotFoundError extends AppError {
//   constructor(resource = 'Resource') {
//     super(`${resource} not found`, HTTP_STATUS.NOT_FOUND, 'NOT_FOUND_ERROR');
//   }
// }

// export class ConflictError extends AppError {
//   constructor(message = 'Resource conflict') {
//     super(message, HTTP_STATUS.CONFLICT, 'CONFLICT_ERROR');
//   }
// }

// export class RateLimitError extends AppError {
//   constructor(message = 'Rate limit exceeded') {
//     super(message, HTTP_STATUS.TOO_MANY_REQUESTS, 'RATE_LIMIT_ERROR');
//   }
// }

// export class ServiceUnavailableError extends AppError {
//   constructor(message = 'Service temporarily unavailable') {
//     super(message, HTTP_STATUS.SERVICE_UNAVAILABLE, 'SERVICE_UNAVAILABLE_ERROR');
//   }
// }

// // Default export
// export default ResponseBuilder;