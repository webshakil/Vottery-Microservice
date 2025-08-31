// src/middleware/securityValidation.js
import { param, query, body, validationResult } from 'express-validator';
import mongoose from 'mongoose';

/**
 * Middleware to handle validation results
 */
export const securityHandleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

/**
 * Validate MongoDB ObjectId in route params
 */
export const securityValidateObjectId = [
  param('userId').optional().custom(value => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid userId'),
  param('keyId').optional().custom(value => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid keyId'),
  param('signatureId').optional().custom(value => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid signatureId'),
  param('deviceId').optional().custom(value => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid deviceId'),
  param('incidentId').optional().custom(value => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid incidentId'),
  param('alertId').optional().custom(value => mongoose.Types.ObjectId.isValid(value)).withMessage('Invalid alertId'),
  securityHandleValidation,
];

/**
 * Pagination query validation
 */
export const securityPagination = [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be an integer >= 1'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  securityHandleValidation,
];

/**
 * Date range query validation
 */
export const securityDateRange = [
  query('startDate').optional().isISO8601().toDate().withMessage('Invalid startDate'),
  query('endDate').optional().isISO8601().toDate().withMessage('Invalid endDate'),
  securityHandleValidation,
];

/**
 * Bulk user IDs validation
 */
export const securityBulkUserIds = [
  body('userIds').isArray({ min: 1 }).withMessage('userIds must be a non-empty array'),
  body('userIds.*').custom(value => mongoose.Types.ObjectId.isValid(value)).withMessage('Each userId must be a valid ObjectId'),
  securityHandleValidation,
];

/**
 * Export options validation
 */
export const securityExportOptions = [
  query('format').optional().isIn(['csv', 'json']).withMessage('Invalid export format'),
  query('includeSensitive').optional().isBoolean().withMessage('includeSensitive must be boolean'),
  securityHandleValidation,
];
