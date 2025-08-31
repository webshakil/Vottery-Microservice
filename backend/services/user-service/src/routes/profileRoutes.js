// //debug version
// import express from 'express';
// import profileController from '../controllers/profileController.js';
// import { auth } from '../middleware/auth.js';
// import { rbac } from '../middleware/rbac.js';
// import { validation } from '../middleware/validation.js';
// import { rateLimiting } from '../middleware/rateLimiting.js';
// import { auditLog } from '../middleware/auditLog.js';
// import { security } from '../middleware/security.js';

// const router = express.Router();

// // Debug function to validate middleware
// const validateMiddleware = (middleware, name) => {
//   if (typeof middleware !== 'function') {
//     console.error(`❌ ${name} is not a function:`, typeof middleware);
//     return (req, res, next) => next(); // Return a dummy middleware
//   }
//   console.log(`✅ ${name} is valid`);
//   return middleware;
// };

// // Debug function to validate nested middleware
// const validateNestedMiddleware = (middlewareObj, objName) => {
//   const validated = {};
//   for (const [key, value] of Object.entries(middlewareObj)) {
//     if (typeof value !== 'function') {
//       console.error(`❌ ${objName}.${key} is not a function:`, typeof value);
//       validated[key] = (req, res, next) => next(); // Return dummy middleware
//     } else {
//       console.log(`✅ ${objName}.${key} is valid`);
//       validated[key] = value;
//     }
//   }
//   return validated;
// };

// // Debug controller methods
// console.log('🔍 Debugging profileController methods:');
// const controllerMethods = [
//   'getCurrentProfile', 'createProfile', 'updateCurrentProfile', 'deleteAvatar',
//   'updatePreferences', 'updateDemographics', 'updateVisibility', 'getProfileCompletion',
//   'exportProfile', 'deleteProfileData', 'getPublicProfile', 'searchPublicProfiles',
//   'getAllProfiles', 'getProfileByUserId', 'adminUpdateProfile', 'adminDeleteProfile',
//   'getProfileAnalytics', 'getDemographicsAnalytics', 'getCompletionAnalytics', 'getAvatarAnalytics',
//   'exportProfiles', 'bulkUpdateVisibility', 'bulkVerifyProfiles', 'bulkUnverifyProfiles',
//   'moderateProfile', 'reportProfile', 'getPendingReports'
// ];

// controllerMethods.forEach(method => {
//   if (typeof profileController[method] !== 'function') {
//     console.error(`❌ profileController.${method} is not a function:`, typeof profileController[method]);
//   } else {
//     console.log(`✅ profileController.${method} is valid`);
//   }
// });

// // Debug middleware objects
// console.log('🔍 Debugging middleware objects:');
// const validatedAuth = validateNestedMiddleware(auth, 'auth');
// const validatedRbac = validateNestedMiddleware(rbac, 'rbac');
// const validatedValidation = validateNestedMiddleware(validation, 'validation');
// const validatedRateLimiting = validateNestedMiddleware(rateLimiting, 'rateLimiting');
// const validatedAuditLog = validateNestedMiddleware(auditLog, 'auditLog');
// const validatedSecurity = validateNestedMiddleware(security, 'security');

// // Apply security middleware to all routes
// router.use(validatedSecurity.sanitizeInput || ((req, res, next) => next()));
// router.use(validatedSecurity.preventXSS || ((req, res, next) => next()));

// // All profile routes require authentication
// router.use(validatedAuth.verifyToken || ((req, res, next) => next()));

// // Get current user's profile
// router.get('/me', 
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.getCurrentProfile || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Create/Update current user's profile
// router.post('/me', 
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.createProfile || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.createProfile || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// router.patch('/me', 
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.updateProfile || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.updateCurrentProfile || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Upload avatar
// router.post('/me/avatar', 
//   validatedRateLimiting.uploadLimit || ((req, res, next) => next()),
//   validatedValidation.avatarUpload || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.uploadAvatar || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Delete avatar
// router.delete('/me/avatar', 
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.deleteAvatar || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Update profile preferences
// router.patch('/me/preferences', 
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.profilePreferences || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.updatePreferences || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Update demographics
// router.patch('/me/demographics', 
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.demographics || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.updateDemographics || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Profile visibility settings
// router.patch('/me/visibility', 
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.visibilitySettings || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.updateVisibility || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Get profile completion status
// router.get('/me/completion', 
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.getProfileCompletion || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Export profile data
// router.get('/me/export', 
//   validatedRateLimiting.strict || ((req, res, next) => next()),
//   validatedValidation.exportFormat || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.exportProfile || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Delete all profile data
// router.delete('/me/data', 
//   validatedRateLimiting.strict || ((req, res, next) => next()),
//   validatedValidation.deleteConfirmation || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.deleteProfileData || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Public profile routes (no permission required)
// router.get('/public/:userId', 
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.validateObjectId || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.getPublicProfile || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Search public profiles
// router.get('/search/public', 
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.profileSearchQuery || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.searchPublicProfiles || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Admin-only routes
// router.use(validatedRbac.requirePermission ? 
//   validatedRbac.requirePermission('users:view') : 
//   ((req, res, next) => next())
// );

// // Get all profiles (admin)
// router.get('/', 
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.pagination || ((req, res, next) => next()),
//   validatedValidation.profileFilters || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.getAllProfiles || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Get profile by user ID (admin)
// router.get('/:userId', 
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.validateObjectId || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.getProfileByUserId || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Admin update profile
// router.patch('/:userId', 
//   validatedRbac.requirePermission ? 
//     validatedRbac.requirePermission('users:edit') : 
//     ((req, res, next) => next()),
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.validateObjectId || ((req, res, next) => next()),
//   validatedValidation.adminUpdateProfile || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.adminUpdateProfile || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Delete profile (admin only)
// router.delete('/:userId', 
//   validatedRbac.requirePermission ? 
//     validatedRbac.requirePermission('users:delete') : 
//     ((req, res, next) => next()),
//   validatedRateLimiting.strict || ((req, res, next) => next()),
//   validatedValidation.validateObjectId || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.adminDeleteProfile || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Profile analytics
// router.get('/analytics/overview', 
//   validatedRbac.requirePermission ? 
//     validatedRbac.requirePermission('analytics:view') : 
//     ((req, res, next) => next()),
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.dateRange || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.getProfileAnalytics || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Demographics analytics
// router.get('/analytics/demographics', 
//   validatedRbac.requirePermission ? 
//     validatedRbac.requirePermission('analytics:view') : 
//     ((req, res, next) => next()),
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.dateRange || ((req, res, next) => next()),
//   validatedValidation.demographicFilters || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.getDemographicsAnalytics || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Profile completion analytics
// router.get('/analytics/completion', 
//   validatedRbac.requirePermission ? 
//     validatedRbac.requirePermission('analytics:view') : 
//     ((req, res, next) => next()),
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.dateRange || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.getCompletionAnalytics || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Avatar usage analytics
// router.get('/analytics/avatars', 
//   validatedRbac.requirePermission ? 
//     validatedRbac.requirePermission('analytics:view') : 
//     ((req, res, next) => next()),
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.dateRange || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.getAvatarAnalytics || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Export profiles data
// router.get('/export/csv', 
//   validatedRbac.requirePermission ? 
//     validatedRbac.requirePermission('analytics:export') : 
//     ((req, res, next) => next()),
//   validatedRateLimiting.strict || ((req, res, next) => next()),
//   validatedValidation.exportOptions || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.exportProfiles || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Bulk profile operations
// router.post('/bulk/update-visibility', 
//   validatedRbac.requirePermission ? 
//     validatedRbac.requirePermission('users:edit') : 
//     ((req, res, next) => next()),
//   validatedRateLimiting.strict || ((req, res, next) => next()),
//   validatedValidation.bulkVisibilityUpdate || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.bulkUpdateVisibility || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// router.post('/bulk/verify', 
//   validatedRbac.requirePermission ? 
//     validatedRbac.requirePermission('users:edit') : 
//     ((req, res, next) => next()),
//   validatedRateLimiting.strict || ((req, res, next) => next()),
//   validatedValidation.bulkUserIds || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.bulkVerifyProfiles || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// router.post('/bulk/unverify', 
//   validatedRbac.requirePermission ? 
//     validatedRbac.requirePermission('users:edit') : 
//     ((req, res, next) => next()),
//   validatedRateLimiting.strict || ((req, res, next) => next()),
//   validatedValidation.bulkUserIds || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.bulkUnverifyProfiles || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Profile moderation
// router.post('/moderate/:userId', 
//   validatedRbac.requirePermission ? 
//     validatedRbac.requirePermission('users:moderate') : 
//     ((req, res, next) => next()),
//   validatedRateLimiting.strict || ((req, res, next) => next()),
//   validatedValidation.validateObjectId || ((req, res, next) => next()),
//   validatedValidation.moderationAction || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.moderateProfile || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Profile reporting
// router.post('/report/:userId', 
//   validatedRateLimiting.strict || ((req, res, next) => next()),
//   validatedValidation.validateObjectId || ((req, res, next) => next()),
//   validatedValidation.reportReason || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.reportProfile || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// // Get reported profiles
// router.get('/reports/pending', 
//   validatedRbac.requirePermission ? 
//     validatedRbac.requirePermission('users:moderate') : 
//     ((req, res, next) => next()),
//   validatedRateLimiting.standard || ((req, res, next) => next()),
//   validatedValidation.pagination || ((req, res, next) => next()),
//   validatedAuditLog.logActivity || ((req, res, next) => next()),
//   profileController.getPendingReports || ((req, res) => res.status(501).json({ error: 'Method not implemented' }))
// );

// console.log('✅ All routes configured successfully');

// export default router;


//removing validation
import express from 'express';
import profileController from '../controllers/profileController.js';
import { auth } from '../middleware/auth.js';
import { rbac } from '../middleware/rbac.js';
import { rateLimiting } from '../middleware/rateLimiting.js';
import { auditLog } from '../middleware/auditLog.js';
import { security } from '../middleware/security.js';

const router = express.Router();

// Simple validation middleware as fallback
const simpleValidation = {
  pagination: (req, res, next) => next(),
  validateObjectId: (req, res, next) => next(),
  createProfile: (req, res, next) => next(),
  updateProfile: (req, res, next) => next(),
  avatarUpload: (req, res, next) => next(),
  profilePreferences: (req, res, next) => next(),
  demographics: (req, res, next) => next(),
  visibilitySettings: (req, res, next) => next(),
  exportFormat: (req, res, next) => next(),
  deleteConfirmation: (req, res, next) => next(),
  profileSearchQuery: (req, res, next) => next(),
  profileFilters: (req, res, next) => next(),
  adminUpdateProfile: (req, res, next) => next(),
  dateRange: (req, res, next) => next(),
  demographicFilters: (req, res, next) => next(),
  exportOptions: (req, res, next) => next(),
  bulkVisibilityUpdate: (req, res, next) => next(),
  bulkUserIds: (req, res, next) => next(),
  moderationAction: (req, res, next) => next(),
  reportReason: (req, res, next) => next()
};

// Apply security middleware to all routes
router.use(security.sanitizeInput);
router.use(security.preventXSS);

// All profile routes require authentication
router.use(auth.verifyToken);

// Get current user's profile
router.get('/me', 
  rateLimiting.standard,
  auditLog.logActivity,
  profileController.getCurrentProfile
);

// Create/Update current user's profile
router.post('/me', 
  rateLimiting.standard,
  simpleValidation.createProfile,
  auditLog.logActivity,
  profileController.createProfile
);

router.patch('/me', 
  rateLimiting.standard,
  simpleValidation.updateProfile,
  auditLog.logActivity,
  profileController.updateCurrentProfile
);

// Upload avatar
router.post('/me/avatar', 
  rateLimiting.upload,
  simpleValidation.avatarUpload,
  auditLog.logActivity,
  profileController.uploadAvatar
);

// Delete avatar
router.delete('/me/avatar', 
  rateLimiting.standard,
  auditLog.logActivity,
  profileController.deleteAvatar
);

// Update profile preferences
router.patch('/me/preferences', 
  rateLimiting.standard,
  simpleValidation.profilePreferences,
  auditLog.logActivity,
  profileController.updatePreferences
);

// Update demographics
router.patch('/me/demographics', 
  rateLimiting.standard,
  simpleValidation.demographics,
  auditLog.logActivity,
  profileController.updateDemographics
);

// Profile visibility settings
router.patch('/me/visibility', 
  rateLimiting.standard,
  simpleValidation.visibilitySettings,
  auditLog.logActivity,
  profileController.updateVisibility
);

// Get profile completion status
router.get('/me/completion', 
  rateLimiting.standard,
  auditLog.logActivity,
  profileController.getProfileCompletion
);

// Export profile data
router.get('/me/export', 
  rateLimiting.strict,
  simpleValidation.exportFormat,
  auditLog.logActivity,
  profileController.exportProfile
);

// Delete all profile data
router.delete('/me/data', 
  rateLimiting.strict,
  simpleValidation.deleteConfirmation,
  auditLog.logActivity,
  profileController.deleteProfileData
);

// Public profile routes (no permission required)
router.get('/public/:userId', 
  rateLimiting.standard,
  simpleValidation.validateObjectId,
  auditLog.logActivity,
  profileController.getPublicProfile
);

// Search public profiles
router.get('/search/public', 
  rateLimiting.standard,
  simpleValidation.profileSearchQuery,
  auditLog.logActivity,
  profileController.searchPublicProfiles
);

// Admin-only routes
router.use(rbac.requirePermission('users:view'));

// Get all profiles (admin)
router.get('/', 
  rateLimiting.standard,
  simpleValidation.pagination,
  simpleValidation.profileFilters,
  auditLog.logActivity,
  profileController.getAllProfiles
);

// Get profile by user ID (admin)
router.get('/:userId', 
  rateLimiting.standard,
  simpleValidation.validateObjectId,
  auditLog.logActivity,
  profileController.getProfileByUserId
);

// Admin update profile
router.patch('/:userId', 
  rbac.requirePermission('users:edit'),
  rateLimiting.standard,
  simpleValidation.validateObjectId,
  simpleValidation.adminUpdateProfile,
  auditLog.logActivity,
  profileController.adminUpdateProfile
);

// Delete profile (admin only)
router.delete('/:userId', 
  rbac.requirePermission('users:delete'),
  rateLimiting.strict,
  simpleValidation.validateObjectId,
  auditLog.logActivity,
  profileController.adminDeleteProfile
);

// Profile analytics
router.get('/analytics/overview', 
  rbac.requirePermission('analytics:view'),
  rateLimiting.standard,
  simpleValidation.dateRange,
  auditLog.logActivity,
  profileController.getProfileAnalytics
);

// Demographics analytics
router.get('/analytics/demographics', 
  rbac.requirePermission('analytics:view'),
  rateLimiting.standard,
  simpleValidation.dateRange,
  simpleValidation.demographicFilters,
  auditLog.logActivity,
  profileController.getDemographicsAnalytics
);

// Profile completion analytics
router.get('/analytics/completion', 
  rbac.requirePermission('analytics:view'),
  rateLimiting.standard,
  simpleValidation.dateRange,
  auditLog.logActivity,
  profileController.getCompletionAnalytics
);

// Avatar usage analytics
router.get('/analytics/avatars', 
  rbac.requirePermission('analytics:view'),
  rateLimiting.standard,
  simpleValidation.dateRange,
  auditLog.logActivity,
  profileController.getAvatarAnalytics
);

// Export profiles data
router.get('/export/csv', 
  rbac.requirePermission('analytics:export'),
  rateLimiting.strict,
  simpleValidation.exportOptions,
  auditLog.logActivity,
  profileController.exportProfiles
);

// Bulk profile operations
router.post('/bulk/update-visibility', 
  rbac.requirePermission('users:edit'),
  rateLimiting.strict,
  simpleValidation.bulkVisibilityUpdate,
  auditLog.logActivity,
  profileController.bulkUpdateVisibility
);

router.post('/bulk/verify', 
  rbac.requirePermission('users:edit'),
  rateLimiting.strict,
  simpleValidation.bulkUserIds,
  auditLog.logActivity,
  profileController.bulkVerifyProfiles
);

router.post('/bulk/unverify', 
  rbac.requirePermission('users:edit'),
  rateLimiting.strict,
  simpleValidation.bulkUserIds,
  auditLog.logActivity,
  profileController.bulkUnverifyProfiles
);

// Profile moderation
router.post('/moderate/:userId', 
  rbac.requirePermission('users:moderate'),
  rateLimiting.strict,
  simpleValidation.validateObjectId,
  simpleValidation.moderationAction,
  auditLog.logActivity,
  profileController.moderateProfile
);

// Profile reporting
router.post('/report/:userId', 
  rateLimiting.strict,
  simpleValidation.validateObjectId,
  simpleValidation.reportReason,
  auditLog.logActivity,
  profileController.reportProfile
);

// Get reported profiles
router.get('/reports/pending', 
  rbac.requirePermission('users:moderate'),
  rateLimiting.standard,
  simpleValidation.pagination,
  auditLog.logActivity,
  profileController.getPendingReports
);

export default router;

//latest
// import express from 'express';
// import profileController from '../controllers/profileController.js';
// import { auth } from '../middleware/auth.js';
// import { rbac } from '../middleware/rbac.js';
// import { validation } from '../middleware/validation.js';
// import { rateLimiting } from '../middleware/rateLimiting.js';
// import { auditLog } from '../middleware/auditLog.js';
// import { security } from '../middleware/security.js';

// const router = express.Router();

// // Apply security middleware to all routes
// router.use(security.sanitizeInput);
// router.use(security.preventXSS);

// // All profile routes require authentication
// router.use(auth.verifyToken);

// // Get current user's profile
// router.get('/me', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   profileController.getCurrentProfile
// );

// // Create/Update current user's profile
// router.post('/me', 
//   rateLimiting.standard,
//   validation.createProfile,
//   auditLog.logActivity,
//   profileController.createProfile
// );

// router.patch('/me', 
//   rateLimiting.standard,
//   validation.updateProfile,
//   auditLog.logActivity,
//   profileController.updateCurrentProfile
// );

// // Upload avatar
// router.post('/me/avatar', 
//   rateLimiting.uploadLimit,
//   validation.avatarUpload,
//   auditLog.logActivity,
//   profileController.uploadAvatar
// );

// // Delete avatar
// router.delete('/me/avatar', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   profileController.deleteAvatar
// );

// // Update profile preferences
// router.patch('/me/preferences', 
//   rateLimiting.standard,
//   validation.profilePreferences,
//   auditLog.logActivity,
//   profileController.updatePreferences
// );

// // Update demographics
// router.patch('/me/demographics', 
//   rateLimiting.standard,
//   validation.demographics,
//   auditLog.logActivity,
//   profileController.updateDemographics
// );

// // Profile visibility settings
// router.patch('/me/visibility', 
//   rateLimiting.standard,
//   validation.visibilitySettings,
//   auditLog.logActivity,
//   profileController.updateVisibility
// );

// // Get profile completion status
// router.get('/me/completion', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   profileController.getProfileCompletion
// );

// // Export profile data
// router.get('/me/export', 
//   rateLimiting.strict,
//   validation.exportFormat,
//   auditLog.logActivity,
//   profileController.exportProfile
// );

// // Delete all profile data
// router.delete('/me/data', 
//   rateLimiting.strict,
//   validation.deleteConfirmation,
//   auditLog.logActivity,
//   profileController.deleteProfileData
// );

// // Public profile routes (no permission required)
// router.get('/public/:userId', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   profileController.getPublicProfile
// );

// // Search public profiles
// router.get('/search/public', 
//   rateLimiting.standard,
//   validation.profileSearchQuery,
//   auditLog.logActivity,
//   profileController.searchPublicProfiles
// );

// // Admin-only routes
// router.use(rbac.requirePermission('users:view'));

// // Get all profiles (admin)
// router.get('/', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.profileFilters,
//   auditLog.logActivity,
//   profileController.getAllProfiles
// );

// // Get profile by user ID (admin)
// router.get('/:userId', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   profileController.getProfileByUserId
// );

// // Admin update profile
// router.patch('/:userId', 
//   rbac.requirePermission('users:edit'),
//   rateLimiting.standard,
//   validation.validateObjectId,
//   validation.adminUpdateProfile,
//   auditLog.logActivity,
//   profileController.adminUpdateProfile
// );

// // Delete profile (admin only)
// router.delete('/:userId', 
//   rbac.requirePermission('users:delete'),
//   rateLimiting.strict,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   profileController.adminDeleteProfile
// );

// // Profile analytics
// router.get('/analytics/overview', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   profileController.getProfileAnalytics
// );

// // Demographics analytics
// router.get('/analytics/demographics', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   validation.dateRange,
//   validation.demographicFilters,
//   auditLog.logActivity,
//   profileController.getDemographicsAnalytics
// );

// // Profile completion analytics
// router.get('/analytics/completion', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   profileController.getCompletionAnalytics
// );

// // Avatar usage analytics
// router.get('/analytics/avatars', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   profileController.getAvatarAnalytics
// );

// // Export profiles data
// router.get('/export/csv', 
//   rbac.requirePermission('analytics:export'),
//   rateLimiting.strict,
//   validation.exportOptions,
//   auditLog.logActivity,
//   profileController.exportProfiles
// );

// // Bulk profile operations
// router.post('/bulk/update-visibility', 
//   rbac.requirePermission('users:edit'),
//   rateLimiting.strict,
//   validation.bulkVisibilityUpdate,
//   auditLog.logActivity,
//   profileController.bulkUpdateVisibility
// );

// router.post('/bulk/verify', 
//   rbac.requirePermission('users:edit'),
//   rateLimiting.strict,
//   validation.bulkUserIds,
//   auditLog.logActivity,
//   profileController.bulkVerifyProfiles
// );

// router.post('/bulk/unverify', 
//   rbac.requirePermission('users:edit'),
//   rateLimiting.strict,
//   validation.bulkUserIds,
//   auditLog.logActivity,
//   profileController.bulkUnverifyProfiles
// );

// // Profile moderation
// router.post('/moderate/:userId', 
//   rbac.requirePermission('users:moderate'),
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.moderationAction,
//   auditLog.logActivity,
//   profileController.moderateProfile
// );

// // Profile reporting
// router.post('/report/:userId', 
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.reportReason,
//   auditLog.logActivity,
//   profileController.reportProfile
// );

// // Get reported profiles
// router.get('/reports/pending', 
//   rbac.requirePermission('users:moderate'),
//   rateLimiting.standard,
//   validation.pagination,
//   auditLog.logActivity,
//   profileController.getPendingReports
// );

// export default router;