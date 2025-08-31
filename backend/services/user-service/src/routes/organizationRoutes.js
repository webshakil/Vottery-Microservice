// import express from 'express';
// import * as profileController from '../controllers/profileController.js';
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