import express from 'express';
import userController from '../controllers/userController.js';
import { auth } from '../middleware/auth.js';
import { rbac } from '../middleware/rbac.js';
import { validation } from '../middleware/validation.js';
import { rateLimiting } from '../middleware/rateLimiting.js';
import { auditLogger } from '../middleware/auditLog.js';
import security from '../middleware/security.js';

const router = express.Router();

// Apply security middleware to all routes
if (security?.sanitizeInput) {
  router.use(security.sanitizeInput);
}
if (security?.preventXSS) {
  router.use(security.preventXSS);
}

// Public routes (no authentication required)
router.get('/check-username/:username', 
  rateLimiting.strict,
  ...validation.checkUsername,
  userController.checkUsernameAvailability
);

router.get('/check-email/:email', 
  rateLimiting.strict,
  ...validation.checkEmail,
  userController.checkEmailAvailability
);

// Protected routes (authentication required)
router.use(auth.verifyToken);

// Current user routes
router.get('/me', 
  rateLimiting.standard,
  auditLogger(),
  userController.getCurrentUser
);

router.patch('/me', 
  rateLimiting.standard,
  ...validation.updateUser,
  auditLogger(),
  userController.updateCurrentUser
);

router.delete('/me', 
  rateLimiting.strict,
  auditLogger(),
  userController.deleteCurrentUser
);

router.patch('/me/password', 
  rateLimiting.strict,
  ...validation.changePassword,
  auditLogger(),
  userController.changePassword
);

router.patch('/me/2fa', 
  rateLimiting.standard,
  ...validation.toggle2FA,
  auditLogger(),
  userController.toggle2FA
);

router.get('/me/activity', 
  rateLimiting.standard,
  ...validation.pagination,
  auditLogger(),
  userController.getUserActivity
);

router.get('/me/sessions', 
  rateLimiting.standard,
  auditLogger(),
  userController.getUserSessions
);

router.delete('/me/sessions/:sessionId', 
  rateLimiting.standard,
  ...validation.validateObjectId,
  auditLogger(),
  userController.revokeSession
);

router.delete('/me/sessions', 
  rateLimiting.strict,
  auditLogger(),
  userController.revokeAllSessions
);

// Admin-only routes - User management
router.use(rbac.requirePermission('users:view'));

router.get('/', 
  rateLimiting.standard,
  ...validation.pagination,
  ...validation.userFilters,
  auditLogger(),
  userController.getAllUsers
);

router.get('/search/query', 
  rateLimiting.standard,
  ...validation.searchQuery,
  auditLogger(),
  userController.searchUsers
);

router.post('/filter/advanced', 
  rateLimiting.standard,
  ...validation.advancedFilters,
  auditLogger(),
  userController.advancedUserFilter
);

router.get('/stats/overview', 
  rbac.requirePermission('analytics:view'),
  rateLimiting.standard,
  auditLogger(),
  userController.getUserStats
);

router.get('/stats/demographics', 
  rbac.requirePermission('analytics:view'),
  rateLimiting.standard,
  ...validation.dateRange,
  auditLogger(),
  userController.getUserDemographics
);

router.get('/export/csv', 
  rbac.requirePermission('analytics:export'),
  rateLimiting.strict,
  ...validation.exportOptions,
  auditLogger(),
  userController.exportUsers
);

// Individual user management
router.get('/:userId', 
  rateLimiting.standard,
  ...validation.validateObjectId,
  auditLogger(),
  userController.getUserById
);

router.patch('/:userId', 
  rbac.requirePermission('users:edit'),
  rateLimiting.standard,
  ...validation.validateObjectId,
  ...validation.adminUpdateUser,
  auditLogger(),
  userController.adminUpdateUser
);

router.patch('/:userId/suspension', 
  rbac.requirePermission('users:suspend'),
  rateLimiting.strict,
  ...validation.validateObjectId,
  ...validation.userSuspension,
  auditLogger(),
  userController.toggleUserSuspension
);

router.delete('/:userId', 
  rbac.requirePermission('users:delete'),
  rateLimiting.strict,
  ...validation.validateObjectId,
  auditLogger(),
  userController.adminDeleteUser
);

// Bulk user operations
router.post('/bulk/suspend', 
  rbac.requirePermission('users:suspend'),
  rateLimiting.strict,
  ...validation.bulkUserIds,
  auditLogger(),
  userController.bulkSuspendUsers
);

router.post('/bulk/unsuspend', 
  rbac.requirePermission('users:suspend'),
  rateLimiting.strict,
  ...validation.bulkUserIds,
  auditLogger(),
  userController.bulkUnsuspendUsers
);

router.post('/bulk/delete', 
  rbac.requirePermission('users:delete'),
  rateLimiting.strict,
  ...validation.bulkUserIds,
  auditLogger(),
  userController.bulkDeleteUsers
);

export default router;
// import express from 'express';
// import * as userController from '../controllers/userController.js';
// import { auth } from '../middleware/auth.js';
// import { rbac } from '../middleware/rbac.js';
// import { validation } from '../middleware/validation.js';

// import { rateLimiting } from '../middleware/rateLimiting.js';
// import { auditLogger } from '../middleware/auditLog.js';
// import security from '../middleware/security.js';

// const router = express.Router();

// // Verify all middleware imports before using them
// const middlewareCheck = () => {
//   const requiredMiddleware = {
//     'security.sanitizeInput': security?.sanitizeInput,
//     'security.preventXSS': security?.preventXSS,
//     'auth.verifyToken': auth?.verifyToken,
//     'rateLimiting.strict': rateLimiting?.strict,
//     'rateLimiting.standard': rateLimiting?.standard,
//     'validation.checkUsername': validation?.checkUsername,
//     'validation.checkEmail': validation?.checkEmail,
//     'rbac.requirePermission': rbac?.requirePermission
//   };

//   for (const [name, middleware] of Object.entries(requiredMiddleware)) {
//     // Handle both array-based and single function middleware
//     const isValid = middleware && (
//       typeof middleware === 'function' || 
//       (Array.isArray(middleware) && middleware.length > 0)
//     );
    
//     if (!isValid) {
//       throw new Error(`Missing or invalid middleware: ${name}`);
//     }
//   }
// };

// // Perform middleware check
// try {
//   middlewareCheck();
// } catch (error) {
//   console.error('Middleware validation failed:', error.message);
//   process.exit(1);
// }

// // Apply security middleware to all routes (only if they exist)
// if (security?.sanitizeInput) {
//   router.use(security.sanitizeInput);
// }
// if (security?.preventXSS) {
//   router.use(security.preventXSS);
// }

// // Public routes (no authentication required)
// router.get('/check-username/:username', 
//   rateLimiting.strict,
//   ...validation.checkUsername, // Spread the array of middleware
//   userController.checkUsernameAvailability
// );

// router.get('/check-email/:email', 
//   rateLimiting.strict,
//   ...validation.checkEmail, // Spread the array of middleware
//   userController.checkEmailAvailability
// );

// // Protected routes (authentication required)
// router.use(auth.verifyToken);

// // Get current user info
// router.get('/me', 
//   rateLimiting.standard,
//   auditLogger(),
//   userController.getCurrentUser
// );

// // Update current user basic info
// router.patch('/me', 
//   rateLimiting.standard,
//   ...validation.updateUser, // Spread the array
//   auditLogger(),
//   userController.updateCurrentUser
// );

// // Delete current user account
// router.delete('/me', 
//   rateLimiting.strict,
//   auditLogger(),
//   userController.deleteCurrentUser
// );

// // Change password
// router.patch('/me/password', 
//   rateLimiting.strict,
//   ...validation.changePassword, // Spread the array
//   auditLogger(),
//   userController.changePassword
// );

// // Enable/disable 2FA
// router.patch('/me/2fa', 
//   rateLimiting.standard,
//   ...validation.toggle2FA, // Spread the array
//   auditLogger(),
//   userController.toggle2FA
// );

// // Get user activity logs
// router.get('/me/activity', 
//   rateLimiting.standard,
//   ...validation.pagination, // Spread the array
//   auditLogger(),
//   userController.getUserActivity
// );

// // Get user sessions
// router.get('/me/sessions', 
//   rateLimiting.standard,
//   auditLogger(),
//   userController.getUserSessions
// );

// // Revoke specific session
// router.delete('/me/sessions/:sessionId', 
//   rateLimiting.standard,
//   ...validation.validateObjectId, // Spread the array
//   auditLogger(),
//   userController.revokeSession
// );

// // Revoke all sessions except current
// router.delete('/me/sessions', 
//   rateLimiting.strict,
//   auditLogger(),
//   userController.revokeAllSessions
// );

// // Admin-only routes
// router.use(rbac.requirePermission('users:view'));

// // Get all users (paginated)
// router.get('/', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   ...validation.userFilters,
//   auditLogger(),
//   userController.getAllUsers
// );

// // Get user by ID
// router.get('/:userId', 
//   rateLimiting.standard,
//   ...validation.validateObjectId,
//   auditLogger(),
//   userController.getUserById
// );

// // Admin update user
// router.patch('/:userId', 
//   rbac.requirePermission('users:edit'),
//   rateLimiting.standard,
//   ...validation.validateObjectId,
//   ...validation.adminUpdateUser,
//   auditLogger(),
//   userController.adminUpdateUser
// );

// // Suspend/unsuspend user
// router.patch('/:userId/suspension', 
//   rbac.requirePermission('users:suspend'),
//   rateLimiting.strict,
//   ...validation.validateObjectId,
//   ...validation.userSuspension,
//   auditLogger(),
//   userController.toggleUserSuspension
// );

// // Delete user (admin only)
// router.delete('/:userId', 
//   rbac.requirePermission('users:delete'),
//   rateLimiting.strict,
//   ...validation.validateObjectId,
//   auditLogger(),
//   userController.adminDeleteUser
// );

// // Get user statistics
// router.get('/stats/overview', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   auditLogger(),
//   userController.getUserStats
// );

// // Get user demographics
// router.get('/stats/demographics', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   ...validation.dateRange,
//   auditLogger(),
//   userController.getUserDemographics
// );

// // Export user data
// router.get('/export/csv', 
//   rbac.requirePermission('analytics:export'),
//   rateLimiting.strict,
//   ...validation.exportOptions,
//   auditLogger(),
//   userController.exportUsers
// );

// // Bulk user operations
// router.post('/bulk/suspend', 
//   rbac.requirePermission('users:suspend'),
//   rateLimiting.strict,
//   ...validation.bulkUserIds,
//   auditLogger(),
//   userController.bulkSuspendUsers
// );

// router.post('/bulk/unsuspend', 
//   rbac.requirePermission('users:suspend'),
//   rateLimiting.strict,
//   ...validation.bulkUserIds,
//   auditLogger(),
//   userController.bulkUnsuspendUsers
// );

// router.post('/bulk/delete', 
//   rbac.requirePermission('users:delete'),
//   rateLimiting.strict,
//   ...validation.bulkUserIds,
//   auditLogger(),
//   userController.bulkDeleteUsers
// );

// // Search users
// router.get('/search/query', 
//   rateLimiting.standard,
//   ...validation.searchQuery,
//   auditLogger(),
//   userController.searchUsers
// );

// // Advanced user filtering
// router.post('/filter/advanced', 
//   rateLimiting.standard,
//   ...validation.advancedFilters,
//   auditLogger(),
//   userController.advancedUserFilter
// );

// export default router;




// import express from 'express';
// import * as userController from '../controllers/userController.js';
// import { auth } from '../middleware/auth.js';
// import { rbac } from '../middleware/rbac.js';
// import { validation } from '../middleware/validation.js';

// import { rateLimiting } from '../middleware/rateLimiting.js';
// import { auditLogger } from '../middleware/auditLog.js';
// import security from '../middleware/security.js';

// const router = express.Router();

// // Verify all middleware imports before using them
// const middlewareCheck = () => {
//   const requiredMiddleware = {
//     'security.sanitizeInput': security?.sanitizeInput,
//     'security.preventXSS': security?.preventXSS,
//     'auth.verifyToken': auth?.verifyToken,
//     'rateLimiting.strict': rateLimiting?.strict,
//     'rateLimiting.standard': rateLimiting?.standard,
//     'validation.checkUsername': validation?.checkUsername,
//     'validation.checkEmail': validation?.checkEmail,
//     'rbac.requirePermission': rbac?.requirePermission
//   };

//   for (const [name, middleware] of Object.entries(requiredMiddleware)) {
//     if (!middleware || typeof middleware !== 'function') {
//       throw new Error(`Missing or invalid middleware: ${name}`);
//     }
//   }
// };

// // Perform middleware check
// try {
//   middlewareCheck();
// } catch (error) {
//   console.error('Middleware validation failed:', error.message);
//   process.exit(1);
// }

// // Apply security middleware to all routes (only if they exist)
// if (security?.sanitizeInput) {
//   router.use(security.sanitizeInput);
// }
// if (security?.preventXSS) {
//   router.use(security.preventXSS);
// }

// // Public routes (no authentication required)
// router.get('/check-username/:username', 
//   rateLimiting.strict,
//   validation.checkUsername,
//   userController.checkUsernameAvailability
// );

// router.get('/check-email/:email', 
//   rateLimiting.strict,
//   validation.checkEmail,
//   userController.checkEmailAvailability
// );

// // Protected routes (authentication required)
// router.use(auth.verifyToken);

// // Get current user info
// router.get('/me', 
//   rateLimiting.standard,
//   auditLogger(),
//   userController.getCurrentUser
// );

// // Update current user basic info
// router.patch('/me', 
//   rateLimiting.standard,
//   validation.updateUser,
//   auditLogger(),
//   userController.updateCurrentUser
// );

// // Delete current user account
// router.delete('/me', 
//   rateLimiting.strict,
//   auditLogger(),
//   userController.deleteCurrentUser
// );

// // Change password
// router.patch('/me/password', 
//   rateLimiting.strict,
//   validation.changePassword,
//   auditLogger(),
//   userController.changePassword
// );

// // Enable/disable 2FA
// router.patch('/me/2fa', 
//   rateLimiting.standard,
//   validation.toggle2FA,
//   auditLogger(),
//   userController.toggle2FA
// );

// // Get user activity logs
// router.get('/me/activity', 
//   rateLimiting.standard,
//   validation.pagination,
//   auditLogger(),
//   userController.getUserActivity
// );

// // Get user sessions
// router.get('/me/sessions', 
//   rateLimiting.standard,
//   auditLogger(),
//   userController.getUserSessions
// );

// // Revoke specific session
// router.delete('/me/sessions/:sessionId', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLogger(),
//   userController.revokeSession
// );

// // Revoke all sessions except current
// router.delete('/me/sessions', 
//   rateLimiting.strict,
//   auditLogger(),
//   userController.revokeAllSessions
// );

// // Admin-only routes
// router.use(rbac.requirePermission('users:view'));

// // Get all users (paginated)
// router.get('/', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.userFilters,
//   auditLogger(),
//   userController.getAllUsers
// );

// // Get user by ID
// router.get('/:userId', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLogger(),
//   userController.getUserById
// );

// // Admin update user
// router.patch('/:userId', 
//   rbac.requirePermission('users:edit'),
//   rateLimiting.standard,
//   validation.validateObjectId,
//   validation.adminUpdateUser,
//   auditLogger(),
//   userController.adminUpdateUser
// );

// // Suspend/unsuspend user
// router.patch('/:userId/suspension', 
//   rbac.requirePermission('users:suspend'),
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.userSuspension,
//   auditLogger(),
//   userController.toggleUserSuspension
// );

// // Delete user (admin only)
// router.delete('/:userId', 
//   rbac.requirePermission('users:delete'),
//   rateLimiting.strict,
//   validation.validateObjectId,
//   auditLogger(),
//   userController.adminDeleteUser
// );

// // Get user statistics
// router.get('/stats/overview', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   auditLogger(),
//   userController.getUserStats
// );

// // Get user demographics
// router.get('/stats/demographics', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLogger(),
//   userController.getUserDemographics
// );

// // Export user data
// router.get('/export/csv', 
//   rbac.requirePermission('analytics:export'),
//   rateLimiting.strict,
//   validation.exportOptions,
//   auditLogger(),
//   userController.exportUsers
// );

// // Bulk user operations
// router.post('/bulk/suspend', 
//   rbac.requirePermission('users:suspend'),
//   rateLimiting.strict,
//   validation.bulkUserIds,
//   auditLogger(),
//   userController.bulkSuspendUsers
// );

// router.post('/bulk/unsuspend', 
//   rbac.requirePermission('users:suspend'),
//   rateLimiting.strict,
//   validation.bulkUserIds,
//   auditLogger(),
//   userController.bulkUnsuspendUsers
// );

// router.post('/bulk/delete', 
//   rbac.requirePermission('users:delete'),
//   rateLimiting.strict,
//   validation.bulkUserIds,
//   auditLogger(),
//   userController.bulkDeleteUsers
// );

// // Search users
// router.get('/search/query', 
//   rateLimiting.standard,
//   validation.searchQuery,
//   auditLogger(),
//   userController.searchUsers
// );

// // Advanced user filtering
// router.post('/filter/advanced', 
//   rateLimiting.standard,
//   validation.advancedFilters,
//   auditLogger(),
//   userController.advancedUserFilter
// );

// export default router;