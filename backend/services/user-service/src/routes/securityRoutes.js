import express from 'express';
import securityController from '../controllers/securityController.js';
import { auth } from '../middleware/auth.js';
import { rbac } from '../middleware/rbac.js';
// Replace the broken validation import with securityValidation
import * as securityValidation from '../middleware/securityValidation.js';
import { rateLimiting } from '../middleware/rateLimiting.js';
import { auditLog } from '../middleware/auditLog.js';
import { security } from '../middleware/security.js';

const router = express.Router();

// Apply security middleware to all routes
router.use(security.sanitizeInput);
router.use(security.preventXSS);

// All security routes require authentication
router.use(auth.verifyToken);

// User encryption key management
router.get('/keys/me', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.getUserKeys
);

// Generate new encryption key pair
router.post('/keys/generate', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.generateKeyPair
);

// Get public key for user
router.get('/keys/:userId/public', 
  rateLimiting.standard,
  ...securityValidation.securityValidateObjectId,
  auditLog.logActivity,
  securityController.getUserPublicKey
);

// Update encryption key
router.patch('/keys/:keyId', 
  rateLimiting.strict,
  ...securityValidation.securityValidateObjectId,
  auditLog.logActivity,
  securityController.updateEncryptionKey
);

// Revoke encryption key
router.delete('/keys/:keyId', 
  rateLimiting.strict,
  ...securityValidation.securityValidateObjectId,
  auditLog.logActivity,
  securityController.revokeKey
);

// Digital signature operations
router.post('/signatures/create', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.createSignature
);

router.post('/signatures/verify', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.verifySignature
);

// Get user's digital signatures
router.get('/signatures/me', 
  rateLimiting.standard,
  ...securityValidation.securityPagination,
  auditLog.logActivity,
  securityController.getUserSignatures
);

// Get signature by ID
router.get('/signatures/:signatureId', 
  rateLimiting.standard,
  ...securityValidation.securityValidateObjectId,
  auditLog.logActivity,
  securityController.getSignatureById
);

// Security settings
router.get('/settings/me', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.getSecuritySettings
);

router.patch('/settings/me', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.updateSecuritySettings
);

// Two-factor authentication
router.get('/2fa/status', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.get2FAStatus
);

router.post('/2fa/setup', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.setup2FA
);

router.post('/2fa/verify-setup', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.verify2FASetup
);

router.post('/2fa/disable', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.disable2FA
);

router.post('/2fa/backup-codes', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.generateBackupCodes
);

// Biometric authentication settings
router.get('/biometric/status', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.getBiometricStatus
);

router.post('/biometric/register', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.registerBiometric
);

router.delete('/biometric/remove', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.removeBiometric
);

// Security events and logs
router.get('/events/me', 
  rateLimiting.standard,
  ...securityValidation.securityPagination,
  auditLog.logActivity,
  securityController.getUserSecurityEvents
);

// Login history
router.get('/logins/me', 
  rateLimiting.standard,
  ...securityValidation.securityPagination,
  ...securityValidation.securityDateRange,
  auditLog.logActivity,
  securityController.getLoginHistory
);

// Device management
router.get('/devices/me', 
  rateLimiting.standard,
  ...securityValidation.securityPagination,
  auditLog.logActivity,
  securityController.getUserDevices
);

router.delete('/devices/:deviceId', 
  rateLimiting.strict,
  ...securityValidation.securityValidateObjectId,
  auditLog.logActivity,
  securityController.removeDevice
);

router.delete('/devices/all', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.removeAllDevices
);

// Password security
router.post('/password/check-strength', 
  rateLimiting.standard,
  securityController.checkPasswordStrength
);

router.get('/password/breach-check', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.checkPasswordBreach
);

// Security notifications
router.get('/notifications/me', 
  rateLimiting.standard,
  ...securityValidation.securityPagination,
  auditLog.logActivity,
  securityController.getSecurityNotifications
);

router.patch('/notifications/:notificationId/read', 
  rateLimiting.standard,
  ...securityValidation.securityValidateObjectId,
  auditLog.logActivity,
  securityController.markNotificationRead
);

// Encryption/Decryption operations
router.post('/encrypt', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.encryptData
);

router.post('/decrypt', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.decryptData
);

// Threshold cryptography
router.post('/threshold/create', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.createThresholdEncryption
);

router.post('/threshold/decrypt', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.thresholdDecrypt
);

// Key verification
router.post('/keys/verify', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.verifyKeyIntegrity
);

// Security audit for current user
router.get('/audit/me', 
  rateLimiting.standard,
  // ...validation.pagination,
  auditLog.logActivity,
  securityController.getUserSecurityAudit
);

// Generate security report
router.post('/reports/generate', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.generateSecurityReport
);

// Account recovery
router.post('/recovery/initiate', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.initiateAccountRecovery
);

router.post('/recovery/verify', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.verifyAccountRecovery
);

// Security challenges
router.post('/challenge/request', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.requestSecurityChallenge
);

router.post('/challenge/respond', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.respondSecurityChallenge
);

// Activity Log
router.get('/activity/me', 
  rateLimiting.standard,
  // ...validation.pagination,
  auditLog.logActivity,
  securityController.getUserActivityLog
);

// Report security incident
router.post('/incident/report', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.reportIncident
);

// Admin security routes - require security management permissions
router.use(rbac.requirePermission('system:security'));

// System-wide security overview
router.get('/system/overview', 
  rateLimiting.standard,
  ...securityValidation.securityDateRange,
  auditLog.logActivity,
  securityController.getSystemSecurityOverview
);

// All security events (admin)
router.get('/events/all', 
  rateLimiting.standard,
  ...securityValidation.securityPagination,
  auditLog.logActivity,
  securityController.getSecurityEvents
);

// User security management (admin)
router.get('/users/:userId/security', 
  rateLimiting.standard,
  ...securityValidation.securityValidateObjectId,
  auditLog.logActivity,
  securityController.getUserSecurityOverview
);

// Force key regeneration (admin)
router.post('/users/:userId/keys/regenerate', 
  rbac.requirePermission('system:security:keys'),
  rateLimiting.strict,
  ...securityValidation.securityValidateObjectId,
  auditLog.logActivity,
  securityController.forceKeyRegeneration
);

// Revoke all user keys (admin)
router.delete('/users/:userId/keys/all', 
  rbac.requirePermission('system:security:keys'),
  rateLimiting.strict,
  ...securityValidation.securityValidateObjectId,
  auditLog.logActivity,
  securityController.revokeAllUserKeys
);

// Security incident management
router.get('/incidents', 
  rateLimiting.standard,
  ...securityValidation.securityPagination,
  auditLog.logActivity,
  securityController.getSecurityIncidents
);

router.post('/incidents', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.createSecurityIncident
);

router.patch('/incidents/:incidentId', 
  rateLimiting.standard,
  ...securityValidation.securityValidateObjectId,
  auditLog.logActivity,
  securityController.updateSecurityIncident
);

router.post('/incidents/:incidentId/resolve', 
  rateLimiting.strict,
  ...securityValidation.securityValidateObjectId,
  auditLog.logActivity,
  securityController.resolveSecurityIncident
);

// Threat analysis
router.get('/threats/analysis', 
  rateLimiting.standard,
  ...securityValidation.securityDateRange,
  auditLog.logActivity,
  securityController.getThreatAnalysis
);

router.get('/threats/patterns', 
  rateLimiting.standard,
  ...securityValidation.securityDateRange,
  auditLog.logActivity,
  securityController.getThreatPatterns
);

// Security analytics
router.get('/analytics/authentication', 
  rbac.requirePermission('analytics:view'),
  rateLimiting.standard,
  ...securityValidation.securityDateRange,
  auditLog.logActivity,
  securityController.getAuthenticationAnalytics
);

router.get('/analytics/encryption', 
  rbac.requirePermission('analytics:view'),
  rateLimiting.standard,
  ...securityValidation.securityDateRange,
  auditLog.logActivity,
  securityController.getEncryptionAnalytics
);

router.get('/analytics/violations', 
  rbac.requirePermission('analytics:view'),
  rateLimiting.standard,
  ...securityValidation.securityDateRange,
  auditLog.logActivity,
  securityController.getSecurityViolationAnalytics
);

// Compliance and audit
router.get('/compliance/report', 
  rbac.requirePermission('system:audit'),
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.generateComplianceReport
);

router.get('/audit/system', 
  rbac.requirePermission('system:audit'),
  rateLimiting.standard,
  // ...validation.pagination,
  auditLog.logActivity,
  securityController.getSystemAuditLog
);

// Security configuration
router.get('/config/settings', 
  rbac.requirePermission('system:config'),
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.getSecurityConfiguration
);

router.patch('/config/settings', 
  rbac.requirePermission('system:config'),
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.updateSecurityConfiguration
);

// Key management (admin)
router.get('/keys/system', 
  rbac.requirePermission('system:security:keys'),
  rateLimiting.standard,
  ...securityValidation.securityPagination,
  auditLog.logActivity,
  securityController.getSystemKeys
);

router.post('/keys/system/rotate', 
  rbac.requirePermission('system:security:keys'),
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.rotateSystemKeys
);

// Bulk security operations
router.post('/bulk/reset-2fa', 
  rbac.requirePermission('users:security:bulk'),
  rateLimiting.strict,
  ...securityValidation.securityBulkUserIds,
  auditLog.logActivity,
  securityController.bulkReset2FA
);

router.post('/bulk/force-logout', 
  rbac.requirePermission('users:security:bulk'),
  rateLimiting.strict,
  ...securityValidation.securityBulkUserIds,
  auditLog.logActivity,
  securityController.bulkForceLogout
);

router.post('/bulk/revoke-keys', 
  rbac.requirePermission('system:security:keys'),
  rateLimiting.strict,
  ...securityValidation.securityBulkUserIds,
  auditLog.logActivity,
  securityController.bulkRevokeKeys
);

// Security monitoring
router.get('/monitoring/real-time', 
  rbac.requirePermission('system:security:monitor'),
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.getRealTimeSecurityMetrics
);

router.get('/monitoring/alerts', 
  rbac.requirePermission('system:security:monitor'),
  rateLimiting.standard,
  ...securityValidation.securityPagination,
  auditLog.logActivity,
  securityController.getSecurityAlerts
);

router.post('/monitoring/alerts/:alertId/acknowledge', 
  rbac.requirePermission('system:security:monitor'),
  rateLimiting.standard,
  ...securityValidation.securityValidateObjectId,
  auditLog.logActivity,
  securityController.acknowledgeSecurityAlert
);

// Export security data
router.get('/export/events', 
  rbac.requirePermission('analytics:export'),
  rateLimiting.strict,
  ...securityValidation.securityExportOptions,
  auditLog.logActivity,
  securityController.exportSecurityEvents
);

router.get('/export/audit', 
  rbac.requirePermission('analytics:export'),
  rateLimiting.strict,
  ...securityValidation.securityExportOptions,
  auditLog.logActivity,
  securityController.exportAuditLog
);

// Emergency security procedures
router.post('/emergency/lockdown', 
  rbac.requirePermission('system:security:emergency'),
  rateLimiting.emergency,
  auditLog.logActivity,
  securityController.emergencyLockdown
);

router.post('/emergency/unlock', 
  rbac.requirePermission('system:security:emergency'),
  rateLimiting.emergency,
  auditLog.logActivity,
  securityController.emergencyUnlock
);

// Security health check
router.get('/health/check', 
  rateLimiting.standard,
  auditLog.logActivity,
  securityController.securityHealthCheck
);

// Vulnerability reporting
router.post('/vulnerabilities/report', 
  rateLimiting.strict,
  auditLog.logActivity,
  securityController.reportVulnerability
);

router.get('/vulnerabilities', 
  rbac.requirePermission('system:security:vulnerabilities'),
  rateLimiting.standard,
  // ...validation.pagination,
  auditLog.logActivity,
  securityController.getVulnerabilities
);

export default router;


// import express from 'express';
// import securityController from '../controllers/securityController.js';
// import { auth } from '../middleware/auth.js';
// import { rbac } from '../middleware/rbac.js';
// //import  validation  from '../utils/response.js'; // Import from your existing validation
// import { validation } from '../utils/response.js';
// import { rateLimiting } from '../middleware/rateLimiting.js';
// import { auditLog } from '../middleware/auditLog.js';
// import { security } from '../middleware/security.js';

// const router = express.Router();

// // Apply security middleware to all routes
// router.use(security.sanitizeInput);
// router.use(security.preventXSS);

// // All security routes require authentication
// router.use(auth.verifyToken);

// // User encryption key management
// router.get('/keys/me', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getUserKeys
// );

// // Generate new encryption key pair
// router.post('/keys/generate', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.generateKeyPair
// );

// // Get public key for user
// router.get('/keys/:userId/public', 
//   rateLimiting.standard,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getUserPublicKey
// );

// // Update encryption key
// router.patch('/keys/:keyId', 
//   rateLimiting.strict,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.updateEncryptionKey
// );

// // Revoke encryption key
// router.delete('/keys/:keyId', 
//   rateLimiting.strict,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.revokeKey
// );

// // Digital signature operations
// router.post('/signatures/create', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.createSignature
// );

// router.post('/signatures/verify', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.verifySignature
// );

// // Get user's digital signatures
// router.get('/signatures/me', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserSignatures
// );

// // Get signature by ID
// router.get('/signatures/:signatureId', 
//   rateLimiting.standard,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getSignatureById
// );

// // Security settings
// router.get('/settings/me', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getSecuritySettings
// );

// router.patch('/settings/me', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.updateSecuritySettings
// );

// // Two-factor authentication
// router.get('/2fa/status', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.get2FAStatus
// );

// router.post('/2fa/setup', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.setup2FA
// );

// router.post('/2fa/verify-setup', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.verify2FASetup
// );

// router.post('/2fa/disable', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.disable2FA
// );

// router.post('/2fa/backup-codes', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.generateBackupCodes
// );

// // Biometric authentication settings
// router.get('/biometric/status', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getBiometricStatus
// );

// router.post('/biometric/register', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.registerBiometric
// );

// router.delete('/biometric/remove', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.removeBiometric
// );

// // Security events and logs
// router.get('/events/me', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserSecurityEvents
// );

// // Login history
// router.get('/logins/me', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   ...validation.dateRange,
//   auditLog.logActivity,
//   securityController.getLoginHistory
// );

// // Device management
// router.get('/devices/me', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserDevices
// );

// router.delete('/devices/:deviceId', 
//   rateLimiting.strict,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.removeDevice
// );

// router.delete('/devices/all', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.removeAllDevices
// );

// // Password security
// router.post('/password/check-strength', 
//   rateLimiting.standard,
//   securityController.checkPasswordStrength
// );

// router.get('/password/breach-check', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.checkPasswordBreach
// );

// // Security notifications
// router.get('/notifications/me', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getSecurityNotifications
// );

// router.patch('/notifications/:notificationId/read', 
//   rateLimiting.standard,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.markNotificationRead
// );

// // Encryption/Decryption operations
// router.post('/encrypt', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.encryptData
// );

// router.post('/decrypt', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.decryptData
// );

// // Threshold cryptography
// router.post('/threshold/create', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.createThresholdEncryption
// );

// router.post('/threshold/decrypt', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.thresholdDecrypt
// );

// // Key verification
// router.post('/keys/verify', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.verifyKeyIntegrity
// );

// // Security audit for current user
// router.get('/audit/me', 
//   rateLimiting.standard,
//   // ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserSecurityAudit
// );

// // Generate security report
// router.post('/reports/generate', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.generateSecurityReport
// );

// // Account recovery
// router.post('/recovery/initiate', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.initiateAccountRecovery
// );

// router.post('/recovery/verify', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.verifyAccountRecovery
// );

// // Security challenges
// router.post('/challenge/request', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.requestSecurityChallenge
// );

// router.post('/challenge/respond', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.respondSecurityChallenge
// );

// // Activity Log
// router.get('/activity/me', 
//   rateLimiting.standard,
//   // ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserActivityLog
// );

// // Report security incident
// router.post('/incident/report', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.reportIncident
// );

// // Admin security routes - require security management permissions
// router.use(rbac.requirePermission('system:security'));

// // System-wide security overview
// router.get('/system/overview', 
//   rateLimiting.standard,
//   ...validation.dateRange,
//   auditLog.logActivity,
//   securityController.getSystemSecurityOverview
// );

// // All security events (admin)
// router.get('/events/all', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getSecurityEvents
// );

// // User security management (admin)
// router.get('/users/:userId/security', 
//   rateLimiting.standard,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getUserSecurityOverview
// );

// // Force key regeneration (admin)
// router.post('/users/:userId/keys/regenerate', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.forceKeyRegeneration
// );

// // Revoke all user keys (admin)
// router.delete('/users/:userId/keys/all', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.revokeAllUserKeys
// );

// // Security incident management
// router.get('/incidents', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getSecurityIncidents
// );

// router.post('/incidents', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.createSecurityIncident
// );

// router.patch('/incidents/:incidentId', 
//   rateLimiting.standard,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.updateSecurityIncident
// );

// router.post('/incidents/:incidentId/resolve', 
//   rateLimiting.strict,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.resolveSecurityIncident
// );

// // Threat analysis
// router.get('/threats/analysis', 
//   rateLimiting.standard,
//   ...validation.dateRange,
//   auditLog.logActivity,
//   securityController.getThreatAnalysis
// );

// router.get('/threats/patterns', 
//   rateLimiting.standard,
//   ...validation.dateRange,
//   auditLog.logActivity,
//   securityController.getThreatPatterns
// );

// // Security analytics
// router.get('/analytics/authentication', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   ...validation.dateRange,
//   auditLog.logActivity,
//   securityController.getAuthenticationAnalytics
// );

// router.get('/analytics/encryption', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   ...validation.dateRange,
//   auditLog.logActivity,
//   securityController.getEncryptionAnalytics
// );

// router.get('/analytics/violations', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   ...validation.dateRange,
//   auditLog.logActivity,
//   securityController.getSecurityViolationAnalytics
// );

// // Compliance and audit
// router.get('/compliance/report', 
//   rbac.requirePermission('system:audit'),
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.generateComplianceReport
// );

// router.get('/audit/system', 
//   rbac.requirePermission('system:audit'),
//   rateLimiting.standard,
//   // ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getSystemAuditLog
// );

// // Security configuration
// router.get('/config/settings', 
//   rbac.requirePermission('system:config'),
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getSecurityConfiguration
// );

// router.patch('/config/settings', 
//   rbac.requirePermission('system:config'),
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.updateSecurityConfiguration
// );

// // Key management (admin)
// router.get('/keys/system', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.standard,
//   ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getSystemKeys
// );

// router.post('/keys/system/rotate', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.rotateSystemKeys
// );

// // Bulk security operations
// router.post('/bulk/reset-2fa', 
//   rbac.requirePermission('users:security:bulk'),
//   rateLimiting.strict,
//   ...validation.bulkUserIds,
//   auditLog.logActivity,
//   securityController.bulkReset2FA
// );

// router.post('/bulk/force-logout', 
//   rbac.requirePermission('users:security:bulk'),
//   rateLimiting.strict,
//   ...validation.bulkUserIds,
//   auditLog.logActivity,
//   securityController.bulkForceLogout
// );

// router.post('/bulk/revoke-keys', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   ...validation.bulkUserIds,
//   auditLog.logActivity,
//   securityController.bulkRevokeKeys
// );

// // Security monitoring
// router.get('/monitoring/real-time', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getRealTimeSecurityMetrics
// );

// router.get('/monitoring/alerts', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getSecurityAlerts
// );

// router.post('/monitoring/alerts/:alertId/acknowledge', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.acknowledgeSecurityAlert
// );

// // Export security data
// router.get('/export/events', 
//   rbac.requirePermission('analytics:export'),
//   rateLimiting.strict,
//   ...validation.exportOptions,
//   auditLog.logActivity,
//   securityController.exportSecurityEvents
// );

// router.get('/export/audit', 
//   rbac.requirePermission('analytics:export'),
//   rateLimiting.strict,
//   ...validation.exportOptions,
//   auditLog.logActivity,
//   securityController.exportAuditLog
// );

// // Emergency security procedures
// router.post('/emergency/lockdown', 
//   rbac.requirePermission('system:security:emergency'),
//   rateLimiting.emergency,
//   auditLog.logActivity,
//   securityController.emergencyLockdown
// );

// router.post('/emergency/unlock', 
//   rbac.requirePermission('system:security:emergency'),
//   rateLimiting.emergency,
//   auditLog.logActivity,
//   securityController.emergencyUnlock
// );

// // Security health check
// router.get('/health/check', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.securityHealthCheck
// );

// // Vulnerability reporting
// router.post('/vulnerabilities/report', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.reportVulnerability
// );

// router.get('/vulnerabilities', 
//   rbac.requirePermission('system:security:vulnerabilities'),
//   rateLimiting.standard,
//   // ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getVulnerabilities
// );

// export default router;
// import express from 'express';
// import securityController from '../controllers/securityController.js';
// import { auth } from '../middleware/auth.js';
// import { rbac } from '../middleware/rbac.js';
// import validation from '../middleware/validation.js';
// import { rateLimiting } from '../middleware/rateLimiting.js';
// import { auditLog } from '../middleware/auditLog.js';
// import { security } from '../middleware/security.js';

// const router = express.Router();

// // Apply security middleware to all routes
// router.use(security.sanitizeInput);
// router.use(security.preventXSS);

// // All security routes require authentication
// router.use(auth.verifyToken);

// // User encryption key management
// router.get('/keys/me', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getUserKeys  // Changed from getCurrentUserKeys to getUserKeys
// );

// // Generate new encryption key pair
// router.post('/keys/generate', 
//   rateLimiting.strict,
//   ...validation.keyGeneration,
//   auditLog.logActivity,
//   securityController.generateKeyPair
// );

// // Get public key for user
// router.get('/keys/:userId/public', 
//   rateLimiting.standard,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getUserPublicKey
// );

// // Update encryption key
// router.patch('/keys/:keyId', 
//   rateLimiting.strict,
//   ...validation.validateObjectId,
//   ...validation.updateEncryptionKey,
//   auditLog.logActivity,
//   securityController.updateEncryptionKey
// );

// // Revoke encryption key
// router.delete('/keys/:keyId', 
//   rateLimiting.strict,
//   ...validation.validateObjectId,
//   ...validation.revokeKeyReason,
//   auditLog.logActivity,
//   securityController.revokeKey  // Changed from revokeEncryptionKey to revokeKey
// );

// // Digital signature operations
// router.post('/signatures/create', 
//   rateLimiting.standard,
//   ...validation.createSignature,
//   auditLog.logActivity,
//   securityController.createSignature
// );

// router.post('/signatures/verify', 
//   rateLimiting.standard,
//   ...validation.verifySignature,
//   auditLog.logActivity,
//   securityController.verifySignature
// );

// // Get user's digital signatures
// router.get('/signatures/me', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserSignatures
// );

// // Get signature by ID
// router.get('/signatures/:signatureId', 
//   rateLimiting.standard,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getSignatureById
// );

// // Security settings
// router.get('/settings/me', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getSecuritySettings
// );

// router.patch('/settings/me', 
//   rateLimiting.standard,
//   ...validation.securitySettings,
//   auditLog.logActivity,
//   securityController.updateSecuritySettings
// );

// // Two-factor authentication
// router.get('/2fa/status', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.get2FAStatus
// );

// router.post('/2fa/setup', 
//   rateLimiting.strict,
//   ...validation.setup2FA,
//   auditLog.logActivity,
//   securityController.setup2FA
// );

// router.post('/2fa/verify-setup', 
//   rateLimiting.strict,
//   ...validation.verify2FASetup,
//   auditLog.logActivity,
//   securityController.verify2FASetup
// );

// router.post('/2fa/disable', 
//   rateLimiting.strict,
//   ...validation.disable2FA,
//   auditLog.logActivity,
//   securityController.disable2FA
// );

// router.post('/2fa/backup-codes', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.generateBackupCodes
// );

// // Biometric authentication settings
// router.get('/biometric/status', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getBiometricStatus
// );

// router.post('/biometric/register', 
//   rateLimiting.strict,
//   ...validation.registerBiometric,
//   auditLog.logActivity,
//   securityController.registerBiometric
// );

// router.delete('/biometric/remove', 
//   rateLimiting.strict,
//   ...validation.removeBiometric,
//   auditLog.logActivity,
//   securityController.removeBiometric
// );

// // Security events and logs
// router.get('/events/me', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   ...validation.securityEventFilters,
//   auditLog.logActivity,
//   securityController.getUserSecurityEvents
// );

// // Login history
// router.get('/logins/me', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   ...validation.dateRange,
//   auditLog.logActivity,
//   securityController.getLoginHistory
// );

// // Device management
// router.get('/devices/me', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserDevices
// );

// router.delete('/devices/:deviceId', 
//   rateLimiting.strict,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.removeDevice
// );

// router.delete('/devices/all', 
//   rateLimiting.strict,
//   ...validation.removeAllDevices,
//   auditLog.logActivity,
//   securityController.removeAllDevices
// );

// // Password security
// router.post('/password/check-strength', 
//   rateLimiting.standard,
//   ...validation.passwordStrengthCheck,
//   securityController.checkPasswordStrength
// );

// router.get('/password/breach-check', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.checkPasswordBreach
// );

// // Security notifications
// router.get('/notifications/me', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getSecurityNotifications
// );

// router.patch('/notifications/:notificationId/read', 
//   rateLimiting.standard,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.markNotificationRead
// );

// // Encryption/Decryption operations
// router.post('/encrypt', 
//   rateLimiting.standard,
//   ...validation.encryptionRequest,
//   auditLog.logActivity,
//   securityController.encryptData
// );

// router.post('/decrypt', 
//   rateLimiting.standard,
//   ...validation.decryptionRequest,
//   auditLog.logActivity,
//   securityController.decryptData
// );

// // Threshold cryptography
// router.post('/threshold/create', 
//   rateLimiting.strict,
//   ...validation.thresholdCreate,
//   auditLog.logActivity,
//   securityController.createThresholdEncryption
// );

// router.post('/threshold/decrypt', 
//   rateLimiting.standard,
//   ...validation.thresholdDecrypt,
//   auditLog.logActivity,
//   securityController.thresholdDecrypt
// );

// // Key verification
// router.post('/keys/verify', 
//   rateLimiting.standard,
//   ...validation.keyVerification,
//   auditLog.logActivity,
//   securityController.verifyKeyIntegrity
// );

// // Security audit for current user
// router.get('/audit/me', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   ...validation.auditFilters,
//   auditLog.logActivity,
//   securityController.getUserSecurityAudit
// );

// // Generate security report
// router.post('/reports/generate', 
//   rateLimiting.strict,
//   ...validation.securityReportRequest,
//   auditLog.logActivity,
//   securityController.generateSecurityReport
// );

// // Account recovery
// router.post('/recovery/initiate', 
//   rateLimiting.strict,
//   ...validation.initiateRecovery,
//   auditLog.logActivity,
//   securityController.initiateAccountRecovery
// );

// router.post('/recovery/verify', 
//   rateLimiting.strict,
//   ...validation.verifyRecovery,
//   auditLog.logActivity,
//   securityController.verifyAccountRecovery
// );

// // Security challenges
// router.post('/challenge/request', 
//   rateLimiting.standard,
//   ...validation.securityChallenge,
//   auditLog.logActivity,
//   securityController.requestSecurityChallenge
// );

// router.post('/challenge/respond', 
//   rateLimiting.standard,
//   ...validation.challengeResponse,
//   auditLog.logActivity,
//   securityController.respondSecurityChallenge
// );

// // Activity Log
// router.get('/activity/me', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserActivityLog
// );

// // Report security incident
// router.post('/incident/report', 
//   rateLimiting.strict,
//   ...validation.securityIncident,
//   auditLog.logActivity,
//   securityController.reportIncident
// );

// // Admin security routes - require security management permissions
// router.use(rbac.requirePermission('system:security'));

// // System-wide security overview
// router.get('/system/overview', 
//   rateLimiting.standard,
//   ...validation.dateRange,
//   auditLog.logActivity,
//   securityController.getSystemSecurityOverview
// );

// // All security events (admin)
// router.get('/events/all', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   ...validation.adminSecurityEventFilters,
//   auditLog.logActivity,
//   securityController.getSecurityEvents  // Changed from getAllSecurityEvents to getSecurityEvents
// );

// // User security management (admin)
// router.get('/users/:userId/security', 
//   rateLimiting.standard,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getUserSecurityOverview
// );

// // Force key regeneration (admin)
// router.post('/users/:userId/keys/regenerate', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   ...validation.validateObjectId,
//   ...validation.forceKeyRegeneration,
//   auditLog.logActivity,
//   securityController.forceKeyRegeneration
// );

// // Revoke all user keys (admin)
// router.delete('/users/:userId/keys/all', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   ...validation.validateObjectId,
//   ...validation.revokeAllKeysReason,
//   auditLog.logActivity,
//   securityController.revokeAllUserKeys
// );

// // Security incident management
// router.get('/incidents', 
//   rateLimiting.standard,
//   ...validation.pagination,
//   ...validation.incidentFilters,
//   auditLog.logActivity,
//   securityController.getSecurityIncidents
// );

// router.post('/incidents', 
//   rateLimiting.strict,
//   ...validation.createIncident,
//   auditLog.logActivity,
//   securityController.createSecurityIncident
// );

// router.patch('/incidents/:incidentId', 
//   rateLimiting.standard,
//   ...validation.validateObjectId,
//   ...validation.updateIncident,
//   auditLog.logActivity,
//   securityController.updateSecurityIncident
// );

// router.post('/incidents/:incidentId/resolve', 
//   rateLimiting.strict,
//   ...validation.validateObjectId,
//   ...validation.resolveIncident,
//   auditLog.logActivity,
//   securityController.resolveSecurityIncident
// );

// // Threat analysis
// router.get('/threats/analysis', 
//   rateLimiting.standard,
//   ...validation.dateRange,
//   ...validation.threatFilters,
//   auditLog.logActivity,
//   securityController.getThreatAnalysis
// );

// router.get('/threats/patterns', 
//   rateLimiting.standard,
//   ...validation.dateRange,
//   auditLog.logActivity,
//   securityController.getThreatPatterns
// );

// // Security analytics
// router.get('/analytics/authentication', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   ...validation.dateRange,
//   auditLog.logActivity,
//   securityController.getAuthenticationAnalytics
// );

// router.get('/analytics/encryption', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   ...validation.dateRange,
//   auditLog.logActivity,
//   securityController.getEncryptionAnalytics
// );

// router.get('/analytics/violations', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   ...validation.dateRange,
//   ...validation.violationFilters,
//   auditLog.logActivity,
//   securityController.getSecurityViolationAnalytics
// );

// // Compliance and audit
// router.get('/compliance/report', 
//   rbac.requirePermission('system:audit'),
//   rateLimiting.strict,
//   ...validation.complianceReportParams,
//   auditLog.logActivity,
//   securityController.generateComplianceReport
// );

// router.get('/audit/system', 
//   rbac.requirePermission('system:audit'),
//   rateLimiting.standard,
//   ...validation.pagination,
//   ...validation.systemAuditFilters,
//   auditLog.logActivity,
//   securityController.getSystemAuditLog
// );

// // Security configuration
// router.get('/config/settings', 
//   rbac.requirePermission('system:config'),
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getSecurityConfiguration
// );

// router.patch('/config/settings', 
//   rbac.requirePermission('system:config'),
//   rateLimiting.strict,
//   ...validation.securityConfiguration,
//   auditLog.logActivity,
//   securityController.updateSecurityConfiguration
// );

// // Key management (admin)
// router.get('/keys/system', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.standard,
//   ...validation.pagination,
//   ...validation.keyFilters,
//   auditLog.logActivity,
//   securityController.getSystemKeys
// );

// router.post('/keys/system/rotate', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   ...validation.keyRotation,
//   auditLog.logActivity,
//   securityController.rotateSystemKeys
// );

// // Bulk security operations
// router.post('/bulk/reset-2fa', 
//   rbac.requirePermission('users:security:bulk'),
//   rateLimiting.strict,
//   ...validation.bulkUserIds,
//   ...validation.bulk2FAResetReason,
//   auditLog.logActivity,
//   securityController.bulkReset2FA
// );

// router.post('/bulk/force-logout', 
//   rbac.requirePermission('users:security:bulk'),
//   rateLimiting.strict,
//   ...validation.bulkUserIds,
//   ...validation.bulkLogoutReason,
//   auditLog.logActivity,
//   securityController.bulkForceLogout
// );

// router.post('/bulk/revoke-keys', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   ...validation.bulkUserIds,
//   ...validation.bulkRevokeReason,
//   auditLog.logActivity,
//   securityController.bulkRevokeKeys
// );

// // Security monitoring
// router.get('/monitoring/real-time', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getRealTimeSecurityMetrics
// );

// router.get('/monitoring/alerts', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   ...validation.pagination,
//   ...validation.alertFilters,
//   auditLog.logActivity,
//   securityController.getSecurityAlerts
// );

// router.post('/monitoring/alerts/:alertId/acknowledge', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   ...validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.acknowledgeSecurityAlert
// );

// // Export security data
// router.get('/export/events', 
//   rbac.requirePermission('analytics:export'),
//   rateLimiting.strict,
//   ...validation.exportSecurityData,
//   auditLog.logActivity,
//   securityController.exportSecurityEvents
// );

// router.get('/export/audit', 
//   rbac.requirePermission('analytics:export'),
//   rateLimiting.strict,
//   ...validation.exportAuditData,
//   auditLog.logActivity,
//   securityController.exportAuditLog
// );

// // Emergency security procedures
// router.post('/emergency/lockdown', 
//   rbac.requirePermission('system:security:emergency'),
//   rateLimiting.emergency,
//   ...validation.emergencyLockdown,
//   auditLog.logActivity,
//   securityController.emergencyLockdown
// );

// router.post('/emergency/unlock', 
//   rbac.requirePermission('system:security:emergency'),
//   rateLimiting.emergency,
//   ...validation.emergencyUnlock,
//   auditLog.logActivity,
//   securityController.emergencyUnlock
// );

// // Security health check
// router.get('/health/check', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.securityHealthCheck
// );

// // Vulnerability reporting
// router.post('/vulnerabilities/report', 
//   rateLimiting.strict,
//   ...validation.vulnerabilityReport,
//   auditLog.logActivity,
//   securityController.reportVulnerability
// );

// router.get('/vulnerabilities', 
//   rbac.requirePermission('system:security:vulnerabilities'),
//   rateLimiting.standard,
//   ...validation.pagination,
//   ...validation.vulnerabilityFilters,
//   auditLog.logActivity,
//   securityController.getVulnerabilities
// );

// export default router;




// import express from 'express';
// import securityController from '../controllers/securityController.js';
// import { auth } from '../middleware/auth.js';
// import { rbac } from '../middleware/rbac.js';
// import validation from '../middleware/validation.js';
// import { rateLimiting } from '../middleware/rateLimiting.js';
// import { auditLog } from '../middleware/auditLog.js';
// import { security } from '../middleware/security.js';

// const router = express.Router();

// // Apply security middleware to all routes
// router.use(security.sanitizeInput);
// router.use(security.preventXSS);

// // All security routes require authentication
// router.use(auth.verifyToken);

// // User encryption key management
// router.get('/keys/me', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getUserKeys  // Changed from getCurrentUserKeys to getUserKeys
// );

// // Generate new encryption key pair
// router.post('/keys/generate', 
//   rateLimiting.strict,
//   validation.keyGeneration,
//   auditLog.logActivity,
//   securityController.generateKeyPair
// );

// // Get public key for user
// router.get('/keys/:userId/public', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getUserPublicKey
// );

// // Update encryption key
// router.patch('/keys/:keyId', 
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.updateEncryptionKey,
//   auditLog.logActivity,
//   securityController.updateEncryptionKey
// );

// // Revoke encryption key
// router.delete('/keys/:keyId', 
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.revokeKeyReason,
//   auditLog.logActivity,
//   securityController.revokeKey  // Changed from revokeEncryptionKey to revokeKey
// );

// // Digital signature operations
// router.post('/signatures/create', 
//   rateLimiting.standard,
//   validation.createSignature,
//   auditLog.logActivity,
//   securityController.createSignature
// );

// router.post('/signatures/verify', 
//   rateLimiting.standard,
//   validation.verifySignature,
//   auditLog.logActivity,
//   securityController.verifySignature
// );

// // Get user's digital signatures
// router.get('/signatures/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserSignatures
// );

// // Get signature by ID
// router.get('/signatures/:signatureId', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getSignatureById
// );

// // Security settings
// router.get('/settings/me', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getSecuritySettings
// );

// router.patch('/settings/me', 
//   rateLimiting.standard,
//   validation.securitySettings,
//   auditLog.logActivity,
//   securityController.updateSecuritySettings
// );

// // Two-factor authentication
// router.get('/2fa/status', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.get2FAStatus
// );

// router.post('/2fa/setup', 
//   rateLimiting.strict,
//   validation.setup2FA,
//   auditLog.logActivity,
//   securityController.setup2FA
// );

// router.post('/2fa/verify-setup', 
//   rateLimiting.strict,
//   validation.verify2FASetup,
//   auditLog.logActivity,
//   securityController.verify2FASetup
// );

// router.post('/2fa/disable', 
//   rateLimiting.strict,
//   validation.disable2FA,
//   auditLog.logActivity,
//   securityController.disable2FA
// );

// router.post('/2fa/backup-codes', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.generateBackupCodes
// );

// // Biometric authentication settings
// router.get('/biometric/status', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getBiometricStatus
// );

// router.post('/biometric/register', 
//   rateLimiting.strict,
//   validation.registerBiometric,
//   auditLog.logActivity,
//   securityController.registerBiometric
// );

// router.delete('/biometric/remove', 
//   rateLimiting.strict,
//   validation.removeBiometric,
//   auditLog.logActivity,
//   securityController.removeBiometric
// );

// // Security events and logs
// router.get('/events/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.securityEventFilters,
//   auditLog.logActivity,
//   securityController.getUserSecurityEvents
// );

// // Login history
// router.get('/logins/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getLoginHistory
// );

// // Device management
// router.get('/devices/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserDevices
// );

// router.delete('/devices/:deviceId', 
//   rateLimiting.strict,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.removeDevice
// );

// router.delete('/devices/all', 
//   rateLimiting.strict,
//   validation.removeAllDevices,
//   auditLog.logActivity,
//   securityController.removeAllDevices
// );

// // Password security
// router.post('/password/check-strength', 
//   rateLimiting.standard,
//   validation.passwordStrengthCheck,
//   securityController.checkPasswordStrength
// );

// router.get('/password/breach-check', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.checkPasswordBreach
// );

// // Security notifications
// router.get('/notifications/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   auditLog.logActivity,
//   securityController.getSecurityNotifications
// );

// router.patch('/notifications/:notificationId/read', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.markNotificationRead
// );

// // Encryption/Decryption operations
// router.post('/encrypt', 
//   rateLimiting.standard,
//   validation.encryptionRequest,
//   auditLog.logActivity,
//   securityController.encryptData
// );

// router.post('/decrypt', 
//   rateLimiting.standard,
//   validation.decryptionRequest,
//   auditLog.logActivity,
//   securityController.decryptData
// );

// // Threshold cryptography
// router.post('/threshold/create', 
//   rateLimiting.strict,
//   validation.thresholdCreate,
//   auditLog.logActivity,
//   securityController.createThresholdEncryption
// );

// router.post('/threshold/decrypt', 
//   rateLimiting.standard,
//   validation.thresholdDecrypt,
//   auditLog.logActivity,
//   securityController.thresholdDecrypt
// );

// // Key verification
// router.post('/keys/verify', 
//   rateLimiting.standard,
//   validation.keyVerification,
//   auditLog.logActivity,
//   securityController.verifyKeyIntegrity
// );

// // Security audit for current user
// router.get('/audit/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.auditFilters,
//   auditLog.logActivity,
//   securityController.getUserSecurityAudit
// );

// // Generate security report
// router.post('/reports/generate', 
//   rateLimiting.strict,
//   validation.securityReportRequest,
//   auditLog.logActivity,
//   securityController.generateSecurityReport
// );

// // Account recovery
// router.post('/recovery/initiate', 
//   rateLimiting.strict,
//   validation.initiateRecovery,
//   auditLog.logActivity,
//   securityController.initiateAccountRecovery
// );

// router.post('/recovery/verify', 
//   rateLimiting.strict,
//   validation.verifyRecovery,
//   auditLog.logActivity,
//   securityController.verifyAccountRecovery
// );

// // Security challenges
// router.post('/challenge/request', 
//   rateLimiting.standard,
//   validation.securityChallenge,
//   auditLog.logActivity,
//   securityController.requestSecurityChallenge
// );

// router.post('/challenge/respond', 
//   rateLimiting.standard,
//   validation.challengeResponse,
//   auditLog.logActivity,
//   securityController.respondSecurityChallenge
// );

// // Activity Log
// router.get('/activity/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserActivityLog
// );

// // Report security incident
// router.post('/incident/report', 
//   rateLimiting.strict,
//   validation.securityIncident,
//   auditLog.logActivity,
//   securityController.reportIncident
// );

// // Admin security routes - require security management permissions
// router.use(rbac.requirePermission('system:security'));

// // System-wide security overview
// router.get('/system/overview', 
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getSystemSecurityOverview
// );

// // All security events (admin)
// router.get('/events/all', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.adminSecurityEventFilters,
//   auditLog.logActivity,
//   securityController.getSecurityEvents  // Changed from getAllSecurityEvents to getSecurityEvents
// );

// // User security management (admin)
// router.get('/users/:userId/security', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getUserSecurityOverview
// );

// // Force key regeneration (admin)
// router.post('/users/:userId/keys/regenerate', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.forceKeyRegeneration,
//   auditLog.logActivity,
//   securityController.forceKeyRegeneration
// );

// // Revoke all user keys (admin)
// router.delete('/users/:userId/keys/all', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.revokeAllKeysReason,
//   auditLog.logActivity,
//   securityController.revokeAllUserKeys
// );

// // Security incident management
// router.get('/incidents', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.incidentFilters,
//   auditLog.logActivity,
//   securityController.getSecurityIncidents
// );

// router.post('/incidents', 
//   rateLimiting.strict,
//   validation.createIncident,
//   auditLog.logActivity,
//   securityController.createSecurityIncident
// );

// router.patch('/incidents/:incidentId', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   validation.updateIncident,
//   auditLog.logActivity,
//   securityController.updateSecurityIncident
// );

// router.post('/incidents/:incidentId/resolve', 
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.resolveIncident,
//   auditLog.logActivity,
//   securityController.resolveSecurityIncident
// );

// // Threat analysis
// router.get('/threats/analysis', 
//   rateLimiting.standard,
//   validation.dateRange,
//   validation.threatFilters,
//   auditLog.logActivity,
//   securityController.getThreatAnalysis
// );

// router.get('/threats/patterns', 
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getThreatPatterns
// );

// // Security analytics
// router.get('/analytics/authentication', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getAuthenticationAnalytics
// );

// router.get('/analytics/encryption', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getEncryptionAnalytics
// );

// router.get('/analytics/violations', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   validation.dateRange,
//   validation.violationFilters,
//   auditLog.logActivity,
//   securityController.getSecurityViolationAnalytics
// );

// // Compliance and audit
// router.get('/compliance/report', 
//   rbac.requirePermission('system:audit'),
//   rateLimiting.strict,
//   validation.complianceReportParams,
//   auditLog.logActivity,
//   securityController.generateComplianceReport
// );

// router.get('/audit/system', 
//   rbac.requirePermission('system:audit'),
//   rateLimiting.standard,
//   validation.pagination,
//   validation.systemAuditFilters,
//   auditLog.logActivity,
//   securityController.getSystemAuditLog
// );

// // Security configuration
// router.get('/config/settings', 
//   rbac.requirePermission('system:config'),
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getSecurityConfiguration
// );

// router.patch('/config/settings', 
//   rbac.requirePermission('system:config'),
//   rateLimiting.strict,
//   validation.securityConfiguration,
//   auditLog.logActivity,
//   securityController.updateSecurityConfiguration
// );

// // Key management (admin)
// router.get('/keys/system', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.standard,
//   validation.pagination,
//   validation.keyFilters,
//   auditLog.logActivity,
//   securityController.getSystemKeys
// );

// router.post('/keys/system/rotate', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   validation.keyRotation,
//   auditLog.logActivity,
//   securityController.rotateSystemKeys
// );

// // Bulk security operations
// router.post('/bulk/reset-2fa', 
//   rbac.requirePermission('users:security:bulk'),
//   rateLimiting.strict,
//   validation.bulkUserIds,
//   validation.bulk2FAResetReason,
//   auditLog.logActivity,
//   securityController.bulkReset2FA
// );

// router.post('/bulk/force-logout', 
//   rbac.requirePermission('users:security:bulk'),
//   rateLimiting.strict,
//   validation.bulkUserIds,
//   validation.bulkLogoutReason,
//   auditLog.logActivity,
//   securityController.bulkForceLogout
// );

// router.post('/bulk/revoke-keys', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   validation.bulkUserIds,
//   validation.bulkRevokeReason,
//   auditLog.logActivity,
//   securityController.bulkRevokeKeys
// );

// // Security monitoring
// router.get('/monitoring/real-time', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getRealTimeSecurityMetrics
// );

// router.get('/monitoring/alerts', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   validation.pagination,
//   validation.alertFilters,
//   auditLog.logActivity,
//   securityController.getSecurityAlerts
// );

// router.post('/monitoring/alerts/:alertId/acknowledge', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.acknowledgeSecurityAlert
// );

// // Export security data
// router.get('/export/events', 
//   rbac.requirePermission('analytics:export'),
//   rateLimiting.strict,
//   validation.exportSecurityData,
//   auditLog.logActivity,
//   securityController.exportSecurityEvents
// );

// router.get('/export/audit', 
//   rbac.requirePermission('analytics:export'),
//   rateLimiting.strict,
//   validation.exportAuditData,
//   auditLog.logActivity,
//   securityController.exportAuditLog
// );

// // Emergency security procedures
// router.post('/emergency/lockdown', 
//   rbac.requirePermission('system:security:emergency'),
//   rateLimiting.emergency,
//   validation.emergencyLockdown,
//   auditLog.logActivity,
//   securityController.emergencyLockdown
// );

// router.post('/emergency/unlock', 
//   rbac.requirePermission('system:security:emergency'),
//   rateLimiting.emergency,
//   validation.emergencyUnlock,
//   auditLog.logActivity,
//   securityController.emergencyUnlock
// );

// // Security health check
// router.get('/health/check', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.securityHealthCheck
// );

// // Vulnerability reporting
// router.post('/vulnerabilities/report', 
//   rateLimiting.strict,
//   validation.vulnerabilityReport,
//   auditLog.logActivity,
//   securityController.reportVulnerability
// );

// router.get('/vulnerabilities', 
//   rbac.requirePermission('system:security:vulnerabilities'),
//   rateLimiting.standard,
//   validation.pagination,
//   validation.vulnerabilityFilters,
//   auditLog.logActivity,
//   securityController.getVulnerabilities
// );

// export default router;
// import express from 'express';
// import * as securityController from '../controllers/securityController.js';
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

// // All security routes require authentication
// router.use(auth.verifyToken);

// // User encryption key management
// router.get('/keys/me', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getUserKeys  // Changed from getCurrentUserKeys to getUserKeys
// );

// // Generate new encryption key pair
// router.post('/keys/generate', 
//   rateLimiting.strict,
//   validation.keyGeneration,
//   auditLog.logActivity,
//   securityController.generateKeyPair
// );

// // Get public key for user
// router.get('/keys/:userId/public', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getUserPublicKey
// );

// // Update encryption key
// router.patch('/keys/:keyId', 
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.updateEncryptionKey,
//   auditLog.logActivity,
//   securityController.updateEncryptionKey
// );

// // Revoke encryption key
// router.delete('/keys/:keyId', 
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.revokeKeyReason,
//   auditLog.logActivity,
//   securityController.revokeKey  // Changed from revokeEncryptionKey to revokeKey
// );

// // Digital signature operations
// router.post('/signatures/create', 
//   rateLimiting.standard,
//   validation.createSignature,
//   auditLog.logActivity,
//   securityController.createSignature
// );

// router.post('/signatures/verify', 
//   rateLimiting.standard,
//   validation.verifySignature,
//   auditLog.logActivity,
//   securityController.verifySignature
// );

// // Get user's digital signatures
// router.get('/signatures/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserSignatures
// );

// // Get signature by ID
// router.get('/signatures/:signatureId', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getSignatureById
// );

// // Security settings
// router.get('/settings/me', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getSecuritySettings
// );

// router.patch('/settings/me', 
//   rateLimiting.standard,
//   validation.securitySettings,
//   auditLog.logActivity,
//   securityController.updateSecuritySettings
// );

// // Two-factor authentication
// router.get('/2fa/status', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.get2FAStatus
// );

// router.post('/2fa/setup', 
//   rateLimiting.strict,
//   validation.setup2FA,
//   auditLog.logActivity,
//   securityController.setup2FA
// );

// router.post('/2fa/verify-setup', 
//   rateLimiting.strict,
//   validation.verify2FASetup,
//   auditLog.logActivity,
//   securityController.verify2FASetup
// );

// router.post('/2fa/disable', 
//   rateLimiting.strict,
//   validation.disable2FA,
//   auditLog.logActivity,
//   securityController.disable2FA
// );

// router.post('/2fa/backup-codes', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.generateBackupCodes
// );

// // Biometric authentication settings
// router.get('/biometric/status', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getBiometricStatus
// );

// router.post('/biometric/register', 
//   rateLimiting.strict,
//   validation.registerBiometric,
//   auditLog.logActivity,
//   securityController.registerBiometric
// );

// router.delete('/biometric/remove', 
//   rateLimiting.strict,
//   validation.removeBiometric,
//   auditLog.logActivity,
//   securityController.removeBiometric
// );

// // Security events and logs
// router.get('/events/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.securityEventFilters,
//   auditLog.logActivity,
//   securityController.getUserSecurityEvents
// );

// // Login history
// router.get('/logins/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getLoginHistory
// );

// // Device management
// router.get('/devices/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserDevices
// );

// router.delete('/devices/:deviceId', 
//   rateLimiting.strict,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.removeDevice
// );

// router.delete('/devices/all', 
//   rateLimiting.strict,
//   validation.removeAllDevices,
//   auditLog.logActivity,
//   securityController.removeAllDevices
// );

// // Password security
// router.post('/password/check-strength', 
//   rateLimiting.standard,
//   validation.passwordStrengthCheck,
//   securityController.checkPasswordStrength
// );

// router.get('/password/breach-check', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.checkPasswordBreach
// );

// // Security notifications
// router.get('/notifications/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   auditLog.logActivity,
//   securityController.getSecurityNotifications
// );

// router.patch('/notifications/:notificationId/read', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.markNotificationRead
// );

// // Encryption/Decryption operations
// router.post('/encrypt', 
//   rateLimiting.standard,
//   validation.encryptionRequest,
//   auditLog.logActivity,
//   securityController.encryptData
// );

// router.post('/decrypt', 
//   rateLimiting.standard,
//   validation.decryptionRequest,
//   auditLog.logActivity,
//   securityController.decryptData
// );

// // Threshold cryptography
// router.post('/threshold/create', 
//   rateLimiting.strict,
//   validation.thresholdCreate,
//   auditLog.logActivity,
//   securityController.createThresholdEncryption
// );

// router.post('/threshold/decrypt', 
//   rateLimiting.standard,
//   validation.thresholdDecrypt,
//   auditLog.logActivity,
//   securityController.thresholdDecrypt
// );

// // Key verification
// router.post('/keys/verify', 
//   rateLimiting.standard,
//   validation.keyVerification,
//   auditLog.logActivity,
//   securityController.verifyKeyIntegrity
// );

// // Security audit for current user
// router.get('/audit/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.auditFilters,
//   auditLog.logActivity,
//   securityController.getUserSecurityAudit
// );

// // Generate security report
// router.post('/reports/generate', 
//   rateLimiting.strict,
//   validation.securityReportRequest,
//   auditLog.logActivity,
//   securityController.generateSecurityReport
// );

// // Account recovery
// router.post('/recovery/initiate', 
//   rateLimiting.strict,
//   validation.initiateRecovery,
//   auditLog.logActivity,
//   securityController.initiateAccountRecovery
// );

// router.post('/recovery/verify', 
//   rateLimiting.strict,
//   validation.verifyRecovery,
//   auditLog.logActivity,
//   securityController.verifyAccountRecovery
// );

// // Security challenges
// router.post('/challenge/request', 
//   rateLimiting.standard,
//   validation.securityChallenge,
//   auditLog.logActivity,
//   securityController.requestSecurityChallenge
// );

// router.post('/challenge/respond', 
//   rateLimiting.standard,
//   validation.challengeResponse,
//   auditLog.logActivity,
//   securityController.respondSecurityChallenge
// );

// // Activity Log
// router.get('/activity/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserActivityLog
// );

// // Report security incident
// router.post('/incident/report', 
//   rateLimiting.strict,
//   validation.securityIncident,
//   auditLog.logActivity,
//   securityController.reportIncident
// );

// // Admin security routes - require security management permissions
// router.use(rbac.requirePermission('system:security'));

// // System-wide security overview
// router.get('/system/overview', 
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getSystemSecurityOverview
// );

// // All security events (admin)
// router.get('/events/all', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.adminSecurityEventFilters,
//   auditLog.logActivity,
//   securityController.getSecurityEvents  // Changed from getAllSecurityEvents to getSecurityEvents
// );

// // User security management (admin)
// router.get('/users/:userId/security', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getUserSecurityOverview
// );

// // Force key regeneration (admin)
// router.post('/users/:userId/keys/regenerate', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.forceKeyRegeneration,
//   auditLog.logActivity,
//   securityController.forceKeyRegeneration
// );

// // Revoke all user keys (admin)
// router.delete('/users/:userId/keys/all', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.revokeAllKeysReason,
//   auditLog.logActivity,
//   securityController.revokeAllUserKeys
// );

// // Security incident management
// router.get('/incidents', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.incidentFilters,
//   auditLog.logActivity,
//   securityController.getSecurityIncidents
// );

// router.post('/incidents', 
//   rateLimiting.strict,
//   validation.createIncident,
//   auditLog.logActivity,
//   securityController.createSecurityIncident
// );

// router.patch('/incidents/:incidentId', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   validation.updateIncident,
//   auditLog.logActivity,
//   securityController.updateSecurityIncident
// );

// router.post('/incidents/:incidentId/resolve', 
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.resolveIncident,
//   auditLog.logActivity,
//   securityController.resolveSecurityIncident
// );

// // Threat analysis
// router.get('/threats/analysis', 
//   rateLimiting.standard,
//   validation.dateRange,
//   validation.threatFilters,
//   auditLog.logActivity,
//   securityController.getThreatAnalysis
// );

// router.get('/threats/patterns', 
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getThreatPatterns
// );

// // Security analytics
// router.get('/analytics/authentication', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getAuthenticationAnalytics
// );

// router.get('/analytics/encryption', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getEncryptionAnalytics
// );

// router.get('/analytics/violations', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   validation.dateRange,
//   validation.violationFilters,
//   auditLog.logActivity,
//   securityController.getSecurityViolationAnalytics
// );

// // Compliance and audit
// router.get('/compliance/report', 
//   rbac.requirePermission('system:audit'),
//   rateLimiting.strict,
//   validation.complianceReportParams,
//   auditLog.logActivity,
//   securityController.generateComplianceReport
// );

// router.get('/audit/system', 
//   rbac.requirePermission('system:audit'),
//   rateLimiting.standard,
//   validation.pagination,
//   validation.systemAuditFilters,
//   auditLog.logActivity,
//   securityController.getSystemAuditLog
// );

// // Security configuration
// router.get('/config/settings', 
//   rbac.requirePermission('system:config'),
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getSecurityConfiguration
// );

// router.patch('/config/settings', 
//   rbac.requirePermission('system:config'),
//   rateLimiting.strict,
//   validation.securityConfiguration,
//   auditLog.logActivity,
//   securityController.updateSecurityConfiguration
// );

// // Key management (admin)
// router.get('/keys/system', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.standard,
//   validation.pagination,
//   validation.keyFilters,
//   auditLog.logActivity,
//   securityController.getSystemKeys
// );

// router.post('/keys/system/rotate', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   validation.keyRotation,
//   auditLog.logActivity,
//   securityController.rotateSystemKeys
// );

// // Bulk security operations
// router.post('/bulk/reset-2fa', 
//   rbac.requirePermission('users:security:bulk'),
//   rateLimiting.strict,
//   validation.bulkUserIds,
//   validation.bulk2FAResetReason,
//   auditLog.logActivity,
//   securityController.bulkReset2FA
// );

// router.post('/bulk/force-logout', 
//   rbac.requirePermission('users:security:bulk'),
//   rateLimiting.strict,
//   validation.bulkUserIds,
//   validation.bulkLogoutReason,
//   auditLog.logActivity,
//   securityController.bulkForceLogout
// );

// router.post('/bulk/revoke-keys', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   validation.bulkUserIds,
//   validation.bulkRevokeReason,
//   auditLog.logActivity,
//   securityController.bulkRevokeKeys
// );

// // Security monitoring
// router.get('/monitoring/real-time', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getRealTimeSecurityMetrics
// );

// router.get('/monitoring/alerts', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   validation.pagination,
//   validation.alertFilters,
//   auditLog.logActivity,
//   securityController.getSecurityAlerts
// );

// router.post('/monitoring/alerts/:alertId/acknowledge', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.acknowledgeSecurityAlert
// );

// // Export security data
// router.get('/export/events', 
//   rbac.requirePermission('analytics:export'),
//   rateLimiting.strict,
//   validation.exportSecurityData,
//   auditLog.logActivity,
//   securityController.exportSecurityEvents
// );

// router.get('/export/audit', 
//   rbac.requirePermission('analytics:export'),
//   rateLimiting.strict,
//   validation.exportAuditData,
//   auditLog.logActivity,
//   securityController.exportAuditLog
// );

// // Emergency security procedures
// router.post('/emergency/lockdown', 
//   rbac.requirePermission('system:security:emergency'),
//   rateLimiting.emergency,
//   validation.emergencyLockdown,
//   auditLog.logActivity,
//   securityController.emergencyLockdown
// );

// router.post('/emergency/unlock', 
//   rbac.requirePermission('system:security:emergency'),
//   rateLimiting.emergency,
//   validation.emergencyUnlock,
//   auditLog.logActivity,
//   securityController.emergencyUnlock
// );

// // Security health check
// router.get('/health/check', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.securityHealthCheck
// );

// // Vulnerability reporting
// router.post('/vulnerabilities/report', 
//   rateLimiting.strict,
//   validation.vulnerabilityReport,
//   auditLog.logActivity,
//   securityController.reportVulnerability
// );

// router.get('/vulnerabilities', 
//   rbac.requirePermission('system:security:vulnerabilities'),
//   rateLimiting.standard,
//   validation.pagination,
//   validation.vulnerabilityFilters,
//   auditLog.logActivity,
//   securityController.getVulnerabilities
// );

// export default router;
// import express from 'express';
// import * as securityController from '../controllers/securityController.js';
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

// // All security routes require authentication
// router.use(auth.verifyToken);

// // User encryption key management
// router.get('/keys/me', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getCurrentUserKeys
// );

// // Generate new encryption key pair
// router.post('/keys/generate', 
//   rateLimiting.strict,
//   validation.keyGeneration,
//   auditLog.logActivity,
//   securityController.generateKeyPair
// );

// // Get public key for user
// router.get('/keys/:userId/public', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getUserPublicKey
// );

// // Update encryption key
// router.patch('/keys/:keyId', 
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.updateEncryptionKey,
//   auditLog.logActivity,
//   securityController.updateEncryptionKey
// );

// // Revoke encryption key
// router.delete('/keys/:keyId', 
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.revokeKeyReason,
//   auditLog.logActivity,
//   securityController.revokeEncryptionKey
// );

// // Digital signature operations
// router.post('/signatures/create', 
//   rateLimiting.standard,
//   validation.createSignature,
//   auditLog.logActivity,
//   securityController.createDigitalSignature
// );

// router.post('/signatures/verify', 
//   rateLimiting.standard,
//   validation.verifySignature,
//   auditLog.logActivity,
//   securityController.verifyDigitalSignature
// );

// // Get user's digital signatures
// router.get('/signatures/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserSignatures
// );

// // Get signature by ID
// router.get('/signatures/:signatureId', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getSignatureById
// );

// // Security settings
// router.get('/settings/me', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getSecuritySettings
// );

// router.patch('/settings/me', 
//   rateLimiting.standard,
//   validation.securitySettings,
//   auditLog.logActivity,
//   securityController.updateSecuritySettings
// );

// // Two-factor authentication
// router.get('/2fa/status', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.get2FAStatus
// );

// router.post('/2fa/setup', 
//   rateLimiting.strict,
//   validation.setup2FA,
//   auditLog.logActivity,
//   securityController.setup2FA
// );

// router.post('/2fa/verify-setup', 
//   rateLimiting.strict,
//   validation.verify2FASetup,
//   auditLog.logActivity,
//   securityController.verify2FASetup
// );

// router.post('/2fa/disable', 
//   rateLimiting.strict,
//   validation.disable2FA,
//   auditLog.logActivity,
//   securityController.disable2FA
// );

// router.post('/2fa/backup-codes', 
//   rateLimiting.strict,
//   auditLog.logActivity,
//   securityController.generateBackupCodes
// );

// // Biometric authentication settings
// router.get('/biometric/status', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getBiometricStatus
// );

// router.post('/biometric/register', 
//   rateLimiting.strict,
//   validation.registerBiometric,
//   auditLog.logActivity,
//   securityController.registerBiometric
// );

// router.delete('/biometric/remove', 
//   rateLimiting.strict,
//   validation.removeBiometric,
//   auditLog.logActivity,
//   securityController.removeBiometric
// );

// // Security events and logs
// router.get('/events/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.securityEventFilters,
//   auditLog.logActivity,
//   securityController.getUserSecurityEvents
// );

// // Login history
// router.get('/logins/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getLoginHistory
// );

// // Device management
// router.get('/devices/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   auditLog.logActivity,
//   securityController.getUserDevices
// );

// router.delete('/devices/:deviceId', 
//   rateLimiting.strict,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.removeDevice
// );

// router.delete('/devices/all', 
//   rateLimiting.strict,
//   validation.removeAllDevices,
//   auditLog.logActivity,
//   securityController.removeAllDevices
// );

// // Password security
// router.post('/password/check-strength', 
//   rateLimiting.standard,
//   validation.passwordStrengthCheck,
//   securityController.checkPasswordStrength
// );

// router.get('/password/breach-check', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.checkPasswordBreach
// );

// // Security notifications
// router.get('/notifications/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   auditLog.logActivity,
//   securityController.getSecurityNotifications
// );

// router.patch('/notifications/:notificationId/read', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.markNotificationRead
// );

// // Encryption/Decryption operations
// router.post('/encrypt', 
//   rateLimiting.standard,
//   validation.encryptionRequest,
//   auditLog.logActivity,
//   securityController.encryptData
// );

// router.post('/decrypt', 
//   rateLimiting.standard,
//   validation.decryptionRequest,
//   auditLog.logActivity,
//   securityController.decryptData
// );

// // Threshold cryptography
// router.post('/threshold/create', 
//   rateLimiting.strict,
//   validation.thresholdCreate,
//   auditLog.logActivity,
//   securityController.createThresholdEncryption
// );

// router.post('/threshold/decrypt', 
//   rateLimiting.standard,
//   validation.thresholdDecrypt,
//   auditLog.logActivity,
//   securityController.thresholdDecrypt
// );

// // Key verification
// router.post('/keys/verify', 
//   rateLimiting.standard,
//   validation.keyVerification,
//   auditLog.logActivity,
//   securityController.verifyKeyIntegrity
// );

// // Security audit for current user
// router.get('/audit/me', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.auditFilters,
//   auditLog.logActivity,
//   securityController.getUserSecurityAudit
// );

// // Generate security report
// router.post('/reports/generate', 
//   rateLimiting.strict,
//   validation.securityReportRequest,
//   auditLog.logActivity,
//   securityController.generateSecurityReport
// );

// // Account recovery
// router.post('/recovery/initiate', 
//   rateLimiting.strict,
//   validation.initiateRecovery,
//   auditLog.logActivity,
//   securityController.initiateAccountRecovery
// );

// router.post('/recovery/verify', 
//   rateLimiting.strict,
//   validation.verifyRecovery,
//   auditLog.logActivity,
//   securityController.verifyAccountRecovery
// );

// // Security challenges
// router.post('/challenge/request', 
//   rateLimiting.standard,
//   validation.securityChallenge,
//   auditLog.logActivity,
//   securityController.requestSecurityChallenge
// );

// router.post('/challenge/respond', 
//   rateLimiting.standard,
//   validation.challengeResponse,
//   auditLog.logActivity,
//   securityController.respondSecurityChallenge
// );

// // Admin security routes - require security management permissions
// router.use(rbac.requirePermission('system:security'));

// // System-wide security overview
// router.get('/system/overview', 
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getSystemSecurityOverview
// );

// // All security events (admin)
// router.get('/events/all', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.adminSecurityEventFilters,
//   auditLog.logActivity,
//   securityController.getAllSecurityEvents
// );

// // User security management (admin)
// router.get('/users/:userId/security', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.getUserSecurityOverview
// );

// // Force key regeneration (admin)
// router.post('/users/:userId/keys/regenerate', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.forceKeyRegeneration,
//   auditLog.logActivity,
//   securityController.forceKeyRegeneration
// );

// // Revoke all user keys (admin)
// router.delete('/users/:userId/keys/all', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.revokeAllKeysReason,
//   auditLog.logActivity,
//   securityController.revokeAllUserKeys
// );

// // Security incident management
// router.get('/incidents', 
//   rateLimiting.standard,
//   validation.pagination,
//   validation.incidentFilters,
//   auditLog.logActivity,
//   securityController.getSecurityIncidents
// );

// router.post('/incidents', 
//   rateLimiting.strict,
//   validation.createIncident,
//   auditLog.logActivity,
//   securityController.createSecurityIncident
// );

// router.patch('/incidents/:incidentId', 
//   rateLimiting.standard,
//   validation.validateObjectId,
//   validation.updateIncident,
//   auditLog.logActivity,
//   securityController.updateSecurityIncident
// );

// router.post('/incidents/:incidentId/resolve', 
//   rateLimiting.strict,
//   validation.validateObjectId,
//   validation.resolveIncident,
//   auditLog.logActivity,
//   securityController.resolveSecurityIncident
// );

// // Threat analysis
// router.get('/threats/analysis', 
//   rateLimiting.standard,
//   validation.dateRange,
//   validation.threatFilters,
//   auditLog.logActivity,
//   securityController.getThreatAnalysis
// );

// router.get('/threats/patterns', 
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getThreatPatterns
// );

// // Security analytics
// router.get('/analytics/authentication', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getAuthenticationAnalytics
// );

// router.get('/analytics/encryption', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   validation.dateRange,
//   auditLog.logActivity,
//   securityController.getEncryptionAnalytics
// );

// router.get('/analytics/violations', 
//   rbac.requirePermission('analytics:view'),
//   rateLimiting.standard,
//   validation.dateRange,
//   validation.violationFilters,
//   auditLog.logActivity,
//   securityController.getSecurityViolationAnalytics
// );

// // Compliance and audit
// router.get('/compliance/report', 
//   rbac.requirePermission('system:audit'),
//   rateLimiting.strict,
//   validation.complianceReportParams,
//   auditLog.logActivity,
//   securityController.generateComplianceReport
// );

// router.get('/audit/system', 
//   rbac.requirePermission('system:audit'),
//   rateLimiting.standard,
//   validation.pagination,
//   validation.systemAuditFilters,
//   auditLog.logActivity,
//   securityController.getSystemAuditLog
// );

// // Security configuration
// router.get('/config/settings', 
//   rbac.requirePermission('system:config'),
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getSecurityConfiguration
// );

// router.patch('/config/settings', 
//   rbac.requirePermission('system:config'),
//   rateLimiting.strict,
//   validation.securityConfiguration,
//   auditLog.logActivity,
//   securityController.updateSecurityConfiguration
// );

// // Key management (admin)
// router.get('/keys/system', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.standard,
//   validation.pagination,
//   validation.keyFilters,
//   auditLog.logActivity,
//   securityController.getSystemKeys
// );

// router.post('/keys/system/rotate', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   validation.keyRotation,
//   auditLog.logActivity,
//   securityController.rotateSystemKeys
// );

// // Bulk security operations
// router.post('/bulk/reset-2fa', 
//   rbac.requirePermission('users:security:bulk'),
//   rateLimiting.strict,
//   validation.bulkUserIds,
//   validation.bulk2FAResetReason,
//   auditLog.logActivity,
//   securityController.bulkReset2FA
// );

// router.post('/bulk/force-logout', 
//   rbac.requirePermission('users:security:bulk'),
//   rateLimiting.strict,
//   validation.bulkUserIds,
//   validation.bulkLogoutReason,
//   auditLog.logActivity,
//   securityController.bulkForceLogout
// );

// router.post('/bulk/revoke-keys', 
//   rbac.requirePermission('system:security:keys'),
//   rateLimiting.strict,
//   validation.bulkUserIds,
//   validation.bulkRevokeReason,
//   auditLog.logActivity,
//   securityController.bulkRevokeKeys
// );

// // Security monitoring
// router.get('/monitoring/real-time', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.getRealTimeSecurityMetrics
// );

// router.get('/monitoring/alerts', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   validation.pagination,
//   validation.alertFilters,
//   auditLog.logActivity,
//   securityController.getSecurityAlerts
// );

// router.post('/monitoring/alerts/:alertId/acknowledge', 
//   rbac.requirePermission('system:security:monitor'),
//   rateLimiting.standard,
//   validation.validateObjectId,
//   auditLog.logActivity,
//   securityController.acknowledgeSecurityAlert
// );

// // Export security data
// router.get('/export/events', 
//   rbac.requirePermission('analytics:export'),
//   rateLimiting.strict,
//   validation.exportSecurityData,
//   auditLog.logActivity,
//   securityController.exportSecurityEvents
// );

// router.get('/export/audit', 
//   rbac.requirePermission('analytics:export'),
//   rateLimiting.strict,
//   validation.exportAuditData,
//   auditLog.logActivity,
//   securityController.exportAuditLog
// );

// // Emergency security procedures
// router.post('/emergency/lockdown', 
//   rbac.requirePermission('system:security:emergency'),
//   rateLimiting.emergency,
//   validation.emergencyLockdown,
//   auditLog.logActivity,
//   securityController.emergencyLockdown
// );

// router.post('/emergency/unlock', 
//   rbac.requirePermission('system:security:emergency'),
//   rateLimiting.emergency,
//   validation.emergencyUnlock,
//   auditLog.logActivity,
//   securityController.emergencyUnlock
// );

// // Security health check
// router.get('/health/check', 
//   rateLimiting.standard,
//   auditLog.logActivity,
//   securityController.securityHealthCheck
// );

// // Vulnerability reporting
// router.post('/vulnerabilities/report', 
//   rateLimiting.strict,
//   validation.vulnerabilityReport,
//   auditLog.logActivity,
//   securityController.reportVulnerability
// );

// router.get('/vulnerabilities', 
//   rbac.requirePermission('system:security:vulnerabilities'),
//   rateLimiting.standard,
//   validation.pagination,
//   validation.vulnerabilityFilters,
//   auditLog.logActivity,
//   securityController.getVulnerabilities
// );

// export default router;