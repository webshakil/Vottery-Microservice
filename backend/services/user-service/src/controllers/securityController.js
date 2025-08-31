import models from '../models/index.js';
import { Op } from 'sequelize';

const { 
  UserActivityLog, 
  SecurityEvent, 
  EncryptionKey,
  DigitalSignature 
} = models;
import securityService from '../services/securityService.js';
import encryptionService from '../services/encryptionService.js';
import signatureService from '../services/signatureService.js';
import auditService from '../services/auditService.js';
//import validateInput from '../middleware/validation.js';
import { APIResponse } from '../utils/response.js';
import logger from '../utils/logger.js';
import { USER_ACTIONS, HTTP_STATUS, SECURITY_EVENTS } from '../utils/constants.js';

class SecurityController {
  /**
   * Get user activity log
   */
  async getUserActivityLog(req, res, next) {
    try {
      const userId = req.user.id;
      const {
        page = 1,
        limit = 50,
        category = '',
        action = '',
        start_date = '',
        end_date = '',
        severity = ''
      } = req.query;

      const whereClause = { user_id: userId };
      
      if (category) whereClause.category = category;
      if (action) whereClause.action = action;
      if (severity) whereClause.severity = severity;
      
      if (start_date && end_date) {
        whereClause.created_at = {
          [Op.between]: [new Date(start_date), new Date(end_date)]
        };
      }

      const offset = (page - 1) * limit;

      const { rows: activities, count } = await UserActivityLog.findAndCountAll({
        where: whereClause,
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [['created_at', 'DESC']],
        attributes: { exclude: ['user_agent'] }
      });

      const totalPages = Math.ceil(count / limit);

      return APIResponse.success(res, {
        activities,
        pagination: {
          current_page: parseInt(page),
          total_pages: totalPages,
          total_count: count,
          limit: parseInt(limit)
        }
      }, 'Activity log retrieved successfully');

    } catch (error) {
      logger.error('Error getting activity log:', error);
      return next(error);
    }
  }

  /**
   * Get security events (admin)
   */
  async getSecurityEvents(req, res, next) {
    try {
      const {
        page = 1,
        limit = 50,
        event_type = '',
        severity = '',
        start_date = '',
        end_date = '',
        user_id = ''
      } = req.query;

      const whereClause = {};
      
      if (event_type) whereClause.event_type = event_type;
      if (severity) whereClause.severity = severity;
      if (user_id) whereClause.user_id = user_id;
      
      if (start_date && end_date) {
        whereClause.created_at = {
          [Op.between]: [new Date(start_date), new Date(end_date)]
        };
      }

      const offset = (page - 1) * limit;

      const { rows: events, count } = await SecurityEvent.findAndCountAll({
        where: whereClause,
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [['created_at', 'DESC']]
      });

      const totalPages = Math.ceil(count / limit);

      return APIResponse.success(res, {
        events,
        pagination: {
          current_page: parseInt(page),
          total_pages: totalPages,
          total_count: count,
          limit: parseInt(limit)
        }
      }, 'Security events retrieved successfully');

    } catch (error) {
      logger.error('Error getting security events:', error);
      return next(error);
    }
  }

  /**
   * Generate encryption key pair
   */
  async generateKeyPair(req, res, next) {
    try {
      const userId = req.user.id;
      const { key_type = 'rsa', key_size = 2048, purpose = 'user_data' } = req.body;

      // Generate key pair through service
      const keyPair = await encryptionService.generateKeyPair(key_type, key_size, purpose, userId);

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.KEY_GENERATE,
        category: 'security',
        severity: 'medium',
        resource_type: 'encryption_key',
        resource_id: keyPair.id,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { key_type, key_size, purpose }
      });

      return APIResponse.success(res, {
        key_id: keyPair.key_id,
        public_key: keyPair.public_key,
        key_type: keyPair.key_type,
        algorithm: keyPair.algorithm,
        created_at: keyPair.created_at
      }, 'Key pair generated successfully', HTTP_STATUS.CREATED);

    } catch (error) {
      logger.error('Error generating key pair:', error);
      return next(error);
    }
  }

  /**
   * Get user encryption keys
   */
  async getUserKeys(req, res, next) {
    try {
      const userId = req.user.id;

      const keys = await EncryptionKey.findAll({
        where: {
          owner_id: userId,
          status: 'active'
        },
        attributes: [
          'id', 'key_id', 'key_type', 'purpose', 'algorithm', 
          'key_size', 'status', 'usage_count', 'created_at', 'expires_at'
        ],
        order: [['created_at', 'DESC']]
      });

      return APIResponse.success(res, keys, 'Encryption keys retrieved successfully');

    } catch (error) {
      logger.error('Error getting user keys:', error);
      return next(error);
    }
  }

  /**
   * Get user public key
   */
  async getUserPublicKey(req, res, next) {
    try {
      const { userId } = req.params;

      const key = await EncryptionKey.findOne({
        where: {
          owner_id: userId,
          status: 'active',
          key_type: 'rsa'
        },
        attributes: ['public_key', 'key_id', 'algorithm', 'created_at']
      });

      if (!key) {
        return APIResponse.error(res, 'Public key not found', HTTP_STATUS.NOT_FOUND);
      }

      return APIResponse.success(res, key, 'Public key retrieved successfully');

    } catch (error) {
      logger.error('Error getting user public key:', error);
      return next(error);
    }
  }

  /**
   * Update encryption key
   */
  async updateEncryptionKey(req, res, next) {
    try {
      const { keyId } = req.params;
      const userId = req.user.id;
      const updateData = req.body;

      const key = await EncryptionKey.findOne({
        where: {
          id: keyId,
          owner_id: userId
        }
      });

      if (!key) {
        return APIResponse.error(res, 'Key not found', HTTP_STATUS.NOT_FOUND);
      }

      await key.update(updateData);

      return APIResponse.success(res, key, 'Encryption key updated successfully');

    } catch (error) {
      logger.error('Error updating encryption key:', error);
      return next(error);
    }
  }

  /**
   * Revoke encryption key
   */
  async revokeKey(req, res, next) {
    try {
      const { keyId } = req.params;
      const userId = req.user.id;

      const key = await EncryptionKey.findOne({
        where: {
          id: keyId,
          owner_id: userId
        }
      });

      if (!key) {
        return APIResponse.error(res, 'Key not found', HTTP_STATUS.NOT_FOUND);
      }

      if (key.status === 'compromised') {
        return APIResponse.error(res, 'Key is already compromised', HTTP_STATUS.BAD_REQUEST);
      }

      await key.update({ status: 'compromised' });

      // Log security event
      await securityService.logSecurityEvent({
        user_id: userId,
        event_type: SECURITY_EVENTS.KEY_REVOKED,
        severity: 'high',
        description: 'Encryption key manually revoked',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { key_id: key.key_id, key_type: key.key_type }
      });

      return APIResponse.success(res, null, 'Key revoked successfully');

    } catch (error) {
      logger.error('Error revoking key:', error);
      return next(error);
    }
  }

  /**
   * Create digital signature
   */
  async createSignature(req, res, next) {
    try {
      const userId = req.user.id;
      const { data, key_id } = req.body;

      if (!data || !key_id) {
        return APIResponse.error(res, 'Data and key ID are required', HTTP_STATUS.BAD_REQUEST);
      }

      // Create signature through service
      const signature = await signatureService.createSignature(data, key_id, userId);

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.SIGNATURE_CREATE,
        category: 'security',
        severity: 'medium',
        resource_type: 'digital_signature',
        resource_id: signature.id,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { key_id, data_hash: signature.data_hash }
      });

      return APIResponse.success(res, signature, 'Digital signature created successfully', HTTP_STATUS.CREATED);

    } catch (error) {
      logger.error('Error creating signature:', error);
      return next(error);
    }
  }

  /**
   * Verify digital signature
   */
  async verifySignature(req, res, next) {
    try {
      const { data, signature_id } = req.body;

      if (!data || !signature_id) {
        return APIResponse.error(res, 'Data and signature ID are required', HTTP_STATUS.BAD_REQUEST);
      }

      const signature = await DigitalSignature.findByPk(signature_id);

      if (!signature) {
        return APIResponse.error(res, 'Signature not found', HTTP_STATUS.NOT_FOUND);
      }

      // Verify signature through service
      const isValid = await signatureService.verifySignature(signature, data);

      // Update verification count
      await signature.increment('verification_count');

      // Log activity
      await auditService.logActivity({
        user_id: req.user.id,
        action: USER_ACTIONS.SIGNATURE_VERIFY,
        category: 'security',
        severity: 'low',
        resource_type: 'digital_signature',
        resource_id: signature_id,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { verification_result: isValid }
      });

      return APIResponse.success(res, { 
        is_valid: isValid,
        signature_id: signature_id,
        verified_at: new Date()
      }, 'Signature verification completed');

    } catch (error) {
      logger.error('Error verifying signature:', error);
      return next(error);
    }
  }

  /**
   * Get user signatures
   */
  async getUserSignatures(req, res, next) {
    try {
      const userId = req.user.id;
      const { page = 1, limit = 50 } = req.query;
      const offset = (page - 1) * limit;

      const { rows: signatures, count } = await DigitalSignature.findAndCountAll({
        where: { signer_id: userId },
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [['created_at', 'DESC']],
        attributes: { exclude: ['signature_value'] }
      });

      const totalPages = Math.ceil(count / limit);

      return APIResponse.success(res, {
        signatures,
        pagination: {
          current_page: parseInt(page),
          total_pages: totalPages,
          total_count: count,
          limit: parseInt(limit)
        }
      }, 'User signatures retrieved successfully');

    } catch (error) {
      logger.error('Error getting user signatures:', error);
      return next(error);
    }
  }

  /**
   * Get signature by ID
   */
  async getSignatureById(req, res, next) {
    try {
      const { signatureId } = req.params;
      const userId = req.user.id;

      const signature = await DigitalSignature.findOne({
        where: {
          id: signatureId,
          signer_id: userId
        }
      });

      if (!signature) {
        return APIResponse.error(res, 'Signature not found', HTTP_STATUS.NOT_FOUND);
      }

      return APIResponse.success(res, signature, 'Signature retrieved successfully');

    } catch (error) {
      logger.error('Error getting signature:', error);
      return next(error);
    }
  }

  /**
   * Get security settings
   */
  async getSecuritySettings(req, res, next) {
    try {
      const userId = req.user.id;

      const settings = await securityService.getUserSecuritySettings(userId);

      return APIResponse.success(res, settings, 'Security settings retrieved successfully');

    } catch (error) {
      logger.error('Error getting security settings:', error);
      return next(error);
    }
  }

  /**
   * Update security settings
   */
  async updateSecuritySettings(req, res, next) {
    try {
      const userId = req.user.id;
      const settingsData = req.body;

      await securityService.updateUserSecuritySettings(userId, settingsData);

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.SECURITY_SETTINGS_UPDATE,
        category: 'security',
        severity: 'medium',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        new_values: settingsData
      });

      return APIResponse.success(res, null, 'Security settings updated successfully');

    } catch (error) {
      logger.error('Error updating security settings:', error);
      return next(error);
    }
  }

  /**
   * Get 2FA status
   */
  async get2FAStatus(req, res, next) {
    try {
      const userId = req.user.id;
      const status = await securityService.get2FAStatus(userId);
      return APIResponse.success(res, status, '2FA status retrieved successfully');
    } catch (error) {
      logger.error('Error getting 2FA status:', error);
      return next(error);
    }
  }

  /**
   * Setup 2FA
   */
  async setup2FA(req, res, next) {
    try {
      const userId = req.user.id;
      const result = await securityService.setup2FA(userId);
      return APIResponse.success(res, result, '2FA setup initiated');
    } catch (error) {
      logger.error('Error setting up 2FA:', error);
      return next(error);
    }
  }

  /**
   * Verify 2FA setup
   */
  async verify2FASetup(req, res, next) {
    try {
      const userId = req.user.id;
      const { token } = req.body;
      const result = await securityService.verify2FASetup(userId, token);
      return APIResponse.success(res, result, '2FA verified successfully');
    } catch (error) {
      logger.error('Error verifying 2FA setup:', error);
      return next(error);
    }
  }

  /**
   * Disable 2FA
   */
  async disable2FA(req, res, next) {
    try {
      const userId = req.user.id;
      const { password } = req.body;
      await securityService.disable2FA(userId, password);
      return APIResponse.success(res, null, '2FA disabled successfully');
    } catch (error) {
      logger.error('Error disabling 2FA:', error);
      return next(error);
    }
  }

  /**
   * Generate backup codes
   */
  async generateBackupCodes(req, res, next) {
    try {
      const userId = req.user.id;
      const codes = await securityService.generateBackupCodes(userId);
      return APIResponse.success(res, { backup_codes: codes }, 'Backup codes generated successfully');
    } catch (error) {
      logger.error('Error generating backup codes:', error);
      return next(error);
    }
  }

  /**
   * Get biometric status
   */
  async getBiometricStatus(req, res, next) {
    try {
      const userId = req.user.id;
      const status = await securityService.getBiometricStatus(userId);
      return APIResponse.success(res, status, 'Biometric status retrieved successfully');
    } catch (error) {
      logger.error('Error getting biometric status:', error);
      return next(error);
    }
  }

  /**
   * Register biometric
   */
  async registerBiometric(req, res, next) {
    try {
      const userId = req.user.id;
      const biometricData = req.body;
      const result = await securityService.registerBiometric(userId, biometricData);
      return APIResponse.success(res, result, 'Biometric registered successfully');
    } catch (error) {
      logger.error('Error registering biometric:', error);
      return next(error);
    }
  }

  /**
   * Remove biometric
   */
  async removeBiometric(req, res, next) {
    try {
      const userId = req.user.id;
      const { biometric_type } = req.body;
      await securityService.removeBiometric(userId, biometric_type);
      return APIResponse.success(res, null, 'Biometric removed successfully');
    } catch (error) {
      logger.error('Error removing biometric:', error);
      return next(error);
    }
  }

  /**
   * Get user security events
   */
  async getUserSecurityEvents(req, res, next) {
    try {
      const userId = req.user.id;
      const { page = 1, limit = 50 } = req.query;
      const offset = (page - 1) * limit;

      const { rows: events, count } = await SecurityEvent.findAndCountAll({
        where: { user_id: userId },
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [['created_at', 'DESC']]
      });

      return APIResponse.success(res, {
        events,
        pagination: {
          current_page: parseInt(page),
          total_pages: Math.ceil(count / limit),
          total_count: count,
          limit: parseInt(limit)
        }
      }, 'User security events retrieved successfully');

    } catch (error) {
      logger.error('Error getting user security events:', error);
      return next(error);
    }
  }

  /**
   * Get login history
   */
  async getLoginHistory(req, res, next) {
    try {
      const userId = req.user.id;
      const { page = 1, limit = 50 } = req.query;
      const history = await securityService.getLoginHistory(userId, { page, limit });
      return APIResponse.success(res, history, 'Login history retrieved successfully');
    } catch (error) {
      logger.error('Error getting login history:', error);
      return next(error);
    }
  }

  /**
   * Get user devices
   */
  async getUserDevices(req, res, next) {
    try {
      const userId = req.user.id;
      const { page = 1, limit = 50 } = req.query;
      const devices = await securityService.getUserDevices(userId, { page, limit });
      return APIResponse.success(res, devices, 'User devices retrieved successfully');
    } catch (error) {
      logger.error('Error getting user devices:', error);
      return next(error);
    }
  }

  /**
   * Remove device
   */
  async removeDevice(req, res, next) {
    try {
      const userId = req.user.id;
      const { deviceId } = req.params;
      await securityService.removeDevice(userId, deviceId);
      return APIResponse.success(res, null, 'Device removed successfully');
    } catch (error) {
      logger.error('Error removing device:', error);
      return next(error);
    }
  }

  /**
   * Remove all devices
   */
  async removeAllDevices(req, res, next) {
    try {
      const userId = req.user.id;
      await securityService.removeAllDevices(userId);
      return APIResponse.success(res, null, 'All devices removed successfully');
    } catch (error) {
      logger.error('Error removing all devices:', error);
      return next(error);
    }
  }

  /**
   * Check password strength
   */
  async checkPasswordStrength(req, res, next) {
    try {
      const { password } = req.body;
      const strength = await securityService.checkPasswordStrength(password);
      return APIResponse.success(res, strength, 'Password strength checked');
    } catch (error) {
      logger.error('Error checking password strength:', error);
      return next(error);
    }
  }

  /**
   * Check password breach
   */
  async checkPasswordBreach(req, res, next) {
    try {
      const userId = req.user.id;
      const result = await securityService.checkPasswordBreach(userId);
      return APIResponse.success(res, result, 'Password breach check completed');
    } catch (error) {
      logger.error('Error checking password breach:', error);
      return next(error);
    }
  }

  /**
   * Get security notifications
   */
  async getSecurityNotifications(req, res, next) {
    try {
      const userId = req.user.id;
      const { page = 1, limit = 50 } = req.query;
      const notifications = await securityService.getSecurityNotifications(userId, { page, limit });
      return APIResponse.success(res, notifications, 'Security notifications retrieved successfully');
    } catch (error) {
      logger.error('Error getting security notifications:', error);
      return next(error);
    }
  }

  /**
   * Mark notification as read
   */
  async markNotificationRead(req, res, next) {
    try {
      const userId = req.user.id;
      const { notificationId } = req.params;
      await securityService.markNotificationRead(userId, notificationId);
      return APIResponse.success(res, null, 'Notification marked as read');
    } catch (error) {
      logger.error('Error marking notification as read:', error);
      return next(error);
    }
  }

  /**
   * Encrypt data
   */
  async encryptData(req, res, next) {
    try {
      const userId = req.user.id;
      const { data, key_id } = req.body;
      const result = await encryptionService.encryptData(data, key_id, userId);
      return APIResponse.success(res, result, 'Data encrypted successfully');
    } catch (error) {
      logger.error('Error encrypting data:', error);
      return next(error);
    }
  }

  /**
   * Decrypt data
   */
  async decryptData(req, res, next) {
    try {
      const userId = req.user.id;
      const { encrypted_data, key_id } = req.body;
      const result = await encryptionService.decryptData(encrypted_data, key_id, userId);
      return APIResponse.success(res, result, 'Data decrypted successfully');
    } catch (error) {
      logger.error('Error decrypting data:', error);
      return next(error);
    }
  }

  /**
   * Create threshold encryption
   */
  async createThresholdEncryption(req, res, next) {
    try {
      const userId = req.user.id;
      const thresholdData = req.body;
      const result = await encryptionService.createThresholdEncryption(userId, thresholdData);
      return APIResponse.success(res, result, 'Threshold encryption created successfully');
    } catch (error) {
      logger.error('Error creating threshold encryption:', error);
      return next(error);
    }
  }

  /**
   * Threshold decrypt
   */
  async thresholdDecrypt(req, res, next) {
    try {
      const userId = req.user.id;
      const decryptData = req.body;
      const result = await encryptionService.thresholdDecrypt(userId, decryptData);
      return APIResponse.success(res, result, 'Threshold decryption completed');
    } catch (error) {
      logger.error('Error in threshold decryption:', error);
      return next(error);
    }
  }

  /**
   * Verify key integrity
   */
  async verifyKeyIntegrity(req, res, next) {
    try {
      const userId = req.user.id;
      const { key_id } = req.body;
      const result = await encryptionService.verifyKeyIntegrity(key_id, userId);
      return APIResponse.success(res, result, 'Key integrity verified');
    } catch (error) {
      logger.error('Error verifying key integrity:', error);
      return next(error);
    }
  }

  /**
   * Get user security audit
   */
  async getUserSecurityAudit(req, res, next) {
    try {
      const userId = req.user.id;
      const { page = 1, limit = 50 } = req.query;
      const audit = await auditService.getUserSecurityAudit(userId, { page, limit });
      return APIResponse.success(res, audit, 'Security audit retrieved successfully');
    } catch (error) {
      logger.error('Error getting security audit:', error);
      return next(error);
    }
  }

  /**
   * Generate security report
   */
  async generateSecurityReport(req, res, next) {
    try {
      const userId = req.user.id;
      const reportParams = req.body;
      const report = await securityService.generateSecurityReport(userId, reportParams);
      return APIResponse.success(res, report, 'Security report generated successfully');
    } catch (error) {
      logger.error('Error generating security report:', error);
      return next(error);
    }
  }

  /**
   * Initiate account recovery
   */
  async initiateAccountRecovery(req, res, next) {
    try {
      const recoveryData = req.body;
      const result = await securityService.initiateAccountRecovery(recoveryData);
      return APIResponse.success(res, result, 'Account recovery initiated');
    } catch (error) {
      logger.error('Error initiating account recovery:', error);
      return next(error);
    }
  }

  /**
   * Verify account recovery
   */
  async verifyAccountRecovery(req, res, next) {
    try {
      const verificationData = req.body;
      const result = await securityService.verifyAccountRecovery(verificationData);
      return APIResponse.success(res, result, 'Account recovery verified');
    } catch (error) {
      logger.error('Error verifying account recovery:', error);
      return next(error);
    }
  }

  /**
   * Request security challenge
   */
  async requestSecurityChallenge(req, res, next) {
    try {
      const userId = req.user.id;
      const challengeData = req.body;
      const result = await securityService.requestSecurityChallenge(userId, challengeData);
      return APIResponse.success(res, result, 'Security challenge requested');
    } catch (error) {
      logger.error('Error requesting security challenge:', error);
      return next(error);
    }
  }

  /**
   * Respond to security challenge
   */
  async respondSecurityChallenge(req, res, next) {
    try {
      const userId = req.user.id;
      const responseData = req.body;
      const result = await securityService.respondSecurityChallenge(userId, responseData);
      return APIResponse.success(res, result, 'Security challenge response processed');
    } catch (error) {
      logger.error('Error responding to security challenge:', error);
      return next(error);
    }
  }

  /**
   * Report security incident
   */
  async reportIncident(req, res, next) {
    try {
      const userId = req.user.id;
      const { incident_type, description, metadata } = req.body;

      // Log security event
      const securityEvent = await securityService.logSecurityEvent({
        user_id: userId,
        event_type: incident_type,
        severity: 'high',
        description,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: {
          ...metadata,
          reported_by_user: true
        }
      });

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.SECURITY_INCIDENT_REPORT,
        category: 'security',
        severity: 'high',
        resource_type: 'security_event',
        resource_id: securityEvent.id,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { incident_type, description }
      });

      return APIResponse.success(res, { 
        incident_id: securityEvent.id 
      }, 'Security incident reported successfully', HTTP_STATUS.CREATED);

    } catch (error) {
      logger.error('Error reporting security incident:', error);
      return next(error);
    }
  }

  /**
   * Get system security overview (admin)
   */
  async getSystemSecurityOverview(req, res, next) {
    try {
      const overview = await securityService.getSystemSecurityOverview();
      return APIResponse.success(res, overview, 'System security overview retrieved');
    } catch (error) {
      logger.error('Error getting system security overview:', error);
      return next(error);
    }
  }

  /**
   * Get user security overview (admin)
   */
  async getUserSecurityOverview(req, res, next) {
    try {
      const { userId } = req.params;
      const overview = await securityService.getUserSecurityOverview(userId);
      return APIResponse.success(res, overview, 'User security overview retrieved');
    } catch (error) {
      logger.error('Error getting user security overview:', error);
      return next(error);
    }
  }

  /**
   * Force key regeneration (admin)
   */
  async forceKeyRegeneration(req, res, next) {
    try {
      const { userId } = req.params;
      const { reason } = req.body;
      const result = await securityService.forceKeyRegeneration(userId, reason);
      return APIResponse.success(res, result, 'Key regeneration forced successfully');
    } catch (error) {
      logger.error('Error forcing key regeneration:', error);
      return next(error);
    }
  }

  /**
   * Revoke all user keys (admin)
   */
  async revokeAllUserKeys(req, res, next) {
    try {
      const { userId } = req.params;
      const { reason } = req.body;
      await securityService.revokeAllUserKeys(userId, reason);
      return APIResponse.success(res, null, 'All user keys revoked successfully');
    } catch (error) {
      logger.error('Error revoking all user keys:', error);
      return next(error);
    }
  }

  /**
   * Get security incidents
   */
  async getSecurityIncidents(req, res, next) {
    try {
      const { page = 1, limit = 50 } = req.query;
      const incidents = await securityService.getSecurityIncidents({ page, limit });
      return APIResponse.success(res, incidents, 'Security incidents retrieved successfully');
    } catch (error) {
      logger.error('Error getting security incidents:', error);
      return next(error);
    }
  }

  /**
   * Create security incident
   */
  async createSecurityIncident(req, res, next) {
    try {
      const incidentData = req.body;
      const incident = await securityService.createSecurityIncident(incidentData);
      return APIResponse.success(res, incident, 'Security incident created successfully', HTTP_STATUS.CREATED);
    } catch (error) {
      logger.error('Error creating security incident:', error);
      return next(error);
    }
  }

  /**
   * Update security incident
   */
  async updateSecurityIncident(req, res, next) {
    try {
      const { incidentId } = req.params;
      const updateData = req.body;
      const incident = await securityService.updateSecurityIncident(incidentId, updateData);
      return APIResponse.success(res, incident, 'Security incident updated successfully');
    } catch (error) {
      logger.error('Error updating security incident:', error);
      return next(error);
    }
  }

  /**
   * Resolve security incident
   */
  async resolveSecurityIncident(req, res, next) {
    try {
      const { incidentId } = req.params;
      const { resolution_notes } = req.body;
      await securityService.resolveSecurityIncident(incidentId, resolution_notes);
      return APIResponse.success(res, null, 'Security incident resolved successfully');
    } catch (error) {
      logger.error('Error resolving security incident:', error);
      return next(error);
    }
  }

  /**
   * Get threat analysis
   */
  async getThreatAnalysis(req, res, next) {
    try {
      const { start_date, end_date } = req.query;
      const analysis = await securityService.getThreatAnalysis({ start_date, end_date });
      return APIResponse.success(res, analysis, 'Threat analysis retrieved successfully');
    } catch (error) {
      logger.error('Error getting threat analysis:', error);
      return next(error);
    }
  }

  /**
   * Get threat patterns
   */
  async getThreatPatterns(req, res, next) {
    try {
      const { start_date, end_date } = req.query;
      const patterns = await securityService.getThreatPatterns({ start_date, end_date });
      return APIResponse.success(res, patterns, 'Threat patterns retrieved successfully');
    } catch (error) {
      logger.error('Error getting threat patterns:', error);
      return next(error);
    }
  }

  /**
   * Get authentication analytics
   */
  async getAuthenticationAnalytics(req, res, next) {
    try {
      const { start_date, end_date } = req.query;
      const analytics = await securityService.getAuthenticationAnalytics({ start_date, end_date });
      return APIResponse.success(res, analytics, 'Authentication analytics retrieved successfully');
    } catch (error) {
      logger.error('Error getting authentication analytics:', error);
      return next(error);
    }
  }

  /**
   * Get encryption analytics
   */
  async getEncryptionAnalytics(req, res, next) {
    try {
      const { start_date, end_date } = req.query;
      const analytics = await securityService.getEncryptionAnalytics({ start_date, end_date });
      return APIResponse.success(res, analytics, 'Encryption analytics retrieved successfully');
    } catch (error) {
      logger.error('Error getting encryption analytics:', error);
      return next(error);
    }
  }

  /**
   * Get security violation analytics
   */
  async getSecurityViolationAnalytics(req, res, next) {
    try {
      const { start_date, end_date } = req.query;
      const analytics = await securityService.getSecurityViolationAnalytics({ start_date, end_date });
      return APIResponse.success(res, analytics, 'Security violation analytics retrieved successfully');
    } catch (error) {
      logger.error('Error getting security violation analytics:', error);
      return next(error);
    }
  }

  /**
   * Generate compliance report
   */
  async generateComplianceReport(req, res, next) {
    try {
      const reportParams = req.body;
      const report = await securityService.generateComplianceReport(reportParams);
      return APIResponse.success(res, report, 'Compliance report generated successfully');
    } catch (error) {
      logger.error('Error generating compliance report:', error);
      return next(error);
    }
  }

  /**
   * Get system audit log
   */
  async getSystemAuditLog(req, res, next) {
    try {
      const { page = 1, limit = 50 } = req.query;
      const auditLog = await auditService.getSystemAuditLog({ page, limit });
      return APIResponse.success(res, auditLog, 'System audit log retrieved successfully');
    } catch (error) {
      logger.error('Error getting system audit log:', error);
      return next(error);
    }
  }

  /**
   * Get security configuration
   */
  async getSecurityConfiguration(req, res, next) {
    try {
      const config = await securityService.getSecurityConfiguration();
      return APIResponse.success(res, config, 'Security configuration retrieved successfully');
    } catch (error) {
      logger.error('Error getting security configuration:', error);
      return next(error);
    }
  }

  /**
   * Update security configuration
   */
  async updateSecurityConfiguration(req, res, next) {
    try {
      const configData = req.body;
      const config = await securityService.updateSecurityConfiguration(configData);
      return APIResponse.success(res, config, 'Security configuration updated successfully');
    } catch (error) {
      logger.error('Error updating security configuration:', error);
      return next(error);
    }
  }

  /**
   * Get system keys
   */
  async getSystemKeys(req, res, next) {
    try {
      const { page = 1, limit = 50 } = req.query;
      const keys = await securityService.getSystemKeys({ page, limit });
      return APIResponse.success(res, keys, 'System keys retrieved successfully');
    } catch (error) {
      logger.error('Error getting system keys:', error);
      return next(error);
    }
  }

  /**
   * Rotate system keys
   */
  async rotateSystemKeys(req, res, next) {
    try {
      const rotationData = req.body;
      const result = await securityService.rotateSystemKeys(rotationData);
      return APIResponse.success(res, result, 'System keys rotated successfully');
    } catch (error) {
      logger.error('Error rotating system keys:', error);
      return next(error);
    }
  }

  /**
   * Bulk reset 2FA
   */
  async bulkReset2FA(req, res, next) {
    try {
      const { user_ids, reason } = req.body;
      const result = await securityService.bulkReset2FA(user_ids, reason);
      return APIResponse.success(res, result, 'Bulk 2FA reset completed');
    } catch (error) {
      logger.error('Error in bulk 2FA reset:', error);
      return next(error);
    }
  }

  /**
   * Bulk force logout
   */
  async bulkForceLogout(req, res, next) {
    try {
      const { user_ids, reason } = req.body;
      const result = await securityService.bulkForceLogout(user_ids, reason);
      return APIResponse.success(res, result, 'Bulk force logout completed');
    } catch (error) {
      logger.error('Error in bulk force logout:', error);
      return next(error);
    }
  }

  /**
   * Bulk revoke keys
   */
  async bulkRevokeKeys(req, res, next) {
    try {
      const { user_ids, reason } = req.body;
      const result = await securityService.bulkRevokeKeys(user_ids, reason);
      return APIResponse.success(res, result, 'Bulk key revocation completed');
    } catch (error) {
      logger.error('Error in bulk key revocation:', error);
      return next(error);
    }
  }

  /**
   * Get real-time security metrics
   */
  async getRealTimeSecurityMetrics(req, res, next) {
    try {
      const metrics = await securityService.getRealTimeSecurityMetrics();
      return APIResponse.success(res, metrics, 'Real-time security metrics retrieved');
    } catch (error) {
      logger.error('Error getting real-time security metrics:', error);
      return next(error);
    }
  }

  /**
   * Get security alerts
   */
  async getSecurityAlerts(req, res, next) {
    try {
      const { page = 1, limit = 50 } = req.query;
      const alerts = await securityService.getSecurityAlerts({ page, limit });
      return APIResponse.success(res, alerts, 'Security alerts retrieved successfully');
    } catch (error) {
      logger.error('Error getting security alerts:', error);
      return next(error);
    }
  }

  /**
   * Acknowledge security alert
   */
  async acknowledgeSecurityAlert(req, res, next) {
    try {
      const { alertId } = req.params;
      const userId = req.user.id;
      await securityService.acknowledgeSecurityAlert(alertId, userId);
      return APIResponse.success(res, null, 'Security alert acknowledged');
    } catch (error) {
      logger.error('Error acknowledging security alert:', error);
      return next(error);
    }
  }

  /**
   * Export security events
   */
  async exportSecurityEvents(req, res, next) {
    try {
      const exportParams = req.query;
      const exportData = await securityService.exportSecurityEvents(exportParams);
      return APIResponse.success(res, exportData, 'Security events exported successfully');
    } catch (error) {
      logger.error('Error exporting security events:', error);
      return next(error);
    }
  }

  /**
   * Export audit log
   */
  async exportAuditLog(req, res, next) {
    try {
      const exportParams = req.query;
      const exportData = await auditService.exportAuditLog(exportParams);
      return APIResponse.success(res, exportData, 'Audit log exported successfully');
    } catch (error) {
      logger.error('Error exporting audit log:', error);
      return next(error);
    }
  }

  /**
   * Emergency lockdown
   */
  async emergencyLockdown(req, res, next) {
    try {
      const lockdownData = req.body;
      const result = await securityService.emergencyLockdown(lockdownData);
      return APIResponse.success(res, result, 'Emergency lockdown initiated');
    } catch (error) {
      logger.error('Error in emergency lockdown:', error);
      return next(error);
    }
  }

  /**
   * Emergency unlock
   */
  async emergencyUnlock(req, res, next) {
    try {
      const unlockData = req.body;
      const result = await securityService.emergencyUnlock(unlockData);
      return APIResponse.success(res, result, 'Emergency unlock completed');
    } catch (error) {
      logger.error('Error in emergency unlock:', error);
      return next(error);
    }
  }

  /**
   * Security health check
   */
  async securityHealthCheck(req, res, next) {
    try {
      const healthStatus = await securityService.securityHealthCheck();
      return APIResponse.success(res, healthStatus, 'Security health check completed');
    } catch (error) {
      logger.error('Error in security health check:', error);
      return next(error);
    }
  }

  /**
   * Report vulnerability
   */
  async reportVulnerability(req, res, next) {
    try {
      const vulnerabilityData = req.body;
      const vulnerability = await securityService.reportVulnerability(vulnerabilityData);
      return APIResponse.success(res, vulnerability, 'Vulnerability reported successfully', HTTP_STATUS.CREATED);
    } catch (error) {
      logger.error('Error reporting vulnerability:', error);
      return next(error);
    }
  }

  /**
   * Get vulnerabilities
   */
  async getVulnerabilities(req, res, next) {
    try {
      const { page = 1, limit = 50 } = req.query;
      const vulnerabilities = await securityService.getVulnerabilities({ page, limit });
      return APIResponse.success(res, vulnerabilities, 'Vulnerabilities retrieved successfully');
    } catch (error) {
      logger.error('Error getting vulnerabilities:', error);
      return next(error);
    }
  }
}

export default new SecurityController();
// import { Op } from 'sequelize';
// import models from '../models/index.js';

// const { 
//   UserActivityLog, 
//   SecurityEvent, 
//   EncryptionKey,
//   DigitalSignature 
// } = models;

// import securityService from '../services/securityService.js';
// import encryptionService from '../services/encryptionService.js';
// import signatureService from '../services/signatureService.js';
// import auditService from '../services/auditService.js';
// import validateInput from '../middleware/validation.js';
// import { APIResponse } from '../utils/response.js';
// import logger from '../utils/logger.js';
// import { USER_ACTIONS, HTTP_STATUS, SECURITY_EVENTS } from '../utils/constants.js';


// class SecurityController {
//   /**
//    * Get user activity log
//    */
//   async getUserActivityLog(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const {
//         page = 1,
//         limit = 50,
//         category = '',
//         action = '',
//         start_date = '',
//         end_date = '',
//         severity = ''
//       } = req.query;

//       const whereClause = { user_id: userId };
      
//       if (category) whereClause.category = category;
//       if (action) whereClause.action = action;
//       if (severity) whereClause.severity = severity;
      
//       if (start_date && end_date) {
//         whereClause.created_at = {
//           [Op.between]: [new Date(start_date), new Date(end_date)]
//         };
//       }

//       const offset = (page - 1) * limit;

//       const { rows: activities, count } = await UserActivityLog.findAndCountAll({
//         where: whereClause,
//         limit: parseInt(limit),
//         offset: parseInt(offset),
//         order: [['created_at', 'DESC']],
//         attributes: { exclude: ['user_agent'] }
//       });

//       const totalPages = Math.ceil(count / limit);

//       return APIResponse.success(res, {
//         activities,
//         pagination: {
//           current_page: parseInt(page),
//           total_pages: totalPages,
//           total_count: count,
//           limit: parseInt(limit)
//         }
//       }, 'Activity log retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting activity log:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get security events (admin)
//    */
//   async getSecurityEvents(req, res, next) {
//     try {
//       // Check permissions
//       if (!req.user.hasPermission('security.read')) {
//         return APIResponse.error(res, 'Insufficient permissions', HTTP_STATUS.FORBIDDEN);
//       }

//       const {
//         page = 1,
//         limit = 50,
//         event_type = '',
//         severity = '',
//         start_date = '',
//         end_date = '',
//         user_id = ''
//       } = req.query;

//       const whereClause = {};
      
//       if (event_type) whereClause.event_type = event_type;
//       if (severity) whereClause.severity = severity;
//       if (user_id) whereClause.user_id = user_id;
      
//       if (start_date && end_date) {
//         whereClause.created_at = {
//           [Op.between]: [new Date(start_date), new Date(end_date)]
//         };
//       }

//       const offset = (page - 1) * limit;

//       const { rows: events, count } = await SecurityEvent.findAndCountAll({
//         where: whereClause,
//         limit: parseInt(limit),
//         offset: parseInt(offset),
//         order: [['created_at', 'DESC']]
//       });

//       const totalPages = Math.ceil(count / limit);

//       return APIResponse.success(res, {
//         events,
//         pagination: {
//           current_page: parseInt(page),
//           total_pages: totalPages,
//           total_count: count,
//           limit: parseInt(limit)
//         }
//       }, 'Security events retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting security events:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Generate encryption key pair
//    */
//   async generateKeyPair(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { key_type = 'rsa', key_size = 2048, purpose = 'user_data' } = req.body;

//       // Validate input
//       const validation = validateInput({ key_type, key_size, purpose }, 'generateKeyPair');
//       if (!validation.isValid) {
//         return APIResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
//       }

//       // Generate key pair through service
//       const keyPair = await encryptionService.generateKeyPair(key_type, key_size, purpose, userId);

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.KEY_GENERATE,
//         category: 'security',
//         severity: 'medium',
//         resource_type: 'encryption_key',
//         resource_id: keyPair.id,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: { key_type, key_size, purpose }
//       });

//       return APIResponse.success(res, {
//         key_id: keyPair.key_id,
//         public_key: keyPair.public_key,
//         key_type: keyPair.key_type,
//         algorithm: keyPair.algorithm,
//         created_at: keyPair.created_at
//       }, 'Key pair generated successfully', HTTP_STATUS.CREATED);

//     } catch (error) {
//       logger.error('Error generating key pair:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get user encryption keys
//    */
//   async getUserKeys(req, res, next) {
//     try {
//       const userId = req.user.id;

//       const keys = await EncryptionKey.findAll({
//         where: {
//           owner_id: userId,
//           status: 'active'
//         },
//         attributes: [
//           'id', 'key_id', 'key_type', 'purpose', 'algorithm', 
//           'key_size', 'status', 'usage_count', 'created_at', 'expires_at'
//         ],
//         order: [['created_at', 'DESC']]
//       });

//       return APIResponse.success(res, keys, 'Encryption keys retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting user keys:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get user public key
//    */
//   async getUserPublicKey(req, res, next) {
//     try {
//       const { userId } = req.params;

//       const key = await EncryptionKey.findOne({
//         where: {
//           owner_id: userId,
//           status: 'active'
//         },
//         attributes: ['id', 'key_id', 'public_key', 'key_type', 'algorithm', 'created_at']
//       });

//       if (!key) {
//         return APIResponse.error(res, 'Public key not found', HTTP_STATUS.NOT_FOUND);
//       }

//       return APIResponse.success(res, {
//         key_id: key.key_id,
//         public_key: key.public_key,
//         key_type: key.key_type,
//         algorithm: key.algorithm,
//         created_at: key.created_at
//       }, 'Public key retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting public key:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Update encryption key
//    */
//   async updateEncryptionKey(req, res, next) {
//     try {
//       const { keyId } = req.params;
//       const userId = req.user.id;
//       const updateData = req.body;

//       const key = await EncryptionKey.findOne({
//         where: {
//           id: keyId,
//           owner_id: userId
//         }
//       });

//       if (!key) {
//         return APIResponse.error(res, 'Key not found', HTTP_STATUS.NOT_FOUND);
//       }

//       await key.update(updateData);

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.KEY_UPDATE,
//         category: 'security',
//         severity: 'medium',
//         resource_type: 'encryption_key',
//         resource_id: keyId,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         new_values: updateData
//       });

//       return APIResponse.success(res, null, 'Key updated successfully');

//     } catch (error) {
//       logger.error('Error updating key:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Revoke encryption key
//    */
//   async revokeKey(req, res, next) {
//     try {
//       const { keyId } = req.params;
//       const userId = req.user.id;

//       const key = await EncryptionKey.findOne({
//         where: {
//           id: keyId,
//           owner_id: userId
//         }
//       });

//       if (!key) {
//         return APIResponse.error(res, 'Key not found', HTTP_STATUS.NOT_FOUND);
//       }

//       if (key.status === 'compromised') {
//         return APIResponse.error(res, 'Key is already compromised', HTTP_STATUS.BAD_REQUEST);
//       }

//       await key.update({ status: 'compromised' });

//       // Log security event
//       await securityService.logSecurityEvent({
//         user_id: userId,
//         event_type: SECURITY_EVENTS.KEY_REVOKED,
//         severity: 'high',
//         description: 'Encryption key manually revoked',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: { key_id: key.key_id, key_type: key.key_type }
//       });

//       return APIResponse.success(res, null, 'Key revoked successfully');

//     } catch (error) {
//       logger.error('Error revoking key:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Create digital signature
//    */
//   async createSignature(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { data, key_id } = req.body;

//       if (!data || !key_id) {
//         return APIResponse.error(res, 'Data and key ID are required', HTTP_STATUS.BAD_REQUEST);
//       }

//       // Create signature through service
//       const signature = await signatureService.createSignature(data, key_id, userId);

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.SIGNATURE_CREATE,
//         category: 'security',
//         severity: 'medium',
//         resource_type: 'digital_signature',
//         resource_id: signature.id,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: { key_id, data_hash: signature.data_hash }
//       });

//       return APIResponse.success(res, signature, 'Digital signature created successfully', HTTP_STATUS.CREATED);

//     } catch (error) {
//       logger.error('Error creating signature:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Verify digital signature
//    */
//   async verifySignature(req, res, next) {
//     try {
//       const { signatureId } = req.params;
//       const { data } = req.body;

//       if (!data) {
//         return APIResponse.error(res, 'Data is required for verification', HTTP_STATUS.BAD_REQUEST);
//       }

//       const signature = await DigitalSignature.findByPk(signatureId);

//       if (!signature) {
//         return APIResponse.error(res, 'Signature not found', HTTP_STATUS.NOT_FOUND);
//       }

//       // Verify signature through service
//       const isValid = await signatureService.verifySignature(signature, data);

//       // Update verification count
//       await signature.increment('verification_count');

//       // Log activity
//       await auditService.logActivity({
//         user_id: req.user.id,
//         action: USER_ACTIONS.SIGNATURE_VERIFY,
//         category: 'security',
//         severity: 'low',
//         resource_type: 'digital_signature',
//         resource_id: signatureId,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: { verification_result: isValid }
//       });

//       return APIResponse.success(res, { 
//         is_valid: isValid,
//         signature_id: signatureId,
//         verified_at: new Date()
//       }, 'Signature verification completed');

//     } catch (error) {
//       logger.error('Error verifying signature:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get user signatures
//    */
//   async getUserSignatures(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { page = 1, limit = 50 } = req.query;
//       const offset = (page - 1) * limit;

//       const { rows: signatures, count } = await DigitalSignature.findAndCountAll({
//         where: { user_id: userId },
//         limit: parseInt(limit),
//         offset: parseInt(offset),
//         order: [['created_at', 'DESC']]
//       });

//       const totalPages = Math.ceil(count / limit);

//       return APIResponse.success(res, {
//         signatures,
//         pagination: {
//           current_page: parseInt(page),
//           total_pages: totalPages,
//           total_count: count,
//           limit: parseInt(limit)
//         }
//       }, 'User signatures retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting user signatures:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get signature by ID
//    */
//   async getSignatureById(req, res, next) {
//     try {
//       const { signatureId } = req.params;
//       const signature = await DigitalSignature.findByPk(signatureId);

//       if (!signature) {
//         return APIResponse.error(res, 'Signature not found', HTTP_STATUS.NOT_FOUND);
//       }

//       return APIResponse.success(res, signature, 'Signature retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting signature:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get security settings
//    */
//   async getSecuritySettings(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const settings = await securityService.getUserSecuritySettings(userId);
//       return APIResponse.success(res, settings, 'Security settings retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting security settings:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Update security settings
//    */
//   async updateSecuritySettings(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const settingsData = req.body;

//       // Validate input
//       const validation = validateInput(settingsData, 'securitySettings');
//       if (!validation.isValid) {
//         return APIResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
//       }

//       await securityService.updateUserSecuritySettings(userId, settingsData);

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.SECURITY_SETTINGS_UPDATE,
//         category: 'security',
//         severity: 'medium',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         new_values: settingsData
//       });

//       return APIResponse.success(res, null, 'Security settings updated successfully');

//     } catch (error) {
//       logger.error('Error updating security settings:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Report security incident
//    */
//   async reportIncident(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { incident_type, description, metadata } = req.body;

//       // Validate input
//       const validation = validateInput(req.body, 'securityIncident');
//       if (!validation.isValid) {
//         return APIResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
//       }

//       // Log security event
//       const securityEvent = await securityService.logSecurityEvent({
//         user_id: userId,
//         event_type: incident_type,
//         severity: 'high',
//         description,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: {
//           ...metadata,
//           reported_by_user: true
//         }
//       });

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.SECURITY_INCIDENT_REPORT,
//         category: 'security',
//         severity: 'high',
//         resource_type: 'security_event',
//         resource_id: securityEvent.id,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: { incident_type, description }
//       });

//       return APIResponse.success(res, { 
//         incident_id: securityEvent.id 
//       }, 'Security incident reported successfully', HTTP_STATUS.CREATED);

//     } catch (error) {
//       logger.error('Error reporting security incident:', error);
//       return next(error);
//     }
//   }

//   // Placeholder methods for missing controller functions
//   // You'll need to implement these based on your business logic

//   async get2FAStatus(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const status = await securityService.get2FAStatus(userId);
//       return APIResponse.success(res, status, '2FA status retrieved successfully');
//     } catch (error) {
//       logger.error('Error getting 2FA status:', error);
//       return next(error);
//     }
//   }

//   async setup2FA(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const result = await securityService.setup2FA(userId, req.body);
//       return APIResponse.success(res, result, '2FA setup initiated successfully');
//     } catch (error) {
//       logger.error('Error setting up 2FA:', error);
//       return next(error);
//     }
//   }

//   async verify2FASetup(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { token } = req.body;
//       const result = await securityService.verify2FASetup(userId, token);
//       return APIResponse.success(res, result, '2FA setup verified successfully');
//     } catch (error) {
//       logger.error('Error verifying 2FA setup:', error);
//       return next(error);
//     }
//   }

//   async disable2FA(req, res, next) {
//     try {
//       const userId = req.user.id;
//       await securityService.disable2FA(userId, req.body);
//       return APIResponse.success(res, null, '2FA disabled successfully');
//     } catch (error) {
//       logger.error('Error disabling 2FA:', error);
//       return next(error);
//     }
//   }

//   async generateBackupCodes(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const codes = await securityService.generateBackupCodes(userId);
//       return APIResponse.success(res, { backup_codes: codes }, 'Backup codes generated successfully');
//     } catch (error) {
//       logger.error('Error generating backup codes:', error);
//       return next(error);
//     }
//   }

//   async getBiometricStatus(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const status = await securityService.getBiometricStatus(userId);
//       return APIResponse.success(res, status, 'Biometric status retrieved successfully');
//     } catch (error) {
//       logger.error('Error getting biometric status:', error);
//       return next(error);
//     }
//   }

//   async registerBiometric(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const result = await securityService.registerBiometric(userId, req.body);
//       return APIResponse.success(res, result, 'Biometric registered successfully');
//     } catch (error) {
//       logger.error('Error registering biometric:', error);
//       return next(error);
//     }
//   }

//   async removeBiometric(req, res, next) {
//     try {
//       const userId = req.user.id;
//       await securityService.removeBiometric(userId, req.body);
//       return APIResponse.success(res, null, 'Biometric removed successfully');
//     } catch (error) {
//       logger.error('Error removing biometric:', error);
//       return next(error);
//     }
//   }

//   async getUserSecurityEvents(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { page = 1, limit = 50 } = req.query;
//       const events = await securityService.getUserSecurityEvents(userId, { page, limit });
//       return APIResponse.success(res, events, 'User security events retrieved successfully');
//     } catch (error) {
//       logger.error('Error getting user security events:', error);
//       return next(error);
//     }
//   }

//   async getLoginHistory(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { page = 1, limit = 50 } = req.query;
//       const history = await securityService.getLoginHistory(userId, { page, limit });
//       return APIResponse.success(res, history, 'Login history retrieved successfully');
//     } catch (error) {
//       logger.error('Error getting login history:', error);
//       return next(error);
//     }
//   }

//   async getUserDevices(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const devices = await securityService.getUserDevices(userId);
//       return APIResponse.success(res, devices, 'User devices retrieved successfully');
//     } catch (error) {
//       logger.error('Error getting user devices:', error);
//       return next(error);
//     }
//   }

//   async removeDevice(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { deviceId } = req.params;
//       await securityService.removeDevice(userId, deviceId);
//       return APIResponse.success(res, null, 'Device removed successfully');
//     } catch (error) {
//       logger.error('Error removing device:', error);
//       return next(error);
//     }
//   }

//   async removeAllDevices(req, res, next) {
//     try {
//       const userId = req.user.id;
//       await securityService.removeAllDevices(userId);
//       return APIResponse.success(res, null, 'All devices removed successfully');
//     } catch (error) {
//       logger.error('Error removing all devices:', error);
//       return next(error);
//     }
//   }

//   async checkPasswordStrength(req, res, next) {
//     try {
//       const { password } = req.body;
//       const strength = await securityService.checkPasswordStrength(password);
//       return APIResponse.success(res, strength, 'Password strength checked successfully');
//     } catch (error) {
//       logger.error('Error checking password strength:', error);
//       return next(error);
//     }
//   }

//   async checkPasswordBreach(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const result = await securityService.checkPasswordBreach(userId);
//       return APIResponse.success(res, result, 'Password breach check completed');
//     } catch (error) {
//       logger.error('Error checking password breach:', error);
//       return next(error);
//     }
//   }

//   async getSecurityNotifications(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { page = 1, limit = 50 } = req.query;
//       const notifications = await securityService.getSecurityNotifications(userId, { page, limit });
//       return APIResponse.success(res, notifications, 'Security notifications retrieved successfully');
//     } catch (error) {
//       logger.error('Error getting security notifications:', error);
//       return next(error);
//     }
//   }

//   async markNotificationRead(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { notificationId } = req.params;
//       await securityService.markNotificationRead(userId, notificationId);
//       return APIResponse.success(res, null, 'Notification marked as read');
//     } catch (error) {
//       logger.error('Error marking notification as read:', error);
//       return next(error);
//     }
//   }

//   async encryptData(req, res, next) {
//     try {
//       const { data, keyId } = req.body;
//       const result = await encryptionService.encryptData(data, keyId);
//       return APIResponse.success(res, result, 'Data encrypted successfully');
//     } catch (error) {
//       logger.error('Error encrypting data:', error);
//       return next(error);
//     }
//   }

//   async decryptData(req, res, next) {
//     try {
//       const { encryptedData, keyId } = req.body;
//       const result = await encryptionService.decryptData(encryptedData, keyId);
//       return APIResponse.success(res, result, 'Data decrypted successfully');
//     } catch (error) {
//       logger.error('Error decrypting data:', error);
//       return next(error);
//     }
//   }

//   // Add remaining placeholder methods
//   async createThresholdEncryption(req, res, next) {
//     try {
//       // Implementation needed
//       return APIResponse.success(res, null, 'Threshold encryption created');
//     } catch (error) {
//       logger.error('Error creating threshold encryption:', error);
//       return next(error);
//     }
//   }

//   async thresholdDecrypt(req, res, next) {
//     try {
//       // Implementation needed
//       return APIResponse.success(res, null, 'Threshold decryption completed');
//     } catch (error) {
//       logger.error('Error with threshold decryption:', error);
//       return next(error);
//     }
//   }

//   async verifyKeyIntegrity(req, res, next) {
//     try {
//       const { keyId } = req.body;
//       const result = await encryptionService.verifyKeyIntegrity(keyId);
//       return APIResponse.success(res, result, 'Key integrity verified');
//     } catch (error) {
//       logger.error('Error verifying key integrity:', error);
//       return next(error);
//     }
//   }

//   async getUserSecurityAudit(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const audit = await auditService.getUserSecurityAudit(userId, req.query);
//       return APIResponse.success(res, audit, 'Security audit retrieved successfully');
//     } catch (error) {
//       logger.error('Error getting security audit:', error);
//       return next(error);
//     }
//   }

//   async generateSecurityReport(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const report = await securityService.generateSecurityReport(userId, req.body);
//       return APIResponse.success(res, report, 'Security report generated successfully');
//     } catch (error) {
//       logger.error('Error generating security report:', error);
//       return next(error);
//     }
//   }

//   async initiateAccountRecovery(req, res, next) {
//     try {
//       const result = await securityService.initiateAccountRecovery(req.body);
//       return APIResponse.success(res, result, 'Account recovery initiated');
//     } catch (error) {
//       logger.error('Error initiating account recovery:', error);
//       return next(error);
//     }
//   }

//   async verifyAccountRecovery(req, res, next) {
//     try {
//       const result = await securityService.verifyAccountRecovery(req.body);
//       return APIResponse.success(res, result, 'Account recovery verified');
//     } catch (error) {
//       logger.error('Error verifying account recovery:', error);
//       return next(error);
//     }
//   }

//   async requestSecurityChallenge(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const challenge = await securityService.requestSecurityChallenge(userId, req.body);
//       return APIResponse.success(res, challenge, 'Security challenge requested');
//     } catch (error) {
//       logger.error('Error requesting security challenge:', error);
//       return next(error);
//     }
//   }

//   async respondSecurityChallenge(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const result = await securityService.respondSecurityChallenge(userId, req.body);
//       return APIResponse.success(res, result, 'Security challenge response processed');
//     } catch (error) {
//       logger.error('Error responding to security challenge:', error);
//       return next(error);
//     }
//   }

//   // Admin methods - implement based on requirements
//   async getSystemSecurityOverview(req, res, next) {
//     try {
//       const overview = await securityService.getSystemSecurityOverview(req.query);
//       return APIResponse.success(res, overview, 'System security overview retrieved');
//     } catch (error) {
//       logger.error('Error getting system security overview:', error);
//       return next(error);
//     }
//   }

//   async getUserSecurityOverview(req, res, next) {
//     try {
//       const { userId } = req.params;
//       const overview = await securityService.getUserSecurityOverview(userId);
//       return APIResponse.success(res, overview, 'User security overview retrieved');
//     } catch (error) {
//       logger.error('Error getting user security overview:', error);
//       return next(error);
//     }
//   }

//   // Add all remaining placeholder methods with basic implementations
//   // You'll need to implement the actual business logic in your services

//   async forceKeyRegeneration(req, res, next) {
//     try {
//       const { userId } = req.params;
//       const result = await securityService.forceKeyRegeneration(userId, req.body);
//       return APIResponse.success(res, result, 'Key regeneration forced successfully');
//     } catch (error) {
//       logger.error('Error forcing key regeneration:', error);
//       return next(error);
//     }
//   }

//   async revokeAllUserKeys(req, res, next) {
//     try {
//       const { userId } = req.params;
//       await securityService.revokeAllUserKeys(userId, req.body);
//       return APIResponse.success(res, null, 'All user keys revoked successfully');
//     } catch (error) {
//       logger.error('Error revoking all user keys:', error);
//       return next(error);
//     }
//   }

//   async getSecurityIncidents(req, res, next) {
//     try {
//       const incidents = await securityService.getSecurityIncidents(req.query);
//       return APIResponse.success(res, incidents, 'Security incidents retrieved');
//     } catch (error) {
//       logger.error('Error getting security incidents:', error);
//       return next(error);
//     }
//   }

//   async createSecurityIncident(req, res, next) {
//     try {
//       const incident = await securityService.createSecurityIncident(req.body);
//       return APIResponse.success(res, incident, 'Security incident created', HTTP_STATUS.CREATED);
//     } catch (error) {
//       logger.error('Error creating security incident:', error);
//       return next(error);
//     }
//   }

//   async updateSecurityIncident(req, res, next) {
//     try {
//       const { incidentId } = req.params;
//       await securityService.updateSecurityIncident(incidentId, req.body);
//       return APIResponse.success(res, null, 'Security incident updated');
//     } catch (error) {
//       logger.error('Error updating security incident:', error);
//       return next(error);
//     }
//   }

//   async resolveSecurityIncident(req, res, next) {
//     try {
//       const { incidentId } = req.params;
//       await securityService.resolveSecurityIncident(incidentId, req.body);
//       return APIResponse.success(res, null, 'Security incident resolved');
//     } catch (error) {
//       logger.error('Error resolving security incident:', error);
//       return next(error);
//     }
//   }

//   async getThreatAnalysis(req, res, next) {
//     try {
//       const analysis = await securityService.getThreatAnalysis(req.query);
//       return APIResponse.success(res, analysis, 'Threat analysis retrieved');
//     } catch (error) {
//       logger.error('Error getting threat analysis:', error);
//       return next(error);
//     }
//   }

//   async getThreatPatterns(req, res, next) {
//     try {
//       const patterns = await securityService.getThreatPatterns(req.query);
//       return APIResponse.success(res, patterns, 'Threat patterns retrieved');
//     } catch (error) {
//       logger.error('Error getting threat patterns:', error);
//       return next(error);
//     }
//   }

//   async getAuthenticationAnalytics(req, res, next) {
//     try {
//       const analytics = await securityService.getAuthenticationAnalytics(req.query);
//       return APIResponse.success(res, analytics, 'Authentication analytics retrieved');
//     } catch (error) {
//       logger.error('Error getting authentication analytics:', error);
//       return next(error);
//     }
//   }

//   async getEncryptionAnalytics(req, res, next) {
//     try {
//       const analytics = await securityService.getEncryptionAnalytics(req.query);
//       return APIResponse.success(res, analytics, 'Encryption analytics retrieved');
//     } catch (error) {
//       logger.error('Error getting encryption analytics:', error);
//       return next(error);
//     }
//   }

//   async getSecurityViolationAnalytics(req, res, next) {
//     try {
//       const analytics = await securityService.getSecurityViolationAnalytics(req.query);
//       return APIResponse.success(res, analytics, 'Security violation analytics retrieved');
//     } catch (error) {
//       logger.error('Error getting security violation analytics:', error);
//       return next(error);
//     }
//   }

//   async generateComplianceReport(req, res, next) {
//     try {
//       const report = await securityService.generateComplianceReport(req.query);
//       return APIResponse.success(res, report, 'Compliance report generated');
//     } catch (error) {
//       logger.error('Error generating compliance report:', error);
//       return next(error);
//     }
//   }

//   async getSystemAuditLog(req, res, next) {
//     try {
//       const auditLog = await auditService.getSystemAuditLog(req.query);
//       return APIResponse.success(res, auditLog, 'System audit log retrieved');
//     } catch (error) {
//       logger.error('Error getting system audit log:', error);
//       return next(error);
//     }
//   }

//   async getSecurityConfiguration(req, res, next) {
//     try {
//       const config = await securityService.getSecurityConfiguration();
//       return APIResponse.success(res, config, 'Security configuration retrieved');
//     } catch (error) {
//       logger.error('Error getting security configuration:', error);
//       return next(error);
//     }
//   }

//   async updateSecurityConfiguration(req, res, next) {
//     try {
//       await securityService.updateSecurityConfiguration(req.body);
//       return APIResponse.success(res, null, 'Security configuration updated');
//     } catch (error) {
//       logger.error('Error updating security configuration:', error);
//       return next(error);
//     }
//   }

//   async getSystemKeys(req, res, next) {
//     try {
//       const keys = await encryptionService.getSystemKeys(req.query);
//       return APIResponse.success(res, keys, 'System keys retrieved');
//     } catch (error) {
//       logger.error('Error getting system keys:', error);
//       return next(error);
//     }
//   }

//   async rotateSystemKeys(req, res, next) {
//     try {
//       const result = await encryptionService.rotateSystemKeys(req.body);
//       return APIResponse.success(res, result, 'System keys rotated successfully');
//     } catch (error) {
//       logger.error('Error rotating system keys:', error);
//       return next(error);
//     }
//   }

//   async bulkReset2FA(req, res, next) {
//     try {
//       const result = await securityService.bulkReset2FA(req.body);
//       return APIResponse.success(res, result, 'Bulk 2FA reset completed');
//     } catch (error) {
//       logger.error('Error with bulk 2FA reset:', error);
//       return next(error);
//     }
//   }

//   async bulkForceLogout(req, res, next) {
//     try {
//       const result = await securityService.bulkForceLogout(req.body);
//       return APIResponse.success(res, result, 'Bulk force logout completed');
//     } catch (error) {
//       logger.error('Error with bulk force logout:', error);
//       return next(error);
//     }
//   }

//   async bulkRevokeKeys(req, res, next) {
//     try {
//       const result = await encryptionService.bulkRevokeKeys(req.body);
//       return APIResponse.success(res, result, 'Bulk key revocation completed');
//     } catch (error) {
//       logger.error('Error with bulk key revocation:', error);
//       return next(error);
//     }
//   }

//   async getRealTimeSecurityMetrics(req, res, next) {
//     try {
//       const metrics = await securityService.getRealTimeSecurityMetrics();
//       return APIResponse.success(res, metrics, 'Real-time security metrics retrieved');
//     } catch (error) {
//       logger.error('Error getting real-time security metrics:', error);
//       return next(error);
//     }
//   }

//   async getSecurityAlerts(req, res, next) {
//     try {
//       const alerts = await securityService.getSecurityAlerts(req.query);
//       return APIResponse.success(res, alerts, 'Security alerts retrieved');
//     } catch (error) {
//       logger.error('Error getting security alerts:', error);
//       return next(error);
//     }
//   }

//   async acknowledgeSecurityAlert(req, res, next) {
//     try {
//       const { alertId } = req.params;
//       await securityService.acknowledgeSecurityAlert(alertId);
//       return APIResponse.success(res, null, 'Security alert acknowledged');
//     } catch (error) {
//       logger.error('Error acknowledging security alert:', error);
//       return next(error);
//     }
//   }

//   async exportSecurityEvents(req, res, next) {
//     try {
//       const exportData = await securityService.exportSecurityEvents(req.query);
//       return APIResponse.success(res, exportData, 'Security events exported');
//     } catch (error) {
//       logger.error('Error exporting security events:', error);
//       return next(error);
//     }
//   }

//   async exportAuditLog(req, res, next) {
//     try {
//       const exportData = await auditService.exportAuditLog(req.query);
//       return APIResponse.success(res, exportData, 'Audit log exported');
//     } catch (error) {
//       logger.error('Error exporting audit log:', error);
//       return next(error);
//     }
//   }

//   async emergencyLockdown(req, res, next) {
//     try {
//       const result = await securityService.emergencyLockdown(req.body);
//       return APIResponse.success(res, result, 'Emergency lockdown initiated');
//     } catch (error) {
//       logger.error('Error initiating emergency lockdown:', error);
//       return next(error);
//     }
//   }

//   async emergencyUnlock(req, res, next) {
//     try {
//       const result = await securityService.emergencyUnlock(req.body);
//       return APIResponse.success(res, result, 'Emergency unlock completed');
//     } catch (error) {
//       logger.error('Error completing emergency unlock:', error);
//       return next(error);
//     }
//   }

//   async securityHealthCheck(req, res, next) {
//     try {
//       const healthCheck = await securityService.securityHealthCheck();
//       return APIResponse.success(res, healthCheck, 'Security health check completed');
//     } catch (error) {
//       logger.error('Error performing security health check:', error);
//       return next(error);
//     }
//   }

//   async reportVulnerability(req, res, next) {
//     try {
//       const report = await securityService.reportVulnerability(req.body);
//       return APIResponse.success(res, report, 'Vulnerability reported successfully', HTTP_STATUS.CREATED);
//     } catch (error) {
//       logger.error('Error reporting vulnerability:', error);
//       return next(error);
//     }
//   }

//   async getVulnerabilities(req, res, next) {
//     try {
//       const vulnerabilities = await securityService.getVulnerabilities(req.query);
//       return APIResponse.success(res, vulnerabilities, 'Vulnerabilities retrieved');
//     } catch (error) {
//       logger.error('Error getting vulnerabilities:', error);
//       return next(error);
//     }
//   }




// import { Op } from 'sequelize';
// // import { 
// //   UserActivityLog, 
// //   SecurityEvent, 
// //   EncryptionKey,
// //   DigitalSignature 
// // } from '../models/index.js';
// import models from '../models/index.js';

// const { 
//   UserActivityLog, 
//   SecurityEvent, 
//   EncryptionKey,
//   DigitalSignature 
// } = models;
// import  securityService  from '../services/securityService.js';
// import  encryptionService  from '../services/encryptionService.js';
// import  signatureService  from '../services/signatureService.js';
// import  auditService  from '../services/auditService.js';
// import  validateInput  from '../middleware/validation.js';
// //import { ApiResponse } from '../utils/response.js';
// import { APIResponse } from '../utils/response.js';
// import logger  from '../utils/logger.js';
// import { USER_ACTIONS, HTTP_STATUS, SECURITY_EVENTS } from '../utils/constants.js';

// class SecurityController {
//   /**
//    * Get user activity log
//    */
//   async getUserActivityLog(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const {
//         page = 1,
//         limit = 50,
//         category = '',
//         action = '',
//         start_date = '',
//         end_date = '',
//         severity = ''
//       } = req.query;

//       const whereClause = { user_id: userId };
      
//       if (category) whereClause.category = category;
//       if (action) whereClause.action = action;
//       if (severity) whereClause.severity = severity;
      
//       if (start_date && end_date) {
//         whereClause.created_at = {
//           [Op.between]: [new Date(start_date), new Date(end_date)]
//         };
//       }

//       const offset = (page - 1) * limit;

//       const { rows: activities, count } = await UserActivityLog.findAndCountAll({
//         where: whereClause,
//         limit: parseInt(limit),
//         offset: parseInt(offset),
//         order: [['created_at', 'DESC']],
//         attributes: { exclude: ['user_agent'] } // Exclude potentially long user agent strings
//       });

//       const totalPages = Math.ceil(count / limit);

//       return APIResponse.success(res, {
//         activities,
//         pagination: {
//           current_page: parseInt(page),
//           total_pages: totalPages,
//           total_count: count,
//           limit: parseInt(limit)
//         }
//       }, 'Activity log retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting activity log:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get security events (admin)
//    */
//   async getSecurityEvents(req, res, next) {
//     try {
//       // Check permissions
//       if (!req.user.hasPermission('security.read')) {
//         return APIResponse.error(res, 'Insufficient permissions', HTTP_STATUS.FORBIDDEN);
//       }

//       const {
//         page = 1,
//         limit = 50,
//         event_type = '',
//         severity = '',
//         start_date = '',
//         end_date = '',
//         user_id = ''
//       } = req.query;

//       const whereClause = {};
      
//       if (event_type) whereClause.event_type = event_type;
//       if (severity) whereClause.severity = severity;
//       if (user_id) whereClause.user_id = user_id;
      
//       if (start_date && end_date) {
//         whereClause.created_at = {
//           [Op.between]: [new Date(start_date), new Date(end_date)]
//         };
//       }

//       const offset = (page - 1) * limit;

//       const { rows: events, count } = await SecurityEvent.findAndCountAll({
//         where: whereClause,
//         limit: parseInt(limit),
//         offset: parseInt(offset),
//         order: [['created_at', 'DESC']]
//       });

//       const totalPages = Math.ceil(count / limit);

//       return APIResponse.success(res, {
//         events,
//         pagination: {
//           current_page: parseInt(page),
//           total_pages: totalPages,
//           total_count: count,
//           limit: parseInt(limit)
//         }
//       }, 'Security events retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting security events:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Generate encryption key pair
//    */
//   async generateKeyPair(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { key_type = 'rsa', key_size = 2048, purpose = 'user_data' } = req.body;

//       // Validate input
//       const validation = validateInput({ key_type, key_size, purpose }, 'generateKeyPair');
//       if (!validation.isValid) {
//         return APIResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
//       }

//       // Generate key pair through service
//       const keyPair = await encryptionService.generateKeyPair(key_type, key_size, purpose, userId);

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.KEY_GENERATE,
//         category: 'security',
//         severity: 'medium',
//         resource_type: 'encryption_key',
//         resource_id: keyPair.id,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: { key_type, key_size, purpose }
//       });

//       return APIResponse.success(res, {
//         key_id: keyPair.key_id,
//         public_key: keyPair.public_key,
//         key_type: keyPair.key_type,
//         algorithm: keyPair.algorithm,
//         created_at: keyPair.created_at
//       }, 'Key pair generated successfully', HTTP_STATUS.CREATED);

//     } catch (error) {
//       logger.error('Error generating key pair:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get user encryption keys
//    */
//   async getUserKeys(req, res, next) {
//     try {
//       const userId = req.user.id;

//       const keys = await EncryptionKey.findAll({
//         where: {
//           owner_id: userId,
//           status: 'active'
//         },
//         attributes: [
//           'id', 'key_id', 'key_type', 'purpose', 'algorithm', 
//           'key_size', 'status', 'usage_count', 'created_at', 'expires_at'
//         ],
//         order: [['created_at', 'DESC']]
//       });

//       return APIResponse.success(res, keys, 'Encryption keys retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting user keys:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Revoke encryption key
//    */
//   async revokeKey(req, res, next) {
//     try {
//       const { keyId } = req.params;
//       const userId = req.user.id;

//       const key = await EncryptionKey.findOne({
//         where: {
//           id: keyId,
//           owner_id: userId
//         }
//       });

//       if (!key) {
//         return APIResponse.error(res, 'Key not found', HTTP_STATUS.NOT_FOUND);
//       }

//       if (key.status === 'compromised') {
//         return APIResponse.error(res, 'Key is already compromised', HTTP_STATUS.BAD_REQUEST);
//       }

//       await key.update({ status: 'compromised' });

//       // Log security event
//       await securityService.logSecurityEvent({
//         user_id: userId,
//         event_type: SECURITY_EVENTS.KEY_REVOKED,
//         severity: 'high',
//         description: 'Encryption key manually revoked',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: { key_id: key.key_id, key_type: key.key_type }
//       });

//       return APIResponse.success(res, null, 'Key revoked successfully');

//     } catch (error) {
//       logger.error('Error revoking key:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Create digital signature
//    */
//   async createSignature(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { data, key_id } = req.body;

//       if (!data || !key_id) {
//         return APIResponse.error(res, 'Data and key ID are required', HTTP_STATUS.BAD_REQUEST);
//       }

//       // Create signature through service
//       const signature = await signatureService.createSignature(data, key_id, userId);

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.SIGNATURE_CREATE,
//         category: 'security',
//         severity: 'medium',
//         resource_type: 'digital_signature',
//         resource_id: signature.id,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: { key_id, data_hash: signature.data_hash }
//       });

//       return APIResponse.success(res, signature, 'Digital signature created successfully', HTTP_STATUS.CREATED);

//     } catch (error) {
//       logger.error('Error creating signature:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Verify digital signature
//    */
//   async verifySignature(req, res, next) {
//     try {
//       const { signatureId } = req.params;
//       const { data } = req.body;

//       if (!data) {
//         return APIResponse.error(res, 'Data is required for verification', HTTP_STATUS.BAD_REQUEST);
//       }

//       const signature = await DigitalSignature.findByPk(signatureId);

//       if (!signature) {
//         return APIResponse.error(res, 'Signature not found', HTTP_STATUS.NOT_FOUND);
//       }

//       // Verify signature through service
//       const isValid = await signatureService.verifySignature(signature, data);

//       // Update verification count
//       await signature.increment('verification_count');

//       // Log activity
//       await auditService.logActivity({
//         user_id: req.user.id,
//         action: USER_ACTIONS.SIGNATURE_VERIFY,
//         category: 'security',
//         severity: 'low',
//         resource_type: 'digital_signature',
//         resource_id: signatureId,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: { verification_result: isValid }
//       });

//       return APIResponse.success(res, { 
//         is_valid: isValid,
//         signature_id: signatureId,
//         verified_at: new Date()
//       }, 'Signature verification completed');

//     } catch (error) {
//       logger.error('Error verifying signature:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get security settings
//    */
//   async getSecuritySettings(req, res, next) {
//     try {
//       const userId = req.user.id;

//       const settings = await securityService.getUserSecuritySettings(userId);

//       return APIResponse.success(res, settings, 'Security settings retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting security settings:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Update security settings
//    */
//   async updateSecuritySettings(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const settingsData = req.body;

//       // Validate input
//       const validation = validateInput(settingsData, 'securitySettings');
//       if (!validation.isValid) {
//         return APIResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
//       }

//       await securityService.updateUserSecuritySettings(userId, settingsData);

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.SECURITY_SETTINGS_UPDATE,
//         category: 'security',
//         severity: 'medium',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         new_values: settingsData
//       });

//       return APIResponse.success(res, null, 'Security settings updated successfully');

//     } catch (error) {
//       logger.error('Error updating security settings:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Report security incident
//    */
//   async reportIncident(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { incident_type, description, metadata } = req.body;

//       // Validate input
//       const validation = validateInput(req.body, 'securityIncident');
//       if (!validation.isValid) {
//         return APIResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
//       }

//       // Log security event
//       const securityEvent = await securityService.logSecurityEvent({
//         user_id: userId,
//         event_type: incident_type,
//         severity: 'high',
//         description,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: {
//           ...metadata,
//           reported_by_user: true
//         }
//       });

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.SECURITY_INCIDENT_REPORT,
//         category: 'security',
//         severity: 'high',
//         resource_type: 'security_event',
//         resource_id: securityEvent.id,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: { incident_type, description }
//       });

//       return APIResponse.success(res, { 
//         incident_id: securityEvent.id 
//       }, 'Security incident reported successfully', HTTP_STATUS.CREATED);

//     } catch (error) {
//       logger.error('Error reporting security incident:', error);
//       return next(error);
//     }
//   }
// }

// export default new SecurityController();