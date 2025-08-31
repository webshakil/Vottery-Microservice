import { Op } from 'sequelize';
import models from '../models/index.js';
const { VotteryUser, UserProfile, UserRole, Role, Organization, UserActivityLog } = models;

import encryptionService from '../services/encryptionService.js';
import auditService from '../services/auditService.js';
import validateInput from '../middleware/validation.js';
import ApiResponse from '../utils/response.js';
import logger from '../utils/logger.js';
import { USER_ACTIONS, HTTP_STATUS, ERROR_CODES } from '../utils/constants.js';
import bcrypt from 'bcrypt';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

class UserController {
  /**
   * Check username availability
   */
  async checkUsernameAvailability(req, res, next) {
    try {
      const { username } = req.params;

      const existingUser = await VotteryUser.findOne({
        where: { username: username.toLowerCase() }
      });

      const isAvailable = !existingUser;

      await auditService.logActivity({
        action: USER_ACTIONS.USERNAME_CHECK,
        category: 'system',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { username, available: isAvailable }
      });

      return ApiResponse.success(res, { 
        username, 
        available: isAvailable 
      }, isAvailable ? 'Username is available' : 'Username is not available');

    } catch (error) {
      logger.error('Error checking username availability:', error);
      return next(error);
    }
  }

  /**
   * Check email availability
   */
  async checkEmailAvailability(req, res, next) {
    try {
      const { email } = req.params;

      const existingUser = await VotteryUser.findOne({
        where: { email: email.toLowerCase() }
      });

      const isAvailable = !existingUser;

      await auditService.logActivity({
        action: USER_ACTIONS.EMAIL_CHECK,
        category: 'system',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { email, available: isAvailable }
      });

      return ApiResponse.success(res, { 
        email, 
        available: isAvailable 
      }, isAvailable ? 'Email is available' : 'Email is not available');

    } catch (error) {
      logger.error('Error checking email availability:', error);
      return next(error);
    }
  }

  /**
   * Get current user profile
   */
  async getCurrentUser(req, res, next) {
    try {
      const userId = req.user.id;

      const user = await VotteryUser.findByPk(userId, {
        include: [
          {
            model: UserProfile,
            as: 'profile'
          },
          {
            model: UserRole,
            as: 'userRoles',
            include: [{
              model: Role,
              as: 'role'
            }],
            where: { is_active: true },
            required: false
          }
        ]
      });

      if (!user) {
        return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
      }

      // Decrypt sensitive profile data
      if (user.profile && user.profile.encrypted_personal_data) {
        try {
          const decryptedData = await encryptionService.decrypt(
            user.profile.encrypted_personal_data,
            userId
          );
          user.profile.dataValues.personal_data = JSON.parse(decryptedData);
        } catch (error) {
          logger.warn(`Failed to decrypt user data for ${userId}:`, error);
        }
      }

      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.PROFILE_VIEW,
        category: 'profile',
        ip_address: req.ip,
        user_agent: req.get('User-Agent')
      });

      return ApiResponse.success(res, user, 'User profile retrieved successfully');

    } catch (error) {
      logger.error('Error getting current user:', error);
      return next(error);
    }
  }

  /**
   * Update current user profile
   */
  async updateCurrentUser(req, res, next) {
    try {
      const userId = req.user.id;
      const updateData = req.body;

      const user = await VotteryUser.findByPk(userId, {
        include: [{ model: UserProfile, as: 'profile' }]
      });

      if (!user) {
        return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
      }

      const { 
        personal_data, 
        public_display_name, 
        avatar_url, 
        country, 
        timezone, 
        preferred_language,
        privacy_settings,
        notification_preferences,
        ...sensitiveData 
      } = updateData;

      const profileUpdates = {};
      if (public_display_name) profileUpdates.public_display_name = public_display_name;
      if (avatar_url) profileUpdates.avatar_url = avatar_url;
      if (country) profileUpdates.country = country;
      if (timezone) profileUpdates.timezone = timezone;
      if (preferred_language) profileUpdates.preferred_language = preferred_language;
      if (privacy_settings) profileUpdates.privacy_settings = privacy_settings;
      if (notification_preferences) profileUpdates.notification_preferences = notification_preferences;

      if (personal_data || Object.keys(sensitiveData).length > 0) {
        const currentEncryptedData = user.profile?.encrypted_personal_data;
        let existingData = {};

        if (currentEncryptedData) {
          try {
            existingData = JSON.parse(
              await encryptionService.decrypt(currentEncryptedData, userId)
            );
          } catch (error) {
            logger.warn('Failed to decrypt existing data:', error);
          }
        }

        const newSensitiveData = {
          ...existingData,
          ...personal_data,
          ...sensitiveData
        };

        const encryptedData = await encryptionService.encrypt(
          JSON.stringify(newSensitiveData),
          userId
        );
        profileUpdates.encrypted_personal_data = encryptedData;
      }

      if (user.profile) {
        await user.profile.update(profileUpdates);
      } else {
        await UserProfile.create({
          user_id: userId,
          ...profileUpdates
        });
      }

      const completionScore = this.calculateProfileCompletion(user.profile);
      await user.profile.update({ profile_completion_score: completionScore });

      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.PROFILE_UPDATE,
        category: 'profile',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        new_values: profileUpdates
      });

      return ApiResponse.success(res, null, 'Profile updated successfully');

    } catch (error) {
      logger.error('Error updating current user:', error);
      return next(error);
    }
  }

  /**
   * Delete current user account
   */
  async deleteCurrentUser(req, res, next) {
    try {
      const userId = req.user.id;
      const { password, reason } = req.body;

      const user = await VotteryUser.findByPk(userId);
      if (!user) {
        return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
      }

      // Verify password for security
      const isValidPassword = await bcrypt.compare(password, user.password_hash);
      if (!isValidPassword) {
        return ApiResponse.error(res, 'Invalid password', HTTP_STATUS.UNAUTHORIZED);
      }

      // Soft delete
      await user.destroy();

      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.ACCOUNT_DELETE,
        category: 'security',
        severity: 'high',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { reason, self_delete: true }
      });

      return ApiResponse.success(res, null, 'Account deleted successfully');

    } catch (error) {
      logger.error('Error deleting current user:', error);
      return next(error);
    }
  }

  /**
   * Change user password
   */
  async changePassword(req, res, next) {
    try {
      const userId = req.user.id;
      const { current_password, new_password } = req.body;

      const user = await VotteryUser.findByPk(userId);
      if (!user) {
        return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
      }

      const isValidPassword = await bcrypt.compare(current_password, user.password_hash);
      if (!isValidPassword) {
        return ApiResponse.error(res, 'Current password is incorrect', HTTP_STATUS.UNAUTHORIZED);
      }

      const saltRounds = 12;
      const newPasswordHash = await bcrypt.hash(new_password, saltRounds);

      await user.update({ 
        password_hash: newPasswordHash,
        password_updated_at: new Date()
      });

      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.PASSWORD_CHANGE,
        category: 'security',
        severity: 'medium',
        ip_address: req.ip,
        user_agent: req.get('User-Agent')
      });

      return ApiResponse.success(res, null, 'Password changed successfully');

    } catch (error) {
      logger.error('Error changing password:', error);
      return next(error);
    }
  }

  /**
   * Toggle 2FA (Two-Factor Authentication)
   */
  async toggle2FA(req, res, next) {
    try {
      const userId = req.user.id;
      const { enable, token } = req.body;

      const user = await VotteryUser.findByPk(userId, {
        include: [{ model: UserProfile, as: 'profile' }]
      });

      if (!user) {
        return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
      }

      if (enable) {
        // Generate secret for 2FA
        const secret = speakeasy.generateSecret({
          name: `Vottery (${user.email})`,
          issuer: 'Vottery'
        });

        // Verify the token before enabling
        if (!token) {
          const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
          return ApiResponse.success(res, {
            secret: secret.base32,
            qr_code: qrCodeUrl
          }, 'Scan QR code with your authenticator app');
        }

        const verified = speakeasy.totp.verify({
          secret: secret.base32,
          encoding: 'base32',
          token: token,
          window: 2
        });

        if (!verified) {
          return ApiResponse.error(res, 'Invalid 2FA token', HTTP_STATUS.BAD_REQUEST);
        }

        await user.profile.update({
          two_factor_secret: secret.base32,
          two_factor_enabled: true
        });

        await auditService.logActivity({
          user_id: userId,
          action: USER_ACTIONS.TWO_FACTOR_ENABLE,
          category: 'security',
          severity: 'medium',
          ip_address: req.ip,
          user_agent: req.get('User-Agent')
        });

        return ApiResponse.success(res, null, '2FA enabled successfully');

      } else {
        // Verify token before disabling
        if (!token) {
          return ApiResponse.error(res, '2FA token required to disable', HTTP_STATUS.BAD_REQUEST);
        }

        const verified = speakeasy.totp.verify({
          secret: user.profile.two_factor_secret,
          encoding: 'base32',
          token: token,
          window: 2
        });

        if (!verified) {
          return ApiResponse.error(res, 'Invalid 2FA token', HTTP_STATUS.BAD_REQUEST);
        }

        await user.profile.update({
          two_factor_secret: null,
          two_factor_enabled: false
        });

        await auditService.logActivity({
          user_id: userId,
          action: USER_ACTIONS.TWO_FACTOR_DISABLE,
          category: 'security',
          severity: 'high',
          ip_address: req.ip,
          user_agent: req.get('User-Agent')
        });

        return ApiResponse.success(res, null, '2FA disabled successfully');
      }

    } catch (error) {
      logger.error('Error toggling 2FA:', error);
      return next(error);
    }
  }

  /**
   * Get user activity logs
   */
  async getUserActivity(req, res, next) {
    try {
      const userId = req.user.id;
      const { page = 1, limit = 20, action_type, start_date, end_date } = req.query;

      const offset = (page - 1) * limit;
      const whereClause = { user_id: userId };

      if (action_type) whereClause.action = action_type;
      if (start_date && end_date) {
        whereClause.created_at = {
          [Op.between]: [new Date(start_date), new Date(end_date)]
        };
      }

      const { rows: activities, count } = await UserActivityLog.findAndCountAll({
        where: whereClause,
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [['created_at', 'DESC']]
      });

      const totalPages = Math.ceil(count / limit);

      return ApiResponse.success(res, {
        activities,
        pagination: {
          current_page: parseInt(page),
          total_pages: totalPages,
          total_count: count,
          limit: parseInt(limit)
        }
      }, 'User activity retrieved successfully');

    } catch (error) {
      logger.error('Error getting user activity:', error);
      return next(error);
    }
  }

  /**
   * Get user sessions
   */
  async getUserSessions(req, res, next) {
    try {
      const userId = req.user.id;

      // This would typically come from a sessions table or Redis
      // For now, return current session info
      const currentSession = {
        id: req.sessionID || 'current',
        user_agent: req.get('User-Agent'),
        ip_address: req.ip,
        created_at: new Date(),
        last_activity: new Date(),
        is_current: true
      };

      return ApiResponse.success(res, { sessions: [currentSession] }, 'User sessions retrieved successfully');

    } catch (error) {
      logger.error('Error getting user sessions:', error);
      return next(error);
    }
  }

  /**
   * Revoke specific session
   */
  async revokeSession(req, res, next) {
    try {
      const userId = req.user.id;
      const { sessionId } = req.params;

      // Implementation would depend on session storage mechanism
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.SESSION_REVOKE,
        category: 'security',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { revoked_session_id: sessionId }
      });

      return ApiResponse.success(res, null, 'Session revoked successfully');

    } catch (error) {
      logger.error('Error revoking session:', error);
      return next(error);
    }
  }

  /**
   * Revoke all sessions except current
   */
  async revokeAllSessions(req, res, next) {
    try {
      const userId = req.user.id;

      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.SESSION_REVOKE_ALL,
        category: 'security',
        severity: 'high',
        ip_address: req.ip,
        user_agent: req.get('User-Agent')
      });

      return ApiResponse.success(res, null, 'All sessions revoked successfully');

    } catch (error) {
      logger.error('Error revoking all sessions:', error);
      return next(error);
    }
  }

  /**
   * Get all users (admin only)
   */
  async getAllUsers(req, res, next) {
    try {
      const {
        page = 1,
        limit = 20,
        search = '',
        country = '',
        account_type = '',
        subscription_status = '',
        verification_status = '',
        is_active = '',
        sort_by = 'created_at',
        sort_order = 'DESC'
      } = req.query;

      const offset = (page - 1) * limit;
      const whereClause = {};
      const profileWhereClause = {};

      if (search) {
        profileWhereClause[Op.or] = [
          { public_display_name: { [Op.iLike]: `%${search}%` } }
        ];
      }

      if (country) profileWhereClause.country = country;
      if (account_type) profileWhereClause.account_type = account_type;
      if (subscription_status) profileWhereClause.subscription_status = subscription_status;
      if (verification_status) profileWhereClause.verification_status = verification_status;
      if (is_active !== '') profileWhereClause.is_active = is_active === 'true';

      const { rows: users, count } = await VotteryUser.findAndCountAll({
        where: whereClause,
        include: [{
          model: UserProfile,
          as: 'profile',
          where: Object.keys(profileWhereClause).length > 0 ? profileWhereClause : undefined,
          required: Object.keys(profileWhereClause).length > 0
        }],
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [[{ model: UserProfile, as: 'profile' }, sort_by, sort_order]],
        distinct: true
      });

      const totalPages = Math.ceil(count / limit);

      await auditService.logActivity({
        user_id: req.user.id,
        action: USER_ACTIONS.USER_LIST,
        category: 'system',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { page, limit, filters: req.query }
      });

      return ApiResponse.success(res, {
        users,
        pagination: {
          current_page: parseInt(page),
          total_pages: totalPages,
          total_count: count,
          limit: parseInt(limit)
        }
      }, 'Users retrieved successfully');

    } catch (error) {
      logger.error('Error getting all users:', error);
      return next(error);
    }
  }

  /**
   * Get user by ID (admin only)
   */
  async getUserById(req, res, next) {
    try {
      const { userId } = req.params;

      const user = await VotteryUser.findByPk(userId, {
        include: [
          {
            model: UserProfile,
            as: 'profile'
          },
          {
            model: UserRole,
            as: 'userRoles',
            include: [{
              model: Role,
              as: 'role'
            }],
            where: { is_active: true },
            required: false
          }
        ]
      });

      if (!user) {
        return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
      }

      await auditService.logActivity({
        user_id: req.user.id,
        action: USER_ACTIONS.USER_VIEW,
        category: 'system',
        resource_type: 'user',
        resource_id: userId,
        ip_address: req.ip,
        user_agent: req.get('User-Agent')
      });

      return ApiResponse.success(res, user, 'User retrieved successfully');

    } catch (error) {
      logger.error('Error getting user by ID:', error);
      return next(error);
    }
  }

  /**
   * Admin update user
   */
  async adminUpdateUser(req, res, next) {
    try {
      const { userId } = req.params;
      const updateData = req.body;

      const user = await VotteryUser.findByPk(userId, {
        include: [{ model: UserProfile, as: 'profile' }]
      });

      if (!user) {
        return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
      }

      // Update user profile
      if (user.profile) {
        await user.profile.update(updateData);
      }

      await auditService.logActivity({
        user_id: req.user.id,
        action: USER_ACTIONS.USER_UPDATE_ADMIN,
        category: 'admin',
        resource_type: 'user',
        resource_id: userId,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        new_values: updateData
      });

      return ApiResponse.success(res, null, 'User updated successfully');

    } catch (error) {
      logger.error('Error admin updating user:', error);
      return next(error);
    }
  }

  /**
   * Toggle user suspension
   */
  async toggleUserSuspension(req, res, next) {
    try {
      const { userId } = req.params;
      const { suspend, reason } = req.body;

      const user = await VotteryUser.findByPk(userId, {
        include: [{ model: UserProfile, as: 'profile' }]
      });

      if (!user) {
        return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
      }

      await user.profile.update({ 
        is_suspended: suspend,
        suspension_reason: suspend ? reason : null,
        suspended_at: suspend ? new Date() : null
      });

      await auditService.logActivity({
        user_id: req.user.id,
        action: suspend ? USER_ACTIONS.USER_SUSPEND : USER_ACTIONS.USER_UNSUSPEND,
        category: 'security',
        severity: 'high',
        resource_type: 'user',
        resource_id: userId,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { reason, suspended_by: req.user.id }
      });

      return ApiResponse.success(res, null, `User ${suspend ? 'suspended' : 'unsuspended'} successfully`);

    } catch (error) {
      logger.error('Error toggling user suspension:', error);
      return next(error);
    }
  }

  /**
   * Admin delete user
   */
  async adminDeleteUser(req, res, next) {
    try {
      const { userId } = req.params;

      if (userId === req.user.id) {
        return ApiResponse.error(res, 'Cannot delete your own account', HTTP_STATUS.BAD_REQUEST);
      }

      const user = await VotteryUser.findByPk(userId);

      if (!user) {
        return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
      }

      await user.destroy();

      await auditService.logActivity({
        user_id: req.user.id,
        action: USER_ACTIONS.USER_DELETE,
        category: 'security',
        severity: 'critical',
        resource_type: 'user',
        resource_id: userId,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { deleted_by: req.user.id }
      });

      return ApiResponse.success(res, null, 'User deleted successfully');

    } catch (error) {
      logger.error('Error admin deleting user:', error);
      return next(error);
    }
  }

  /**
   * Get user statistics
   */
  async getUserStats(req, res, next) {
    try {
      const stats = await Promise.all([
        VotteryUser.count(),
        UserProfile.count({ where: { is_active: true } }),
        VotteryUser.count({
          where: {
            created_at: {
              [Op.gte]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
            }
          }
        })
      ]);

      const [totalUsers, activeUsers, newUsersLast30Days] = stats;

      const userStats = {
        total_users: totalUsers,
        active_users: activeUsers,
        inactive_users: totalUsers - activeUsers,
        new_users_last_30_days: newUsersLast30Days
      };

      return ApiResponse.success(res, userStats, 'User statistics retrieved successfully');

    } catch (error) {
      logger.error('Error getting user stats:', error);
      return next(error);
    }
  }

  /**
   * Get user demographics
   */
  async getUserDemographics(req, res, next) {
    try {
      const { start_date, end_date } = req.query;
      const whereClause = {};

      if (start_date && end_date) {
        whereClause.created_at = {
          [Op.between]: [new Date(start_date), new Date(end_date)]
        };
      }

      const demographics = {
        by_country: await UserProfile.findAll({
          attributes: ['country', [models.sequelize.fn('COUNT', models.sequelize.col('country')), 'count']],
          where: { country: { [Op.not]: null } },
          group: ['country'],
          order: [[models.sequelize.literal('count'), 'DESC']],
          limit: 10
        }),
        by_age_group: await UserProfile.findAll({
          attributes: ['age_group', [models.sequelize.fn('COUNT', models.sequelize.col('age_group')), 'count']],
          where: { age_group: { [Op.not]: null } },
          group: ['age_group'],
          order: [[models.sequelize.literal('count'), 'DESC']]
        })
      };

      return ApiResponse.success(res, demographics, 'User demographics retrieved successfully');

    } catch (error) {
      logger.error('Error getting user demographics:', error);
      return next(error);
    }
  }

  /**
   * Export users to CSV
   */
  async exportUsers(req, res, next) {
    try {
      const { format = 'csv', fields = 'all' } = req.query;

      const users = await VotteryUser.findAll({
        include: [{ model: UserProfile, as: 'profile' }]
      });

      // Implementation would generate CSV/Excel file
      await auditService.logActivity({
        user_id: req.user.id,
        action: USER_ACTIONS.USER_EXPORT,
        category: 'system',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { format, fields, count: users.length }
      });

      return ApiResponse.success(res, { export_url: '/exports/users.csv' }, 'Export initiated successfully');

    } catch (error) {
      logger.error('Error exporting users:', error);
      return next(error);
    }
  }

  /**
   * Bulk suspend users
   */
  async bulkSuspendUsers(req, res, next) {
    try {
      const { user_ids, reason } = req.body;

      await UserProfile.update(
        { 
          is_suspended: true,
          suspension_reason: reason,
          suspended_at: new Date()
        },
        { where: { user_id: { [Op.in]: user_ids } } }
      );

      await auditService.logActivity({
        user_id: req.user.id,
        action: USER_ACTIONS.USER_BULK_SUSPEND,
        category: 'security',
        severity: 'critical',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { user_ids, reason, count: user_ids.length }
      });

      return ApiResponse.success(res, null, `${user_ids.length} users suspended successfully`);

    } catch (error) {
      logger.error('Error bulk suspending users:', error);
      return next(error);
    }
  }

  /**
   * Bulk unsuspend users
   */
  async bulkUnsuspendUsers(req, res, next) {
    try {
      const { user_ids } = req.body;

      await UserProfile.update(
        { 
          is_suspended: false,
          suspension_reason: null,
          suspended_at: null
        },
        { where: { user_id: { [Op.in]: user_ids } } }
      );

      await auditService.logActivity({
        user_id: req.user.id,
        action: USER_ACTIONS.USER_BULK_UNSUSPEND,
        category: 'security',
        severity: 'high',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { user_ids, count: user_ids.length }
      });

      return ApiResponse.success(res, null, `${user_ids.length} users unsuspended successfully`);

    } catch (error) {
      logger.error('Error bulk unsuspending users:', error);
      return next(error);
    }
  }

  /**
   * Bulk delete users
   */
  async bulkDeleteUsers(req, res, next) {
    try {
      const { user_ids } = req.body;

      // Prevent self-deletion
      if (user_ids.includes(req.user.id)) {
        return ApiResponse.error(res, 'Cannot delete your own account', HTTP_STATUS.BAD_REQUEST);
      }

      await VotteryUser.destroy({
        where: { id: { [Op.in]: user_ids } }
      });

      await auditService.logActivity({
        user_id: req.user.id,
        action: USER_ACTIONS.USER_BULK_DELETE,
        category: 'security',
        severity: 'critical',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { user_ids, count: user_ids.length }
      });

      return ApiResponse.success(res, null, `${user_ids.length} users deleted successfully`);

    } catch (error) {
      logger.error('Error bulk deleting users:', error);
      return next(error);
    }
  }

  /**
   * Search users
   */
  async searchUsers(req, res, next) {
    try {
      const { query, page = 1, limit = 20 } = req.query;
      const offset = (page - 1) * limit;

      if (!query || query.length < 2) {
        return ApiResponse.error(res, 'Search query must be at least 2 characters', HTTP_STATUS.BAD_REQUEST);
      }

      const { rows: users, count } = await VotteryUser.findAndCountAll({
        include: [{
          model: UserProfile,
          as: 'profile',
          where: {
            [Op.or]: [
              { public_display_name: { [Op.iLike]: `%${query}%` } },
              { country: { [Op.iLike]: `%${query}%` } }
            ]
          }
        }],
        limit: parseInt(limit),
        offset: parseInt(offset),
        distinct: true
      });

      const totalPages = Math.ceil(count / limit);

      return ApiResponse.success(res, {
        users,
        pagination: {
          current_page: parseInt(page),
          total_pages: totalPages,
          total_count: count,
          limit: parseInt(limit)
        }
      }, 'Search completed successfully');

    } catch (error) {
      logger.error('Error searching users:', error);
      return next(error);
    }
  }

  /**
   * Advanced user filtering
   */
  async advancedUserFilter(req, res, next) {
    try {
      const { 
        filters, 
        page = 1, 
        limit = 20,
        sort_by = 'created_at',
        sort_order = 'DESC'
      } = req.body;

      const offset = (page - 1) * limit;
      const whereClause = {};
      const profileWhereClause = {};

      // Apply advanced filters
      if (filters.age_range) {
        profileWhereClause.age_group = { [Op.in]: filters.age_range };
      }
      
      if (filters.countries) {
        profileWhereClause.country = { [Op.in]: filters.countries };
      }

      if (filters.account_types) {
        profileWhereClause.account_type = { [Op.in]: filters.account_types };
      }

      if (filters.subscription_status) {
        profileWhereClause.subscription_status = { [Op.in]: filters.subscription_status };
      }

      if (filters.date_range) {
        whereClause.created_at = {
          [Op.between]: [new Date(filters.date_range.start), new Date(filters.date_range.end)]
        };
      }

      const { rows: users, count } = await VotteryUser.findAndCountAll({
        where: whereClause,
        include: [{
          model: UserProfile,
          as: 'profile',
          where: Object.keys(profileWhereClause).length > 0 ? profileWhereClause : undefined,
          required: Object.keys(profileWhereClause).length > 0
        }],
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [[{ model: UserProfile, as: 'profile' }, sort_by, sort_order]],
        distinct: true
      });

      const totalPages = Math.ceil(count / limit);

      await auditService.logActivity({
        user_id: req.user.id,
        action: USER_ACTIONS.USER_FILTER,
        category: 'system',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        metadata: { filters, results_count: count }
      });

      return ApiResponse.success(res, {
        users,
        pagination: {
          current_page: parseInt(page),
          total_pages: totalPages,
          total_count: count,
          limit: parseInt(limit)
        }
      }, 'Advanced filter applied successfully');

    } catch (error) {
      logger.error('Error applying advanced user filter:', error);
      return next(error);
    }
  }

  /**
   * Calculate profile completion score
   */
  calculateProfileCompletion(profile) {
    if (!profile) return 0;

    let score = 20; // Base score for having a profile

    // Required fields (20 points each)
    if (profile.public_display_name) score += 20;
    if (profile.country) score += 20;
    
    // Optional fields (10 points each)
    if (profile.avatar_url) score += 10;
    if (profile.timezone && profile.timezone !== 'UTC') score += 10;
    if (profile.preferred_language && profile.preferred_language !== 'en-US') score += 10;

    // Verification status (20 points)
    if (profile.verification_status === 'fully_verified') score += 20;
    else if (profile.verification_status === 'email_verified') score += 10;

    return Math.min(score, 100);
  }
}

export default new UserController();
// import { Op } from 'sequelize';
// // import { 
// //   VotteryUser, 
// //   UserProfile, 
// //   UserRole, 
// //   Role, 
// //   Organization,
// //   UserActivityLog 
// // } from '../models/index.js';
// import models from '../models/index.js';
// const { VotteryUser, UserProfile, UserRole, Role, Organization, UserActivityLog } = models;

// //import { encryptionService } from '../services/encryptionService.js';
// import  encryptionService  from '../services/encryptionService.js';
// //import { auditService } from '../services/auditService.js';
// import  auditService  from '../services/auditService.js';
// import  validateInput  from '../middleware/validation.js';
// import  ApiResponse  from '../utils/response.js';
// //import { ApiResponse } from '../utils/response.js';
// //import { logger } from '../utils/logger.js';
// import logger  from '../utils/logger.js';
// //import { USER_ACTIONS, HTTP_STATUS, ERROR_CODES } from '../utils/constants.js';
// import USER_ACTIONS from '../utils/constants.js';
// import HTTP_STATUS from '../utils/constants.js';
// import ERROR_CODES  from '../utils/constants.js';

// class UserController {
//   /**
//    * Get current user profile
//    */
//   async getCurrentUser(req, res, next) {
//     try {
//       const userId = req.user.id;

//       const user = await VotteryUser.findByPk(userId, {
//         include: [
//           {
//             model: UserProfile,
//             as: 'profile'
//           },
//           {
//             model: UserRole,
//             as: 'userRoles',
//             include: [{
//               model: Role,
//               as: 'role'
//             }],
//             where: { is_active: true },
//             required: false
//           }
//         ]
//       });

//       if (!user) {
//         return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
//       }

//       // Decrypt sensitive profile data
//       if (user.profile && user.profile.encrypted_personal_data) {
//         try {
//           const decryptedData = await encryptionService.decrypt(
//             user.profile.encrypted_personal_data,
//             userId
//           );
//           user.profile.dataValues.personal_data = JSON.parse(decryptedData);
//         } catch (error) {
//           logger.warn(`Failed to decrypt user data for ${userId}:`, error);
//         }
//       }

//       // Log access
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.PROFILE_VIEW,
//         category: 'profile',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent')
//       });

//       return ApiResponse.success(res, user, 'User profile retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting current user:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Update user profile
//    */
//   async updateProfile(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const updateData = req.body;

//       // Validate input
//       const validation = validateInput(updateData, 'userProfileUpdate');
//       if (!validation.isValid) {
//         return ApiResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
//       }

//       const user = await VotteryUser.findByPk(userId, {
//         include: [{ model: UserProfile, as: 'profile' }]
//       });

//       if (!user) {
//         return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
//       }

//       // Separate sensitive and non-sensitive data
//       const { 
//         personal_data, 
//         public_display_name, 
//         avatar_url, 
//         country, 
//         timezone, 
//         preferred_language,
//         privacy_settings,
//         notification_preferences,
//         ...sensitiveData 
//       } = updateData;

//       // Prepare profile updates
//       const profileUpdates = {};
//       if (public_display_name) profileUpdates.public_display_name = public_display_name;
//       if (avatar_url) profileUpdates.avatar_url = avatar_url;
//       if (country) profileUpdates.country = country;
//       if (timezone) profileUpdates.timezone = timezone;
//       if (preferred_language) profileUpdates.preferred_language = preferred_language;
//       if (privacy_settings) profileUpdates.privacy_settings = privacy_settings;
//       if (notification_preferences) profileUpdates.notification_preferences = notification_preferences;

//       // Handle sensitive data encryption
//       if (personal_data || Object.keys(sensitiveData).length > 0) {
//         const currentEncryptedData = user.profile?.encrypted_personal_data;
//         let existingData = {};

//         if (currentEncryptedData) {
//           try {
//             existingData = JSON.parse(
//               await encryptionService.decrypt(currentEncryptedData, userId)
//             );
//           } catch (error) {
//             logger.warn('Failed to decrypt existing data:', error);
//           }
//         }

//         // Merge with new data
//         const newSensitiveData = {
//           ...existingData,
//           ...personal_data,
//           ...sensitiveData
//         };

//         // Encrypt updated sensitive data
//         const encryptedData = await encryptionService.encrypt(
//           JSON.stringify(newSensitiveData),
//           userId
//         );
//         profileUpdates.encrypted_personal_data = encryptedData;
//       }

//       // Update profile
//       if (user.profile) {
//         await user.profile.update(profileUpdates);
//       } else {
//         await UserProfile.create({
//           user_id: userId,
//           ...profileUpdates
//         });
//       }

//       // Calculate completion score
//       const completionScore = this.calculateProfileCompletion(user.profile);
//       await user.profile.update({ profile_completion_score: completionScore });

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.PROFILE_UPDATE,
//         category: 'profile',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         new_values: profileUpdates
//       });

//       return ApiResponse.success(res, null, 'Profile updated successfully');

//     } catch (error) {
//       logger.error('Error updating profile:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get user by ID (admin only)
//    */
//   async getUserById(req, res, next) {
//     try {
//       const { userId } = req.params;
//       const requestingUserId = req.user.id;

//       // Check permissions
//       if (!req.user.hasPermission('user.read')) {
//         return ApiResponse.error(res, 'Insufficient permissions', HTTP_STATUS.FORBIDDEN);
//       }

//       const user = await VotteryUser.findByPk(userId, {
//         include: [
//           {
//             model: UserProfile,
//             as: 'profile'
//           },
//           {
//             model: UserRole,
//             as: 'userRoles',
//             include: [{
//               model: Role,
//               as: 'role'
//             }],
//             where: { is_active: true },
//             required: false
//           }
//         ]
//       });

//       if (!user) {
//         return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
//       }

//       // Log access
//       await auditService.logActivity({
//         user_id: requestingUserId,
//         action: USER_ACTIONS.USER_VIEW,
//         category: 'system',
//         resource_type: 'user',
//         resource_id: userId,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent')
//       });

//       return ApiResponse.success(res, user, 'User retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting user by ID:', error);
//       return next(error);
//     }
//   }

//   /**
//    * List users with filtering and pagination
//    */
//   async listUsers(req, res, next) {
//     try {
//       // Check permissions
//       if (!req.user.hasPermission('user.list')) {
//         return ApiResponse.error(res, 'Insufficient permissions', HTTP_STATUS.FORBIDDEN);
//       }

//       const {
//         page = 1,
//         limit = 20,
//         search = '',
//         country = '',
//         account_type = '',
//         subscription_status = '',
//         verification_status = '',
//         is_active = '',
//         sort_by = 'created_at',
//         sort_order = 'DESC'
//       } = req.query;

//       const offset = (page - 1) * limit;
//       const whereClause = {};
//       const profileWhereClause = {};

//       // Build search conditions
//       if (search) {
//         profileWhereClause[Op.or] = [
//           { public_display_name: { [Op.iLike]: `%${search}%` } }
//         ];
//       }

//       if (country) profileWhereClause.country = country;
//       if (account_type) profileWhereClause.account_type = account_type;
//       if (subscription_status) profileWhereClause.subscription_status = subscription_status;
//       if (verification_status) profileWhereClause.verification_status = verification_status;
//       if (is_active !== '') profileWhereClause.is_active = is_active === 'true';

//       const { rows: users, count } = await VotteryUser.findAndCountAll({
//         where: whereClause,
//         include: [{
//           model: UserProfile,
//           as: 'profile',
//           where: Object.keys(profileWhereClause).length > 0 ? profileWhereClause : undefined,
//           required: Object.keys(profileWhereClause).length > 0
//         }],
//         limit: parseInt(limit),
//         offset: parseInt(offset),
//         order: [[{ model: UserProfile, as: 'profile' }, sort_by, sort_order]],
//         distinct: true
//       });

//       const totalPages = Math.ceil(count / limit);

//       // Log access
//       await auditService.logActivity({
//         user_id: req.user.id,
//         action: USER_ACTIONS.USER_LIST,
//         category: 'system',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: { page, limit, filters: req.query }
//       });

//       return ApiResponse.success(res, {
//         users,
//         pagination: {
//           current_page: parseInt(page),
//           total_pages: totalPages,
//           total_count: count,
//           limit: parseInt(limit),
//           has_next: page < totalPages,
//           has_prev: page > 1
//         }
//       }, 'Users retrieved successfully');

//     } catch (error) {
//       logger.error('Error listing users:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Deactivate user account
//    */
//   async deactivateUser(req, res, next) {
//     try {
//       const { userId } = req.params;
//       const { reason } = req.body;

//       // Check permissions
//       if (!req.user.hasPermission('user.deactivate')) {
//         return ApiResponse.error(res, 'Insufficient permissions', HTTP_STATUS.FORBIDDEN);
//       }

//       const user = await VotteryUser.findByPk(userId, {
//         include: [{ model: UserProfile, as: 'profile' }]
//       });

//       if (!user) {
//         return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
//       }

//       if (!user.profile.is_active) {
//         return ApiResponse.error(res, 'User is already deactivated', HTTP_STATUS.BAD_REQUEST);
//       }

//       // Deactivate user profile
//       await user.profile.update({ is_active: false });

//       // Log activity
//       await auditService.logActivity({
//         user_id: req.user.id,
//         action: USER_ACTIONS.USER_DEACTIVATE,
//         category: 'security',
//         severity: 'high',
//         resource_type: 'user',
//         resource_id: userId,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: { reason, deactivated_by: req.user.id }
//       });

//       return ApiResponse.success(res, null, 'User deactivated successfully');

//     } catch (error) {
//       logger.error('Error deactivating user:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Reactivate user account
//    */
//   async reactivateUser(req, res, next) {
//     try {
//       const { userId } = req.params;

//       // Check permissions
//       if (!req.user.hasPermission('user.reactivate')) {
//         return ApiResponse.error(res, 'Insufficient permissions', HTTP_STATUS.FORBIDDEN);
//       }

//       const user = await VotteryUser.findByPk(userId, {
//         include: [{ model: UserProfile, as: 'profile' }]
//       });

//       if (!user) {
//         return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
//       }

//       if (user.profile.is_active) {
//         return ApiResponse.error(res, 'User is already active', HTTP_STATUS.BAD_REQUEST);
//       }

//       // Reactivate user profile
//       await user.profile.update({ is_active: true });

//       // Log activity
//       await auditService.logActivity({
//         user_id: req.user.id,
//         action: USER_ACTIONS.USER_REACTIVATE,
//         category: 'security',
//         severity: 'medium',
//         resource_type: 'user',
//         resource_id: userId,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: { reactivated_by: req.user.id }
//       });

//       return ApiResponse.success(res, null, 'User reactivated successfully');

//     } catch (error) {
//       logger.error('Error reactivating user:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Delete user account (soft delete)
//    */
//   async deleteUser(req, res, next) {
//     try {
//       const { userId } = req.params;

//       // Check permissions
//       if (!req.user.hasPermission('user.delete')) {
//         return ApiResponse.error(res, 'Insufficient permissions', HTTP_STATUS.FORBIDDEN);
//       }

//       // Prevent self-deletion
//       if (userId === req.user.id) {
//         return ApiResponse.error(res, 'Cannot delete your own account', HTTP_STATUS.BAD_REQUEST);
//       }

//       const user = await VotteryUser.findByPk(userId);

//       if (!user) {
//         return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
//       }

//       // Soft delete
//       await user.destroy();

//       // Log activity
//       await auditService.logActivity({
//         user_id: req.user.id,
//         action: USER_ACTIONS.USER_DELETE,
//         category: 'security',
//         severity: 'critical',
//         resource_type: 'user',
//         resource_id: userId,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         metadata: { deleted_by: req.user.id }
//       });

//       return ApiResponse.success(res, null, 'User deleted successfully');

//     } catch (error) {
//       logger.error('Error deleting user:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get user statistics
//    */
//   async getUserStats(req, res, next) {
//     try {
//       // Check permissions
//       if (!req.user.hasPermission('user.stats')) {
//         return ApiResponse.error(res, 'Insufficient permissions', HTTP_STATUS.FORBIDDEN);
//       }

//       const stats = await Promise.all([
//         // Total users
//         VotteryUser.count(),
        
//         // Active users
//         UserProfile.count({ where: { is_active: true } }),
        
//         // Users by account type
//         UserProfile.count({
//           attributes: ['account_type'],
//           group: ['account_type']
//         }),
        
//         // Users by subscription status
//         UserProfile.count({
//           attributes: ['subscription_status'],
//           group: ['subscription_status']
//         }),
        
//         // Users by country (top 10)
//         UserProfile.findAll({
//           attributes: ['country', [sequelize.fn('COUNT', sequelize.col('country')), 'count']],
//           where: { country: { [Op.not]: null } },
//           group: ['country'],
//           order: [[sequelize.literal('count'), 'DESC']],
//           limit: 10
//         }),
        
//         // New users in last 30 days
//         VotteryUser.count({
//           where: {
//             created_at: {
//               [Op.gte]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
//             }
//           }
//         })
//       ]);

//       const [
//         totalUsers,
//         activeUsers,
//         usersByAccountType,
//         usersBySubscription,
//         usersByCountry,
//         newUsersLast30Days
//       ] = stats;

//       const userStats = {
//         total_users: totalUsers,
//         active_users: activeUsers,
//         inactive_users: totalUsers - activeUsers,
//         new_users_last_30_days: newUsersLast30Days,
//         by_account_type: usersByAccountType,
//         by_subscription_status: usersBySubscription,
//         top_countries: usersByCountry
//       };

//       return ApiResponse.success(res, userStats, 'User statistics retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting user stats:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Calculate profile completion score
//    */
//   calculateProfileCompletion(profile) {
//     if (!profile) return 0;

//     let score = 20; // Base score for having a profile

//     // Required fields (20 points each)
//     if (profile.public_display_name) score += 20;
//     if (profile.country) score += 20;
    
//     // Optional fields (10 points each)
//     if (profile.avatar_url) score += 10;
//     if (profile.timezone && profile.timezone !== 'UTC') score += 10;
//     if (profile.preferred_language && profile.preferred_language !== 'en-US') score += 10;

//     // Verification status (20 points)
//     if (profile.verification_status === 'fully_verified') score += 20;
//     else if (profile.verification_status === 'email_verified') score += 10;

//     return Math.min(score, 100);
//   }
// }

// export default new UserController();