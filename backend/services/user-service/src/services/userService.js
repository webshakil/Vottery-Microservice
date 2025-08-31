// services/userService.js
import VotteryUser from '../models/VotteryUser.js';
import UserProfile from '../models/UserProfile.js';
import UserRole from '../models/UserRole.js';
import Role from '../models/Role.js';
import encryptionService from './encryptionService.js';
import auditService from './auditService.js';
import { AppError } from '../utils/response.js';
import { USER_STATUS } from '../utils/constants.js';

class UserService {
  /**
   * Get user by ID with decrypted profile data
   * @param {number} userId 
   * @param {boolean} includeProfile 
   * @param {object} requestingUser 
   * @returns {Promise<object>}
   */
  async getUserById(userId, includeProfile = true, requestingUser = null) {
    try {
      const user = await VotteryUser.findByPk(userId, {
        include: includeProfile ? [
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
            }]
          }
        ] : []
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      // Log access for audit
      if (requestingUser) {
        await auditService.logActivity(
          requestingUser.id,
          'USER_VIEW',
          'user',
          userId,
          { accessed_by: requestingUser.id }
        );
      }

      // Decrypt profile data if included
      if (includeProfile && user.profile) {
        user.profile = await this.decryptProfileData(user.profile);
      }

      return this.sanitizeUserData(user);
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Update user status (suspend, activate, etc.)
   * @param {number} userId 
   * @param {string} status 
   * @param {object} adminUser 
   * @param {string} reason 
   * @returns {Promise<object>}
   */
  async updateUserStatus(userId, status, adminUser, reason = null) {
    try {
      const user = await VotteryUser.findByPk(userId);
      if (!user) {
        throw new AppError('User not found', 404);
      }

      const oldStatus = user.status;
      user.status = status;
      user.updated_at = new Date();
      
      await user.save();

      // Log status change
      await auditService.logActivity(
        adminUser.id,
        'USER_STATUS_CHANGE',
        'user',
        userId,
        {
          old_status: oldStatus,
          new_status: status,
          reason,
          changed_by: adminUser.id
        }
      );

      return this.sanitizeUserData(user);
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Get users with filtering and pagination
   * @param {object} filters 
   * @param {number} page 
   * @param {number} limit 
   * @returns {Promise<object>}
   */
  async getUsers(filters = {}, page = 1, limit = 10) {
    try {
      const offset = (page - 1) * limit;
      const whereClause = {};

      // Apply filters
      if (filters.status) {
        whereClause.status = filters.status;
      }
      if (filters.email) {
        whereClause.email = { [Op.iLike]: `%${filters.email}%` };
      }
      if (filters.dateFrom) {
        whereClause.created_at = { [Op.gte]: filters.dateFrom };
      }
      if (filters.dateTo) {
        whereClause.created_at = { 
          ...whereClause.created_at,
          [Op.lte]: filters.dateTo 
        };
      }

      const { count, rows } = await VotteryUser.findAndCountAll({
        where: whereClause,
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
            }]
          }
        ],
        limit,
        offset,
        order: [['created_at', 'DESC']]
      });

      // Decrypt profile data for each user
      const sanitizedUsers = await Promise.all(
        rows.map(async (user) => {
          if (user.profile) {
            user.profile = await this.decryptProfileData(user.profile);
          }
          return this.sanitizeUserData(user);
        })
      );

      return {
        users: sanitizedUsers,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(count / limit),
          totalCount: count,
          limit
        }
      };
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Delete user account (soft delete with encryption cleanup)
   * @param {number} userId 
   * @param {object} requestingUser 
   * @returns {Promise<boolean>}
   */
  async deleteUser(userId, requestingUser) {
    try {
      const user = await VotteryUser.findByPk(userId, {
        include: [{ model: UserProfile, as: 'profile' }]
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      // Soft delete - update status and clear sensitive data
      user.status = USER_STATUS.DELETED;
      user.email = `deleted_${Date.now()}@vottery.deleted`;
      user.updated_at = new Date();

      await user.save();

      // Clear encrypted profile data
      if (user.profile) {
        await user.profile.destroy();
      }

      // Log deletion
      await auditService.logActivity(
        requestingUser.id,
        'USER_DELETE',
        'user',
        userId,
        {
          deleted_by: requestingUser.id,
          deletion_reason: 'Admin action'
        }
      );

      return true;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Decrypt profile data fields
   * @param {object} profile 
   * @returns {Promise<object>}
   */
  async decryptProfileData(profile) {
    try {
      const decryptedProfile = { ...profile.toJSON() };

      const encryptedFields = [
        'first_name_encrypted',
        'last_name_encrypted',
        'age_encrypted',
        'gender_encrypted',
        'country_encrypted',
        'city_encrypted',
        'preferences_encrypted',
        'bio_encrypted'
      ];

      for (const field of encryptedFields) {
        if (decryptedProfile[field]) {
          const decryptedField = field.replace('_encrypted', '');
          decryptedProfile[decryptedField] = await encryptionService.decrypt(
            decryptedProfile[field]
          );
          delete decryptedProfile[field]; // Remove encrypted version
        }
      }

      return decryptedProfile;
    } catch (error) {
      throw new AppError('Error decrypting profile data', 500);
    }
  }

  /**
   * Sanitize user data for API response
   * @param {object} user 
   * @returns {object}
   */
  sanitizeUserData(user) {
    const userData = user.toJSON ? user.toJSON() : user;
    
    // Remove sensitive fields
    delete userData.password_hash;
    delete userData.two_factor_secret;
    delete userData.reset_token;
    delete userData.verification_token;

    return userData;
  }

  /**
   * Get user statistics
   * @returns {Promise<object>}
   */
  async getUserStats() {
    try {
      const [
        totalUsers,
        activeUsers,
        suspendedUsers,
        recentUsers
      ] = await Promise.all([
        VotteryUser.count(),
        VotteryUser.count({ where: { status: USER_STATUS.ACTIVE } }),
        VotteryUser.count({ where: { status: USER_STATUS.SUSPENDED } }),
        VotteryUser.count({
          where: {
            created_at: {
              [Op.gte]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Last 30 days
            }
          }
        })
      ]);

      return {
        total: totalUsers,
        active: activeUsers,
        suspended: suspendedUsers,
        recent: recentUsers
      };
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }
}

export default new UserService();