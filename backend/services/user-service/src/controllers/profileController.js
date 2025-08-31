import { Op } from 'sequelize'; // Added missing import
import encryptionService from '../services/encryptionService.js';
import auditService from '../services/auditService.js';
import validateInput from '../middleware/validation.js';
import { APIResponse } from '../utils/response.js';
import logger from '../utils/logger.js';
import { USER_ACTIONS, HTTP_STATUS } from '../utils/constants.js';
import models from '../models/index.js';

const { UserProfile, VotteryUser } = models;

class ProfileController {
  constructor() {
    // Bind all methods to maintain 'this' context
    this.getCurrentProfile = this.getCurrentProfile.bind(this);
    this.createProfile = this.createProfile.bind(this);
    this.updateCurrentProfile = this.updateCurrentProfile.bind(this);
    this.deleteAvatar = this.deleteAvatar.bind(this);
    this.updatePreferences = this.updatePreferences.bind(this);
    this.updateDemographics = this.updateDemographics.bind(this);
    this.updateVisibility = this.updateVisibility.bind(this);
    this.getProfileCompletion = this.getProfileCompletion.bind(this);
    this.exportProfile = this.exportProfile.bind(this);
    this.getProfileByUserId = this.getProfileByUserId.bind(this);
    this.getAllProfiles = this.getAllProfiles.bind(this);
    this.adminUpdateProfile = this.adminUpdateProfile.bind(this);
    this.adminDeleteProfile = this.adminDeleteProfile.bind(this);
    this.getProfileAnalytics = this.getProfileAnalytics.bind(this);
    this.getDemographicsAnalytics = this.getDemographicsAnalytics.bind(this);
    this.getCompletionAnalytics = this.getCompletionAnalytics.bind(this);
    this.getAvatarAnalytics = this.getAvatarAnalytics.bind(this);
    this.exportProfiles = this.exportProfiles.bind(this);
    this.searchPublicProfiles = this.searchPublicProfiles.bind(this);
    this.bulkUpdateVisibility = this.bulkUpdateVisibility.bind(this);
    this.bulkVerifyProfiles = this.bulkVerifyProfiles.bind(this);
    this.bulkUnverifyProfiles = this.bulkUnverifyProfiles.bind(this);
    this.moderateProfile = this.moderateProfile.bind(this);
    this.reportProfile = this.reportProfile.bind(this);
    this.getPendingReports = this.getPendingReports.bind(this);
    this.getProfileSettings = this.getProfileSettings.bind(this);
    this.updatePrivacySettings = this.updatePrivacySettings.bind(this);
    this.updateNotificationPreferences = this.updateNotificationPreferences.bind(this);
    this.uploadAvatar = this.uploadAvatar.bind(this);
    this.getPublicProfile = this.getPublicProfile.bind(this);
    this.deleteProfileData = this.deleteProfileData.bind(this);
  }

  /**
   * Get current user's profile (alias for getProfileSettings)
   */
  async getCurrentProfile(req, res, next) {
    return this.getProfileSettings(req, res, next);
  }

  /**
   * Create new profile
   */
  async createProfile(req, res, next) {
    try {
      const userId = req.user.id;
      const profileData = req.body;

      // Check if profile already exists
      const existingProfile = await UserProfile.findOne({
        where: { user_id: userId }
      });

      if (existingProfile) {
        return APIResponse.error(res, 'Profile already exists', HTTP_STATUS.CONFLICT);
      }

      // Create new profile
      const profile = await UserProfile.create({
        user_id: userId,
        ...profileData
      });

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: 'profile_create',
        category: 'profile',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        new_values: profileData
      });

      return APIResponse.success(res, profile, 'Profile created successfully');

    } catch (error) {
      logger.error('Error creating profile:', error);
      return next(error);
    }
  }

  /**
   * Update current user's profile
   */
  async updateCurrentProfile(req, res, next) {
    try {
      const userId = req.user.id;
      const updates = req.body;

      const profile = await UserProfile.findOne({
        where: { user_id: userId }
      });

      if (!profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      const oldValues = profile.toJSON();
      await profile.update(updates);

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: 'profile_update',
        category: 'profile',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        old_values: oldValues,
        new_values: updates
      });

      return APIResponse.success(res, profile, 'Profile updated successfully');

    } catch (error) {
      logger.error('Error updating profile:', error);
      return next(error);
    }
  }

  /**
   * Delete avatar
   */
  async deleteAvatar(req, res, next) {
    try {
      const userId = req.user.id;

      const profile = await UserProfile.findOne({
        where: { user_id: userId }
      });

      if (!profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      const oldAvatarUrl = profile.avatar_url;
      await profile.update({ avatar_url: null });

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.AVATAR_UPDATE,
        category: 'profile',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        old_values: { avatar_url: oldAvatarUrl },
        new_values: { avatar_url: null }
      });

      return APIResponse.success(res, null, 'Avatar deleted successfully');

    } catch (error) {
      logger.error('Error deleting avatar:', error);
      return next(error);
    }
  }

  /**
   * Update preferences
   */
  async updatePreferences(req, res, next) {
    return this.updateNotificationPreferences(req, res, next);
  }

  /**
   * Update demographics
   */
  async updateDemographics(req, res, next) {
    try {
      const userId = req.user.id;
      const { demographics } = req.body;

      const profile = await UserProfile.findOne({
        where: { user_id: userId }
      });

      if (!profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      const oldDemographics = profile.demographics;
      await profile.update({ demographics });

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: 'demographics_update',
        category: 'profile',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        old_values: { demographics: oldDemographics },
        new_values: { demographics }
      });

      return APIResponse.success(res, null, 'Demographics updated successfully');

    } catch (error) {
      logger.error('Error updating demographics:', error);
      return next(error);
    }
  }

  /**
   * Update visibility settings
   */
  async updateVisibility(req, res, next) {
    try {
      const userId = req.user.id;
      const { visibility_settings } = req.body;

      const profile = await UserProfile.findOne({
        where: { user_id: userId }
      });

      if (!profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      // Update privacy settings with visibility
      const updatedPrivacySettings = {
        ...profile.privacy_settings,
        ...visibility_settings
      };

      await profile.update({ privacy_settings: updatedPrivacySettings });

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: 'visibility_update',
        category: 'profile',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        new_values: { visibility_settings }
      });

      return APIResponse.success(res, null, 'Visibility settings updated successfully');

    } catch (error) {
      logger.error('Error updating visibility:', error);
      return next(error);
    }
  }

  /**
   * Get profile completion status
   */
  async getProfileCompletion(req, res, next) {
    try {
      const userId = req.user.id;

      const profile = await UserProfile.findOne({
        where: { user_id: userId }
      });

      if (!profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      const completion = {
        percentage: profile.profile_completion_score || 0,
        completedFields: [],
        missingFields: []
      };

      // Calculate completion based on available fields
      const requiredFields = ['public_display_name', 'avatar_url', 'country', 'demographics'];
      requiredFields.forEach(field => {
        if (profile[field]) {
          completion.completedFields.push(field);
        } else {
          completion.missingFields.push(field);
        }
      });

      completion.percentage = Math.round((completion.completedFields.length / requiredFields.length) * 100);

      return APIResponse.success(res, completion, 'Profile completion retrieved successfully');

    } catch (error) {
      logger.error('Error getting profile completion:', error);
      return next(error);
    }
  }

  /**
   * Export profile data
   */
  async exportProfile(req, res, next) {
    try {
      const userId = req.user.id;
      const format = req.query.format || 'json';

      const profile = await UserProfile.findOne({
        where: { user_id: userId }
      });

      if (!profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      let exportData = profile.toJSON();

      // Decrypt sensitive data if needed
      if (profile.encrypted_personal_data) {
        try {
          const personalData = JSON.parse(
            await encryptionService.decrypt(profile.encrypted_personal_data, userId)
          );
          exportData.personal_data = personalData;
          delete exportData.encrypted_personal_data;
        } catch (error) {
          logger.warn('Failed to decrypt profile data for export:', error);
        }
      }

      if (format === 'csv') {
        // TODO: Convert to CSV format
        return APIResponse.success(res, exportData, 'Profile exported as CSV');
      }

      return APIResponse.success(res, exportData, 'Profile exported successfully');

    } catch (error) {
      logger.error('Error exporting profile:', error);
      return next(error);
    }
  }

  /**
   * Get profile by user ID (admin)
   */
  async getProfileByUserId(req, res, next) {
    try {
      const { userId } = req.params;

      const profile = await UserProfile.findOne({
        where: { user_id: userId },
        include: [{
          model: VotteryUser,
          as: 'user',
          attributes: ['id', 'email', 'username']
        }]
      });

      if (!profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      return APIResponse.success(res, profile, 'Profile retrieved successfully');

    } catch (error) {
      logger.error('Error getting profile by user ID:', error);
      return next(error);
    }
  }

  /**
   * Get all profiles (admin)
   */
  async getAllProfiles(req, res, next) {
    try {
      const { page = 1, limit = 20, search, country, account_type } = req.query;
      const offset = (page - 1) * limit;

      const whereConditions = {};
      if (search) {
        whereConditions.public_display_name = { [Op.iLike]: `%${search}%` };
      }
      if (country) {
        whereConditions.country = country;
      }
      if (account_type) {
        whereConditions.account_type = account_type;
      }

      const { count, rows } = await UserProfile.findAndCountAll({
        where: whereConditions,
        limit: parseInt(limit),
        offset: parseInt(offset),
        include: [{
          model: VotteryUser,
          as: 'user',
          attributes: ['id', 'email', 'username']
        }],
        order: [['created_at', 'DESC']]
      });

      const result = {
        profiles: rows,
        pagination: {
          total: count,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(count / limit)
        }
      };

      return APIResponse.success(res, result, 'Profiles retrieved successfully');

    } catch (error) {
      logger.error('Error getting all profiles:', error);
      return next(error);
    }
  }

  /**
   * Admin update profile
   */
  async adminUpdateProfile(req, res, next) {
    try {
      const { userId } = req.params;
      const updates = req.body;

      const profile = await UserProfile.findOne({
        where: { user_id: userId }
      });

      if (!profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      const oldValues = profile.toJSON();
      await profile.update(updates);

      // Log admin activity
      await auditService.logActivity({
        user_id: req.user.id,
        action: 'admin_profile_update',
        category: 'admin',
        target_user_id: userId,
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        old_values: oldValues,
        new_values: updates
      });

      return APIResponse.success(res, profile, 'Profile updated successfully');

    } catch (error) {
      logger.error('Error updating profile (admin):', error);
      return next(error);
    }
  }

  /**
   * Admin delete profile
   */
  async adminDeleteProfile(req, res, next) {
    try {
      const { userId } = req.params;

      const profile = await UserProfile.findOne({
        where: { user_id: userId }
      });

      if (!profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      await profile.destroy();

      // Log admin activity
      await auditService.logActivity({
        user_id: req.user.id,
        action: 'admin_profile_delete',
        category: 'admin',
        target_user_id: userId,
        severity: 'high',
        ip_address: req.ip,
        user_agent: req.get('User-Agent')
      });

      return APIResponse.success(res, null, 'Profile deleted successfully');

    } catch (error) {
      logger.error('Error deleting profile (admin):', error);
      return next(error);
    }
  }

  // Analytics methods
  async getProfileAnalytics(req, res, next) {
    try {
      // TODO: Implement analytics logic
      const analytics = {
        totalProfiles: 0,
        completedProfiles: 0,
        averageCompletion: 0
      };

      return APIResponse.success(res, analytics, 'Profile analytics retrieved successfully');
    } catch (error) {
      logger.error('Error getting profile analytics:', error);
      return next(error);
    }
  }

  async getDemographicsAnalytics(req, res, next) {
    try {
      // TODO: Implement demographics analytics
      const analytics = {
        byCountry: {},
        byAge: {},
        byGender: {}
      };

      return APIResponse.success(res, analytics, 'Demographics analytics retrieved successfully');
    } catch (error) {
      logger.error('Error getting demographics analytics:', error);
      return next(error);
    }
  }

  async getCompletionAnalytics(req, res, next) {
    try {
      // TODO: Implement completion analytics
      const analytics = {
        completionDistribution: {},
        averageScore: 0
      };

      return APIResponse.success(res, analytics, 'Completion analytics retrieved successfully');
    } catch (error) {
      logger.error('Error getting completion analytics:', error);
      return next(error);
    }
  }

  async getAvatarAnalytics(req, res, next) {
    try {
      // TODO: Implement avatar analytics
      const analytics = {
        profilesWithAvatar: 0,
        profilesWithoutAvatar: 0,
        percentage: 0
      };

      return APIResponse.success(res, analytics, 'Avatar analytics retrieved successfully');
    } catch (error) {
      logger.error('Error getting avatar analytics:', error);
      return next(error);
    }
  }

  async exportProfiles(req, res, next) {
    try {
      // TODO: Implement bulk export
      return APIResponse.success(res, [], 'Profiles exported successfully');
    } catch (error) {
      logger.error('Error exporting profiles:', error);
      return next(error);
    }
  }

  async searchPublicProfiles(req, res, next) {
    try {
      // TODO: Implement public profile search
      return APIResponse.success(res, [], 'Public profiles search completed');
    } catch (error) {
      logger.error('Error searching public profiles:', error);
      return next(error);
    }
  }

  // Bulk operations
  async bulkUpdateVisibility(req, res, next) {
    try {
      // TODO: Implement bulk visibility update
      return APIResponse.success(res, null, 'Bulk visibility update completed');
    } catch (error) {
      logger.error('Error bulk updating visibility:', error);
      return next(error);
    }
  }

  async bulkVerifyProfiles(req, res, next) {
    try {
      // TODO: Implement bulk verification
      return APIResponse.success(res, null, 'Bulk profile verification completed');
    } catch (error) {
      logger.error('Error bulk verifying profiles:', error);
      return next(error);
    }
  }

  async bulkUnverifyProfiles(req, res, next) {
    try {
      // TODO: Implement bulk unverification
      return APIResponse.success(res, null, 'Bulk profile unverification completed');
    } catch (error) {
      logger.error('Error bulk unverifying profiles:', error);
      return next(error);
    }
  }

  // Moderation
  async moderateProfile(req, res, next) {
    try {
      // TODO: Implement profile moderation
      return APIResponse.success(res, null, 'Profile moderation action completed');
    } catch (error) {
      logger.error('Error moderating profile:', error);
      return next(error);
    }
  }

  async reportProfile(req, res, next) {
    try {
      // TODO: Implement profile reporting
      return APIResponse.success(res, null, 'Profile reported successfully');
    } catch (error) {
      logger.error('Error reporting profile:', error);
      return next(error);
    }
  }

  async getPendingReports(req, res, next) {
    try {
      // TODO: Implement pending reports retrieval
      return APIResponse.success(res, [], 'Pending reports retrieved successfully');
    } catch (error) {
      logger.error('Error getting pending reports:', error);
      return next(error);
    }
  }

  /**
   * Get user profile settings (existing method)
   */
  async getProfileSettings(req, res, next) {
    try {
      const userId = req.user.id;

      const profile = await UserProfile.findOne({
        where: { user_id: userId }
      });

      if (!profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      // Decrypt sensitive data if needed
      let personalData = null;
      if (profile.encrypted_personal_data) {
        try {
          personalData = JSON.parse(
            await encryptionService.decrypt(profile.encrypted_personal_data, userId)
          );
        } catch (error) {
          logger.warn('Failed to decrypt profile data:', error);
        }
      }

      const profileData = {
        ...profile.toJSON(),
        personal_data: personalData
      };

      delete profileData.encrypted_personal_data;

      return APIResponse.success(res, profileData, 'Profile settings retrieved successfully');

    } catch (error) {
      logger.error('Error getting profile settings:', error);
      return next(error);
    }
  }

  /**
   * Update privacy settings (existing method)
   */
  async updatePrivacySettings(req, res, next) {
    try {
      const userId = req.user.id;
      const { privacy_settings } = req.body;

      // Validate input
      const validation = validateInput({ privacy_settings }, 'privacySettings');
      if (!validation.isValid) {
        return APIResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
      }

      const profile = await UserProfile.findOne({
        where: { user_id: userId }
      });

      if (!profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      const oldSettings = profile.privacy_settings;
      await profile.update({ privacy_settings });

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.PRIVACY_UPDATE,
        category: 'profile',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        old_values: { privacy_settings: oldSettings },
        new_values: { privacy_settings }
      });

      return APIResponse.success(res, null, 'Privacy settings updated successfully');

    } catch (error) {
      logger.error('Error updating privacy settings:', error);
      return next(error);
    }
  }

  /**
   * Update notification preferences (existing method)
   */
  async updateNotificationPreferences(req, res, next) {
    try {
      const userId = req.user.id;
      const { notification_preferences } = req.body;

      // Validate input
      const validation = validateInput({ notification_preferences }, 'notificationPreferences');
      if (!validation.isValid) {
        return APIResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
      }

      const profile = await UserProfile.findOne({
        where: { user_id: userId }
      });

      if (!profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      const oldPreferences = profile.notification_preferences;
      await profile.update({ notification_preferences });

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.NOTIFICATIONS_UPDATE,
        category: 'profile',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        old_values: { notification_preferences: oldPreferences },
        new_values: { notification_preferences }
      });

      return APIResponse.success(res, null, 'Notification preferences updated successfully');

    } catch (error) {
      logger.error('Error updating notification preferences:', error);
      return next(error);
    }
  }

  /**
   * Upload avatar (existing method)
   */
  async uploadAvatar(req, res, next) {
    try {
      const userId = req.user.id;
      const { avatar_url } = req.body;

      if (!avatar_url) {
        return APIResponse.error(res, 'Avatar URL is required', HTTP_STATUS.BAD_REQUEST);
      }

      const profile = await UserProfile.findOne({
        where: { user_id: userId }
      });

      if (!profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      const oldAvatarUrl = profile.avatar_url;
      await profile.update({ avatar_url });

      // Log activity
      await auditService.logActivity({
        user_id: userId,
        action: USER_ACTIONS.AVATAR_UPDATE,
        category: 'profile',
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        old_values: { avatar_url: oldAvatarUrl },
        new_values: { avatar_url }
      });

      return APIResponse.success(res, { avatar_url }, 'Avatar updated successfully');

    } catch (error) {
      logger.error('Error uploading avatar:', error);
      return next(error);
    }
  }

  /**
   * Get public profile (existing method)
   */
  async getPublicProfile(req, res, next) {
    try {
      const { userId } = req.params;

      const user = await VotteryUser.findByPk(userId, {
        include: [{
          model: UserProfile,
          as: 'profile',
          attributes: [
            'public_display_name',
            'avatar_url',
            'country',
            'account_type',
            'verification_status',
            'profile_completion_score',
            'created_at'
          ]
        }]
      });

      if (!user || !user.profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      // Check privacy settings
      const privacySettings = user.profile.privacy_settings;
      if (privacySettings?.profile_visibility === 'private' && req.user?.id !== userId) {
        return APIResponse.error(res, 'Profile is private', HTTP_STATUS.FORBIDDEN);
      }

      return APIResponse.success(res, user.profile, 'Public profile retrieved successfully');

    } catch (error) {
      logger.error('Error getting public profile:', error);
      return next(error);
    }
  }

  /**
   * Delete profile data (GDPR compliance) (existing method)
   */
  async deleteProfileData(req, res, next) {
    try {
      const userId = req.user.id;
      const { data_types } = req.body;

      if (!data_types || !Array.isArray(data_types)) {
        return APIResponse.error(res, 'Data types array is required', HTTP_STATUS.BAD_REQUEST);
      }

      const profile = await UserProfile.findOne({
        where: { user_id: userId }
      });

      if (!profile) {
        return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
      }

      const updates = {};

      // Handle different data types
      if (data_types.includes('personal_data')) {
        updates.encrypted_personal_data = null;
      }
      
      if (data_types.includes('avatar')) {
        updates.avatar_url = null;
      }

      if (data_types.includes('demographics')) {
        updates.demographics = null;
      }

      if (Object.keys(updates).length > 0) {
        await profile.update(updates);

        // Log activity
        await auditService.logActivity({
          user_id: userId,
          action: USER_ACTIONS.DATA_DELETE,
          category: 'security',
          severity: 'high',
          ip_address: req.ip,
          user_agent: req.get('User-Agent'),
          metadata: { deleted_data_types: data_types }
        });
      }

      return APIResponse.success(res, null, 'Profile data deleted successfully');

    } catch (error) {
      logger.error('Error deleting profile data:', error);
      return next(error);
    }
  }
}

export default new ProfileController();
// //import { UserProfile, VotteryUser } from '../models/index.js';
// import  encryptionService  from '../services/encryptionService.js';
// import  auditService  from '../services/auditService.js';
// import  validateInput  from '../middleware/validation.js';
// //import { ApiResponse } from '../utils/response.js';
// import { APIResponse } from '../utils/response.js';
// import  logger  from '../utils/logger.js';
// import { USER_ACTIONS, HTTP_STATUS } from '../utils/constants.js';
// import models from '../models/index.js';
// const { UserProfile, VotteryUser } = models;

// class ProfileController {
//   /**
//    * Get current user's profile (alias for getProfileSettings)
//    */
//   async getCurrentProfile(req, res, next) {
//     return this.getProfileSettings(req, res, next);
//   }

//   /**
//    * Create new profile
//    */
//   async createProfile(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const profileData = req.body;

//       // Check if profile already exists
//       const existingProfile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (existingProfile) {
//         return APIResponse.error(res, 'Profile already exists', HTTP_STATUS.CONFLICT);
//       }

//       // Create new profile
//       const profile = await UserProfile.create({
//         user_id: userId,
//         ...profileData
//       });

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: 'profile_create',
//         category: 'profile',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         new_values: profileData
//       });

//       return APIResponse.success(res, profile, 'Profile created successfully');

//     } catch (error) {
//       logger.error('Error creating profile:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Update current user's profile
//    */
//   async updateCurrentProfile(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const updates = req.body;

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       const oldValues = profile.toJSON();
//       await profile.update(updates);

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: 'profile_update',
//         category: 'profile',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         old_values: oldValues,
//         new_values: updates
//       });

//       return APIResponse.success(res, profile, 'Profile updated successfully');

//     } catch (error) {
//       logger.error('Error updating profile:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Delete avatar
//    */
//   async deleteAvatar(req, res, next) {
//     try {
//       const userId = req.user.id;

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       const oldAvatarUrl = profile.avatar_url;
//       await profile.update({ avatar_url: null });

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.AVATAR_UPDATE,
//         category: 'profile',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         old_values: { avatar_url: oldAvatarUrl },
//         new_values: { avatar_url: null }
//       });

//       return APIResponse.success(res, null, 'Avatar deleted successfully');

//     } catch (error) {
//       logger.error('Error deleting avatar:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Update preferences
//    */
//   async updatePreferences(req, res, next) {
//     return this.updateNotificationPreferences(req, res, next);
//   }

//   /**
//    * Update demographics
//    */
//   async updateDemographics(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { demographics } = req.body;

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       const oldDemographics = profile.demographics;
//       await profile.update({ demographics });

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: 'demographics_update',
//         category: 'profile',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         old_values: { demographics: oldDemographics },
//         new_values: { demographics }
//       });

//       return APIResponse.success(res, null, 'Demographics updated successfully');

//     } catch (error) {
//       logger.error('Error updating demographics:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Update visibility settings
//    */
//   async updateVisibility(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { visibility_settings } = req.body;

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       // Update privacy settings with visibility
//       const updatedPrivacySettings = {
//         ...profile.privacy_settings,
//         ...visibility_settings
//       };

//       await profile.update({ privacy_settings: updatedPrivacySettings });

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: 'visibility_update',
//         category: 'profile',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         new_values: { visibility_settings }
//       });

//       return APIResponse.success(res, null, 'Visibility settings updated successfully');

//     } catch (error) {
//       logger.error('Error updating visibility:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get profile completion status
//    */
//   async getProfileCompletion(req, res, next) {
//     try {
//       const userId = req.user.id;

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       const completion = {
//         percentage: profile.profile_completion_score || 0,
//         completedFields: [],
//         missingFields: []
//       };

//       // Calculate completion based on available fields
//       const requiredFields = ['public_display_name', 'avatar_url', 'country', 'demographics'];
//       requiredFields.forEach(field => {
//         if (profile[field]) {
//           completion.completedFields.push(field);
//         } else {
//           completion.missingFields.push(field);
//         }
//       });

//       completion.percentage = Math.round((completion.completedFields.length / requiredFields.length) * 100);

//       return APIResponse.success(res, completion, 'Profile completion retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting profile completion:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Export profile data
//    */
//   async exportProfile(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const format = req.query.format || 'json';

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       let exportData = profile.toJSON();

//       // Decrypt sensitive data if needed
//       if (profile.encrypted_personal_data) {
//         try {
//           const personalData = JSON.parse(
//             await encryptionService.decrypt(profile.encrypted_personal_data, userId)
//           );
//           exportData.personal_data = personalData;
//           delete exportData.encrypted_personal_data;
//         } catch (error) {
//           logger.warn('Failed to decrypt profile data for export:', error);
//         }
//       }

//       if (format === 'csv') {
//         // TODO: Convert to CSV format
//         return APIResponse.success(res, exportData, 'Profile exported as CSV');
//       }

//       return APIResponse.success(res, exportData, 'Profile exported successfully');

//     } catch (error) {
//       logger.error('Error exporting profile:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get profile by user ID (admin)
//    */
//   async getProfileByUserId(req, res, next) {
//     try {
//       const { userId } = req.params;

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId },
//         include: [{
//           model: VotteryUser,
//           as: 'user',
//           attributes: ['id', 'email', 'username']
//         }]
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       return APIResponse.success(res, profile, 'Profile retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting profile by user ID:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get all profiles (admin)
//    */
//   async getAllProfiles(req, res, next) {
//     try {
//       const { page = 1, limit = 20, search, country, account_type } = req.query;
//       const offset = (page - 1) * limit;

//       const whereConditions = {};
//       if (search) {
//         whereConditions.public_display_name = { [Op.iLike]: `%${search}%` };
//       }
//       if (country) {
//         whereConditions.country = country;
//       }
//       if (account_type) {
//         whereConditions.account_type = account_type;
//       }

//       const { count, rows } = await UserProfile.findAndCountAll({
//         where: whereConditions,
//         limit: parseInt(limit),
//         offset: parseInt(offset),
//         include: [{
//           model: VotteryUser,
//           as: 'user',
//           attributes: ['id', 'email', 'username']
//         }],
//         order: [['created_at', 'DESC']]
//       });

//       const result = {
//         profiles: rows,
//         pagination: {
//           total: count,
//           page: parseInt(page),
//           limit: parseInt(limit),
//           totalPages: Math.ceil(count / limit)
//         }
//       };

//       return APIResponse.success(res, result, 'Profiles retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting all profiles:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Admin update profile
//    */
//   async adminUpdateProfile(req, res, next) {
//     try {
//       const { userId } = req.params;
//       const updates = req.body;

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       const oldValues = profile.toJSON();
//       await profile.update(updates);

//       // Log admin activity
//       await auditService.logActivity({
//         user_id: req.user.id,
//         action: 'admin_profile_update',
//         category: 'admin',
//         target_user_id: userId,
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         old_values: oldValues,
//         new_values: updates
//       });

//       return APIResponse.success(res, profile, 'Profile updated successfully');

//     } catch (error) {
//       logger.error('Error updating profile (admin):', error);
//       return next(error);
//     }
//   }

//   /**
//    * Admin delete profile
//    */
//   async adminDeleteProfile(req, res, next) {
//     try {
//       const { userId } = req.params;

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       await profile.destroy();

//       // Log admin activity
//       await auditService.logActivity({
//         user_id: req.user.id,
//         action: 'admin_profile_delete',
//         category: 'admin',
//         target_user_id: userId,
//         severity: 'high',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent')
//       });

//       return APIResponse.success(res, null, 'Profile deleted successfully');

//     } catch (error) {
//       logger.error('Error deleting profile (admin):', error);
//       return next(error);
//     }
//   }

//   // Placeholder methods for analytics and other features
//   async getProfileAnalytics(req, res, next) {
//     try {
//       // TODO: Implement analytics logic
//       const analytics = {
//         totalProfiles: 0,
//         completedProfiles: 0,
//         averageCompletion: 0
//       };

//       return APIResponse.success(res, analytics, 'Profile analytics retrieved successfully');
//     } catch (error) {
//       logger.error('Error getting profile analytics:', error);
//       return next(error);
//     }
//   }

//   async getDemographicsAnalytics(req, res, next) {
//     try {
//       // TODO: Implement demographics analytics
//       const analytics = {
//         byCountry: {},
//         byAge: {},
//         byGender: {}
//       };

//       return APIResponse.success(res, analytics, 'Demographics analytics retrieved successfully');
//     } catch (error) {
//       logger.error('Error getting demographics analytics:', error);
//       return next(error);
//     }
//   }

//   async getCompletionAnalytics(req, res, next) {
//     try {
//       // TODO: Implement completion analytics
//       const analytics = {
//         completionDistribution: {},
//         averageScore: 0
//       };

//       return APIResponse.success(res, analytics, 'Completion analytics retrieved successfully');
//     } catch (error) {
//       logger.error('Error getting completion analytics:', error);
//       return next(error);
//     }
//   }

//   async getAvatarAnalytics(req, res, next) {
//     try {
//       // TODO: Implement avatar analytics
//       const analytics = {
//         profilesWithAvatar: 0,
//         profilesWithoutAvatar: 0,
//         percentage: 0
//       };

//       return APIResponse.success(res, analytics, 'Avatar analytics retrieved successfully');
//     } catch (error) {
//       logger.error('Error getting avatar analytics:', error);
//       return next(error);
//     }
//   }

//   async exportProfiles(req, res, next) {
//     try {
//       // TODO: Implement bulk export
//       return APIResponse.success(res, [], 'Profiles exported successfully');
//     } catch (error) {
//       logger.error('Error exporting profiles:', error);
//       return next(error);
//     }
//   }

//   async searchPublicProfiles(req, res, next) {
//     try {
//       // TODO: Implement public profile search
//       return APIResponse.success(res, [], 'Public profiles search completed');
//     } catch (error) {
//       logger.error('Error searching public profiles:', error);
//       return next(error);
//     }
//   }

//   // Bulk operations
//   async bulkUpdateVisibility(req, res, next) {
//     try {
//       // TODO: Implement bulk visibility update
//       return APIResponse.success(res, null, 'Bulk visibility update completed');
//     } catch (error) {
//       logger.error('Error bulk updating visibility:', error);
//       return next(error);
//     }
//   }

//   async bulkVerifyProfiles(req, res, next) {
//     try {
//       // TODO: Implement bulk verification
//       return APIResponse.success(res, null, 'Bulk profile verification completed');
//     } catch (error) {
//       logger.error('Error bulk verifying profiles:', error);
//       return next(error);
//     }
//   }

//   async bulkUnverifyProfiles(req, res, next) {
//     try {
//       // TODO: Implement bulk unverification
//       return APIResponse.success(res, null, 'Bulk profile unverification completed');
//     } catch (error) {
//       logger.error('Error bulk unverifying profiles:', error);
//       return next(error);
//     }
//   }

//   // Moderation
//   async moderateProfile(req, res, next) {
//     try {
//       // TODO: Implement profile moderation
//       return APIResponse.success(res, null, 'Profile moderation action completed');
//     } catch (error) {
//       logger.error('Error moderating profile:', error);
//       return next(error);
//     }
//   }

//   async reportProfile(req, res, next) {
//     try {
//       // TODO: Implement profile reporting
//       return APIResponse.success(res, null, 'Profile reported successfully');
//     } catch (error) {
//       logger.error('Error reporting profile:', error);
//       return next(error);
//     }
//   }

//   async getPendingReports(req, res, next) {
//     try {
//       // TODO: Implement pending reports retrieval
//       return APIResponse.success(res, [], 'Pending reports retrieved successfully');
//     } catch (error) {
//       logger.error('Error getting pending reports:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get user profile settings (existing method)
//    */
//   async getProfileSettings(req, res, next) {
//     try {
//       const userId = req.user.id;

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       // Decrypt sensitive data if needed
//       let personalData = null;
//       if (profile.encrypted_personal_data) {
//         try {
//           personalData = JSON.parse(
//             await encryptionService.decrypt(profile.encrypted_personal_data, userId)
//           );
//         } catch (error) {
//           logger.warn('Failed to decrypt profile data:', error);
//         }
//       }

//       const profileData = {
//         ...profile.toJSON(),
//         personal_data: personalData
//       };

//       delete profileData.encrypted_personal_data;

//       return APIResponse.success(res, profileData, 'Profile settings retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting profile settings:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Update privacy settings (existing method)
//    */
//   async updatePrivacySettings(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { privacy_settings } = req.body;

//       // Validate input
//       const validation = validateInput({ privacy_settings }, 'privacySettings');
//       if (!validation.isValid) {
//         return APIResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
//       }

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       const oldSettings = profile.privacy_settings;
//       await profile.update({ privacy_settings });

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.PRIVACY_UPDATE,
//         category: 'profile',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         old_values: { privacy_settings: oldSettings },
//         new_values: { privacy_settings }
//       });

//       return APIResponse.success(res, null, 'Privacy settings updated successfully');

//     } catch (error) {
//       logger.error('Error updating privacy settings:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Update notification preferences (existing method)
//    */
//   async updateNotificationPreferences(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { notification_preferences } = req.body;

//       // Validate input
//       const validation = validateInput({ notification_preferences }, 'notificationPreferences');
//       if (!validation.isValid) {
//         return APIResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
//       }

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       const oldPreferences = profile.notification_preferences;
//       await profile.update({ notification_preferences });

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.NOTIFICATIONS_UPDATE,
//         category: 'profile',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         old_values: { notification_preferences: oldPreferences },
//         new_values: { notification_preferences }
//       });

//       return APIResponse.success(res, null, 'Notification preferences updated successfully');

//     } catch (error) {
//       logger.error('Error updating notification preferences:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Upload avatar (existing method)
//    */
//   async uploadAvatar(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { avatar_url } = req.body;

//       if (!avatar_url) {
//         return APIResponse.error(res, 'Avatar URL is required', HTTP_STATUS.BAD_REQUEST);
//       }

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       const oldAvatarUrl = profile.avatar_url;
//       await profile.update({ avatar_url });

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.AVATAR_UPDATE,
//         category: 'profile',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         old_values: { avatar_url: oldAvatarUrl },
//         new_values: { avatar_url }
//       });

//       return APIResponse.success(res, { avatar_url }, 'Avatar updated successfully');

//     } catch (error) {
//       logger.error('Error uploading avatar:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get public profile (existing method)
//    */
//   async getPublicProfile(req, res, next) {
//     try {
//       const { userId } = req.params;

//       const user = await VotteryUser.findByPk(userId, {
//         include: [{
//           model: UserProfile,
//           as: 'profile',
//           attributes: [
//             'public_display_name',
//             'avatar_url',
//             'country',
//             'account_type',
//             'verification_status',
//             'profile_completion_score',
//             'created_at'
//           ]
//         }]
//       });

//       if (!user || !user.profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       // Check privacy settings
//       const privacySettings = user.profile.privacy_settings;
//       if (privacySettings?.profile_visibility === 'private' && req.user?.id !== userId) {
//         return APIResponse.error(res, 'Profile is private', HTTP_STATUS.FORBIDDEN);
//       }

//       return APIResponse.success(res, user.profile, 'Public profile retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting public profile:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Delete profile data (GDPR compliance) (existing method)
//    */
//   async deleteProfileData(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { data_types } = req.body;

//       if (!data_types || !Array.isArray(data_types)) {
//         return APIResponse.error(res, 'Data types array is required', HTTP_STATUS.BAD_REQUEST);
//       }

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       const updates = {};

//       // Handle different data types
//       if (data_types.includes('personal_data')) {
//         updates.encrypted_personal_data = null;
//       }
      
//       if (data_types.includes('avatar')) {
//         updates.avatar_url = null;
//       }

//       if (data_types.includes('demographics')) {
//         updates.demographics = null;
//       }

//       if (Object.keys(updates).length > 0) {
//         await profile.update(updates);

//         // Log activity
//         await auditService.logActivity({
//           user_id: userId,
//           action: USER_ACTIONS.DATA_DELETE,
//           category: 'security',
//           severity: 'high',
//           ip_address: req.ip,
//           user_agent: req.get('User-Agent'),
//           metadata: { deleted_data_types: data_types }
//         });
//       }

//       return APIResponse.success(res, null, 'Profile data deleted successfully');

//     } catch (error) {
//       logger.error('Error deleting profile data:', error);
//       return next(error);
//     }
//   }
// }

// export default new ProfileController();
// //import { UserProfile, VotteryUser } from '../models/index.js';
// import  encryptionService  from '../services/encryptionService.js';
// import  auditService  from '../services/auditService.js';
// import  validateInput  from '../middleware/validation.js';
// //import { ApiResponse } from '../utils/response.js';
// import { APIResponse } from '../utils/response.js';
// import  logger  from '../utils/logger.js';
// import { USER_ACTIONS, HTTP_STATUS } from '../utils/constants.js';
// import models from '../models/index.js';
// const { UserProfile, VotteryUser } = models;

// class ProfileController {
//   /**
//    * Get user profile settings
//    */
//   async getProfileSettings(req, res, next) {
//     try {
//       const userId = req.user.id;

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       // Decrypt sensitive data if needed
//       let personalData = null;
//       if (profile.encrypted_personal_data) {
//         try {
//           personalData = JSON.parse(
//             await encryptionService.decrypt(profile.encrypted_personal_data, userId)
//           );
//         } catch (error) {
//           logger.warn('Failed to decrypt profile data:', error);
//         }
//       }

//       const profileData = {
//         ...profile.toJSON(),
//         personal_data: personalData
//       };

//       delete profileData.encrypted_personal_data;

//       return APIResponse.success(res, profileData, 'Profile settings retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting profile settings:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Update privacy settings
//    */
//   async updatePrivacySettings(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { privacy_settings } = req.body;

//       // Validate input
//       const validation = validateInput({ privacy_settings }, 'privacySettings');
//       if (!validation.isValid) {
//         return APIResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
//       }

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       const oldSettings = profile.privacy_settings;
//       await profile.update({ privacy_settings });

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.PRIVACY_UPDATE,
//         category: 'profile',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         old_values: { privacy_settings: oldSettings },
//         new_values: { privacy_settings }
//       });

//       return APIResponse.success(res, null, 'Privacy settings updated successfully');

//     } catch (error) {
//       logger.error('Error updating privacy settings:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Update notification preferences
//    */
//   async updateNotificationPreferences(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { notification_preferences } = req.body;

//       // Validate input
//       const validation = validateInput({ notification_preferences }, 'notificationPreferences');
//       if (!validation.isValid) {
//         return APIResponse.error(res, validation.errors, HTTP_STATUS.BAD_REQUEST);
//       }

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       const oldPreferences = profile.notification_preferences;
//       await profile.update({ notification_preferences });

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.NOTIFICATIONS_UPDATE,
//         category: 'profile',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         old_values: { notification_preferences: oldPreferences },
//         new_values: { notification_preferences }
//       });

//       return APIResponse.success(res, null, 'Notification preferences updated successfully');

//     } catch (error) {
//       logger.error('Error updating notification preferences:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Upload avatar
//    */
//   async uploadAvatar(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { avatar_url } = req.body;

//       if (!avatar_url) {
//         return APIResponse.error(res, 'Avatar URL is required', HTTP_STATUS.BAD_REQUEST);
//       }

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       const oldAvatarUrl = profile.avatar_url;
//       await profile.update({ avatar_url });

//       // Log activity
//       await auditService.logActivity({
//         user_id: userId,
//         action: USER_ACTIONS.AVATAR_UPDATE,
//         category: 'profile',
//         ip_address: req.ip,
//         user_agent: req.get('User-Agent'),
//         old_values: { avatar_url: oldAvatarUrl },
//         new_values: { avatar_url }
//       });

//       return APIResponse.success(res, { avatar_url }, 'Avatar updated successfully');

//     } catch (error) {
//       logger.error('Error uploading avatar:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Get public profile
//    */
//   async getPublicProfile(req, res, next) {
//     try {
//       const { userId } = req.params;

//       const user = await VotteryUser.findByPk(userId, {
//         include: [{
//           model: UserProfile,
//           as: 'profile',
//           attributes: [
//             'public_display_name',
//             'avatar_url',
//             'country',
//             'account_type',
//             'verification_status',
//             'profile_completion_score',
//             'created_at'
//           ]
//         }]
//       });

//       if (!user || !user.profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       // Check privacy settings
//       const privacySettings = user.profile.privacy_settings;
//       if (privacySettings?.profile_visibility === 'private' && req.user?.id !== userId) {
//         return APIResponse.error(res, 'Profile is private', HTTP_STATUS.FORBIDDEN);
//       }

//       return APIResponse.success(res, user.profile, 'Public profile retrieved successfully');

//     } catch (error) {
//       logger.error('Error getting public profile:', error);
//       return next(error);
//     }
//   }

//   /**
//    * Delete profile data (GDPR compliance)
//    */
//   async deleteProfileData(req, res, next) {
//     try {
//       const userId = req.user.id;
//       const { data_types } = req.body;

//       if (!data_types || !Array.isArray(data_types)) {
//         return APIResponse.error(res, 'Data types array is required', HTTP_STATUS.BAD_REQUEST);
//       }

//       const profile = await UserProfile.findOne({
//         where: { user_id: userId }
//       });

//       if (!profile) {
//         return APIResponse.error(res, 'Profile not found', HTTP_STATUS.NOT_FOUND);
//       }

//       const updates = {};

//       // Handle different data types
//       if (data_types.includes('personal_data')) {
//         updates.encrypted_personal_data = null;
//       }
      
//       if (data_types.includes('avatar')) {
//         updates.avatar_url = null;
//       }

//       if (data_types.includes('demographics')) {
//         updates.demographics = null;
//       }

//       if (Object.keys(updates).length > 0) {
//         await profile.update(updates);

//         // Log activity
//         await auditService.logActivity({
//           user_id: userId,
//           action: USER_ACTIONS.DATA_DELETE,
//           category: 'security',
//           severity: 'high',
//           ip_address: req.ip,
//           user_agent: req.get('User-Agent'),
//           metadata: { deleted_data_types: data_types }
//         });
//       }

//       return APIResponse.success(res, null, 'Profile data deleted successfully');

//     } catch (error) {
//       logger.error('Error deleting profile data:', error);
//       return next(error);
//     }
//   }
// }

// export default new ProfileController();