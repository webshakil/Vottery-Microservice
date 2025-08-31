// services/profileService.js
import UserProfile from '../models/UserProfile.js';
import encryptionService from './encryptionService.js';
import auditService from './auditService.js';
import { AppError } from '../utils/response.js';
import { validateProfileData } from '../utils/validators.js';

class ProfileService {
  /**
   * Create user profile with encrypted data
   * @param {number} userId 
   * @param {object} profileData 
   * @returns {Promise<object>}
   */
  async createProfile(userId, profileData) {
    try {
      // Validate input data
      const validation = validateProfileData(profileData);
      if (!validation.isValid) {
        throw new AppError(validation.errors.join(', '), 400);
      }

      // Check if profile already exists
      const existingProfile = await UserProfile.findOne({ where: { user_id: userId } });
      if (existingProfile) {
        throw new AppError('Profile already exists for this user', 400);
      }

      // Encrypt sensitive fields
      const encryptedData = await this.encryptProfileData(profileData);

      // Create profile
      const profile = await UserProfile.create({
        user_id: userId,
        ...encryptedData,
        avatar_url: profileData.avatar_url || null
      });

      // Log activity
      await auditService.logActivity(
        userId,
        'PROFILE_CREATE',
        'user_profile',
        profile.id,
        { fields_updated: Object.keys(profileData) }
      );

      return await this.getDecryptedProfile(profile.id);
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Update user profile
   * @param {number} userId 
   * @param {object} updateData 
   * @returns {Promise<object>}
   */
  async updateProfile(userId, updateData) {
    try {
      const profile = await UserProfile.findOne({ where: { user_id: userId } });
      if (!profile) {
        throw new AppError('Profile not found', 404);
      }

      // Validate update data
      const validation = validateProfileData(updateData, true); // partial validation
      if (!validation.isValid) {
        throw new AppError(validation.errors.join(', '), 400);
      }

      // Encrypt new data
      const encryptedData = await this.encryptProfileData(updateData);

      // Update profile
      await profile.update({
        ...encryptedData,
        avatar_url: updateData.avatar_url !== undefined ? updateData.avatar_url : profile.avatar_url,
        updated_at: new Date()
      });

      // Log activity
      await auditService.logActivity(
        userId,
        'PROFILE_UPDATE',
        'user_profile',
        profile.id,
        { 
          fields_updated: Object.keys(updateData),
          updated_fields: Object.keys(encryptedData)
        }
      );

      return await this.getDecryptedProfile(profile.id);
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Get user profile by user ID
   * @param {number} userId 
   * @returns {Promise<object|null>}
   */
  async getProfileByUserId(userId) {
    try {
      const profile = await UserProfile.findOne({ where: { user_id: userId } });
      if (!profile) {
        return null;
      }

      return await this.getDecryptedProfile(profile.id);
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Get decrypted profile by profile ID
   * @param {number} profileId 
   * @returns {Promise<object>}
   */
  async getDecryptedProfile(profileId) {
    try {
      const profile = await UserProfile.findByPk(profileId);
      if (!profile) {
        throw new AppError('Profile not found', 404);
      }

      return await this.decryptProfileData(profile);
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Delete user profile
   * @param {number} userId 
   * @returns {Promise<boolean>}
   */
  async deleteProfile(userId) {
    try {
      const profile = await UserProfile.findOne({ where: { user_id: userId } });
      if (!profile) {
        throw new AppError('Profile not found', 404);
      }

      await profile.destroy();

      // Log activity
      await auditService.logActivity(
        userId,
        'PROFILE_DELETE',
        'user_profile',
        profile.id,
        { deleted_by: userId }
      );

      return true;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Update avatar URL
   * @param {number} userId 
   * @param {string} avatarUrl 
   * @returns {Promise<object>}
   */
  async updateAvatar(userId, avatarUrl) {
    try {
      const profile = await UserProfile.findOne({ where: { user_id: userId } });
      if (!profile) {
        throw new AppError('Profile not found', 404);
      }

      await profile.update({ 
        avatar_url: avatarUrl,
        updated_at: new Date()
      });

      // Log activity
      await auditService.logActivity(
        userId,
        'AVATAR_UPDATE',
        'user_profile',
        profile.id,
        { new_avatar_url: avatarUrl }
      );

      return await this.getDecryptedProfile(profile.id);
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Get profile demographics for analytics
   * @returns {Promise<object>}
   */
  async getProfileDemographics() {
    try {
      const profiles = await UserProfile.findAll();
      
      const demographics = {
        genderDistribution: {},
        countryDistribution: {},
        ageDistribution: { '18-25': 0, '26-35': 0, '36-50': 0, '51+': 0 },
        totalProfiles: profiles.length
      };

      for (const profile of profiles) {
        try {
          // Decrypt demographic fields
          if (profile.gender_encrypted) {
            const gender = await encryptionService.decrypt(profile.gender_encrypted);
            demographics.genderDistribution[gender] = (demographics.genderDistribution[gender] || 0) + 1;
          }

          if (profile.country_encrypted) {
            const country = await encryptionService.decrypt(profile.country_encrypted);
            demographics.countryDistribution[country] = (demographics.countryDistribution[country] || 0) + 1;
          }

          if (profile.age_encrypted) {
            const age = parseInt(await encryptionService.decrypt(profile.age_encrypted));
            if (age >= 18 && age <= 25) demographics.ageDistribution['18-25']++;
            else if (age >= 26 && age <= 35) demographics.ageDistribution['26-35']++;
            else if (age >= 36 && age <= 50) demographics.ageDistribution['36-50']++;
            else if (age > 50) demographics.ageDistribution['51+']++;
          }
        } catch (decryptError) {
          // Skip corrupted data
          continue;
        }
      }

      return demographics;
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Encrypt profile data fields
   * @param {object} data 
   * @returns {Promise<object>}
   */
  async encryptProfileData(data) {
    const encryptedData = {};
    
    const fieldsToEncrypt = [
      'first_name', 'last_name', 'age', 'gender', 
      'country', 'city', 'preferences', 'bio'
    ];

    for (const field of fieldsToEncrypt) {
      if (data[field] !== undefined && data[field] !== null) {
        encryptedData[`${field}_encrypted`] = await encryptionService.encrypt(
          String(data[field])
        );
      }
    }

    return encryptedData;
  }

  /**
   * Decrypt profile data fields
   * @param {object} profile 
   * @returns {Promise<object>}
   */
  async decryptProfileData(profile) {
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
        try {
          const decryptedField = field.replace('_encrypted', '');
          decryptedProfile[decryptedField] = await encryptionService.decrypt(
            decryptedProfile[field]
          );
          delete decryptedProfile[field]; // Remove encrypted version
        } catch (error) {
          // If decryption fails, remove the field
          delete decryptedProfile[field];
        }
      }
    }

    return decryptedProfile;
  }

  /**
   * Search profiles by criteria (encrypted search)
   * @param {object} searchCriteria 
   * @param {number} page 
   * @param {number} limit 
   * @returns {Promise<object>}
   */
  async searchProfiles(searchCriteria, page = 1, limit = 10) {
    try {
      const offset = (page - 1) * limit;
      
      // Get all profiles (we need to decrypt to search)
      const allProfiles = await UserProfile.findAll({
        include: [{
          model: VotteryUser,
          as: 'user',
          attributes: ['id', 'email', 'status', 'created_at']
        }]
      });

      let filteredProfiles = [];

      // Decrypt and filter profiles
      for (const profile of allProfiles) {
        try {
          const decryptedProfile = await this.decryptProfileData(profile);
          
          let matches = true;
          
          if (searchCriteria.country && decryptedProfile.country) {
            matches = matches && decryptedProfile.country.toLowerCase().includes(
              searchCriteria.country.toLowerCase()
            );
          }
          
          if (searchCriteria.city && decryptedProfile.city) {
            matches = matches && decryptedProfile.city.toLowerCase().includes(
              searchCriteria.city.toLowerCase()
            );
          }
          
          if (searchCriteria.gender && decryptedProfile.gender) {
            matches = matches && decryptedProfile.gender.toLowerCase() === 
              searchCriteria.gender.toLowerCase();
          }

          if (matches) {
            filteredProfiles.push(decryptedProfile);
          }
        } catch (error) {
          // Skip profiles with decryption errors
          continue;
        }
      }

      // Apply pagination
      const totalCount = filteredProfiles.length;
      const paginatedProfiles = filteredProfiles.slice(offset, offset + limit);

      return {
        profiles: paginatedProfiles,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(totalCount / limit),
          totalCount,
          limit
        }
      };
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }
}

export default new ProfileService();