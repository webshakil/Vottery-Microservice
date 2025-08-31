import { DataTypes, Model } from 'sequelize';
import { encrypt, decrypt } from '../utils/encryption.js';

class UserProfile extends Model {
  static init(sequelize) {
    return super.init({
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      user_id: {
        type: DataTypes.INTEGER,
        allowNull: false,
        unique: true
      },
      first_name_encrypted: {
        type: DataTypes.TEXT
      },
      last_name_encrypted: {
        type: DataTypes.TEXT
      },
      age_encrypted: {
        type: DataTypes.TEXT
      },
      gender_encrypted: {
        type: DataTypes.TEXT
      },
      country_encrypted: {
        type: DataTypes.TEXT
      },
      city_encrypted: {
        type: DataTypes.TEXT
      },
      preferences_encrypted: {
        type: DataTypes.TEXT
      },
      avatar_url: {
        type: DataTypes.STRING(500)
      },
      bio_encrypted: {
        type: DataTypes.TEXT
      },
      privacy_settings: {
        type: DataTypes.JSON,
        defaultValue: {
          profile_visibility: 'public',
          email_visibility: 'private',
          activity_visibility: 'friends'
        }
      },
      notification_preferences: {
        type: DataTypes.JSON,
        defaultValue: {
          email_notifications: true,
          push_notifications: true,
          sms_notifications: false
        }
      },
      profile_completion_score: {
        type: DataTypes.INTEGER,
        defaultValue: 0
      }
    }, {
      sequelize,
      modelName: 'UserProfile',
      tableName: 'vottery_user_profiles',
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at',
      underscored: true
    });
  }

  static associate(models) {
    // Fixed: Changed from models.User to models.VotteryUser
    UserProfile.belongsTo(models.VotteryUser, {
      foreignKey: 'user_id',
      as: 'user',
      onDelete: 'CASCADE'
    });
  }

  // Encrypted field getters and setters
  get firstName() {
    return this.first_name_encrypted ? decrypt(this.first_name_encrypted) : null;
  }

  set firstName(value) {
    this.first_name_encrypted = value ? encrypt(value) : null;
  }

  get lastName() {
    return this.last_name_encrypted ? decrypt(this.last_name_encrypted) : null;
  }

  set lastName(value) {
    this.last_name_encrypted = value ? encrypt(value) : null;
  }

  get age() {
    return this.age_encrypted ? parseInt(decrypt(this.age_encrypted)) : null;
  }

  set age(value) {
    this.age_encrypted = value ? encrypt(value.toString()) : null;
  }

  get gender() {
    return this.gender_encrypted ? decrypt(this.gender_encrypted) : null;
  }

  set gender(value) {
    this.gender_encrypted = value ? encrypt(value) : null;
  }

  get country() {
    return this.country_encrypted ? decrypt(this.country_encrypted) : null;
  }

  set country(value) {
    this.country_encrypted = value ? encrypt(value) : null;
  }

  get city() {
    return this.city_encrypted ? decrypt(this.city_encrypted) : null;
  }

  set city(value) {
    this.city_encrypted = value ? encrypt(value) : null;
  }

  get preferences() {
    return this.preferences_encrypted ? JSON.parse(decrypt(this.preferences_encrypted)) : null;
  }

  set preferences(value) {
    this.preferences_encrypted = value ? encrypt(JSON.stringify(value)) : null;
  }

  get bio() {
    return this.bio_encrypted ? decrypt(this.bio_encrypted) : null;
  }

  set bio(value) {
    this.bio_encrypted = value ? encrypt(value) : null;
  }

  // Instance methods
  async updateCompletionScore() {
    let score = 0;
    const fields = [
      this.firstName,
      this.lastName,
      this.age,
      this.gender,
      this.country,
      this.city,
      this.bio,
      this.avatar_url
    ];
    
    fields.forEach(field => {
      if (field) score += 12.5; // Each field worth 12.5% (8 fields = 100%)
    });

    this.profile_completion_score = Math.round(score);
    await this.save();
    return this.profile_completion_score;
  }

  // Get safe profile data (for public viewing)
  getSafeProfile() {
    const safeData = {
      id: this.id,
      user_id: this.user_id,
      avatar_url: this.avatar_url,
      profile_completion_score: this.profile_completion_score,
      created_at: this.created_at,
      updated_at: this.updated_at
    };

    // Add fields based on privacy settings
    if (this.privacy_settings.profile_visibility === 'public') {
      safeData.firstName = this.firstName;
      safeData.lastName = this.lastName;
      safeData.bio = this.bio;
      safeData.country = this.country;
      safeData.city = this.city;
    }

    return safeData;
  }

  // Get full profile data (for owner or admin)
  getFullProfile() {
    return {
      id: this.id,
      user_id: this.user_id,
      firstName: this.firstName,
      lastName: this.lastName,
      age: this.age,
      gender: this.gender,
      country: this.country,
      city: this.city,
      preferences: this.preferences,
      bio: this.bio,
      avatar_url: this.avatar_url,
      privacy_settings: this.privacy_settings,
      notification_preferences: this.notification_preferences,
      profile_completion_score: this.profile_completion_score,
      created_at: this.created_at,
      updated_at: this.updated_at
    };
  }

  // Update privacy settings
  async updatePrivacySettings(newSettings) {
    this.privacy_settings = {
      ...this.privacy_settings,
      ...newSettings
    };
    await this.save();
    return this.privacy_settings;
  }

  // Update notification preferences
  async updateNotificationPreferences(newPreferences) {
    this.notification_preferences = {
      ...this.notification_preferences,
      ...newPreferences
    };
    await this.save();
    return this.notification_preferences;
  }
}

export default UserProfile;