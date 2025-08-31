// models/UserProfile.js
import { DataTypes, Model } from 'sequelize';
import encryptionService from '../services/encryptionService.js';

class UserProfile extends Model {
  static init(sequelize) {
    return super.init(
      {
        id: {
          type: DataTypes.INTEGER,
          primaryKey: true,
          autoIncrement: true
        },
        user_id: {
          type: DataTypes.INTEGER,
          allowNull: false,
          references: {
            model: 'vottery_users',
            key: 'id'
          },
          onDelete: 'CASCADE'
        },
        // Encrypted fields stored as TEXT
        first_name_encrypted: {
          type: DataTypes.TEXT,
          allowNull: true
        },
        last_name_encrypted: {
          type: DataTypes.TEXT,
          allowNull: true
        },
        age_encrypted: {
          type: DataTypes.TEXT,
          allowNull: true
        },
        gender_encrypted: {
          type: DataTypes.TEXT,
          allowNull: true
        },
        country_encrypted: {
          type: DataTypes.TEXT,
          allowNull: true
        },
        city_encrypted: {
          type: DataTypes.TEXT,
          allowNull: true
        },
        preferences_encrypted: {
          type: DataTypes.TEXT,
          allowNull: true
        },
        bio_encrypted: {
          type: DataTypes.TEXT,
          allowNull: true
        },
        // Non-encrypted fields
        avatar_url: {
          type: DataTypes.STRING(500),
          allowNull: true,
          validate: {
            isUrl: {
              msg: 'Avatar URL must be a valid URL'
            }
          }
        },
        // Virtual fields for decrypted data (not stored in DB)
        firstName: {
          type: DataTypes.VIRTUAL,
          get() {
            return this.decryptField('first_name_encrypted');
          },
          set(value) {
            this.encryptField('first_name_encrypted', value);
          }
        },
        lastName: {
          type: DataTypes.VIRTUAL,
          get() {
            return this.decryptField('last_name_encrypted');
          },
          set(value) {
            this.encryptField('last_name_encrypted', value);
          }
        },
        age: {
          type: DataTypes.VIRTUAL,
          get() {
            const decrypted = this.decryptField('age_encrypted');
            return decrypted ? parseInt(decrypted, 10) : null;
          },
          set(value) {
            this.encryptField('age_encrypted', value ? value.toString() : null);
          }
        },
        gender: {
          type: DataTypes.VIRTUAL,
          get() {
            return this.decryptField('gender_encrypted');
          },
          set(value) {
            this.encryptField('gender_encrypted', value);
          }
        },
        country: {
          type: DataTypes.VIRTUAL,
          get() {
            return this.decryptField('country_encrypted');
          },
          set(value) {
            this.encryptField('country_encrypted', value);
          }
        },
        city: {
          type: DataTypes.VIRTUAL,
          get() {
            return this.decryptField('city_encrypted');
          },
          set(value) {
            this.encryptField('city_encrypted', value);
          }
        },
        preferences: {
          type: DataTypes.VIRTUAL,
          get() {
            const decrypted = this.decryptField('preferences_encrypted');
            return decrypted ? JSON.parse(decrypted) : null;
          },
          set(value) {
            this.encryptField('preferences_encrypted', value ? JSON.stringify(value) : null);
          }
        },
        bio: {
          type: DataTypes.VIRTUAL,
          get() {
            return this.decryptField('bio_encrypted');
          },
          set(value) {
            this.encryptField('bio_encrypted', value);
          }
        },
        // Computed virtual field for full name
        fullName: {
          type: DataTypes.VIRTUAL,
          get() {
            const firstName = this.firstName || '';
            const lastName = this.lastName || '';
            return `${firstName} ${lastName}`.trim();
          }
        }
      },
      {
        sequelize,
        modelName: 'UserProfile',
        tableName: 'user_profiles',
        timestamps: true,
        createdAt: 'created_at',
        updatedAt: 'updated_at',
        paranoid: false,
        indexes: [
          {
            unique: true,
            fields: ['user_id']
          },
          {
            fields: ['created_at']
          }
        ]
      }
    );
  }

  // Instance method to encrypt a field
  async encryptField(fieldName, value) {
    try {
      if (!value) {
        this.setDataValue(fieldName, null);
        return;
      }

      // Get user's encryption key (you'll need to implement this based on your key management)
      const userKey = await this.getUserEncryptionKey();
      const encryptedValue = encryptionService.encryptRSA(value, userKey.publicKey);
      this.setDataValue(fieldName, encryptedValue);
    } catch (error) {
      throw new Error(`Encryption failed for ${fieldName}: ${error.message}`);
    }
  }

  // Instance method to decrypt a field
  decryptField(fieldName) {
    try {
      const encryptedValue = this.getDataValue(fieldName);
      if (!encryptedValue) return null;

      // This is a simplified version - in production, you'd need proper key management
      // For now, we'll store the decrypted value in a private property to avoid infinite loops
      const cacheKey = `_decrypted_${fieldName}`;
      if (this[cacheKey] !== undefined) {
        return this[cacheKey];
      }

      // In a real implementation, you'd decrypt here
      // For now, returning the encrypted value as placeholder
      this[cacheKey] = null; // Will be properly implemented with key management
      return this[cacheKey];
    } catch (error) {
      console.error(`Decryption failed for ${fieldName}:`, error.message);
      return null;
    }
  }

  // Get user's encryption key (to be implemented with EncryptionKey model)
  async getUserEncryptionKey() {
    // This will be implemented when we create the EncryptionKey model
    // For now, generate a temporary key
    return encryptionService.generateRSAKeyPair();
  }

  // Static method to create profile with encrypted data
  static async createProfile(userId, profileData) {
    try {
      const profile = await this.create({
        user_id: userId,
        firstName: profileData.firstName,
        lastName: profileData.lastName,
        age: profileData.age,
        gender: profileData.gender,
        country: profileData.country,
        city: profileData.city,
        preferences: profileData.preferences,
        bio: profileData.bio,
        avatar_url: profileData.avatar_url
      });

      return profile;
    } catch (error) {
      throw new Error(`Profile creation failed: ${error.message}`);
    }
  }

  // Static method to find profile with decrypted data
  static async findByUserId(userId) {
    try {
      const profile = await this.findOne({
        where: { user_id: userId }
      });

      return profile;
    } catch (error) {
      throw new Error(`Profile lookup failed: ${error.message}`);
    }
  }

  // Update profile with encryption
  async updateProfile(updateData) {
    try {
      // Set virtual fields which will trigger encryption
      Object.keys(updateData).forEach(key => {
        if (this[key] !== undefined) {
          this[key] = updateData[key];
        }
      });

      await this.save();
      return this;
    } catch (error) {
      throw new Error(`Profile update failed: ${error.message}`);
    }
  }

  // Get public profile data (safe for external use)
  getPublicProfile() {
    return {
      id: this.id,
      fullName: this.fullName,
      avatar_url: this.avatar_url,
      bio: this.bio,
      country: this.country,
      city: this.city,
      created_at: this.created_at
    };
  }

  // Get private profile data (for profile owner)
  getPrivateProfile() {
    return {
      id: this.id,
      firstName: this.firstName,
      lastName: this.lastName,
      fullName: this.fullName,
      age: this.age,
      gender: this.gender,
      country: this.country,
      city: this.city,
      preferences: this.preferences,
      bio: this.bio,
      avatar_url: this.avatar_url,
      created_at: this.created_at,
      updated_at: this.updated_at
    };
  }

  // Define associations
  static associate(models) {
    UserProfile.belongsTo(models.VotteryUser, {
      foreignKey: 'user_id',
      as: 'user'
    });
  }
}

export default UserProfile;