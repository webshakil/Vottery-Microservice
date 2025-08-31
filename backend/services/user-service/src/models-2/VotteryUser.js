import { DataTypes, Model } from 'sequelize';
import bcrypt from 'bcrypt';
import crypto from 'node:crypto';
import { authenticator } from 'otplib';

class VotteryUser extends Model {
  static init(sequelize) {
    return super.init(
      {
        id: {
          type: DataTypes.UUID,
          defaultValue: DataTypes.UUIDV4,
          primaryKey: true,
          allowNull: false,
        },
        email: {
          type: DataTypes.STRING(320),
          allowNull: false,
          unique: true,
          validate: {
            isEmail: true,
          },
        },
        username: {
          type: DataTypes.STRING(50),
          allowNull: false,
          unique: true,
          validate: {
            len: [3, 50],
            isAlphanumeric: true,
          },
        },
        password_hash: {
          type: DataTypes.TEXT,
          allowNull: false,
        },
        salt: {
          type: DataTypes.STRING(128),
          allowNull: false,
        },
        first_name: {
          type: DataTypes.STRING(100),
          allowNull: false,
          validate: {
            len: [1, 100],
          },
        },
        last_name: {
          type: DataTypes.STRING(100),
          allowNull: false,
          validate: {
            len: [1, 100],
          },
        },
        phone_number: {
          type: DataTypes.STRING(20),
          allowNull: true,
          validate: {
            is: /^[\+]?[1-9][\d]{0,15}$/,
          },
        },
        date_of_birth: {
          type: DataTypes.DATEONLY,
          allowNull: true,
        },
        profile_image_url: {
          type: DataTypes.TEXT,
          allowNull: true,
          validate: {
            isUrl: true,
          },
        },
        is_active: {
          type: DataTypes.BOOLEAN,
          defaultValue: true,
          allowNull: false,
        },
        is_verified: {
          type: DataTypes.BOOLEAN,
          defaultValue: false,
          allowNull: false,
        },
        email_verified: {
          type: DataTypes.BOOLEAN,
          defaultValue: false,
          allowNull: false,
        },
        phone_verified: {
          type: DataTypes.BOOLEAN,
          defaultValue: false,
          allowNull: false,
        },
        two_factor_enabled: {
          type: DataTypes.BOOLEAN,
          defaultValue: false,
          allowNull: false,
        },
        two_factor_secret: {
          type: DataTypes.TEXT,
          allowNull: true,
        },
        backup_codes: {
          type: DataTypes.JSON,
          allowNull: true,
        },
        last_login_at: {
          type: DataTypes.DATE,
          allowNull: true,
        },
        last_login_ip: {
          type: DataTypes.INET,
          allowNull: true,
        },
        failed_login_attempts: {
          type: DataTypes.INTEGER,
          defaultValue: 0,
          allowNull: false,
        },
        locked_until: {
          type: DataTypes.DATE,
          allowNull: true,
        },
        password_changed_at: {
          type: DataTypes.DATE,
          allowNull: true,
        },
        privacy_settings: {
          type: DataTypes.JSON,
          defaultValue: {
            profile_visibility: 'public',
            activity_visibility: 'friends',
            email_notifications: true,
            sms_notifications: false,
          },
          allowNull: false,
        },
        preferences: {
          type: DataTypes.JSON,
          defaultValue: {
            language: 'en',
            timezone: 'UTC',
            theme: 'light',
            currency: 'USD',
          },
          allowNull: false,
        },
        metadata: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
        },
      },
      {
        sequelize,
        modelName: 'VotteryUser',
        tableName: 'vottery_users',
        paranoid: true,
        hooks: {
          beforeCreate: async (user) => {
            await user.hashPassword();
          },
          beforeUpdate: async (user) => {
            if (user.changed('password_hash')) {
              await user.hashPassword();
            }
          },
        },
      }
    );
  }

  // Instance methods
  async hashPassword() {
    if (this.password_hash && !this.password_hash.startsWith('$2b$')) {
      this.salt = await bcrypt.genSalt(12);
      this.password_hash = await bcrypt.hash(this.password_hash, this.salt);
      this.password_changed_at = new Date();
    }
  }

  async validatePassword(password) {
    if (!this.password_hash || !password) {
      return false;
    }
    return await bcrypt.compare(password, this.password_hash);
  }

  async incrementFailedLogins() {
    this.failed_login_attempts += 1;
    
    // Lock account after 5 failed attempts for 30 minutes
    if (this.failed_login_attempts >= 5) {
      this.locked_until = new Date(Date.now() + 30 * 60 * 1000);
    }
    
    await this.save();
  }

  async resetFailedLogins() {
    this.failed_login_attempts = 0;
    this.locked_until = null;
    await this.save();
  }

  isLocked() {
    return this.locked_until && new Date() < this.locked_until;
  }

  async updateLastLogin(ipAddress) {
    this.last_login_at = new Date();
    this.last_login_ip = ipAddress;
    await this.resetFailedLogins();
  }

  // Two-Factor Authentication methods
  async enableTwoFactor() {
    if (!this.two_factor_secret) {
      this.two_factor_secret = authenticator.generateSecret();
    }
    
    this.two_factor_enabled = true;
    this.backup_codes = this.generateBackupCodes();
    await this.save();
    
    return {
      secret: this.two_factor_secret,
      qrCodeUrl: authenticator.keyuri(this.email, 'Vottery', this.two_factor_secret),
      backupCodes: this.backup_codes,
    };
  }

  async disableTwoFactor() {
    this.two_factor_enabled = false;
    this.two_factor_secret = null;
    this.backup_codes = null;
    await this.save();
  }

  verifyTwoFactorToken(token) {
    if (!this.two_factor_enabled || !this.two_factor_secret) {
      return false;
    }
    
    return authenticator.verify({
      token: token,
      secret: this.two_factor_secret,
      window: 2, // Allow 2 time steps variance
    });
  }

  async verifyBackupCode(code) {
    if (!this.backup_codes || !Array.isArray(this.backup_codes)) {
      return false;
    }
    
    const codeIndex = this.backup_codes.findIndex(backupCode => 
      backupCode.code === code && !backupCode.used
    );
    
    if (codeIndex === -1) {
      return false;
    }
    
    // Mark backup code as used
    this.backup_codes[codeIndex].used = true;
    this.backup_codes[codeIndex].used_at = new Date();
    await this.save();
    
    return true;
  }

  generateBackupCodes(count = 10) {
    const codes = [];
    for (let i = 0; i < count; i++) {
      codes.push({
        code: crypto.randomBytes(4).toString('hex').toUpperCase(),
        used: false,
        used_at: null,
      });
    }
    return codes;
  }

  // Privacy and security methods
  getPublicProfile() {
    const publicFields = [
      'id', 'username', 'first_name', 'last_name',
      'profile_image_url', 'is_verified', 'created_at'
    ];
    
    const profile = {};
    publicFields.forEach(field => {
      profile[field] = this[field];
    });
    
    return profile;
  }

  toSafeJSON() {
    const safeFields = [
      'id', 'email', 'username', 'first_name', 'last_name',
      'phone_number', 'profile_image_url', 'is_active', 'is_verified',
      'email_verified', 'phone_verified', 'two_factor_enabled',
      'last_login_at', 'privacy_settings', 'preferences',
      'created_at', 'updated_at'
    ];
    
    const safeUser = {};
    safeFields.forEach(field => {
      safeUser[field] = this[field];
    });
    
    return safeUser;
  }

  // Static methods
  static async findByEmailOrUsername(identifier) {
    return await this.findOne({
      where: {
        $or: [
          { email: identifier },
          { username: identifier }
        ]
      }
    });
  }

  static async findActiveById(id) {
    return await this.findOne({
      where: {
        id,
        is_active: true
      }
    });
  }

  // Associations
  static associate(models) {
    // User roles (many-to-many through user_roles)
    this.belongsToMany(models.VotteryRole, {
      through: models.VotteryUserRole,
      foreignKey: 'user_id',
      otherKey: 'role_id',
      as: 'roles'
    });

    // Organization memberships
    this.hasMany(models.OrganizationMember, {
      foreignKey: 'user_id',
      as: 'organizationMemberships'
    });

    // Organizations through memberships
    this.belongsToMany(models.VotteryOrganization, {
      through: models.OrganizationMember,
      foreignKey: 'user_id',
      otherKey: 'organization_id',
      as: 'organizations'
    });

    // User activity logs
    this.hasMany(models.UserActivityLog, {
      foreignKey: 'user_id',
      as: 'activityLogs'
    });

    // Encryption keys
    this.hasMany(models.EncryptionKey, {
      foreignKey: 'user_id',
      as: 'encryptionKeys'
    });

    // Digital signatures
    this.hasMany(models.DigitalSignature, {
      foreignKey: 'signer_user_id',
      as: 'digitalSignatures'
    });

    // Security events
    this.hasMany(models.SecurityEvent, {
      foreignKey: 'user_id',
      as: 'securityEvents'
    });

    // Created organizations
    this.hasMany(models.VotteryOrganization, {
      foreignKey: 'created_by',
      as: 'createdOrganizations'
    });

    // Created roles
    this.hasMany(models.VotteryRole, {
      foreignKey: 'created_by',
      as: 'createdRoles'
    });
  }
}

export default (sequelize) => {
  return VotteryUser.init(sequelize);
};