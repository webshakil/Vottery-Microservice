import { DataTypes, Model } from 'sequelize';
import crypto from 'node:crypto';

class EncryptionKey extends Model {
  static init(sequelize) {
    return super.init(
      {
        id: {
          type: DataTypes.UUID,
          defaultValue: DataTypes.UUIDV4,
          primaryKey: true,
          allowNull: false,
        },
        key_id: {
          type: DataTypes.STRING(64),
          allowNull: false,
          unique: true,
          comment: 'Unique identifier for the key',
        },
        organization_id: {
          type: DataTypes.UUID,
          allowNull: false,
        },
        user_id: {
          type: DataTypes.UUID,
          allowNull: true,
          comment: 'User-specific keys (null for organization keys)',
        },
        key_type: {
          type: DataTypes.ENUM,
          values: ['RSA', 'ElGamal', 'AES', 'ECDSA', 'threshold'],
          allowNull: false,
        },
        key_purpose: {
          type: DataTypes.ENUM,
          values: ['voting', 'signature', 'encryption', 'authentication', 'threshold_share'],
          allowNull: false,
        },
        algorithm: {
          type: DataTypes.STRING(50),
          allowNull: false,
          comment: 'Specific algorithm variant (e.g., RSA-2048, ElGamal-256)',
        },
        key_size: {
          type: DataTypes.INTEGER,
          allowNull: false,
          comment: 'Key size in bits',
        },
        public_key: {
          type: DataTypes.TEXT,
          allowNull: false,
          comment: 'Base64 encoded public key',
        },
        private_key_encrypted: {
          type: DataTypes.TEXT,
          allowNull: true,
          comment: 'Encrypted private key (null for public-only keys)',
        },
        key_parameters: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
          comment: 'Algorithm-specific parameters (p, q, g for ElGamal, etc.)',
        },
        threshold_config: {
          type: DataTypes.JSON,
          allowNull: true,
          comment: 'Threshold cryptography configuration (n, k, shares)',
        },
        is_master_key: {
          type: DataTypes.BOOLEAN,
          defaultValue: false,
          allowNull: false,
          comment: 'Whether this is a master key for key derivation',
        },
        is_active: {
          type: DataTypes.BOOLEAN,
          defaultValue: true,
          allowNull: false,
        },
        is_revoked: {
          type: DataTypes.BOOLEAN,
          defaultValue: false,
          allowNull: false,
        },
        revocation_reason: {
          type: DataTypes.STRING(200),
          allowNull: true,
        },
        revoked_at: {
          type: DataTypes.DATE,
          allowNull: true,
        },
        expires_at: {
          type: DataTypes.DATE,
          allowNull: true,
          comment: 'Key expiration date',
        },
        last_used_at: {
          type: DataTypes.DATE,
          allowNull: true,
        },
        usage_count: {
          type: DataTypes.INTEGER,
          defaultValue: 0,
          allowNull: false,
          comment: 'Number of times key has been used',
        },
        max_usage_count: {
          type: DataTypes.INTEGER,
          allowNull: true,
          comment: 'Maximum allowed usage count',
        },
        rotation_schedule: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
          comment: 'Automatic rotation configuration',
        },
        backup_locations: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Secure backup storage locations',
        },
        access_log: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Recent access attempts and usage',
        },
        security_metadata: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
          comment: 'Security-related metadata and flags',
        },
        created_by: {
          type: DataTypes.UUID,
          allowNull: false,
        },
        updated_by: {
          type: DataTypes.UUID,
          allowNull: true,
        },
        metadata: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
        },
      },
      {
        sequelize,
        modelName: 'EncryptionKey',
        tableName: 'vottery_encryption_keys',
        paranoid: true,
        hooks: {
          beforeCreate: (key) => {
            if (!key.key_id) {
              key.key_id = crypto.randomBytes(16).toString('hex');
            }
          },
          afterCreate: (key) => {
            key.logAccess('created', 'Key generated');
          },
        },
      }
    );
  }

  // Instance methods
  isExpired() {
    if (!this.expires_at) {
      return false;
    }
    return new Date() > this.expires_at;
  }

  isValid() {
    return this.is_active && !this.is_revoked && !this.isExpired();
  }

  isAtMaxUsage() {
    if (!this.max_usage_count) {
      return false;
    }
    return this.usage_count >= this.max_usage_count;
  }

  canBeUsed() {
    return this.isValid() && !this.isAtMaxUsage();
  }

  async incrementUsage() {
    this.usage_count += 1;
    this.last_used_at = new Date();
    return await this.save();
  }

  async revoke(reason = null, revokedBy = null) {
    this.is_revoked = true;
    this.is_active = false;
    this.revocation_reason = reason;
    this.revoked_at = new Date();
    
    if (revokedBy) {
      this.updated_by = revokedBy;
    }
    
    this.logAccess('revoked', `Key revoked: ${reason}`);
    return await this.save();
  }

  async activate() {
    if (this.is_revoked) {
      throw new Error('Cannot activate revoked key');
    }
    
    this.is_active = true;
    this.logAccess('activated', 'Key activated');
    return await this.save();
  }

  async deactivate() {
    this.is_active = false;
    this.logAccess('deactivated', 'Key deactivated');
    return await this.save();
  }

  async extendExpiration(days) {
    if (!this.expires_at) {
      this.expires_at = new Date();
    }
    
    this.expires_at.setDate(this.expires_at.getDate() + days);
    this.logAccess('extended', `Key expiration extended by ${days} days`);
    return await this.save();
  }

  async setExpiration(date) {
    this.expires_at = date;
    this.logAccess('expiration_updated', `Key expiration set to ${date.toISOString()}`);
    return await this.save();
  }

  getDaysUntilExpiration() {
    if (!this.expires_at) {
      return null;
    }
    
    const now = new Date();
    const expiration = new Date(this.expires_at);
    const diffTime = expiration - now;
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  }

  isExpiringWithin(days) {
    const daysUntil = this.getDaysUntilExpiration();
    return daysUntil !== null && daysUntil <= days && daysUntil > 0;
  }

  shouldAutoRotate() {
    if (!this.rotation_schedule.auto_rotate) {
      return false;
    }
    
    const rotationDays = this.rotation_schedule.rotation_days || 365;
    const daysSinceCreation = Math.floor((new Date() - this.created_at) / (1000 * 60 * 60 * 24));
    
    return daysSinceCreation >= rotationDays;
  }

  // Key format conversion methods
  getPublicKeyPEM() {
    try {
      return Buffer.from(this.public_key, 'base64').toString('utf8');
    } catch (error) {
      throw new Error('Invalid public key format');
    }
  }

  async getPrivateKeyPEM(passphrase) {
    if (!this.private_key_encrypted) {
      return null;
    }
    
    try {
      // This would need proper decryption implementation
      // For now, returning placeholder
      this.logAccess('private_key_accessed', 'Private key accessed');
      return '[ENCRYPTED_PRIVATE_KEY]'; // Placeholder
    } catch (error) {
      this.logAccess('private_key_access_failed', `Failed to decrypt private key: ${error.message}`);
      throw new Error('Failed to decrypt private key');
    }
  }

  // Threshold cryptography methods
  isThresholdKey() {
    return this.key_type === 'threshold';
  }

  getThresholdConfig() {
    if (!this.isThresholdKey()) {
      return null;
    }
    
    return this.threshold_config;
  }

  getThresholdRequirement() {
    const config = this.getThresholdConfig();
    return config ? `${config.k} of ${config.n}` : null;
  }

  // Access logging
  logAccess(action, description = '', metadata = {}) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      action,
      description,
      metadata,
      user_id: metadata.user_id || null,
      ip_address: metadata.ip_address || null,
    };
    
    // Keep only last 100 entries
    const maxEntries = 100;
    this.access_log.push(logEntry);
    if (this.access_log.length > maxEntries) {
      this.access_log = this.access_log.slice(-maxEntries);
    }
    
    return logEntry;
  }

  getRecentAccess(limit = 10) {
    return this.access_log
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, limit);
  }

  // Security metadata management
  addSecurityFlag(flag, value = true) {
    if (!this.security_metadata.flags) {
      this.security_metadata.flags = {};
    }
    
    this.security_metadata.flags[flag] = value;
    return this;
  }

  hasSecurityFlag(flag) {
    return this.security_metadata.flags?.[flag] === true;
  }

  removeSecurityFlag(flag) {
    if (this.security_metadata.flags && this.security_metadata.flags[flag]) {
      delete this.security_metadata.flags[flag];
    }
    return this;
  }

  // Static methods
  static async generateKeyPair(options = {}) {
    const {
      keyType = 'RSA',
      keySize = 2048,
      organizationId,
      userId = null,
      purpose = 'encryption',
      createdBy,
    } = options;
    
    try {
      let publicKey, privateKey, algorithm;
      
      switch (keyType) {
        case 'RSA':
          const rsaKeys = crypto.generateKeyPairSync('rsa', {
            modulusLength: keySize,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
          });
          publicKey = Buffer.from(rsaKeys.publicKey).toString('base64');
          privateKey = Buffer.from(rsaKeys.privateKey).toString('base64');
          algorithm = `RSA-${keySize}`;
          break;
          
        case 'ECDSA':
          const ecKeys = crypto.generateKeyPairSync('ec', {
            namedCurve: 'secp256k1',
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
          });
          publicKey = Buffer.from(ecKeys.publicKey).toString('base64');
          privateKey = Buffer.from(ecKeys.privateKey).toString('base64');
          algorithm = 'ECDSA-secp256k1';
          break;
          
        default:
          throw new Error(`Unsupported key type: ${keyType}`);
      }
      
      return await this.create({
        organization_id: organizationId,
        user_id: userId,
        key_type: keyType,
        key_purpose: purpose,
        algorithm,
        key_size: keySize,
        public_key: publicKey,
        private_key_encrypted: privateKey, // Would be encrypted in production
        created_by: createdBy,
      });
      
    } catch (error) {
      throw new Error(`Failed to generate key pair: ${error.message}`);
    }
  }

  static async findActiveKeys(organizationId, keyType = null) {
    const whereClause = {
      organization_id: organizationId,
      is_active: true,
      is_revoked: false,
    };
    
    if (keyType) {
      whereClause.key_type = keyType;
    }
    
    return await this.findAll({
      where: whereClause,
      order: [['created_at', 'DESC']],
    });
  }

  static async findExpiringKeys(days = 30) {
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + days);
    
    return await this.findAll({
      where: {
        is_active: true,
        is_revoked: false,
        expires_at: {
          [this.sequelize.Sequelize.Op.between]: [new Date(), futureDate],
        },
      },
      include: [
        {
          model: this.sequelize.models.VotteryOrganization,
          as: 'organization',
        },
      ],
    });
  }

  static async findKeysForRotation() {
    const keys = await this.findAll({
      where: {
        is_active: true,
        is_revoked: false,
      },
    });
    
    return keys.filter(key => key.shouldAutoRotate());
  }

  static async findByPurpose(organizationId, purpose) {
    return await this.findAll({
      where: {
        organization_id: organizationId,
        key_purpose: purpose,
        is_active: true,
        is_revoked: false,
      },
      order: [['created_at', 'DESC']],
    });
  }

  static async findMasterKeys(organizationId) {
    return await this.findAll({
      where: {
        organization_id: organizationId,
        is_master_key: true,
        is_active: true,
        is_revoked: false,
      },
    });
  }

  static async findUserKeys(userId) {
    return await this.findAll({
      where: {
        user_id: userId,
        is_active: true,
        is_revoked: false,
      },
      order: [['created_at', 'DESC']],
    });
  }

  static async cleanupExpiredKeys() {
    const expiredKeys = await this.findAll({
      where: {
        is_active: true,
        expires_at: {
          [this.sequelize.Sequelize.Op.lt]: new Date(),
        },
      },
    });
    
    const results = {
      processed: 0,
      deactivated: 0,
      errors: 0,
    };
    
    for (const key of expiredKeys) {
      try {
        await key.deactivate();
        results.deactivated++;
      } catch (error) {
        results.errors++;
        console.error('Error deactivating expired key:', error);
      }
      results.processed++;
    }
    
    return results;
  }

  // Associations
  static associate(models) {
    // Organization
    this.belongsTo(models.VotteryOrganization, {
      foreignKey: 'organization_id',
      as: 'organization'
    });

    // User (optional)
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'user_id',
      as: 'user'
    });

    // Created by user
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'created_by',
      as: 'creator'
    });

    // Updated by user
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'updated_by',
      as: 'updater'
    });

    // Digital signatures using this key
    this.hasMany(models.DigitalSignature, {
      foreignKey: 'encryption_key_id',
      as: 'digitalSignatures'
    });
  }
}

export default (sequelize) => {
  return EncryptionKey.init(sequelize);
};