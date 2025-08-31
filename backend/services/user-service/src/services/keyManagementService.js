import EncryptionKey from '../models/EncryptionKey.js';
import { randomBytes, createHash } from 'node:crypto';
import { Sequelize, Op } from 'sequelize';   // ✅ added
import rsaCrypto from '../security/encryption/rsa.js';
import elgamalCrypto from '../security/encryption/elgamal.js';
import aesCrypto from '../security/encryption/aes.js';
import auditService from './auditService.js';
import { AppError } from '../utils/response.js';
import { KEY_TYPES, ENCRYPTION } from '../utils/constants.js'; // ✅ pull key sizes

/**
 * Key Management Service
 * Handles generation, storage, rotation, and management of cryptographic keys
 */
class KeyManagementService {
  constructor() {
    this.systemKeys = new Map();
  }

  /**
   * Generate a new encryption key
   */
  async generateKey(type, options = {}) {
    try {
      let keyPair;

      switch (type) {
        case KEY_TYPES.AES: {
          const size = options.size || ENCRYPTION.KEY_SIZES.AES;
          const key = randomBytes(size / 8);
          return { type, key };
        }

        case KEY_TYPES.RSA:
          keyPair = await rsaCrypto.generateKeyPair(options.size || ENCRYPTION.KEY_SIZES.RSA);
          return { type, ...keyPair };

        case KEY_TYPES.ELGAMAL:
          keyPair = await elgamalCrypto.generateKeyPair(options.size || ENCRYPTION.KEY_SIZES.ELGAMAL);
          return { type, ...keyPair };

        default:
          throw new AppError(`Unsupported key type: ${type}`, 400, 'INVALID_KEY_TYPE');
      }
    } catch (error) {
      throw new AppError(
        'Key generation failed',
        500,
        'KEY_GENERATION_ERROR',
        { error: error.message }
      );
    }
  }

  /**
   * Store a new key in the database
   */
  async storeKey({ type, key, publicKey, privateKey, expiresAt = null, createdBy = null }) {
    try {
      const keyRecord = await EncryptionKey.create({
        type,
        key: key ? key.toString('hex') : null,
        public_key: publicKey,
        private_key: privateKey,
        fingerprint: this.generateFingerprint(key || publicKey),
        expires_at: expiresAt,
        created_by: createdBy
      });

      await auditService.log({
        action: 'KEY_CREATED',
        entity: 'EncryptionKey',
        entityId: keyRecord.id,
        details: { type }
      });

      return keyRecord;
    } catch (error) {
      throw new AppError(
        'Failed to store key',
        500,
        'KEY_STORAGE_ERROR',
        { error: error.message }
      );
    }
  }

  /**
   * Get active key of specific type
   */
  async getActiveKey(type) {
    try {
      const key = await EncryptionKey.findOne({
        where: {
          type,
          is_active: true,
          [Op.or]: [
            { expires_at: null },
            { expires_at: { [Op.gt]: new Date() } }
          ]
        },
        order: [['created_at', 'DESC']]
      });

      if (!key) {
        throw new AppError('No active key found', 404, 'KEY_NOT_FOUND', { type });
      }

      return key;
    } catch (error) {
      throw new AppError(
        'Failed to retrieve active key',
        500,
        'KEY_RETRIEVAL_ERROR',
        { error: error.message }
      );
    }
  }

  /**
   * Rotate a key
   */
  async rotateKey(type, options = {}) {
    try {
      const newKey = await this.generateKey(type, options);

      // Deactivate old keys
      await EncryptionKey.update(
        { is_active: false },
        { where: { type, is_active: true } }
      );

      const keyRecord = await this.storeKey({
        type,
        key: newKey.key,
        publicKey: newKey.publicKey,
        privateKey: newKey.privateKey,
        expiresAt: options.expiresAt,
        createdBy: options.createdBy
      });

      await auditService.log({
        action: 'KEY_ROTATED',
        entity: 'EncryptionKey',
        entityId: keyRecord.id,
        details: { type }
      });

      return keyRecord;
    } catch (error) {
      throw new AppError(
        'Key rotation failed',
        500,
        'KEY_ROTATION_ERROR',
        { error: error.message }
      );
    }
  }

  /**
   * Generate fingerprint of key
   */
  generateFingerprint(key) {
    const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key);
    return createHash('sha256').update(keyBuffer).digest('hex');
  }

  /**
   * Get system AES key (cached)
   */
  async getSystemAESKey() {
    const cacheKey = 'system_aes_key';

    if (this.systemKeys.has(cacheKey)) {
      return this.systemKeys.get(cacheKey);
    }

    if (process.env.SYSTEM_AES_KEY) {
      // ✅ Normalize env key to Buffer
      const key = Buffer.from(process.env.SYSTEM_AES_KEY, 'hex');
      this.systemKeys.set(cacheKey, key);
      return key;
    }

    const aesKey = randomBytes(ENCRYPTION.KEY_SIZES.AES / 8);
    this.systemKeys.set(cacheKey, aesKey);
    return aesKey;
  }

  /**
   * Validate key expiration
   */
  async validateKeyExpiration(keyId) {
    try {
      const key = await EncryptionKey.findByPk(keyId);

      if (!key) {
        throw new AppError('Key not found', 404, 'KEY_NOT_FOUND', { keyId });
      }

      if (key.expires_at && new Date() > key.expires_at) {
        throw new AppError('Key has expired', 400, 'KEY_EXPIRED', { keyId });
      }

      return true;
    } catch (error) {
      throw new AppError(
        'Key validation failed',
        500,
        'KEY_VALIDATION_ERROR',
        { error: error.message }
      );
    }
  }

  /**
   * Get key statistics
   */
  async getKeyStatistics() {
    try {
      const stats = await EncryptionKey.findAll({
        attributes: [
          'type',
          [Sequelize.fn('COUNT', Sequelize.col('id')), 'count'],
          [Sequelize.fn('MAX', Sequelize.col('created_at')), 'last_created']
        ],
        group: ['type']
      });

      return stats;
    } catch (error) {
      throw new AppError(
        'Failed to get key statistics',
        500,
        'KEY_STATS_ERROR',
        { error: error.message }
      );
    }
  }
}

export default new KeyManagementService();

// // services/keyManagementService.js
// import EncryptionKey from '../models/EncryptionKey.js';
// import { randomBytes, createHash } from 'node:crypto';
// import rsaCrypto from '../security/encryption/rsa.js';
// import elgamalCrypto from '../security/encryption/elgamal.js';
// import aesCrypto from '../security/encryption/aes.js';
// import auditService from './auditService.js';
// import { AppError } from '../utils/response.js';
// import { KEY_TYPES } from '../utils/constants.js';

// class KeyManagementService {
//   constructor() {
//     this.systemKeys = new Map();
//     this.keyRotationInterval = 24 * 60 * 60 * 1000; // 24 hours
//   }

//   /**
//    * Generate key pair for user
//    * @param {number} userId 
//    * @param {string} keyType 
//    * @param {number} keySize 
//    * @returns {Promise<object>}
//    */
//   async generateUserKeyPair(userId, keyType = 'RSA', keySize = 2048) {
//     try {
//       let keyPair;
//       let publicKey, privateKey;

//       switch (keyType.toUpperCase()) {
//         case 'RSA':
//           keyPair = await rsaCrypto.generateKeyPair(keySize);
//           publicKey = keyPair.publicKey;
//           privateKey = keyPair.privateKey;
//           break;
        
//         case 'ELGAMAL':
//           keyPair = await elgamalCrypto.generateKeyPair(keySize);
//           publicKey = keyPair.publicKey;
//           privateKey = keyPair.privateKey;
//           break;
        
//         default:
//           throw new AppError(`Unsupported key type: ${keyType}`, 400);
//       }

//       // Generate fingerprints
//       const publicFingerprint = this.generateFingerprint(publicKey);
//       const privateFingerprint = this.generateFingerprint(privateKey);

//       // Encrypt private key before storage
//       const encryptedPrivateKey = await aesCrypto.encrypt(
//         privateKey,
//         await this.getSystemAESKey()
//       );

//       // Store keys in database
//       const [publicKeyRecord, privateKeyRecord] = await Promise.all([
//         EncryptionKey.create({
//           user_id: userId,
//           key_type: `${keyType.toUpperCase()}_PUBLIC`,
//           key_data_encrypted: publicKey, // Public keys don't need encryption
//           key_fingerprint: publicFingerprint,
//           expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year
//         }),
//         EncryptionKey.create({
//           user_id: userId,
//           key_type: `${keyType.toUpperCase()}_PRIVATE`,
//           key_data_encrypted: encryptedPrivateKey,
//           key_fingerprint: privateFingerprint,
//           expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year
//         })
//       ]);

//       // Log key generation
//       await auditService.logActivity(
//         userId,
//         'KEY_GENERATION',
//         'encryption_key',
//         publicKeyRecord.id,
//         {
//           key_type: keyType,
//           key_size: keySize,
//           public_fingerprint: publicFingerprint,
//           private_fingerprint: privateFingerprint
//         }
//       );

//       return {
//         publicKey: {
//           id: publicKeyRecord.id,
//           key: publicKey,
//           fingerprint: publicFingerprint,
//           type: `${keyType.toUpperCase()}_PUBLIC`
//         },
//         privateKey: {
//           id: privateKeyRecord.id,
//           fingerprint: privateFingerprint,
//           type: `${keyType.toUpperCase()}_PRIVATE`
//         }
//       };
//     } catch (error) {
//       throw new AppError(`Key generation failed: ${error.message}`, 500);
//     }
//   }

//   /**
//    * Get user's public key
//    * @param {number} userId 
//    * @param {string} keyType 
//    * @returns {Promise<string>}
//    */
//   async getUserPublicKey(userId, keyType = 'RSA') {
//     try {
//       const keyRecord = await EncryptionKey.findOne({
//         where: {
//           user_id: userId,
//           key_type: `${keyType.toUpperCase()}_PUBLIC`,
//           revoked_at: null,
//           expires_at: { [Op.gt]: new Date() }
//         },
//         order: [['created_at', 'DESC']]
//       });

//       if (!keyRecord) {
//         throw new AppError('Public key not found or expired', 404);
//       }

//       return keyRecord.key_data_encrypted;
//     } catch (error) {
//       throw new AppError(error.message, error.statusCode || 500);
//     }
//   }

//   /**
//    * Get user's private key (decrypted)
//    * @param {number} userId 
//    * @param {string} keyType 
//    * @returns {Promise<string>}
//    */
//   async getUserPrivateKey(userId, keyType = 'RSA') {
//     try {
//       const keyRecord = await EncryptionKey.findOne({
//         where: {
//           user_id: userId,
//           key_type: `${keyType.toUpperCase()}_PRIVATE`,
//           revoked_at: null,
//           expires_at: { [Op.gt]: new Date() }
//         },
//         order: [['created_at', 'DESC']]
//       });

//       if (!keyRecord) {
//         throw new AppError('Private key not found or expired', 404);
//       }

//       // Decrypt private key
//       const decryptedPrivateKey = await aesCrypto.decrypt(
//         keyRecord.key_data_encrypted,
//         await this.getSystemAESKey()
//       );

//       return decryptedPrivateKey;
//     } catch (error) {
//       throw new AppError(error.message, error.statusCode || 500);
//     }
//   }

//   /**
//    * Revoke key
//    * @param {number} keyId 
//    * @param {number} revokedBy 
//    * @param {string} reason 
//    * @returns {Promise<boolean>}
//    */
//   async revokeKey(keyId, revokedBy, reason = null) {
//     try {
//       const keyRecord = await EncryptionKey.findByPk(keyId);
//       if (!keyRecord) {
//         throw new AppError('Key not found', 404);
//       }

//       if (keyRecord.revoked_at) {
//         throw new AppError('Key is already revoked', 400);
//       }

//       await keyRecord.update({ 
//         revoked_at: new Date() 
//       });

//       // Log revocation
//       await auditService.logActivity(
//         revokedBy,
//         'KEY_REVOCATION',
//         'encryption_key',
//         keyId,
//         {
//           key_type: keyRecord.key_type,
//           fingerprint: keyRecord.key_fingerprint,
//           reason,
//           revoked_by: revokedBy
//         }
//       );

//       return true;
//     } catch (error) {
//       throw new AppError(error.message, error.statusCode || 500);
//     }
//   }

//   /**
//    * Rotate user keys
//    * @param {number} userId 
//    * @param {string} keyType 
//    * @returns {Promise<object>}
//    */
//   async rotateUserKeys(userId, keyType = 'RSA') {
//     try {
//       // Get current keys
//       const currentKeys = await EncryptionKey.findAll({
//         where: {
//           user_id: userId,
//           key_type: {
//             [Op.in]: [`${keyType.toUpperCase()}_PUBLIC`, `${keyType.toUpperCase()}_PRIVATE`]
//           },
//           revoked_at: null
//         }
//       });

//       // Generate new key pair
//       const newKeyPair = await this.generateUserKeyPair(userId, keyType);

//       // Revoke old keys
//       for (const oldKey of currentKeys) {
//         await this.revokeKey(oldKey.id, userId, 'Key rotation');
//       }

//       // Log key rotation
//       await auditService.logActivity(
//         userId,
//         'KEY_ROTATION',
//         'encryption_key',
//         newKeyPair.publicKey.id,
//         {
//           key_type: keyType,
//           old_keys_revoked: currentKeys.length
//         }
//       );

//       return newKeyPair;
//     } catch (error) {
//       throw new AppError(`Key rotation failed: ${error.message}`, 500);
//     }
//   }

//   /**
//    * Get system public key
//    * @param {string} keyType 
//    * @returns {Promise<string>}
//    */
//   async getSystemPublicKey(keyType = 'RSA') {
//     try {
//       const cacheKey = `system_public_${keyType}`;
      
//       if (this.systemKeys.has(cacheKey)) {
//         return this.systemKeys.get(cacheKey);
//       }

//       // Generate system keys if they don't exist
//       await this.ensureSystemKeys(keyType);
      
//       return this.systemKeys.get(cacheKey);
//     } catch (error) {
//       throw new AppError(`Failed to get system public key: ${error.message}`, 500);
//     }
//   }

//   /**
//    * Get system private key
//    * @param {string} keyType 
//    * @returns {Promise<string>}
//    */
//   async getSystemPrivateKey(keyType = 'RSA') {
//     try {
//       const cacheKey = `system_private_${keyType}`;
      
//       if (this.systemKeys.has(cacheKey)) {
//         return this.systemKeys.get(cacheKey);
//       }

//       // Generate system keys if they don't exist
//       await this.ensureSystemKeys(keyType);
      
//       return this.systemKeys.get(cacheKey);
//     } catch (error) {
//       throw new AppError(`Failed to get system private key: ${error.message}`, 500);
//     }
//   }

//   /**
//    * Get system AES key
//    * @returns {Promise<string>}
//    */
//   async getSystemAESKey() {
//     try {
//       const cacheKey = 'system_aes_key';
      
//       if (this.systemKeys.has(cacheKey)) {
//         return this.systemKeys.get(cacheKey);
//       }

//       // Check environment variable first
//       if (process.env.SYSTEM_AES_KEY) {
//         const key = process.env.SYSTEM_AES_KEY;
//         this.systemKeys.set(cacheKey, key);
//         return key;
//       }

//       // Generate new AES key
//       const aesKey = await aesCrypto.generateKey();
//       this.systemKeys.set(cacheKey, aesKey);
      
//       console.warn('Generated new system AES key. Please save this in environment variables:', aesKey);
      
//       return aesKey;
//     } catch (error) {
//       throw new AppError(`Failed to get system AES key: ${error.message}`, 500);
//     }
//   }

//   /**
//    * Ensure system keys exist
//    * @param {string} keyType 
//    * @returns {Promise<void>}
//    */
//   async ensureSystemKeys(keyType = 'RSA') {
//     try {
//       const publicCacheKey = `system_public_${keyType}`;
//       const privateCacheKey = `system_private_${keyType}`;

//       // Check if keys are already cached
//       if (this.systemKeys.has(publicCacheKey) && this.systemKeys.has(privateCacheKey)) {
//         return;
//       }

//       // Check environment variables first
//       const envPublicKey = process.env[`SYSTEM_${keyType}_PUBLIC_KEY`];
//       const envPrivateKey = process.env[`SYSTEM_${keyType}_PRIVATE_KEY`];

//       if (envPublicKey && envPrivateKey) {
//         this.systemKeys.set(publicCacheKey, envPublicKey);
//         this.systemKeys.set(privateCacheKey, envPrivateKey);
//         return;
//       }

//       // Generate new system keys
//       let keyPair;
//       switch (keyType.toUpperCase()) {
//         case 'RSA':
//           keyPair = await rsaCrypto.generateKeyPair(2048);
//           break;
//         case 'ELGAMAL':
//           keyPair = await elgamalCrypto.generateKeyPair(2048);
//           break;
//         default:
//           throw new AppError(`Unsupported system key type: ${keyType}`, 400);
//       }

//       this.systemKeys.set(publicCacheKey, keyPair.publicKey);
//       this.systemKeys.set(privateCacheKey, keyPair.privateKey);

//       console.warn(`Generated new system ${keyType} keys. Please save these in environment variables:`);
//       console.warn(`SYSTEM_${keyType}_PUBLIC_KEY=${keyPair.publicKey}`);
//       console.warn(`SYSTEM_${keyType}_PRIVATE_KEY=${keyPair.privateKey}`);

//     } catch (error) {
//       throw new AppError(`Failed to ensure system keys: ${error.message}`, 500);
//     }
//   }

//   /**
//    * Generate key fingerprint
//    * @param {string} key 
//    * @returns {string}
//    */
//   generateFingerprint(key) {
//     return createHash('sha256').update(key).digest('hex');
//   }

//   /**
//    * Validate key format and strength
//    * @param {string} key 
//    * @param {string} keyType 
//    * @returns {object}
//    */
//   validateKey(key, keyType) {
//     try {
//       const validation = {
//         isValid: false,
//         strength: 'unknown',
//         issues: []
//       };

//       if (!key || typeof key !== 'string') {
//         validation.issues.push('Key must be a non-empty string');
//         return validation;
//       }

//       switch (keyType.toUpperCase()) {
//         case 'RSA_PUBLIC':
//         case 'RSA_PRIVATE':
//           validation.isValid = this.validateRSAKey(key, keyType, validation);
//           break;
        
//         case 'AES':
//           validation.isValid = this.validateAESKey(key, validation);
//           break;
        
//         default:
//           validation.issues.push(`Unsupported key type: ${keyType}`);
//       }

//       return validation;
//     } catch (error) {
//       return {
//         isValid: false,
//         strength: 'invalid',
//         issues: [`Validation error: ${error.message}`]
//       };
//     }
//   }

//   /**
//    * Validate RSA key
//    * @param {string} key 
//    * @param {string} keyType 
//    * @param {object} validation 
//    * @returns {boolean}
//    */
//   validateRSAKey(key, keyType, validation) {
//     const isPublic = keyType.includes('PUBLIC');
//     const expectedHeader = isPublic ? '-----BEGIN PUBLIC KEY-----' : '-----BEGIN PRIVATE KEY-----';
//     const expectedFooter = isPublic ? '-----END PUBLIC KEY-----' : '-----END PRIVATE KEY-----';

//     if (!key.includes(expectedHeader) || !key.includes(expectedFooter)) {
//       validation.issues.push('Invalid key format');
//       return false;
//     }

//     // Estimate key size (rough approximation)
//     const keyContent = key.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
//     const keySize = Math.floor(keyContent.length * 6 / 8); // Base64 to bits estimation

//     if (keySize < 1024) {
//       validation.issues.push('Key size appears to be too small (< 1024 bits)');
//       validation.strength = 'weak';
//     } else if (keySize < 2048) {
//       validation.strength = 'medium';
//     } else {
//       validation.strength = 'strong';
//     }

//     return true;
//   }

//   /**
//    * Validate AES key
//    * @param {string} key 
//    * @param {object} validation 
//    * @returns {boolean}
//    */
//   validateAESKey(key, validation) {
//     if (key.length !== 64) { // 256-bit key in hex
//       validation.issues.push('AES key must be 64 characters (256-bit hex)');
//       return false;
//     }

//     if (!/^[0-9a-fA-F]+$/.test(key)) {
//       validation.issues.push('AES key must be hexadecimal');
//       return false;
//     }

//     validation.strength = 'strong';
//     return true;
//   }

//   /**
//    * Get key statistics
//    * @returns {Promise<object>}
//    */
//   async getKeyStatistics() {
//     try {
//       const [
//         totalKeys,
//         revokedKeys,
//         expiredKeys,
//         keysByType
//       ] = await Promise.all([
//         EncryptionKey.count(),
//         EncryptionKey.count({ where: { revoked_at: { [Op.ne]: null } } }),
//         EncryptionKey.count({ where: { expires_at: { [Op.lt]: new Date() } } }),
//         EncryptionKey.findAll({
//           attributes: [
//             'key_type',
//             [Sequelize.fn('COUNT', Sequelize.col('id')), 'count']
//           ],
//           group: ['key_type']
//         })
//       ]);

//       const typeDistribution = {};
//       keysByType.forEach(keyType => {
//         typeDistribution[keyType.key_type] = parseInt(keyType.dataValues.count);
//       });

//       return {
//         total: totalKeys,
//         revoked: revokedKeys,
//         expired: expiredKeys,
//         active: totalKeys - revokedKeys - expiredKeys,
//         typeDistribution
//       };
//     } catch (error) {
//       throw new AppError(error.message, 500);
//     }
//   }

//   /**
//    * Cleanup expired keys
//    * @returns {Promise<number>}
//    */
//   async cleanupExpiredKeys() {
//     try {
//       const expiredKeys = await EncryptionKey.findAll({
//         where: {
//           expires_at: { [Op.lt]: new Date() },
//           revoked_at: null
//         }
//       });

//       let cleaned = 0;
//       for (const key of expiredKeys) {
//         await key.update({ revoked_at: new Date() });
//         cleaned++;
//       }

//       return cleaned;
//     } catch (error) {
//       throw new AppError(`Key cleanup failed: ${error.message}`, 500);
//     }
//   }

//   /**
//    * Export user keys (for backup)
//    * @param {number} userId 
//    * @returns {Promise<object>}
//    */
//   async exportUserKeys(userId) {
//     try {
//       const keys = await EncryptionKey.findAll({
//         where: {
//           user_id: userId,
//           revoked_at: null
//         },
//         attributes: ['id', 'key_type', 'key_fingerprint', 'created_at', 'expires_at']
//       });

//       return {
//         userId,
//         exportedAt: new Date(),
//         keys: keys.map(key => ({
//           id: key.id,
//           type: key.key_type,
//           fingerprint: key.key_fingerprint,
//           created: key.created_at,
//           expires: key.expires_at
//         }))
//       };
//     } catch (error) {
//       throw new AppError(`Key export failed: ${error.message}`, 500);
//     }
//   }
// }

// export default new KeyManagementService();