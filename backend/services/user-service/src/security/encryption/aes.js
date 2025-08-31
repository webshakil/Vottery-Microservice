//import { createCipher, createDecipher, createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import  logger  from '../../utils/logger.js';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';

import encryptionConfig from '../../config/encryption.js';

class AESEncryption {
  constructor() {
    this.config = encryptionConfig.aes;
    this.algorithm = this.config.algorithm; // aes-256-gcm
  }

  /**
   * Generate a random encryption key
   * @returns {Buffer} Encryption key
   */
  generateKey() {
    return randomBytes(this.config.keyLength);
  }

  /**
   * Generate a random IV
   * @returns {Buffer} Initialization vector
   */
  generateIV() {
    return randomBytes(this.config.ivLength);
  }

  /**
   * Generate a random salt
   * @returns {Buffer} Salt for key derivation
   */
  generateSalt() {
    return randomBytes(this.config.saltLength);
  }

  /**
   * Derive key from password using scrypt
   * @param {string} password - Password to derive key from
   * @param {Buffer} salt - Salt for key derivation
   * @returns {Buffer} Derived key
   */
  deriveKeyFromPassword(password, salt) {
    try {
      return scryptSync(password, salt, this.config.keyLength);
    } catch (error) {
      logger.error('Key derivation failed:', error);
      throw new Error('Failed to derive key from password');
    }
  }

  /**
   * Encrypt data using AES-256-GCM
   * @param {string|Buffer} data - Data to encrypt
   * @param {Buffer|string} key - Encryption key or password
   * @param {Buffer} [salt] - Salt for key derivation (if key is password)
   * @returns {Object} Encrypted data with metadata
   */
  encrypt(data, key, salt = null) {
    try {
      let encryptionKey;
      let usedSalt = null;

      // Handle key derivation if password is provided
      if (typeof key === 'string') {
        usedSalt = salt || this.generateSalt();
        encryptionKey = this.deriveKeyFromPassword(key, usedSalt);
      } else {
        encryptionKey = key;
      }

      // Generate IV
      const iv = this.generateIV();

      // Create cipher
      const cipher = createCipheriv(this.algorithm, encryptionKey, iv);

      // Encrypt data
      const input = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
      let encrypted = cipher.update(input);
      encrypted = Buffer.concat([encrypted, cipher.final()]);

      // Get authentication tag
      const tag = cipher.getAuthTag();

      const result = {
        encrypted: encrypted.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        algorithm: this.algorithm
      };

      // Include salt if password-based encryption was used
      if (usedSalt) {
        result.salt = usedSalt.toString('base64');
      }

      logger.debug('AES encryption completed successfully');
      return result;
    } catch (error) {
      logger.error('AES encryption failed:', error);
      throw new Error('AES encryption failed');
    }
  }

  /**
   * Decrypt data using AES-256-GCM
   * @param {Object} encryptedData - Encrypted data object
   * @param {Buffer|string} key - Decryption key or password
   * @returns {string} Decrypted data
   */
  decrypt(encryptedData, key) {
    try {
      const { encrypted, iv, tag, salt, algorithm } = encryptedData;

      if (algorithm !== this.algorithm) {
        throw new Error('Unsupported encryption algorithm');
      }

      let decryptionKey;

      // Handle key derivation if password was used
      if (typeof key === 'string' && salt) {
        const saltBuffer = Buffer.from(salt, 'base64');
        decryptionKey = this.deriveKeyFromPassword(key, saltBuffer);
      } else {
        decryptionKey = key;
      }

      // Convert base64 strings to buffers
      const encryptedBuffer = Buffer.from(encrypted, 'base64');
      const ivBuffer = Buffer.from(iv, 'base64');
      const tagBuffer = Buffer.from(tag, 'base64');

      // Create decipher
      const decipher = createDecipheriv(this.algorithm, decryptionKey, ivBuffer);
      decipher.setAuthTag(tagBuffer);

      // Decrypt data
      let decrypted = decipher.update(encryptedBuffer);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      logger.debug('AES decryption completed successfully');
      return decrypted.toString('utf8');
    } catch (error) {
      logger.error('AES decryption failed:', error);
      throw new Error('AES decryption failed');
    }
  }

  /**
   * Encrypt multiple fields in an object
   * @param {Object} data - Object with fields to encrypt
   * @param {Array<string>} fields - Fields to encrypt
   * @param {Buffer|string} key - Encryption key or password
   * @returns {Object} Object with encrypted fields
   */
  encryptFields(data, fields, key) {
    try {
      const result = { ...data };
      const encryptionMetadata = {};

      for (const field of fields) {
        if (data[field] !== null && data[field] !== undefined) {
          const encrypted = this.encrypt(String(data[field]), key);
          result[field] = encrypted.encrypted;
          
          // Store metadata separately
          encryptionMetadata[field] = {
            iv: encrypted.iv,
            tag: encrypted.tag,
            salt: encrypted.salt,
            algorithm: encrypted.algorithm
          };
        }
      }

      result._encryption = encryptionMetadata;
      return result;
    } catch (error) {
      logger.error('Field encryption failed:', error);
      throw new Error('Field encryption failed');
    }
  }

  /**
   * Decrypt multiple fields in an object
   * @param {Object} data - Object with encrypted fields
   * @param {Array<string>} fields - Fields to decrypt
   * @param {Buffer|string} key - Decryption key or password
   * @returns {Object} Object with decrypted fields
   */
  decryptFields(data, fields, key) {
    try {
      const result = { ...data };
      const metadata = data._encryption || {};

      for (const field of fields) {
        if (data[field] && metadata[field]) {
          const encryptedData = {
            encrypted: data[field],
            ...metadata[field]
          };
          
          result[field] = this.decrypt(encryptedData, key);
        }
      }

      // Remove encryption metadata
      delete result._encryption;
      return result;
    } catch (error) {
      logger.error('Field decryption failed:', error);
      throw new Error('Field decryption failed');
    }
  }

  /**
   * Create encrypted backup of data
   * @param {Object} data - Data to backup
   * @param {string} password - Backup password
   * @returns {string} Encrypted backup string
   */
  createEncryptedBackup(data, password) {
    try {
      const jsonString = JSON.stringify(data);
      const encrypted = this.encrypt(jsonString, password);
      return JSON.stringify(encrypted);
    } catch (error) {
      logger.error('Encrypted backup creation failed:', error);
      throw new Error('Failed to create encrypted backup');
    }
  }

  /**
   * Restore data from encrypted backup
   * @param {string} encryptedBackup - Encrypted backup string
   * @param {string} password - Backup password
   * @returns {Object} Restored data
   */
  restoreFromEncryptedBackup(encryptedBackup, password) {
    try {
      const encryptedData = JSON.parse(encryptedBackup);
      const jsonString = this.decrypt(encryptedData, password);
      return JSON.parse(jsonString);
    } catch (error) {
      logger.error('Encrypted backup restoration failed:', error);
      throw new Error('Failed to restore from encrypted backup');
    }
  }
}

export default new AESEncryption();