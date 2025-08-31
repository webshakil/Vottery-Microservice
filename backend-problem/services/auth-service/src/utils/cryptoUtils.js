import { createHash, createCipheriv, createDecipheriv, randomBytes, scrypt } from 'crypto';
import { promisify } from 'util';
import bcrypt from 'bcryptjs';

const scryptAsync = promisify(scrypt);

export class CryptoUtils {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.keyLength = 32;
    this.ivLength = 16;
    this.saltLength = 32;
    this.tagLength = 16;
    this.encryptionKey = process.env.ENCRYPTION_KEY;
    this.hashAlgorithm = 'sha256';
  }

  // Hash email for database indexing
  hashEmail(email) {
    return createHash(this.hashAlgorithm)
      .update(email.toLowerCase().trim())
      .digest('hex');
  }

  // Hash phone for database indexing
  hashPhone(phone) {
    // Remove all non-digit characters and hash
    const cleanPhone = phone.replace(/\D/g, '');
    return createHash(this.hashAlgorithm)
      .update(cleanPhone)
      .digest('hex');
  }

  // Encrypt sensitive data
  async encrypt(text) {
    try {
      const salt = randomBytes(this.saltLength);
      const key = await scryptAsync(this.encryptionKey, salt, this.keyLength);
      const iv = randomBytes(this.ivLength);
      
      const cipher = createCipheriv(this.algorithm, key, iv);
      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const tag = cipher.getAuthTag();
      
      // Combine salt + iv + tag + encrypted data
      return salt.toString('hex') + ':' + 
             iv.toString('hex') + ':' + 
             tag.toString('hex') + ':' + 
             encrypted;
    } catch (error) {
      throw new Error('Encryption failed');
    }
  }

  // Decrypt sensitive data
  async decrypt(encryptedData) {
    try {
      const [saltHex, ivHex, tagHex, encrypted] = encryptedData.split(':');
      
      const salt = Buffer.from(saltHex, 'hex');
      const iv = Buffer.from(ivHex, 'hex');
      const tag = Buffer.from(tagHex, 'hex');
      
      const key = await scryptAsync(this.encryptionKey, salt, this.keyLength);
      
      const decipher = createDecipheriv(this.algorithm, key, iv);
      decipher.setAuthTag(tag);
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      throw new Error('Decryption failed');
    }
  }

  // Hash biometric data
  async hashBiometric(biometricData, salt = null) {
    try {
      const biometricSalt = salt || randomBytes(this.saltLength);
      const rounds = parseInt(process.env.BIOMETRIC_SALT_ROUNDS) || 12;
      
      // Convert biometric data to string if it's an object
      const dataString = typeof biometricData === 'string' ? 
        biometricData : JSON.stringify(biometricData);
      
      const hash = await bcrypt.hash(dataString + biometricSalt.toString('hex'), rounds);
      
      return {
        hash,
        salt: biometricSalt.toString('hex')
      };
    } catch (error) {
      throw new Error('Biometric hashing failed');
    }
  }

  // Verify biometric data
  async verifyBiometric(biometricData, hashedData, salt) {
    try {
      const dataString = typeof biometricData === 'string' ? 
        biometricData : JSON.stringify(biometricData);
      
      return await bcrypt.compare(dataString + salt, hashedData);
    } catch (error) {
      throw new Error('Biometric verification failed');
    }
  }

  // Generate secure random string
  generateSecureRandom(length = 32) {
    return randomBytes(length).toString('hex');
  }

  // Create device fingerprint
  createDeviceFingerprint(deviceInfo) {
    const fingerprintData = {
      userAgent: deviceInfo.userAgent,
      screenResolution: deviceInfo.screenResolution,
      timezone: deviceInfo.timezone,
      language: deviceInfo.language,
      platform: deviceInfo.platform,
      hardwareConcurrency: deviceInfo.hardwareConcurrency,
      deviceMemory: deviceInfo.deviceMemory,
      colorDepth: deviceInfo.colorDepth
    };

    return createHash(this.hashAlgorithm)
      .update(JSON.stringify(fingerprintData))
      .digest('hex');
  }

  // Hash password (if needed for admin accounts)
  async hashPassword(password) {
    const rounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
    return await bcrypt.hash(password, rounds);
  }

  // Verify password
  async verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
  }
}