import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';

dotenv.config();

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const IV_LENGTH = 16; // For AES, this is always 16

export class EncryptionUtils {
  // Encrypt text
  static encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipher('aes-256-cbc', ENCRYPTION_KEY);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return iv.toString('hex') + ':' + encrypted;
  }

  // Decrypt text
  static decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = textParts.join(':');
    
    const decipher = crypto.createDecipher('aes-256-cbc', ENCRYPTION_KEY);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  // Hash password
  static async hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
  }

  // Verify password
  static async verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
  }

  // Generate OTP
  static generateOTP(length = 6) {
    let otp = '';
    for (let i = 0; i < length; i++) {
      otp += Math.floor(Math.random() * 10);
    }
    return otp;
  }

  // Hash biometric data
  static hashBiometric(biometricData) {
    return crypto.createHash('sha256')
      .update(JSON.stringify(biometricData))
      .digest('hex');
  }

  // Generate device fingerprint
  static generateDeviceFingerprint(deviceInfo) {
    const data = JSON.stringify({
      userAgent: deviceInfo.userAgent,
      screen: deviceInfo.screen,
      timezone: deviceInfo.timezone,
      language: deviceInfo.language,
      browser: deviceInfo.browser,
      os: deviceInfo.os
    });
    
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  // Generate secure token
  static generateToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }
}