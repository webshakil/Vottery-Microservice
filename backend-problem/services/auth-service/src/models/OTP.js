
import pool from '../config/database.js';
import { logger } from '../utils/logger.js';
import { EncryptionUtils } from '../utils/encryption.js';
import { OTP_CONFIG } from '../utils/constants.js';

export class OTP {
  // Create OTP
  static async create(identifier, otpType) {
    const client = await pool.connect();
    try {
      // Generate OTP
      const otpCode = EncryptionUtils.generateOTP(OTP_CONFIG.EMAIL_LENGTH);
      const expiresAt = new Date(Date.now() + (OTP_CONFIG.EXPIRY_MINUTES * 60 * 1000));

      // Delete any existing OTPs for this identifier and type
      await client.query(
        'DELETE FROM vottery_otps WHERE identifier = $1 AND otp_type = $2',
        [identifier, otpType]
      );

      // Insert new OTP
      const query = `
        INSERT INTO vottery_otps (identifier, otp_code, otp_type, expires_at, created_at)
        VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
        RETURNING *
      `;
      
      const result = await client.query(query, [identifier, otpCode, otpType, expiresAt]);
      
      logger.info(`OTP created for ${identifier} (${otpType})`);
      return { otpRecord: result.rows[0], otpCode };
      
    } catch (error) {
      logger.error('Error creating OTP:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Verify OTP
  static async verify(identifier, otpCode, otpType) {
    const client = await pool.connect();
    try {
      // Get OTP record
      const query = `
        SELECT * FROM vottery_otps 
        WHERE identifier = $1 AND otp_type = $2 AND used_at IS NULL
        ORDER BY created_at DESC
        LIMIT 1
      `;
      
      const result = await client.query(query, [identifier, otpType]);
      
      if (result.rows.length === 0) {
        return { success: false, message: 'OTP not found or already used' };
      }

      const otpRecord = result.rows[0];

      // Check if OTP is expired
      if (new Date() > new Date(otpRecord.expires_at)) {
        return { success: false, message: 'OTP has expired' };
      }

      // Check attempts
      if (otpRecord.attempts >= otpRecord.max_attempts) {
        return { success: false, message: 'Maximum OTP attempts exceeded' };
      }

      // Check OTP code
      if (otpRecord.otp_code !== otpCode) {
        // Increment attempts
        await client.query(
          'UPDATE vottery_otps SET attempts = attempts + 1 WHERE id = $1',
          [otpRecord.id]
        );
        return { success: false, message: 'Invalid OTP code' };
      }

      // Mark OTP as used
      await client.query(
        'UPDATE vottery_otps SET used_at = CURRENT_TIMESTAMP WHERE id = $1',
        [otpRecord.id]
      );

      logger.info(`OTP verified successfully for ${identifier} (${otpType})`);
      return { success: true, message: 'OTP verified successfully' };
      
    } catch (error) {
      logger.error('Error verifying OTP:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Check rate limit for OTP requests
  static async checkRateLimit(identifier, otpType) {
    const client = await pool.connect();
    try {
      const timeLimit = new Date(Date.now() - (OTP_CONFIG.RATE_LIMIT_MINUTES * 60 * 1000));
      
      const query = `
        SELECT COUNT(*) as count 
        FROM vottery_otps 
        WHERE identifier = $1 AND otp_type = $2 AND created_at > $3
      `;
      
      const result = await client.query(query, [identifier, otpType, timeLimit]);
      const count = parseInt(result.rows[0].count);

      return {
        allowed: count < OTP_CONFIG.MAX_REQUESTS_PER_PERIOD,
        count,
        limit: OTP_CONFIG.MAX_REQUESTS_PER_PERIOD
      };
      
    } catch (error) {
      logger.error('Error checking OTP rate limit:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Clean expired OTPs
  static async cleanExpired() {
    const client = await pool.connect();
    try {
      const query = 'DELETE FROM vottery_otps WHERE expires_at < CURRENT_TIMESTAMP';
      const result = await client.query(query);
      
      logger.info(`Cleaned ${result.rowCount} expired OTPs`);
      return result.rowCount;
      
    } catch (error) {
      logger.error('Error cleaning expired OTPs:', error);
      throw error;
    } finally {
      client.release();
    }
  }
}