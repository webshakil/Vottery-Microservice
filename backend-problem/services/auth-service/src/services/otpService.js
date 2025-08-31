import { randomInt } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { DatabaseService } from './databaseService.js';
import { CryptoUtils } from '../utils/cryptoUtils.js';
import logger from '../utils/logger.js';

export class OtpService {
  constructor() {
    this.dbService = new DatabaseService();
    this.cryptoUtils = new CryptoUtils();
    this.otpLength = parseInt(process.env.OTP_LENGTH) || 6;
    this.otpExpiryMinutes = parseInt(process.env.OTP_EXPIRES_IN) || 10;
    this.maxAttempts = parseInt(process.env.OTP_RATE_LIMIT_MAX) || 5;
    this.rateLimitWindow = parseInt(process.env.OTP_RATE_LIMIT_WINDOW) || 3600000; // 1 hour
  }

  // Generate secure OTP
  generateOtp(length = this.otpLength) {
    const min = Math.pow(10, length - 1);
    const max = Math.pow(10, length) - 1;
    return randomInt(min, max).toString();
  }

  // Create OTP session
  async generateOtpSession(email, phone, ipAddress, userAgent) {
    try {
      const emailHash = this.cryptoUtils.hashEmail(email);
      const phoneHash = this.cryptoUtils.hashPhone(phone);
      const emailOtp = this.generateOtp();
      const smsOtp = this.generateOtp();
      const sessionId = uuidv4();
      const expiresAt = new Date(Date.now() + (this.otpExpiryMinutes * 60 * 1000));

      // Check if user exists
      let userId = await this.dbService.getUserIdByEmailPhone(emailHash, phoneHash);
      
      // If user doesn't exist, create new user record
      if (!userId) {
        userId = await this.dbService.createUser({
          emailHash,
          phoneHash,
          encryptedEmail: this.cryptoUtils.encrypt(email),
          encryptedPhone: this.cryptoUtils.encrypt(phone),
          sngineReferrerVerified: true // Frontend already verified
        });
      }

      // Create OTP session
      await this.dbService.createOtpSession({
        id: sessionId,
        userId,
        emailHash,
        phoneHash,
        emailOtp,
        smsOtp,
        expiresAt,
        ipAddress,
        userAgent
      });

      return {
        id: sessionId,
        userId,
        emailOtp,
        smsOtp,
        expiresAt,
        expiresIn: this.otpExpiryMinutes
      };

    } catch (error) {
      logger.error('Error generating OTP session:', error);
      throw new Error('Failed to generate OTP session');
    }
  }

  // Verify OTP codes
  async verifyOtp(sessionId, emailOtp, smsOtp, ipAddress) {
    try {
      const session = await this.dbService.getOtpSession(sessionId);
      
      if (!session) {
        return { success: false, error: 'Invalid session ID' };
      }

      if (session.status !== 'pending') {
        return { success: false, error: 'Session already processed' };
      }

      if (new Date() > session.expiresAt) {
        await this.dbService.expireOtpSession(sessionId);
        return { success: false, error: 'OTP expired' };
      }

      if (session.attemptsCount >= this.maxAttempts) {
        await this.dbService.failOtpSession(sessionId);
        return { 
          success: false, 
          error: 'Maximum attempts exceeded',
          locked: true
        };
      }

      // Verify IP address matches
      if (session.ipAddress !== ipAddress) {
        logger.warn(`IP mismatch for session ${sessionId}: ${session.ipAddress} vs ${ipAddress}`);
      }

      // Check OTP codes
      const emailValid = session.emailOtp === emailOtp;
      const smsValid = session.smsOtp === smsOtp;

      if (!emailValid || !smsValid) {
        await this.dbService.incrementOtpAttempts(sessionId);
        return {
          success: false,
          error: 'Invalid OTP codes',
          remainingAttempts: this.maxAttempts - (session.attemptsCount + 1)
        };
      }

      // Mark OTPs as verified
      await this.dbService.markOtpVerified(sessionId, emailValid, smsValid);
      
      // Update user verification level
      await this.dbService.updateUserVerificationLevel(session.userId, 2); // Email + SMS

      return {
        success: true,
        userId: session.userId,
        sessionId
      };

    } catch (error) {
      logger.error('Error verifying OTP:', error);
      throw new Error('Failed to verify OTP');
    }
  }

  // Check rate limiting
  async checkRateLimit(email, ipAddress) {
    try {
      const identifier = this.cryptoUtils.hashEmail(email);
      const rateLimitRecord = await this.dbService.getRateLimit(identifier, 'otp_request');
      
      if (!rateLimitRecord) {
        // First request, create record
        await this.dbService.createRateLimit({
          identifier,
          limitType: 'otp_request',
          currentCount: 1,
          maxCount: this.maxAttempts,
          windowDuration: `${this.rateLimitWindow / 1000} seconds`
        });
        return { allowed: true };
      }

      const windowEnd = new Date(rateLimitRecord.windowStart.getTime() + this.rateLimitWindow);
      const now = new Date();

      if (now > windowEnd) {
        // Window expired, reset counter
        await this.dbService.resetRateLimit(rateLimitRecord.id);
        return { allowed: true };
      }

      if (rateLimitRecord.currentCount >= rateLimitRecord.maxCount) {
        const retryAfter = Math.ceil((windowEnd - now) / 1000);
        return { 
          allowed: false, 
          retryAfter 
        };
      }

      // Increment counter
      await this.dbService.incrementRateLimit(rateLimitRecord.id);
      return { allowed: true };

    } catch (error) {
      logger.error('Error checking rate limit:', error);
      // Allow request on error to avoid blocking legitimate users
      return { allowed: true };
    }
  }

  // Check if resend is allowed
  async canResendOtp(sessionId, ipAddress) {
    try {
      const session = await this.dbService.getOtpSession(sessionId);
      
      if (!session || session.status !== 'pending') {
        return { allowed: false, error: 'Invalid session' };
      }

      // Check if enough time has passed since last send (prevent spam)
      const minResendInterval = 60000; // 1 minute
      const timeSinceCreation = Date.now() - session.createdAt.getTime();
      
      if (timeSinceCreation < minResendInterval) {
        return {
          allowed: false,
          retryAfter: Math.ceil((minResendInterval - timeSinceCreation) / 1000)
        };
      }

      return { allowed: true };

    } catch (error) {
      logger.error('Error checking resend allowance:', error);
      return { allowed: false, error: 'Internal error' };
    }
  }

  // Resend OTP
  async resendOtp(sessionId) {
    try {
      const session = await this.dbService.getOtpSession(sessionId);
      
      if (!session) {
        throw new Error('Session not found');
      }

      // Generate new OTP codes
      const newEmailOtp = this.generateOtp();
      const newSmsOtp = this.generateOtp();
      const newExpiresAt = new Date(Date.now() + (this.otpExpiryMinutes * 60 * 1000));

      // Update session with new OTPs
      await this.dbService.updateOtpSession(sessionId, {
        emailOtp: newEmailOtp,
        smsOtp: newSmsOtp,
        expiresAt: newExpiresAt,
        attemptsCount: 0 // Reset attempts
      });

      // Get decrypted email and phone for sending
      const user = await this.dbService.getUserById(session.userId);
      const email = this.cryptoUtils.decrypt(user.encryptedEmail);
      const phone = this.cryptoUtils.decrypt(user.encryptedPhone);

      return {
        id: sessionId,
        email,
        phone,
        emailOtp: newEmailOtp,
        smsOtp: newSmsOtp,
        expiresAt: newExpiresAt,
        expiresIn: this.otpExpiryMinutes
      };

    } catch (error) {
      logger.error('Error resending OTP:', error);
      throw new Error('Failed to resend OTP');
    }
  }

  // Invalidate OTP session
  async invalidateOtpSession(sessionId) {
    try {
      await this.dbService.updateOtpSession(sessionId, { status: 'failed' });
    } catch (error) {
      logger.error('Error invalidating OTP session:', error);
    }
  }
}