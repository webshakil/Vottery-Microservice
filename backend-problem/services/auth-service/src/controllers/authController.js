import { validationResult } from 'express-validator';
import { User } from '../models/User.js';
import { OTP } from '../models/OTP.js';
import { Session } from '../models/Session.js';
import { EmailService } from '../services/emailService.js';
import { SMSService } from '../services/smsService.js';
import { TokenService } from '../services/tokenService.js';
import { EncryptionUtils } from '../utils/encryption.js';
import { logger } from '../utils/logger.js';
import { USER_STATUS } from '../utils/constants.js';

export class AuthController {
  // Check if user exists in SngEngine database
  static async checkUser(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { email, phone } = req.body;

      // Check SngEngine database
      const sngineUser = await User.checkSngineUser(email, phone);
      
      if (!sngineUser.exists) {
        logger.warn(`User check failed for ${email}, ${phone}: ${sngineUser.message}`);
        return res.status(404).json({
          success: false,
          exists: false,
          message: 'Email and phone combination not found in SngEngine. Please register first.'
        });
      }

      // Create or get Vottery user
      await User.createOrGetVotteryUser(email, phone);

      logger.info(`User check successful for ${email}`);
      
      res.json({
        success: true,
        exists: true,
        message: 'User found in SngEngine database',
        emailVerified: sngineUser.emailVerified,
        phoneVerified: sngineUser.phoneVerified
      });

    } catch (error) {
      logger.error('Check user error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      });
    }
  }

  // Send email OTP
  static async sendEmailOTP(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { email } = req.body;

      // Check rate limit
      const rateLimit = await OTP.checkRateLimit(email, 'email');
      if (!rateLimit.allowed) {
        return res.status(429).json({
          success: false,
          message: `Too many OTP requests. Please wait before requesting again. (${rateLimit.count}/${rateLimit.limit})`
        });
      }

      // Create OTP
      const { otpRecord, otpCode } = await OTP.create(email, 'email');

      // Send email
      await EmailService.sendOTP(email, otpCode);

      logger.info(`Email OTP sent to ${email}`);
      
      res.json({
        success: true,
        message: 'Email OTP sent successfully',
        expiresIn: 300 // 5 minutes in seconds
      });

    } catch (error) {
      logger.error('Send email OTP error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to send email OTP'
      });
    }
  }

  // Send SMS OTP
  static async sendSMSOTP(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { phone } = req.body;

      // Check rate limit
      const rateLimit = await OTP.checkRateLimit(phone, 'sms');
      if (!rateLimit.allowed) {
        return res.status(429).json({
          success: false,
          message: `Too many OTP requests. Please wait before requesting again. (${rateLimit.count}/${rateLimit.limit})`
        });
      }

      // Create OTP
      const { otpRecord, otpCode } = await OTP.create(phone, 'sms');

      // Send SMS
      await SMSService.sendOTP(phone, otpCode);

      logger.info(`SMS OTP sent to ${phone}`);
      
      res.json({
        success: true,
        message: 'SMS OTP sent successfully',
        expiresIn: 300 // 5 minutes in seconds
      });

    } catch (error) {
      logger.error('Send SMS OTP error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to send SMS OTP'
      });
    }
  }

  // Verify email OTP
  static async verifyEmailOTP(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { identifier: email, otp } = req.body;

      // Verify OTP
      const verification = await OTP.verify(email, otp, 'email');
      
      if (!verification.success) {
        return res.status(400).json({
          success: false,
          message: verification.message
        });
      }

      // Update user status
      const votteryUser = await User.createOrGetVotteryUser(email, ''); // We'll get phone later
      await User.updateStatus(votteryUser.id, USER_STATUS.EMAIL_VERIFIED, 'email_verified_at');

      logger.info(`Email OTP verified for ${email}`);
      
      res.json({
        success: true,
        message: 'Email OTP verified successfully'
      });

    } catch (error) {
      logger.error('Verify email OTP error:', error);
      res.status(500).json({
        success: false,
        message: 'Email OTP verification failed'
      });
    }
  }

  // Verify SMS OTP
  static async verifySMSOTP(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { identifier: phone, otp } = req.body;

      // Verify OTP
      const verification = await OTP.verify(phone, otp, 'sms');
      
      if (!verification.success) {
        return res.status(400).json({
          success: false,
          message: verification.message
        });
      }

      // Update user status
      const votteryUser = await User.createOrGetVotteryUser('', phone); // We'll get email from session
      await User.updateStatus(votteryUser.id, USER_STATUS.PHONE_VERIFIED, 'phone_verified_at');

      logger.info(`SMS OTP verified for ${phone}`);
      
      res.json({
        success: true,
        message: 'SMS OTP verified successfully'
      });

    } catch (error) {
      logger.error('Verify SMS OTP error:', error);
      res.status(500).json({
        success: false,
        message: 'SMS OTP verification failed'
      });
    }
  }

  // Complete authentication with biometric data
  static async completeAuth(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { 
        email, 
        phone, 
        deviceFingerprint, 
        device, 
        biometric 
      } = req.body;

      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent');

      // Get Vottery user
      const votteryUser = await User.createOrGetVotteryUser(email, phone);

      // Register device (this would be in biometric-service in production)
      const deviceData = {
        userId: votteryUser.id,
        deviceFingerprint,
        deviceType: device.device?.type || 'desktop',
        browserName: device.browser?.name,
        browserVersion: device.browser?.version,
        osName: device.os?.name,
        osVersion: device.os?.version,
        screenInfo: device.screen,
        ipAddress,
        location: null // Could add geolocation later
      };

      // In production, this would call biometric-service
      // For now, we'll simulate device registration
      const deviceId = Math.floor(Math.random() * 1000000); // Mock device ID

      // Generate tokens
      const tokenPayload = {
        userId: votteryUser.id,
        email: votteryUser.sngine_email,
        phone: votteryUser.sngine_phone,
        deviceId: deviceId,
        deviceFingerprint
      };

      const sessionToken = EncryptionUtils.generateToken();
      const refreshToken = EncryptionUtils.generateToken();

      // Create session
      const session = await Session.create(
        votteryUser.id,
        deviceId,
        sessionToken,
        refreshToken,
        ipAddress,
        userAgent
      );

      // Generate JWT tokens
      const tokens = TokenService.generateTokenPair(tokenPayload);

      // Update user status
      await User.updateStatus(votteryUser.id, USER_STATUS.ACTIVE, 'biometric_registered_at');
      await User.updateLastLogin(votteryUser.id);

      // Send welcome notifications
      try {
        await Promise.all([
          EmailService.sendWelcomeEmail(email, 'User'),
          SMSService.sendWelcomeSMS(phone)
        ]);
      } catch (notificationError) {
        logger.warn('Welcome notification failed:', notificationError);
        // Don't fail the authentication for notification errors
      }

      logger.info(`Authentication completed successfully for user ${votteryUser.id}`);
      
      res.json({
        success: true,
        message: 'Authentication completed successfully',
        token: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user: {
          id: votteryUser.id,
          email: votteryUser.sngine_email,
          phone: votteryUser.sngine_phone,
          status: votteryUser.status,
          emailVerified: !!votteryUser.email_verified_at,
          phoneVerified: !!votteryUser.phone_verified_at,
          biometricRegistered: !!votteryUser.biometric_registered_at,
          lastLogin: votteryUser.last_login
        },
        session: {
          id: session.id,
          deviceId: deviceId,
          expiresAt: session.expires_at
        }
      });

    } catch (error) {
      logger.error('Complete authentication error:', error);
      res.status(500).json({
        success: false,
        message: 'Authentication completion failed'
      });
    }
  }

  // Refresh token
  static async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(400).json({
          success: false,
          message: 'Refresh token is required'
        });
      }

      // Refresh session
      const newSession = await Session.refresh(refreshToken);
      
      if (!newSession) {
        return res.status(401).json({
          success: false,
          message: 'Invalid or expired refresh token'
        });
      }

      // Generate new JWT tokens
      const tokenPayload = {
        userId: newSession.user_id,
        deviceId: newSession.device_id,
        sessionId: newSession.id
      };

      const tokens = TokenService.generateTokenPair(tokenPayload);

      res.json({
        success: true,
        token: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresAt: newSession.expires_at
      });

    } catch (error) {
      logger.error('Token refresh error:', error);
      res.status(500).json({
        success: false,
        message: 'Token refresh failed'
      });
    }
  }

  // Logout
  static async logout(req, res) {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(400).json({
          success: false,
          message: 'Authorization token is required'
        });
      }

      const token = authHeader.substring(7);
      
      // Get session from token
      const session = await Session.getByToken(token);
      
      if (session) {
        // Revoke session
        await Session.revoke(token);
        logger.info(`User ${session.user_id} logged out successfully`);
      }

      res.json({
        success: true,
        message: 'Logged out successfully'
      });

    } catch (error) {
      logger.error('Logout error:', error);
      res.status(500).json({
        success: false,
        message: 'Logout failed'
      });
    }
  }

  // Get user profile
  static async getProfile(req, res) {
    try {
      const userId = req.user.userId;
      
      const user = await User.getById(userId);
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      // Get user sessions
      const sessions = await Session.getUserSessions(userId);

      res.json({
        success: true,
        user: {
          id: user.id,
          email: user.sngine_email,
          phone: user.sngine_phone,
          status: user.status,
          emailVerified: !!user.email_verified_at,
          phoneVerified: !!user.phone_verified_at,
          biometricRegistered: !!user.biometric_registered_at,
          lastLogin: user.last_login,
          createdAt: user.created_at,
          updatedAt: user.updated_at
        },
        sessions: sessions.map(session => ({
          id: session.id,
          deviceType: session.device_type,
          browserName: session.browser_name,
          osName: session.os_name,
          ipAddress: session.ip_address,
          createdAt: session.created_at,
          isActive: session.is_active
        }))
      });

    } catch (error) {
      logger.error('Get profile error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to get user profile'
      });
    }
  }
}