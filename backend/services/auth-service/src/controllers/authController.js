//only changed express validator and logic is same as above but validation changed

// AuthController.js (modified to remove express-validator and add robust validation)
import validator from 'validator';
import { isValidPhoneNumber } from 'libphonenumber-js';
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
  // ---------------------------
  // Internal validation helpers
  // ---------------------------

  static _isEmailValid(email) {
    return typeof email === 'string' && validator.isEmail(email);
  }

  // Expecting E.164 like +8801XXXXXXXXX for reliability
  static _isPhoneValid(phone) {
    return typeof phone === 'string' && isValidPhoneNumber(phone);
  }

  /**
   * Build errors array with friendly messages
   * options: { requireEmail?: boolean, requirePhone?: boolean, requireOTP?: boolean }
   */
  static _collectValidationErrors({ email, phone, otp }, options = {}) {
    const { requireEmail = false, requirePhone = false, requireOTP = false } = options;
    const errors = [];

    // Check required fields first
    if (requireEmail && (!email || email.trim() === '')) {
      errors.push({ msg: 'Email is required', param: 'email' });
    }
    if (requirePhone && (!phone || phone.trim() === '')) {
      errors.push({ msg: 'Phone is required', param: 'phone' });
    }
    if (requireOTP && (!otp || otp.trim() === '')) {
      errors.push({ msg: 'OTP is required', param: 'otp' });
    }

    // Validate format only if value exists
    if (email && email.trim() !== '' && !AuthController._isEmailValid(email)) {
      errors.push({ msg: 'Invalid email format. Please provide a valid email like user@example.com', param: 'email' });
    }
    if (phone && phone.trim() !== '' && !AuthController._isPhoneValid(phone)) {
      errors.push({ msg: 'Invalid phone number format. Use E.164 format like +8801XXXXXXXXX', param: 'phone' });
    }

    return errors;
  }

  // ---------------------------
  // Controllers
  // ---------------------------

  // Check if user exists in SngEngine database
  static async checkUser(req, res) {
    try {
      const { email, phone } = req.body;
  
      // Require both email and phone for the combination check
      const errors = AuthController._collectValidationErrors(
        { email, phone },
        { requireEmail: true, requirePhone: true }
      );
      if (errors.length) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors
        });
      }
  
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
      const votteryUser = await User.createOrGetVotteryUser(email, phone);
  
      logger.info(`User check successful for ${email}`);
  
      res.json({
        success: true,
        exists: true,
        message: 'User found in SngEngine database',
        emailVerified: sngineUser.emailVerified,
        phoneVerified: sngineUser.phoneVerified,
        userId: votteryUser.id   // 👈 added userId here
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
      const { email, phone } = req.body; // phone optional here

      const errors = AuthController._collectValidationErrors(
        { email, phone },
        { requireEmail: true }
      );
      if (errors.length) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors
        });
      }

      // 1. Check if user exists in SngEngine users table
      const sngineUser = await User.checkSngineUser(email, phone || '');
      if (!sngineUser.exists) {
        return res.status(404).json({
          success: false,
          message: 'You are not registered in SngEngine. Go to SngEngine first, then come here.'
        });
      }

      // 2. Check OTP rate limit
      const rateLimit = await OTP.checkRateLimit(email, 'email');
      if (!rateLimit.allowed) {
        return res.status(429).json({
          success: false,
          message: `Too many OTP requests. Please wait before requesting again. (${rateLimit.count}/${rateLimit.limit})`
        });
      }

      // 3. Create OTP
      const { otpRecord, otpCode } = await OTP.create(email, 'email');

      // 4. Send email
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
  // Send SMS OTP - UPDATED for consistent error handling
// Send SMS OTP - UPDATED for consistent error handling
// Send SMS OTP - UPDATED with email fallback
// Send SMS OTP - with automatic email fallback (no extra input required)
static async sendSMSOTP(req, res) {
  try {
    const { phone } = req.body;

    const errors = AuthController._collectValidationErrors(
      { phone },
      { requirePhone: true }
    );
    if (errors.length) {
      return res.status(400).json({
        success: false,
        message: errors[0].msg,
        errors
      });
    }

    // Check if phone exists in User table
    const sngineUser = await User.checkSngineUser('', phone);
    if (!sngineUser.exists) {
      return res.status(404).json({
        success: false,
        message: 'You are not registered in SngEngine. Go to SngEngine first, then come here.'
      });
    }

    // Try to resolve an email for fallback without requiring it from the client
    const fallbackEmail =
      sngineUser.email ||
      sngineUser.sngine_email ||
      (sngineUser.user && sngineUser.user.email) ||
      null;

    // Check rate limit (for SMS channel)
    const rateLimit = await OTP.checkRateLimit(phone, 'sms');
    if (!rateLimit.allowed) {
      return res.status(429).json({
        success: false,
        message: `Too many OTP requests. Please wait before requesting again. (${rateLimit.count}/${rateLimit.limit})`
      });
    }

    // Create OTP (keyed to phone for sms channel)
    const { otpRecord, otpCode } = await OTP.create(phone, 'sms');

    // Send SMS and (if available) Email simultaneously
    const tasks = [
      SMSService.sendOTP(phone, otpCode),
      ...(fallbackEmail ? [EmailService.sendOTP(fallbackEmail, otpCode)] : [])
    ];

    const results = await Promise.allSettled(tasks);
    const smsResult = results[0];
    const emailResult = fallbackEmail ? results[1] : null;
    const emailSent = !!emailResult && emailResult.status === 'fulfilled';

    if (smsResult.status !== 'fulfilled') {
      // Preserve error semantics; still let you know email went out if it did
      logger.warn(`SMS send failed for ${phone}. Email fallback ${emailSent ? 'sent' : 'not sent/failed'}.`);
      return res.status(500).json({
        success: false,
        message: emailSent
          ? 'SMS sending failed, but we emailed the same OTP to you. Please check your inbox (and Spam).'
          : 'Failed to send SMS OTP'
      });
    }

  
    return res.json({
      success: true,
      message: fallbackEmail
        ? 'SMS OTP sent successfully. Sometimes SMS OTPs delay, so we also sent the same OTP to your email.'
        : 'SMS OTP sent successfully',
      expiresIn: 300
    });
   

  } catch (error) {
    logger.error('Send SMS OTP error:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to send SMS OTP'
    });
  }
}



// static async sendSMSOTP(req, res) {
//   try {
//     const { phone } = req.body;
    
    
//     const errors = AuthController._collectValidationErrors(
//       { phone },
//       { requirePhone: true }
//     );
//     if (errors.length) {
//       return res.status(400).json({
//         success: false,
//         message: errors[0].msg, // Use the first error message directly for consistency
//         errors
//       });
//     }

//     // Check if phone exists in User table
//     const sngineUser = await User.checkSngineUser('', phone);
//     if (!sngineUser.exists) {
//       return res.status(404).json({
//         success: false,
//         message: 'You are not registered in SngEngine. Go to SngEngine first, then come here.'
//       });
//     }

//     // Check rate limit
//     const rateLimit = await OTP.checkRateLimit(phone, 'sms');
//     if (!rateLimit.allowed) {
//       return res.status(429).json({
//         success: false,
//         message: `Too many OTP requests. Please wait before requesting again. (${rateLimit.count}/${rateLimit.limit})`
//       });
//     }

//     // Create OTP
//     const { otpRecord, otpCode } = await OTP.create(phone, 'sms');

//     // Send SMS
//     await SMSService.sendOTP(phone, otpCode);

//     logger.info(`SMS OTP sent to ${phone}`);

//     res.json({
//       success: true,
//       message: 'SMS OTP sent successfully',
//       expiresIn: 300 // 5 minutes in seconds
//     });

//   } catch (error) {
//     logger.error('Send SMS OTP error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Failed to send SMS OTP'
//     });
//   }
// }

// Internal validation helpers - Universal phone validation for all countries
static _isPhoneValid(phone) {
  if (!phone || typeof phone !== 'string') return false;
  
  // E.164 format for Twilio compatibility (any country)
  // Total length: 8-15 characters (including +)
  // Examples: +12345678 (shortest) to +123456789012345 (longest)
  const e164Regex = /^\+[1-9]\d{7,14}$/;
  
  return e164Regex.test(phone);
}


  

  // Verify email OTP
  static async verifyEmailOTP(req, res) {
    try {
      const { otp } = req.body;

      const errors = AuthController._collectValidationErrors(
        { otp },
        { requireOTP: true }
      );
      if (errors.length) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors
        });
      }

      // Verify OTP ONLY with otp
      const verification = await OTP.verify(otp, 'email');

      if (!verification.success) {
        return res.status(400).json({
          success: false,
          message: verification.message
        });
      }

      return res.json({
        success: true,
        message: 'OTP verified successfully'
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
      const { otp } = req.body;

      const errors = AuthController._collectValidationErrors(
        {  otp },
        {  requireOTP: true }
      );
      if (errors.length) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors
        });
      }

      // Verify OTP
      const verification = await OTP.verify( otp, 'sms');

      if (!verification.success) {
        return res.status(400).json({
          success: false,
          message: verification.message
        });
      }

      // Update user status
      // const votteryUser = await User.createOrGetVotteryUser('', phone); // We'll get email from session
      // await User.updateStatus(votteryUser.id, USER_STATUS.PHONE_VERIFIED, 'phone_verified_at');

      // logger.info(`SMS OTP verified for ${phone}`);

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
      const {
        email,
        phone,
        deviceFingerprint,
        device,
        biometric
      } = req.body;

      // Require valid email & phone because they are used for user creation + notifications
      const errors = AuthController._collectValidationErrors(
        { email, phone },
        { requireEmail: true, requirePhone: true }
      );
      if (errors.length) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors
        });
      }

      const ipAddress = req.ip || req.connection?.remoteAddress;
      const userAgent = req.get('User-Agent');

      // Get Vottery user
      const votteryUser = await User.createOrGetVotteryUser(email, phone);

      // Register device (simulated)
      const deviceData = {
        userId: votteryUser.id,
        deviceFingerprint,
        deviceType: device?.device?.type || 'desktop',
        browserName: device?.browser?.name,
        browserVersion: device?.browser?.version,
        osName: device?.os?.name,
        osVersion: device?.os?.version,
        screenInfo: device?.screen,
        ipAddress,
        location: null
      };

      // Mock device ID
      const deviceId = Math.floor(Math.random() * 1000000);

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

      // Send welcome notifications (non-blocking failure)
      try {
        await Promise.all([
          EmailService.sendWelcomeEmail(email, 'User'),
          SMSService.sendWelcomeSMS(phone)
        ]);
      } catch (notificationError) {
        logger.warn('Welcome notification failed:', notificationError);
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
