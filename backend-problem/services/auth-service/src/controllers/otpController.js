import { validationResult } from 'express-validator';
import { OtpService } from '../services/otpService.js';
import { EmailService } from '../services/emailService.js';
import { SmsService } from '../services/smsService.js';
import logger from '../utils/logger.js';
import { createResponse, createErrorResponse } from '../utils/responseUtils.js';

export class OtpController {
  constructor() {
    this.otpService = new OtpService();
    this.emailService = new EmailService();
    this.smsService = new SmsService();
  }

  // Send OTP to email and phone
  sendOtp = async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json(createErrorResponse('Validation failed', errors.array()));
      }

      const { email, phone } = req.body;
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent');

      // Check rate limiting
      const rateLimitResult = await this.otpService.checkRateLimit(email, ipAddress);
      if (!rateLimitResult.allowed) {
        return res.status(429).json(createErrorResponse(
          'Rate limit exceeded',
          { retryAfter: rateLimitResult.retryAfter }
        ));
      }

      // Generate OTP session
      const otpSession = await this.otpService.generateOtpSession(
        email, 
        phone, 
        ipAddress, 
        userAgent
      );

      // Send email OTP
      const emailSent = await this.emailService.sendOtp(
        email, 
        otpSession.emailOtp, 
        otpSession.expiresIn
      );

      // Send SMS OTP
      const smsSent = await this.smsService.sendOtp(
        phone, 
        otpSession.smsOtp, 
        otpSession.expiresIn
      );

      if (!emailSent || !smsSent) {
        await this.otpService.invalidateOtpSession(otpSession.id);
        return res.status(500).json(createErrorResponse('Failed to send OTP'));
      }

      logger.info(`OTP sent successfully for session ${otpSession.id}`, {
        sessionId: otpSession.id,
        email: email.replace(/(.{2}).*@/, '$1***@'),
        phone: phone.replace(/(\d{3}).*(\d{2})/, '$1***$2'),
        ipAddress
      });

      res.status(200).json(createResponse(
        'OTP sent successfully',
        {
          sessionId: otpSession.id,
          expiresAt: otpSession.expiresAt,
          expiresIn: otpSession.expiresIn
        }
      ));

    } catch (error) {
      logger.error('Error sending OTP:', error);
      res.status(500).json(createErrorResponse('Internal server error'));
    }
  };

  // Verify OTP codes
  verifyOtp = async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json(createErrorResponse('Validation failed', errors.array()));
      }

      const { sessionId, emailOtp, smsOtp } = req.body;
      const ipAddress = req.ip || req.connection.remoteAddress;

      // Verify OTP session
      const verificationResult = await this.otpService.verifyOtp(
        sessionId, 
        emailOtp, 
        smsOtp, 
        ipAddress
      );

      if (!verificationResult.success) {
        return res.status(400).json(createErrorResponse(
          verificationResult.error,
          {
            remainingAttempts: verificationResult.remainingAttempts,
            locked: verificationResult.locked
          }
        ));
      }

      logger.info(`OTP verification successful for session ${sessionId}`, {
        sessionId,
        userId: verificationResult.userId,
        ipAddress
      });

      res.status(200).json(createResponse(
        'OTP verification successful',
        {
          sessionId,
          userId: verificationResult.userId,
          nextStep: 'biometric_capture',
          verified: true
        }
      ));

    } catch (error) {
      logger.error('Error verifying OTP:', error);
      res.status(500).json(createErrorResponse('Internal server error'));
    }
  };

  // Resend OTP
  resendOtp = async (req, res) => {
    try {
      const { sessionId } = req.params;
      const ipAddress = req.ip || req.connection.remoteAddress;

      // Check if resend is allowed
      const resendResult = await this.otpService.canResendOtp(sessionId, ipAddress);
      if (!resendResult.allowed) {
        return res.status(429).json(createErrorResponse(
          'Resend not allowed',
          { retryAfter: resendResult.retryAfter }
        ));
      }

      // Resend OTP
      const newOtpSession = await this.otpService.resendOtp(sessionId);
      
      // Send new OTPs
      const emailSent = await this.emailService.sendOtp(
        newOtpSession.email, 
        newOtpSession.emailOtp, 
        newOtpSession.expiresIn
      );

      const smsSent = await this.smsService.sendOtp(
        newOtpSession.phone, 
        newOtpSession.smsOtp, 
        newOtpSession.expiresIn
      );

      if (!emailSent || !smsSent) {
        return res.status(500).json(createErrorResponse('Failed to resend OTP'));
      }

      logger.info(`OTP resent successfully for session ${sessionId}`);

      res.status(200).json(createResponse(
        'OTP resent successfully',
        {
          sessionId: newOtpSession.id,
          expiresAt: newOtpSession.expiresAt,
          expiresIn: newOtpSession.expiresIn
        }
      ));

    } catch (error) {
      logger.error('Error resending OTP:', error);
      res.status(500).json(createErrorResponse('Internal server error'));
    }
  };
}