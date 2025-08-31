import { validationResult } from 'express-validator';
import { BiometricService } from '../services/biometricService.js';
import { DeviceService } from '../services/deviceService.js';
import { JwtUtils } from '../utils/jwtUtils.js';
import logger from '../utils/logger.js';
import { createResponse, createErrorResponse } from '../utils/responseUtils.js';

export class BiometricController {
  constructor() {
    this.biometricService = new BiometricService();
    this.deviceService = new DeviceService();
    this.jwtUtils = new JwtUtils();
  }

  // Capture biometric data and complete authentication
  captureBiometric = async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json(createErrorResponse('Validation failed', errors.array()));
      }

      const {
        sessionId,
        biometricData,
        biometricType,
        deviceInfo,
        qualityScore
      } = req.body;

      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent');

      // Verify OTP session is completed
      const otpSession = await this.biometricService.getValidatedOtpSession(sessionId);
      if (!otpSession) {
        return res.status(400).json(createErrorResponse('Invalid or expired session'));
      }

      // Register or update device
      const device = await this.deviceService.registerDevice({
        userId: otpSession.userId,
        deviceInfo,
        ipAddress,
        userAgent,
        biometricCapable: true,
        biometricTypes: [biometricType]
      });

      // Process and store biometric data
      const biometricRecord = await this.biometricService.processBiometric({
        userId: otpSession.userId,
        deviceId: device.id,
        biometricData,
        biometricType,
        qualityScore: qualityScore || 85
      });

      // Generate JWT tokens
      const tokenPayload = {
        userId: otpSession.userId,
        deviceId: device.id,
        email: otpSession.email,
        phone: otpSession.phone,
        biometricVerified: true,
        verificationLevel: 3 // Email + SMS + Biometric
      };

      const tokens = await this.jwtUtils.generateTokenPair(tokenPayload);

      // Create session record
      const session = await this.biometricService.createSession({
        userId: otpSession.userId,
        deviceId: device.id,
        sessionToken: tokens.sessionId,
        refreshToken: tokens.refreshToken,
        jwtTokenId: tokens.jti,
        ipAddress,
        userAgent
      });

      // Mark OTP session as completed
      await this.biometricService.completeOtpSession(sessionId);

      logger.info(`Biometric authentication completed for user ${otpSession.userId}`, {
        userId: otpSession.userId,
        deviceId: device.id,
        biometricType,
        sessionId: session.id
      });

      res.status(200).json(createResponse(
        'Authentication completed successfully',
        {
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresAt: tokens.expiresAt,
          user: {
            id: otpSession.userId,
            email: otpSession.email,
            phone: otpSession.phone,
            verificationLevel: 3,
            biometricEnabled: true
          },
          device: {
            id: device.id,
            type: device.deviceType,
            name: device.deviceName,
            biometricTypes: device.biometricTypes
          },
          session: {
            id: session.id,
            expiresAt: session.expiresAt
          }
        }
      ));

    } catch (error) {
      logger.error('Error capturing biometric:', error);
      res.status(500).json(createErrorResponse('Internal server error'));
    }
  };

  // Verify existing biometric for returning users
  verifyBiometric = async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json(createErrorResponse('Validation failed', errors.array()));
      }

      const {
        userId,
        deviceId,
        biometricData,
        biometricType
      } = req.body;

      const ipAddress = req.ip || req.connection.remoteAddress;

      // Verify biometric data
      const verificationResult = await this.biometricService.verifyBiometric({
        userId,
        deviceId,
        biometricData,
        biometricType
      });

      if (!verificationResult.success) {
        return res.status(401).json(createErrorResponse(
          'Biometric verification failed',
          {
            remainingAttempts: verificationResult.remainingAttempts,
            locked: verificationResult.locked
          }
        ));
      }

      logger.info(`Biometric verification successful for user ${userId}`);

      res.status(200).json(createResponse(
        'Biometric verification successful',
        {
          verified: true,
          userId,
          deviceId,
          trustScore: verificationResult.trustScore
        }
      ));

    } catch (error) {
      logger.error('Error verifying biometric:', error);
      res.status(500).json(createErrorResponse('Internal server error'));
    }
  };

  // Get biometric capabilities for device
  getBiometricCapabilities = async (req, res) => {
    try {
      const { deviceId } = req.params;
      
      const capabilities = await this.biometricService.getDeviceBiometricCapabilities(deviceId);
      
      res.status(200).json(createResponse(
        'Biometric capabilities retrieved',
        {
          deviceId,
          capabilities: capabilities.available,
          supported: capabilities.supported,
          recommended: capabilities.recommended
        }
      ));

    } catch (error) {
      logger.error('Error getting biometric capabilities:', error);
      res.status(500).json(createErrorResponse('Internal server error'));
    }
  };
}