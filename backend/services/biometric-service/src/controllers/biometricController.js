//to solve last problem webauthn

import { DeviceService } from '../services/deviceService.js';
import { BiometricService } from '../services/biometricService.js';
import { WebAuthnService } from '../services/webauthnService.js';
import { db } from '../config/database.js';
import { logger } from '../utils/logger.js';
import { validateInput } from '../utils/validators.js';

export class BiometricController {

  static async getUserId(sngine_email, sngine_phone) {
    try {
      let query;
      let params;

      if (sngine_email && sngine_phone) {
        query = `SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2`;
        params = [sngine_email, sngine_phone];
      } else if (sngine_email) {
        query = `SELECT id FROM vottery_users WHERE sngine_email = $1`;
        params = [sngine_email];
      } else if (sngine_phone) {
        query = `SELECT id FROM vottery_users WHERE sngine_phone = $1`;
        params = [sngine_phone];
      } else {
        throw new Error('Either email or phone is required');
      }

      console.log('Executing query:', query, 'with params:', params);

      const userResult = await db.query(query, params);

      if (userResult.rows.length === 0) {
        throw new Error('User not found for given email/phone');
      }

      const userId = userResult.rows[0].id;
      console.log('Found userId:', userId, 'Type:', typeof userId);

      // Ensure userId is treated as integer, not UUID
      return parseInt(userId);
    } catch (error) {
      console.error('getUserId error:', error);
      throw error;
    }
  }

  // Register a new device
  static async registerDevice(req, res) {
    try {
      const {
        sngine_email,
        sngine_phone,
        deviceInfo,
        location,
        capabilities
      } = req.body;

      console.log('Register device request:', {
        sngine_email,
        sngine_phone,
        deviceInfo
      });

      const ipAddress = req.ip || req.connection?.remoteAddress;
      const userAgent = req.get('User-Agent');

      // Get userId from email/phone
      const userId = await BiometricController.getUserId(sngine_email, sngine_phone);
      console.log('Resolved userId for device registration:', userId);

      // Register device
      const device = await DeviceService.registerDevice({
        userId,
        deviceInfo,
        ipAddress,
        userAgent,
        location,
        capabilities
      });

      logger.info(`Device registered successfully for user ${userId}: ${device.id}`);

      res.status(201).json({
        success: true,
        message: 'Device registered successfully',
        device: {
          id: device.id,
          fingerprint: device.device_fingerprint,
          type: device.device_type,
          capabilities: device.capabilities,
          createdAt: device.created_at
        }
      });

    } catch (error) {
      logger.error('Device registration error:', error);
      console.error('Full error details:', error);
      
      if (error.message === 'User not found for given email/phone') {
        return res.status(404).json({
          success: false,
          message: error.message
        });
      }

      res.status(500).json({
        success: false,
        message: 'Device registration failed',
        error: error.message
      });
    }
  }

  // Get user devices - now accepts email/phone instead of userId param
  static async getUserDevices(req, res) {
    try {
      const { sngine_email, sngine_phone } = req.query;
      
      // Validate that at least one identifier is provided
      if (!sngine_email && !sngine_phone) {
        return res.status(400).json({
          success: false,
          message: 'Either sngine_email or sngine_phone is required'
        });
      }

      // Get userId from email/phone
      const userId = await BiometricController.getUserId(sngine_email, sngine_phone);

      const devices = await DeviceService.getUserDevices(userId);

      res.json({
        success: true,
        devices: devices.map(device => ({
          id: device.id,
          fingerprint: device.device_fingerprint,
          type: device.device_type,
          os: device.os_name,
          browser: device.browser_name,
          lastUsed: device.last_used,
          isActive: device.is_active,
          capabilities: device.capabilities
        }))
      });

    } catch (error) {
      logger.error('Get user devices error:', error);
      
      if (error.message === 'User not found for given email/phone') {
        return res.status(404).json({
          success: false,
          message: error.message
        });
      }

      res.status(500).json({
        success: false,
        message: 'Failed to fetch devices'
      });
    }
  }

  // Update device status
  static async updateDeviceStatus(req, res) {
    try {
      const { deviceId } = req.params;
      const { isActive } = req.body;

      // Ensure deviceId is integer if your schema uses SERIAL
      const parsedDeviceId = parseInt(deviceId);
      if (!parsedDeviceId || !validateInput.isValidId(parsedDeviceId)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid device ID'
        });
      }

      await DeviceService.updateDeviceStatus(parsedDeviceId, isActive);

      res.json({
        success: true,
        message: 'Device status updated successfully'
      });

    } catch (error) {
      logger.error('Update device status error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to update device status'
      });
    }
  }

  // Register biometric data
  static async registerBiometric(req, res) {
    try {
      const {
        sngine_email,
        sngine_phone,
        deviceId,
        biometricType,
        biometricData,
        publicKey,
        credentialId
      } = req.body;

      console.log('Register biometric request:', {
        sngine_email,
        sngine_phone,
        deviceId,
        biometricType
      });

      // Register biometric (BiometricService handles userId lookup internally)
      const biometric = await BiometricService.registerBiometric({
        sngine_email,
        sngine_phone,
        deviceId: parseInt(deviceId), // Ensure deviceId is integer
        biometricType,
        biometricData,
        publicKey,
        credentialId
      });

      // Get userId for logging
      const userId = await BiometricController.getUserId(sngine_email, sngine_phone);
      
      logger.info(`Biometric registered for user ${userId}, device ${deviceId}`);

      res.status(201).json({
        success: true,
        message: 'Biometric registered successfully',
        biometric: {
          id: biometric.id,
          type: biometric.biometric_type,
          deviceId: biometric.device_id,
          createdAt: biometric.created_at
        }
      });

    } catch (error) {
      logger.error('Biometric registration error:', error);
      
      if (error.message === 'User not found for given email/phone') {
        return res.status(404).json({
          success: false,
          message: error.message
        });
      }

      res.status(500).json({
        success: false,
        message: 'Biometric registration failed',
        error: error.message
      });
    }
  }

  // Verify biometric data
  static async verifyBiometric(req, res) {
    try {
      const {
        sngine_email,
        sngine_phone,
        deviceId,
        biometricType,
        biometricData,
        credentialId
      } = req.body;

      // Verify biometric (BiometricService handles userId lookup internally)
      const verification = await BiometricService.verifyBiometric({
        sngine_email,
        sngine_phone,
        deviceId: parseInt(deviceId), // Ensure deviceId is integer
        biometricType,
        biometricData,
        credentialId
      });

      if (!verification.success) {
        return res.status(400).json({
          success: false,
          message: verification.message
        });
      }

      res.json({
        success: true,
        message: 'Biometric verification successful',
        deviceId: verification.deviceId,
        biometricId: verification.biometricId
      });

    } catch (error) {
      logger.error('Biometric verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Biometric verification failed'
      });
    }
  }

  // Get user biometrics - now accepts email/phone instead of userId param
  static async getUserBiometrics(req, res) {
    try {
      const { sngine_email, sngine_phone } = req.query;

      // Validate that at least one identifier is provided
      if (!sngine_email && !sngine_phone) {
        return res.status(400).json({
          success: false,
          message: 'Either sngine_email or sngine_phone is required'
        });
      }

      // Get userId from email/phone
      const userId = await BiometricController.getUserId(sngine_email, sngine_phone);

      const biometrics = await BiometricService.getUserBiometrics(userId);

      res.json({
        success: true,
        biometrics: biometrics.map(bio => ({
          id: bio.id,
          type: bio.biometric_type,
          deviceId: bio.device_id,
          deviceType: bio.device_type,
          isActive: bio.is_active,
          createdAt: bio.created_at
        }))
      });

    } catch (error) {
      logger.error('Get user biometrics error:', error);
      
      if (error.message === 'User not found for given email/phone') {
        return res.status(404).json({
          success: false,
          message: error.message
        });
      }

      res.status(500).json({
        success: false,
        message: 'Failed to fetch biometrics'
      });
    }
  }

  // Delete biometric
  static async deleteBiometric(req, res) {
    try {
      const { biometricId } = req.params;

      // Ensure biometricId is integer if your schema uses SERIAL
      const parsedBiometricId = parseInt(biometricId);
      if (!parsedBiometricId || !validateInput.isValidId(parsedBiometricId)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid biometric ID'
        });
      }

      await BiometricService.deleteBiometric(parsedBiometricId);

      res.json({
        success: true,
        message: 'Biometric deleted successfully'
      });

    } catch (error) {
      logger.error('Delete biometric error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to delete biometric'
      });
    }
  }

  // WebAuthn Registration - Begin
  static async beginWebAuthnRegistration(req, res) {
    try {
      const { sngine_email, sngine_phone, deviceId } = req.body;

      console.log('WebAuthn begin registration request:', {
        sngine_email,
        sngine_phone,
        deviceId
      });

      // Validate inputs
      if (!sngine_email && !sngine_phone) {
        return res.status(400).json({
          success: false,
          message: 'Either email or phone is required'
        });
      }

      if (!deviceId) {
        return res.status(400).json({
          success: false,
          message: 'Device ID is required'
        });
      }

      // Pass the parameters as an object to match WebAuthnService expectation
      const options = await WebAuthnService.beginRegistration({
        sngine_email,
        sngine_phone,
        deviceId: parseInt(deviceId)
      });

      res.json({
        success: true,
        options
      });

    } catch (error) {
      console.error('WebAuthn registration begin error details:', error);
      logger.error('WebAuthn registration begin error:', error);
      
      if (error.message === 'User not found for given email/phone') {
        return res.status(404).json({
          success: false,
          message: error.message
        });
      }

      res.status(500).json({
        success: false,
        message: 'Failed to begin WebAuthn registration',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }

  // WebAuthn Registration - Finish
  static async finishWebAuthnRegistration(req, res) {
    try {
      const { sngine_email, sngine_phone, deviceId, credential } = req.body;

      console.log('WebAuthn finish registration request:', {
        sngine_email,
        sngine_phone,
        deviceId,
        hasCredential: !!credential
      });

      // Validate inputs
      if (!sngine_email && !sngine_phone) {
        return res.status(400).json({
          success: false,
          message: 'Either email or phone is required'
        });
      }

      if (!deviceId || !credential) {
        return res.status(400).json({
          success: false,
          message: 'Device ID and credential are required'
        });
      }

      // Pass parameters as object to match WebAuthnService expectation
      const result = await WebAuthnService.finishRegistration({
        sngine_email,
        sngine_phone,
        deviceId: parseInt(deviceId),
        credential
      });

      if (!result.success) {
        return res.status(400).json(result);
      }

      res.json(result);

    } catch (error) {
      console.error('WebAuthn registration finish error details:', error);
      logger.error('WebAuthn registration finish error:', error);
      
      if (error.message === 'User not found for given email/phone') {
        return res.status(404).json({
          success: false,
          message: error.message
        });
      }

      res.status(500).json({
        success: false,
        message: 'Failed to finish WebAuthn registration',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }

  // WebAuthn Authentication - Begin
  static async beginWebAuthnAuthentication(req, res) {
    try {
      const { sngine_email, sngine_phone } = req.body;

      console.log('WebAuthn begin authentication request:', {
        sngine_email,
        sngine_phone
      });

      // Validate inputs
      if (!sngine_email && !sngine_phone) {
        return res.status(400).json({
          success: false,
          message: 'Either email or phone is required'
        });
      }

      // Pass parameters as object to match WebAuthnService expectation
      const options = await WebAuthnService.beginAuthentication({
        sngine_email,
        sngine_phone
      });

      res.json({
        success: true,
        options
      });

    } catch (error) {
      console.error('WebAuthn authentication begin error details:', error);
      logger.error('WebAuthn authentication begin error:', error);
      
      if (error.message === 'User not found for given email/phone') {
        return res.status(404).json({
          success: false,
          message: error.message
        });
      }

      res.status(500).json({
        success: false,
        message: 'Failed to begin WebAuthn authentication',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }

  // WebAuthn Authentication - Finish
  static async finishWebAuthnAuthentication(req, res) {
    try {
      const { sngine_email, sngine_phone, credential } = req.body;

      console.log('WebAuthn finish authentication request:', {
        sngine_email,
        sngine_phone,
        hasCredential: !!credential
      });

      // Validate inputs
      if (!sngine_email && !sngine_phone) {
        return res.status(400).json({
          success: false,
          message: 'Either email or phone is required'
        });
      }

      if (!credential) {
        return res.status(400).json({
          success: false,
          message: 'Credential is required'
        });
      }

      // Pass parameters as object to match WebAuthnService expectation
      const result = await WebAuthnService.finishAuthentication({
        sngine_email,
        sngine_phone,
        credential
      });

      if (!result.success) {
        return res.status(400).json(result);
      }

      res.json(result);

    } catch (error) {
      console.error('WebAuthn authentication finish error details:', error);
      logger.error('WebAuthn authentication finish error:', error);
      
      if (error.message === 'User not found for given email/phone') {
        return res.status(404).json({
          success: false,
          message: error.message
        });
      }

      res.status(500).json({
        success: false,
        message: 'Failed to finish WebAuthn authentication',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
  // Debug endpoint for testing WebAuthn service
  static async debugWebAuthnTest(req, res) {
    try {
      console.log('Debug: Testing WebAuthn service availability');
      
      // Check if WebAuthnService exists and has required methods
      console.log('WebAuthnService exists:', !!WebAuthnService);
      console.log('WebAuthnService.beginRegistration exists:', typeof WebAuthnService.beginRegistration);
      console.log('WebAuthnService.finishRegistration exists:', typeof WebAuthnService.finishRegistration);
      
      // Test with dummy data
      const testUserId = 1;
      const testDeviceId = 1;
      
      console.log('Testing beginRegistration with userId:', testUserId, 'deviceId:', testDeviceId);
      
      // Try to call beginRegistration
      const result = await WebAuthnService.beginRegistration(testUserId, testDeviceId);
      
      console.log('WebAuthn beginRegistration result:', result);
      
      res.json({
        success: true,
        message: 'WebAuthn service test completed',
        serviceExists: !!WebAuthnService,
        hasBeginRegistration: typeof WebAuthnService.beginRegistration === 'function',
        hasFinishRegistration: typeof WebAuthnService.finishRegistration === 'function',
        testResult: result
      });
      
    } catch (error) {
      console.error('WebAuthn debug test error:', error);
      console.error('Error stack:', error.stack);
      
      res.status(500).json({
        success: false,
        message: 'WebAuthn debug test failed',
        error: error.message,
        stack: error.stack,
        serviceExists: !!WebAuthnService,
        hasBeginRegistration: typeof WebAuthnService?.beginRegistration,
        hasFinishRegistration: typeof WebAuthnService?.finishRegistration
      });
    }
  }

  // Health check endpoint
  static async healthCheck(req, res) {
    res.json({
      success: true,
      message: 'Biometric service is running',
      timestamp: new Date().toISOString(),
      services: {
        WebAuthnService: !!WebAuthnService,
        beginRegistration: typeof WebAuthnService?.beginRegistration,
        finishRegistration: typeof WebAuthnService?.finishRegistration
      }
    });
  }
}
// //email and phone instead of userId
// import { DeviceService } from '../services/deviceService.js';
// import { BiometricService } from '../services/biometricService.js';
// import { WebAuthnService } from '../services/webauthnService.js';
// import { db } from '../config/database.js';
// import { logger } from '../utils/logger.js';
// import { validateInput } from '../utils/validators.js';

// export class BiometricController {

// static async getUserId(sngine_email, sngine_phone) {
//   try {
//     let query;
//     let params;

//     if (sngine_email && sngine_phone) {
//       query = `SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2`;
//       params = [sngine_email, sngine_phone];
//     } else if (sngine_email) {
//       query = `SELECT id FROM vottery_users WHERE sngine_email = $1`;
//       params = [sngine_email];
//     } else if (sngine_phone) {
//       query = `SELECT id FROM vottery_users WHERE sngine_phone = $1`;
//       params = [sngine_phone];
//     } else {
//       throw new Error('Either email or phone is required');
//     }

//     console.log('Executing query:', query, 'with params:', params);

//     const userResult = await db.query(query, params);

//     if (userResult.rows.length === 0) {
//       throw new Error('User not found for given email/phone');
//     }

//     const userId = userResult.rows[0].id;
//     console.log('Found userId:', userId, 'Type:', typeof userId);

//     // Ensure userId is treated as integer, not UUID
//     return parseInt(userId);
//   } catch (error) {
//     console.error('getUserId error:', error);
//     throw error;
//   }
// }

//   // Register a new device
//   static async registerDevice(req, res) {
//     try {
//       const {
//         sngine_email,
//         sngine_phone,
//         deviceInfo,
//         location,
//         capabilities
//       } = req.body;

//       console.log('Register device request:', {
//         sngine_email,
//         sngine_phone,
//         deviceInfo
//       });

//       const ipAddress = req.ip || req.connection?.remoteAddress;
//       const userAgent = req.get('User-Agent');

//       // Get userId from email/phone
//       const userId = await BiometricController.getUserId(sngine_email, sngine_phone);
//       console.log('Resolved userId for device registration:', userId);

//       // Register device
//       const device = await DeviceService.registerDevice({
//         userId,
//         deviceInfo,
//         ipAddress,
//         userAgent,
//         location,
//         capabilities
//       });

//       logger.info(`Device registered successfully for user ${userId}: ${device.id}`);

//       res.status(201).json({
//         success: true,
//         message: 'Device registered successfully',
//         device: {
//           id: device.id,
//           fingerprint: device.device_fingerprint,
//           type: device.device_type,
//           capabilities: device.capabilities,
//           createdAt: device.created_at
//         }
//       });

//     } catch (error) {
//       logger.error('Device registration error:', error);
//       console.error('Full error details:', error);
      
//       if (error.message === 'User not found for given email/phone') {
//         return res.status(404).json({
//           success: false,
//           message: error.message
//         });
//       }

//       res.status(500).json({
//         success: false,
//         message: 'Device registration failed',
//         error: error.message
//       });
//     }
//   }

//   // Get user devices - now accepts email/phone instead of userId param
//   static async getUserDevices(req, res) {
//     try {
//       const { sngine_email, sngine_phone } = req.query;
      
//       // Validate that at least one identifier is provided
//       if (!sngine_email && !sngine_phone) {
//         return res.status(400).json({
//           success: false,
//           message: 'Either sngine_email or sngine_phone is required'
//         });
//       }

//       // Get userId from email/phone
//       const userId = await BiometricController.getUserId(sngine_email, sngine_phone);

//       const devices = await DeviceService.getUserDevices(userId);

//       res.json({
//         success: true,
//         devices: devices.map(device => ({
//           id: device.id,
//           fingerprint: device.device_fingerprint,
//           type: device.device_type,
//           os: device.os_name,
//           browser: device.browser_name,
//           lastUsed: device.last_used,
//           isActive: device.is_active,
//           capabilities: device.capabilities
//         }))
//       });

//     } catch (error) {
//       logger.error('Get user devices error:', error);
      
//       if (error.message === 'User not found for given email/phone') {
//         return res.status(404).json({
//           success: false,
//           message: error.message
//         });
//       }

//       res.status(500).json({
//         success: false,
//         message: 'Failed to fetch devices'
//       });
//     }
//   }

//   // Update device status
//   static async updateDeviceStatus(req, res) {
//     try {
//       const { deviceId } = req.params;
//       const { isActive } = req.body;

//       // Ensure deviceId is integer if your schema uses SERIAL
//       const parsedDeviceId = parseInt(deviceId);
//       if (!parsedDeviceId || !validateInput.isValidId(parsedDeviceId)) {
//         return res.status(400).json({
//           success: false,
//           message: 'Invalid device ID'
//         });
//       }

//       await DeviceService.updateDeviceStatus(parsedDeviceId, isActive);

//       res.json({
//         success: true,
//         message: 'Device status updated successfully'
//       });

//     } catch (error) {
//       logger.error('Update device status error:', error);
//       res.status(500).json({
//         success: false,
//         message: 'Failed to update device status'
//       });
//     }
//   }

//   // Register biometric data
//   static async registerBiometric(req, res) {
//     try {
//       const {
//         sngine_email,
//         sngine_phone,
//         deviceId,
//         biometricType,
//         biometricData,
//         publicKey,
//         credentialId
//       } = req.body;

//       console.log('Register biometric request:', {
//         sngine_email,
//         sngine_phone,
//         deviceId,
//         biometricType
//       });

//       // Register biometric (BiometricService handles userId lookup internally)
//       const biometric = await BiometricService.registerBiometric({
//         sngine_email,
//         sngine_phone,
//         deviceId: parseInt(deviceId), // Ensure deviceId is integer
//         biometricType,
//         biometricData,
//         publicKey,
//         credentialId
//       });

//       // Get userId for logging
//       const userId = await BiometricController.getUserId(sngine_email, sngine_phone);
      
//       logger.info(`Biometric registered for user ${userId}, device ${deviceId}`);

//       res.status(201).json({
//         success: true,
//         message: 'Biometric registered successfully',
//         biometric: {
//           id: biometric.id,
//           type: biometric.biometric_type,
//           deviceId: biometric.device_id,
//           createdAt: biometric.created_at
//         }
//       });

//     } catch (error) {
//       logger.error('Biometric registration error:', error);
      
//       if (error.message === 'User not found for given email/phone') {
//         return res.status(404).json({
//           success: false,
//           message: error.message
//         });
//       }

//       res.status(500).json({
//         success: false,
//         message: 'Biometric registration failed',
//         error: error.message
//       });
//     }
//   }

//   // Verify biometric data
//   static async verifyBiometric(req, res) {
//     try {
//       const {
//         sngine_email,
//         sngine_phone,
//         deviceId,
//         biometricType,
//         biometricData,
//         credentialId
//       } = req.body;

//       // Verify biometric (BiometricService handles userId lookup internally)
//       const verification = await BiometricService.verifyBiometric({
//         sngine_email,
//         sngine_phone,
//         deviceId: parseInt(deviceId), // Ensure deviceId is integer
//         biometricType,
//         biometricData,
//         credentialId
//       });

//       if (!verification.success) {
//         return res.status(400).json({
//           success: false,
//           message: verification.message
//         });
//       }

//       res.json({
//         success: true,
//         message: 'Biometric verification successful',
//         deviceId: verification.deviceId,
//         biometricId: verification.biometricId
//       });

//     } catch (error) {
//       logger.error('Biometric verification error:', error);
//       res.status(500).json({
//         success: false,
//         message: 'Biometric verification failed'
//       });
//     }
//   }

//   // Get user biometrics - now accepts email/phone instead of userId param
//   static async getUserBiometrics(req, res) {
//     try {
//       const { sngine_email, sngine_phone } = req.query;

//       // Validate that at least one identifier is provided
//       if (!sngine_email && !sngine_phone) {
//         return res.status(400).json({
//           success: false,
//           message: 'Either sngine_email or sngine_phone is required'
//         });
//       }

//       // Get userId from email/phone
//       const userId = await BiometricController.getUserId(sngine_email, sngine_phone);

//       const biometrics = await BiometricService.getUserBiometrics(userId);

//       res.json({
//         success: true,
//         biometrics: biometrics.map(bio => ({
//           id: bio.id,
//           type: bio.biometric_type,
//           deviceId: bio.device_id,
//           deviceType: bio.device_type,
//           isActive: bio.is_active,
//           createdAt: bio.created_at
//         }))
//       });

//     } catch (error) {
//       logger.error('Get user biometrics error:', error);
      
//       if (error.message === 'User not found for given email/phone') {
//         return res.status(404).json({
//           success: false,
//           message: error.message
//         });
//       }

//       res.status(500).json({
//         success: false,
//         message: 'Failed to fetch biometrics'
//       });
//     }
//   }

//   // Delete biometric
//   static async deleteBiometric(req, res) {
//     try {
//       const { biometricId } = req.params;

//       // Ensure biometricId is integer if your schema uses SERIAL
//       const parsedBiometricId = parseInt(biometricId);
//       if (!parsedBiometricId || !validateInput.isValidId(parsedBiometricId)) {
//         return res.status(400).json({
//           success: false,
//           message: 'Invalid biometric ID'
//         });
//       }

//       await BiometricService.deleteBiometric(parsedBiometricId);

//       res.json({
//         success: true,
//         message: 'Biometric deleted successfully'
//       });

//     } catch (error) {
//       logger.error('Delete biometric error:', error);
//       res.status(500).json({
//         success: false,
//         message: 'Failed to delete biometric'
//       });
//     }
//   }

//   // WebAuthn Registration - Begin
//   static async beginWebAuthnRegistration(req, res) {
//     try {
//       const { sngine_email, sngine_phone, deviceId } = req.body;

//       // Get userId from email/phone
//       const userId = await BiometricController.getUserId(sngine_email, sngine_phone);

//       const options = await WebAuthnService.beginRegistration(userId, parseInt(deviceId));

//       res.json({
//         success: true,
//         options
//       });

//     } catch (error) {
//       logger.error('WebAuthn registration begin error:', error);
      
//       if (error.message === 'User not found for given email/phone') {
//         return res.status(404).json({
//           success: false,
//           message: error.message
//         });
//       }

//       res.status(500).json({
//         success: false,
//         message: 'Failed to begin WebAuthn registration'
//       });
//     }
//   }

//   // WebAuthn Registration - Finish
//   static async finishWebAuthnRegistration(req, res) {
//     try {
//       const { sngine_email, sngine_phone, deviceId, credential } = req.body;

//       // Get userId from email/phone
//       const userId = await BiometricController.getUserId(sngine_email, sngine_phone);

//       const result = await WebAuthnService.finishRegistration(userId, parseInt(deviceId), credential);

//       if (!result.success) {
//         return res.status(400).json(result);
//       }

//       res.json(result);

//     } catch (error) {
//       logger.error('WebAuthn registration finish error:', error);
      
//       if (error.message === 'User not found for given email/phone') {
//         return res.status(404).json({
//           success: false,
//           message: error.message
//         });
//       }

//       res.status(500).json({
//         success: false,
//         message: 'Failed to finish WebAuthn registration'
//       });
//     }
//   }

//   // WebAuthn Authentication - Begin
//   static async beginWebAuthnAuthentication(req, res) {
//     try {
//       const { sngine_email, sngine_phone } = req.body;

//       // Get userId from email/phone
//       const userId = await BiometricController.getUserId(sngine_email, sngine_phone);

//       const options = await WebAuthnService.beginAuthentication(userId);

//       res.json({
//         success: true,
//         options
//       });

//     } catch (error) {
//       logger.error('WebAuthn authentication begin error:', error);
      
//       if (error.message === 'User not found for given email/phone') {
//         return res.status(404).json({
//           success: false,
//           message: error.message
//         });
//       }

//       res.status(500).json({
//         success: false,
//         message: 'Failed to begin WebAuthn authentication'
//       });
//     }
//   }

//   // WebAuthn Authentication - Finish
//   static async finishWebAuthnAuthentication(req, res) {
//     try {
//       const { sngine_email, sngine_phone, credential } = req.body;

//       // Get userId from email/phone
//       const userId = await BiometricController.getUserId(sngine_email, sngine_phone);

//       const result = await WebAuthnService.finishAuthentication(userId, credential);

//       if (!result.success) {
//         return res.status(400).json(result);
//       }

//       res.json(result);

//     } catch (error) {
//       logger.error('WebAuthn authentication finish error:', error);
      
//       if (error.message === 'User not found for given email/phone') {
//         return res.status(404).json({
//           success: false,
//           message: error.message
//         });
//       }

//       res.status(500).json({
//         success: false,
//         message: 'Failed to finish WebAuthn authentication'
//       });
//     }
//   }
// }