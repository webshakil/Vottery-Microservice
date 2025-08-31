// import { db } from '../config/database.js';
// import { EncryptionUtils } from '../utils/encryption.js';
// import { BiometricUtils } from '../utils/biometricUtils.js';
// import { logger } from '../utils/logger.js';

// export class BiometricService {
//   static async registerBiometric(biometricData) {
//     const {
//       userId,
//       deviceId,
//       biometricType,
//       biometricData: rawBiometricData,
//       publicKey,
//       credentialId
//     } = biometricData;

//     try {
//       // Hash the biometric data
//       const biometricHash = BiometricUtils.generateHash(rawBiometricData);
      
//       // Encrypt public key and credential ID if provided
//       const encryptedPublicKey = publicKey ? 
//         EncryptionUtils.encrypt(publicKey) : null;
//       const encryptedCredentialId = credentialId ? 
//         EncryptionUtils.encrypt(credentialId) : null;

//       // Check if biometric already exists for this user/device/type
//       const existing = await db.query(
//         `SELECT id FROM vottery_biometrics 
//          WHERE user_id = $1 AND device_id = $2 AND biometric_type = $3`,
//         [userId, deviceId, biometricType]
//       );

//       if (existing.rows.length > 0) {
//         // Update existing biometric
//         const result = await db.query(
//           `UPDATE vottery_biometrics 
//            SET biometric_hash = $1, public_key = $2, credential_id = $3,
//                updated_at = CURRENT_TIMESTAMP
//            WHERE user_id = $4 AND device_id = $5 AND biometric_type = $6
//            RETURNING *`,
//           [
//             biometricHash,
//             encryptedPublicKey,
//             encryptedCredentialId,
//             userId,
//             deviceId,
//             biometricType
//           ]
//         );

//         return result.rows[0];
//       }

//       // Register new biometric
//       const result = await db.query(
//         `INSERT INTO vottery_biometrics (
//           user_id, device_id, biometric_type, biometric_hash,
//           public_key, credential_id
//         ) VALUES ($1, $2, $3, $4, $5, $6)
//         RETURNING *`,
//         [
//           userId,
//           deviceId,
//           biometricType,
//           biometricHash,
//           encryptedPublicKey,
//           encryptedCredentialId
//         ]
//       );

//       logger.info(`Biometric registered: ${biometricType} for user ${userId}`);
      
//       return result.rows[0];

//     } catch (error) {
//       logger.error('Biometric registration error:', error);
//       throw new Error('Failed to register biometric');
//     }
//   }

//   static async verifyBiometric(verificationData) {
//     const {
//       userId,
//       deviceId,
//       biometricType,
//       biometricData: rawBiometricData,
//       credentialId
//     } = verificationData;

//     try {
//       // Get stored biometric
//       const result = await db.query(
//         `SELECT b.*, d.device_type 
//          FROM vottery_biometrics b
//          JOIN vottery_devices d ON b.device_id = d.id
//          WHERE b.user_id = $1 AND b.device_id = $2 AND b.biometric_type = $3 AND b.is_active = true`,
//         [userId, deviceId, biometricType]
//       );

//       if (result.rows.length === 0) {
//         return {
//           success: false,
//           message: 'Biometric not found or inactive'
//         };
//       }

//       const storedBiometric = result.rows[0];

//       // Verify biometric hash
//       const providedHash = BiometricUtils.generateHash(rawBiometricData);
//       const isHashValid = BiometricUtils.verifyHash(providedHash, storedBiometric.biometric_hash);

//       // Verify credential ID if provided (for WebAuthn)
//       let isCredentialValid = true;
//       if (credentialId && storedBiometric.credential_id) {
//         const storedCredentialId = EncryptionUtils.decrypt(storedBiometric.credential_id);
//         isCredentialValid = credentialId === storedCredentialId;
//       }

//       if (!isHashValid || !isCredentialValid) {
//         return {
//           success: false,
//           message: 'Biometric verification failed'
//         };
//       }

//       // Update last used timestamp
//       await db.query(
//         'UPDATE vottery_biometrics SET updated_at = CURRENT_TIMESTAMP WHERE id = $1',
//         [storedBiometric.id]
//       );

//       logger.info(`Biometric verification successful for user ${userId}`);

//       return {
//         success: true,
//         message: 'Biometric verification successful',
//         biometricId: storedBiometric.id,
//         deviceId: storedBiometric.device_id
//       };

//     } catch (error) {
//       logger.error('Biometric verification error:', error);
//       throw new Error('Failed to verify biometric');
//     }
//   }

//   static async getUserBiometrics(userId) {
//     try {
//       const result = await db.query(
//         `SELECT b.id, b.biometric_type, b.device_id, b.is_active, b.created_at,
//                 d.device_type
//          FROM vottery_biometrics b
//          JOIN vottery_devices d ON b.device_id = d.id
//          WHERE b.user_id = $1
//          ORDER BY b.created_at DESC`,
//         [userId]
//       );

//       return result.rows;

//     } catch (error) {
//       logger.error('Get user biometrics error:', error);
//       throw new Error('Failed to fetch user biometrics');
//     }
//   }

//   static async deleteBiometric(biometricId) {
//     try {
//       await db.query(
//         'DELETE FROM vottery_biometrics WHERE id = $1',
//         [biometricId]
//       );

//       logger.info(`Biometric deleted: ${biometricId}`);

//     } catch (error) {
//       logger.error('Delete biometric error:', error);
//       throw new Error('Failed to delete biometric');
//     }
//   }
// }


//find out user id based on email and phone
import { db } from '../config/database.js';
import { EncryptionUtils } from '../utils/encryption.js';
import { BiometricUtils } from '../utils/biometricUtils.js';
import { logger } from '../utils/logger.js';

export class BiometricService {
  static async registerBiometric(biometricData) {
    const {
      sngine_email,
      sngine_phone,
      deviceId,
      biometricType,
      biometricData: rawBiometricData,
      publicKey,
      credentialId
    } = biometricData;

    try {
      console.log('BiometricService.registerBiometric called with:', {
        sngine_email,
        sngine_phone,
        deviceId,
        biometricType
      });

      // Find userId based on sngine_email and sngine_phone
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

      const userResult = await db.query(query, params);

      if (userResult.rows.length === 0) {
        throw new Error('User not found for given email/phone');
      }

      // Handle mixed schema: user_id is INTEGER, device_id might be UUID
      const userId = parseInt(userResult.rows[0].id);
      
      console.log('Resolved userId:', userId, 'deviceId:', deviceId);
      console.log('UserId type:', typeof userId, 'DeviceId type:', typeof deviceId);

      // Validate userId as integer
      if (isNaN(userId)) {
        throw new Error(`Invalid userId format: ${userId}`);
      }

      // Helper function to convert integer to UUID for device_id
      const convertToUUID = (value) => {
        if (!value) return null;
        
        // If it's already a valid UUID format, return as is
        if (typeof value === 'string' && value.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
          return value;
        }
        
        // If it's an integer or string number, convert to deterministic UUID
        if (typeof value === 'number' || (typeof value === 'string' && !isNaN(value))) {
          const paddedValue = String(value).padStart(8, '0');
          return `00000000-0000-0000-0000-${paddedValue.padStart(12, '0')}`;
        }
        
        return value;
      };

      // Convert deviceId to UUID format for database operations
      const deviceUUID = convertToUUID(deviceId);
      
      console.log('Final userId:', userId, 'deviceUUID:', deviceUUID);

      // Hash the biometric data
      const biometricHash = BiometricUtils.generateHash(rawBiometricData);
      
      // Encrypt public key and credential ID if provided
      const encryptedPublicKey = publicKey ? 
        EncryptionUtils.encrypt(publicKey) : null;
      const encryptedCredentialId = credentialId ? 
        EncryptionUtils.encrypt(credentialId) : null;

      console.log('About to query with mixed types:', { userId, deviceUUID, biometricType });

      // Check if biometric already exists for this user/device/type
      const existing = await db.query(
        `SELECT id FROM vottery_biometrics 
         WHERE user_id = $1 AND device_id = $2 AND biometric_type = $3`,
        [userId, deviceUUID, biometricType]
      );

      if (existing.rows.length > 0) {
        console.log('Biometric exists, updating...');
        // Update existing biometric
        const result = await db.query(
          `UPDATE vottery_biometrics 
           SET biometric_hash = $1, public_key = $2, credential_id = $3,
               updated_at = CURRENT_TIMESTAMP
           WHERE user_id = $4 AND device_id = $5 AND biometric_type = $6
           RETURNING *`,
          [
            biometricHash,
            encryptedPublicKey,
            encryptedCredentialId,
            userId,
            deviceUUID,
            biometricType
          ]
        );

        return result.rows[0];
      }

      console.log('Creating new biometric with values:', {
        userId,
        deviceUUID,
        biometricType,
        biometricHashLength: biometricHash?.length
      });
      
      // Register new biometric
      const result = await db.query(
        `INSERT INTO vottery_biometrics (
          user_id, device_id, biometric_type, biometric_hash,
          public_key, credential_id
        ) VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *`,
        [
          userId,
          deviceUUID,
          biometricType,
          biometricHash,
          encryptedPublicKey,
          encryptedCredentialId
        ]
      );

      logger.info(`Biometric registered: ${biometricType} for user ${userId}`);
      
      return result.rows[0];

    } catch (error) {
      logger.error('Biometric registration error in service:', error);
      console.error('Full BiometricService error:', error);
      throw error;
    }
  }

  static async verifyBiometric(verificationData) {
    const {
      sngine_email,
      sngine_phone,
      deviceId,
      biometricType,
      biometricData: rawBiometricData,
      credentialId
    } = verificationData;

    try {
      // Find userId based on sngine_email and sngine_phone
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

      const userResult = await db.query(query, params);

      if (userResult.rows.length === 0) {
        return {
          success: false,
          message: 'User not found for given email/phone'
        };
      }

      const userId = parseInt(userResult.rows[0].id);

      // Helper function to convert integer to UUID for device_id (same as above)
      const convertToUUID = (value) => {
        if (!value) return null;
        
        if (typeof value === 'string' && value.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
          return value;
        }
        
        if (typeof value === 'number' || (typeof value === 'string' && !isNaN(value))) {
          const paddedValue = String(value).padStart(8, '0');
          return `00000000-0000-0000-0000-${paddedValue.padStart(12, '0')}`;
        }
        
        return value;
      };

      const deviceUUID = convertToUUID(deviceId);

      // Validate that we have valid values
      if (isNaN(userId)) {
        return {
          success: false,
          message: `Invalid userId format: ${userId}`
        };
      }

      // Get stored biometric
      const result = await db.query(
        `SELECT b.*, d.device_type 
         FROM vottery_biometrics b
         JOIN vottery_devices d ON b.device_id = d.id
         WHERE b.user_id = $1 AND b.device_id = $2 AND b.biometric_type = $3 AND b.is_active = true`,
        [userId, deviceUUID, biometricType]
      );

      if (result.rows.length === 0) {
        return {
          success: false,
          message: 'Biometric not found or inactive'
        };
      }

      const storedBiometric = result.rows[0];

      // Verify biometric hash
      const providedHash = BiometricUtils.generateHash(rawBiometricData);
      const isHashValid = BiometricUtils.verifyHash(providedHash, storedBiometric.biometric_hash);

      // Verify credential ID if provided (for WebAuthn)
      let isCredentialValid = true;
      if (credentialId && storedBiometric.credential_id) {
        const storedCredentialId = EncryptionUtils.decrypt(storedBiometric.credential_id);
        isCredentialValid = credentialId === storedCredentialId;
      }

      if (!isHashValid || !isCredentialValid) {
        return {
          success: false,
          message: 'Biometric verification failed'
        };
      }

      // Update last used timestamp
      await db.query(
        'UPDATE vottery_biometrics SET updated_at = CURRENT_TIMESTAMP WHERE id = $1',
        [storedBiometric.id]
      );

      logger.info(`Biometric verification successful for user ${userId}`);

      return {
        success: true,
        message: 'Biometric verification successful',
        biometricId: storedBiometric.id,
        deviceId: storedBiometric.device_id
      };

    } catch (error) {
      logger.error('Biometric verification error in service:', error);
      throw error;
    }
  }

  static async getUserBiometrics(userId) {
    try {
      const parsedUserId = parseInt(userId);
      
      // Validate that we have a valid integer
      if (isNaN(parsedUserId)) {
        throw new Error(`Invalid userId format: ${userId}`);
      }
      
      const result = await db.query(
        `SELECT b.id, b.biometric_type, b.device_id, b.is_active, b.created_at,
                d.device_type
         FROM vottery_biometrics b
         JOIN vottery_devices d ON b.device_id = d.id
         WHERE b.user_id = $1
         ORDER BY b.created_at DESC`,
        [parsedUserId]
      );

      return result.rows;

    } catch (error) {
      logger.error('Get user biometrics error in service:', error);
      throw error;
    }
  }

  static async deleteBiometric(biometricId) {
    try {
      const parsedBiometricId = parseInt(biometricId);
      
      // Validate that we have a valid integer
      if (isNaN(parsedBiometricId)) {
        throw new Error(`Invalid biometricId format: ${biometricId}`);
      }
      
      await db.query(
        'DELETE FROM vottery_biometrics WHERE id = $1',
        [parsedBiometricId]
      );

      logger.info(`Biometric deleted: ${parsedBiometricId}`);

    } catch (error) {
      logger.error('Delete biometric error in service:', error);
      throw error;
    }
  }
}


