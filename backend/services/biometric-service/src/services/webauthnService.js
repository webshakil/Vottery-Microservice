//FInal solution
import { generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { db } from '../config/database.js';
import { EncryptionUtils } from '../utils/encryption.js';
import { logger } from '../utils/logger.js';

const rpName = 'Vottery';
const rpID = process.env.RP_ID || 'localhost';
const origin = process.env.ORIGIN || 'http://localhost:3000';

// Helper function to convert userId to Uint8Array
const userIdToUint8Array = (userId) => {
  const userIdStr = userId.toString();
  const encoder = new TextEncoder();
  return encoder.encode(userIdStr);
};

export class WebAuthnService {
  static async beginRegistration({ sngine_email, sngine_phone, deviceId }) {
    try {
      logger.info(`WebAuthn registration begin for email: ${sngine_email}, phone: ${sngine_phone}, deviceId: ${deviceId}`);
      
      // Validate inputs
      if (!sngine_email && !sngine_phone) {
        throw new Error('Either email or phone must be provided');
      }

      // Find userId based on sngine_email and sngine_phone
      const userResult = await db.query(
        `SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2`,
        [sngine_email, sngine_phone]
      );

      if (userResult.rows.length === 0) {
        throw new Error('User not found for given email/phone');
      }

      const userId = userResult.rows[0].id;
      logger.info(`Found user ID: ${userId} for WebAuthn registration`);

      // Get existing credentials for this user
      const existingCredentials = await db.query(
        `SELECT credential_id FROM vottery_biometrics 
         WHERE user_id = $1 AND biometric_type = 'webauthn' AND is_active = true`,
        [userId]
      );

      const excludeCredentials = existingCredentials.rows.map(row => {
        try {
          const decryptedCredentialId = EncryptionUtils.decrypt(row.credential_id);
          return {
            id: Buffer.from(decryptedCredentialId, 'base64'),
            type: 'public-key'
          };
        } catch (error) {
          logger.warn(`Failed to decrypt credential ID for user ${userId}:`, error.message);
          return null;
        }
      }).filter(cred => cred !== null);

      logger.info(`Found ${excludeCredentials.length} existing credentials to exclude`);

      // Generate registration options with Uint8Array userID
      const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userID: userIdToUint8Array(userId), // Convert to Uint8Array
        userName: sngine_email || `phone-${sngine_phone}`,
        userDisplayName: sngine_email || `User ${sngine_phone}`,
        attestationType: 'none',
        excludeCredentials,
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required'
        },
        supportedAlgorithmIDs: [-7, -257] // ES256 and RS256
      });

      logger.info(`Generated WebAuthn registration options for user ${userId}`);

      // Store challenge temporarily
      await db.query(
        `INSERT INTO vottery_webauthn_challenges (user_id, device_id, challenge, expires_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, device_id) 
         DO UPDATE SET challenge = $3, expires_at = $4`,
        [
          userId,
          deviceId,
          options.challenge,
          new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
        ]
      );

      logger.info(`Stored WebAuthn challenge for user ${userId}, device ${deviceId}`);
      return options;

    } catch (error) {
      logger.error('WebAuthn begin registration error:', {
        message: error.message,
        stack: error.stack,
        sngine_email,
        sngine_phone,
        deviceId
      });
      throw new Error(`Failed to begin WebAuthn registration: ${error.message}`);
    }
  }

  static async finishRegistration({ sngine_email, sngine_phone, deviceId, credential }) {
    try {
      logger.info(`WebAuthn registration finish for email: ${sngine_email}, phone: ${sngine_phone}, deviceId: ${deviceId}`);
      
      // Validate inputs
      if (!credential) {
        return { success: false, message: 'No credential provided' };
      }

      // Find userId
      const userResult = await db.query(
        `SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2`,
        [sngine_email, sngine_phone]
      );

      if (userResult.rows.length === 0) {
        return { success: false, message: 'User not found for given email/phone' };
      }

      const userId = userResult.rows[0].id;

      // Get stored challenge
      const challengeResult = await db.query(
        `SELECT challenge FROM vottery_webauthn_challenges 
         WHERE user_id = $1 AND device_id = $2 AND expires_at > NOW()`,
        [userId, deviceId]
      );

      if (challengeResult.rows.length === 0) {
        return {
          success: false,
          message: 'Invalid or expired challenge'
        };
      }

      const expectedChallenge = challengeResult.rows[0].challenge;
      logger.info(`Found valid challenge for user ${userId}, device ${deviceId}`);

      // Verify registration response
      const verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: true
      });

      if (!verification.verified) {
        logger.warn(`WebAuthn registration verification failed for user ${userId}`);
        return {
          success: false,
          message: 'Registration verification failed'
        };
      }

      // Store the credential
      const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
      
      if (!credentialID || !credentialPublicKey) {
        throw new Error('Missing credential information from verification');
      }

      logger.info(`WebAuthn verification successful for user ${userId}, storing credential`);

      await db.query(
        `INSERT INTO vottery_biometrics (
          user_id, device_id, biometric_type, biometric_hash,
          public_key, credential_id, counter, created_at
        ) VALUES ($1, $2, 'webauthn', $3, $4, $5, $6, NOW())`,
        [
          userId,
          deviceId,
          EncryptionUtils.generateHash(Buffer.from(credentialID).toString('base64')),
          EncryptionUtils.encrypt(Buffer.from(credentialPublicKey).toString('base64')),
          EncryptionUtils.encrypt(Buffer.from(credentialID).toString('base64')),
          counter || 0
        ]
      );

      // Clean up challenge
      await db.query(
        'DELETE FROM vottery_webauthn_challenges WHERE user_id = $1 AND device_id = $2',
        [userId, deviceId]
      );

      logger.info(`WebAuthn registration completed successfully for user ${userId}`);
      
      return {
        success: true,
        message: 'WebAuthn registration successful'
      };

    } catch (error) {
      logger.error('WebAuthn finish registration error:', {
        message: error.message,
        stack: error.stack,
        sngine_email,
        sngine_phone,
        deviceId
      });
      return {
        success: false,
        message: `Registration failed: ${error.message}`
      };
    }
  }

  static async beginAuthentication({ sngine_email, sngine_phone }) {
    try {
      logger.info(`WebAuthn authentication begin for email: ${sngine_email}, phone: ${sngine_phone}`);
      
      // Find userId
      const userResult = await db.query(
        `SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2`,
        [sngine_email, sngine_phone]
      );

      if (userResult.rows.length === 0) {
        throw new Error('User not found for given email/phone');
      }

      const userId = userResult.rows[0].id;

      // Get user's credentials
      const credentialsResult = await db.query(
        `SELECT credential_id FROM vottery_biometrics 
         WHERE user_id = $1 AND biometric_type = 'webauthn' AND is_active = true`,
        [userId]
      );

      if (credentialsResult.rows.length === 0) {
        throw new Error('No WebAuthn credentials found for user');
      }

      const allowCredentials = credentialsResult.rows.map(row => {
        try {
          const decryptedCredentialId = EncryptionUtils.decrypt(row.credential_id);
          return {
            id: Buffer.from(decryptedCredentialId, 'base64'),
            type: 'public-key'
          };
        } catch (error) {
          logger.warn(`Failed to decrypt credential ID for user ${userId}:`, error.message);
          return null;
        }
      }).filter(cred => cred !== null);

      if (allowCredentials.length === 0) {
        throw new Error('No valid credentials found for user');
      }

      const options = await generateAuthenticationOptions({
        rpID,
        allowCredentials,
        userVerification: 'required'
      });

      // Store challenge with device_id = 0 for authentication
      await db.query(
        `INSERT INTO vottery_webauthn_challenges (user_id, device_id, challenge, expires_at)
         VALUES ($1, 0, $2, $3)
         ON CONFLICT (user_id, device_id)
         DO UPDATE SET challenge = $2, expires_at = $3`,
        [
          userId,
          options.challenge,
          new Date(Date.now() + 5 * 60 * 1000)
        ]
      );

      logger.info(`Generated WebAuthn authentication options for user ${userId}`);
      return options;

    } catch (error) {
      logger.error('WebAuthn begin authentication error:', {
        message: error.message,
        stack: error.stack,
        sngine_email,
        sngine_phone
      });
      throw new Error(`Failed to begin WebAuthn authentication: ${error.message}`);
    }
  }

  static async finishAuthentication({ sngine_email, sngine_phone, credential }) {
    try {
      logger.info(`WebAuthn authentication finish for email: ${sngine_email}, phone: ${sngine_phone}`);
      
      if (!credential) {
        return { success: false, message: 'No credential provided' };
      }

      // Find userId
      const userResult = await db.query(
        `SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2`,
        [sngine_email, sngine_phone]
      );

      if (userResult.rows.length === 0) {
        return { success: false, message: 'User not found for given email/phone' };
      }

      const userId = userResult.rows[0].id;

      // Get challenge
      const challengeResult = await db.query(
        `SELECT challenge FROM vottery_webauthn_challenges 
         WHERE user_id = $1 AND device_id = 0 AND expires_at > NOW()`,
        [userId]
      );

      if (challengeResult.rows.length === 0) {
        return {
          success: false,
          message: 'Invalid or expired challenge'
        };
      }

      // Get credential by matching the rawId from the response
      const credentialId = Buffer.from(credential.rawId, 'base64').toString('base64');
      
      const credentialResult = await db.query(
        `SELECT public_key, credential_id, counter FROM vottery_biometrics 
         WHERE user_id = $1 AND biometric_type = 'webauthn' AND is_active = true`,
        [userId]
      );

      if (credentialResult.rows.length === 0) {
        return {
          success: false,
          message: 'No WebAuthn credentials found'
        };
      }

      // Find matching credential
      let storedCredential = null;
      for (const row of credentialResult.rows) {
        try {
          const decryptedCredentialId = EncryptionUtils.decrypt(row.credential_id);
          if (decryptedCredentialId === credentialId) {
            storedCredential = row;
            break;
          }
        } catch (error) {
          logger.warn(`Failed to decrypt credential ID: ${error.message}`);
        }
      }

      if (!storedCredential) {
        return {
          success: false,
          message: 'Matching credential not found'
        };
      }

      const expectedChallenge = challengeResult.rows[0].challenge;

      const verification = await verifyAuthenticationResponse({
        response: credential,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        authenticator: {
          credentialID: Buffer.from(EncryptionUtils.decrypt(storedCredential.credential_id), 'base64'),
          credentialPublicKey: Buffer.from(EncryptionUtils.decrypt(storedCredential.public_key), 'base64'),
          counter: storedCredential.counter || 0
        },
        requireUserVerification: true
      });

      if (!verification.verified) {
        logger.warn(`WebAuthn authentication verification failed for user ${userId}`);
        return {
          success: false,
          message: 'Authentication verification failed'
        };
      }

      // Update counter if provided
      if (verification.authenticationInfo && verification.authenticationInfo.newCounter !== undefined) {
        await db.query(
          `UPDATE vottery_biometrics 
           SET counter = $1, last_used_at = NOW() 
           WHERE user_id = $2 AND credential_id = $3`,
          [
            verification.authenticationInfo.newCounter,
            userId,
            storedCredential.credential_id
          ]
        );
      }

      // Clean up challenge
      await db.query(
        'DELETE FROM vottery_webauthn_challenges WHERE user_id = $1 AND device_id = 0',
        [userId]
      );

      logger.info(`WebAuthn authentication successful for user ${userId}`);
      
      return {
        success: true,
        message: 'WebAuthn authentication successful'
      };

    } catch (error) {
      logger.error('WebAuthn finish authentication error:', {
        message: error.message,
        stack: error.stack,
        sngine_email,
        sngine_phone
      });
      return {
        success: false,
        message: `Authentication failed: ${error.message}`
      };
    }
  }
}
//to solve last problem webauthn
// import { generateRegistrationOptions, verifyRegistrationResponse,
//   generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
// import { db } from '../config/database.js';
// import { EncryptionUtils } from '../utils/encryption.js';
// import { logger } from '../utils/logger.js';

// const rpName = 'Vottery';
// const rpID = process.env.RP_ID || 'localhost';
// const origin = process.env.ORIGIN || 'http://localhost:3000';

// export class WebAuthnService {
//   static async beginRegistration({ sngine_email, sngine_phone, deviceId }) {
//     try {
//       logger.info(`WebAuthn registration begin for email: ${sngine_email}, phone: ${sngine_phone}, deviceId: ${deviceId}`);
      
//       // Validate inputs
//       if (!sngine_email && !sngine_phone) {
//         throw new Error('Either email or phone must be provided');
//       }

//       // Find userId based on sngine_email and sngine_phone
//       const userResult = await db.query(
//         `SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2`,
//         [sngine_email, sngine_phone]
//       );

//       if (userResult.rows.length === 0) {
//         throw new Error('User not found for given email/phone');
//       }

//       const userId = userResult.rows[0].id;
//       logger.info(`Found user ID: ${userId} for WebAuthn registration`);

//       // Get existing credentials for this user
//       const existingCredentials = await db.query(
//         `SELECT credential_id FROM vottery_biometrics 
//          WHERE user_id = $1 AND biometric_type = 'webauthn' AND is_active = true`,
//         [userId]
//       );

//       const excludeCredentials = existingCredentials.rows.map(row => {
//         try {
//           const decryptedCredentialId = EncryptionUtils.decrypt(row.credential_id);
//           return {
//             id: Buffer.from(decryptedCredentialId, 'base64'),
//             type: 'public-key'
//           };
//         } catch (error) {
//           logger.warn(`Failed to decrypt credential ID for user ${userId}:`, error.message);
//           return null;
//         }
//       }).filter(cred => cred !== null);

//       logger.info(`Found ${excludeCredentials.length} existing credentials to exclude`);

//       // Generate registration options
//       const options = await generateRegistrationOptions({
//         rpName,
//         rpID,
//         userID: userId.toString(),
//         userName: sngine_email || `phone-${sngine_phone}`,
//         userDisplayName: sngine_email || `User ${sngine_phone}`,
//         attestationType: 'none',
//         excludeCredentials,
//         authenticatorSelection: {
//           authenticatorAttachment: 'platform',
//           userVerification: 'required'
//         },
//         supportedAlgorithmIDs: [-7, -257] // ES256 and RS256
//       });

//       logger.info(`Generated WebAuthn registration options for user ${userId}`);

//       // Store challenge temporarily
//       await db.query(
//         `INSERT INTO vottery_webauthn_challenges (user_id, device_id, challenge, expires_at)
//          VALUES ($1, $2, $3, $4)
//          ON CONFLICT (user_id, device_id) 
//          DO UPDATE SET challenge = $3, expires_at = $4`,
//         [
//           userId,
//           deviceId,
//           options.challenge,
//           new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
//         ]
//       );

//       logger.info(`Stored WebAuthn challenge for user ${userId}, device ${deviceId}`);
//       return options;

//     } catch (error) {
//       logger.error('WebAuthn begin registration error:', {
//         message: error.message,
//         stack: error.stack,
//         sngine_email,
//         sngine_phone,
//         deviceId
//       });
//       throw new Error(`Failed to begin WebAuthn registration: ${error.message}`);
//     }
//   }

//   static async finishRegistration({ sngine_email, sngine_phone, deviceId, credential }) {
//     try {
//       logger.info(`WebAuthn registration finish for email: ${sngine_email}, phone: ${sngine_phone}, deviceId: ${deviceId}`);
      
//       // Validate inputs
//       if (!credential) {
//         return { success: false, message: 'No credential provided' };
//       }

//       // Find userId
//       const userResult = await db.query(
//         `SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2`,
//         [sngine_email, sngine_phone]
//       );

//       if (userResult.rows.length === 0) {
//         return { success: false, message: 'User not found for given email/phone' };
//       }

//       const userId = userResult.rows[0].id;

//       // Get stored challenge
//       const challengeResult = await db.query(
//         `SELECT challenge FROM vottery_webauthn_challenges 
//          WHERE user_id = $1 AND device_id = $2 AND expires_at > NOW()`,
//         [userId, deviceId]
//       );

//       if (challengeResult.rows.length === 0) {
//         return {
//           success: false,
//           message: 'Invalid or expired challenge'
//         };
//       }

//       const expectedChallenge = challengeResult.rows[0].challenge;
//       logger.info(`Found valid challenge for user ${userId}, device ${deviceId}`);

//       // Verify registration response
//       const verification = await verifyRegistrationResponse({
//         response: credential,
//         expectedChallenge,
//         expectedOrigin: origin,
//         expectedRPID: rpID,
//         requireUserVerification: true
//       });

//       if (!verification.verified) {
//         logger.warn(`WebAuthn registration verification failed for user ${userId}`);
//         return {
//           success: false,
//           message: 'Registration verification failed'
//         };
//       }

//       // Store the credential
//       const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
      
//       if (!credentialID || !credentialPublicKey) {
//         throw new Error('Missing credential information from verification');
//       }

//       logger.info(`WebAuthn verification successful for user ${userId}, storing credential`);

//       await db.query(
//         `INSERT INTO vottery_biometrics (
//           user_id, device_id, biometric_type, biometric_hash,
//           public_key, credential_id, counter, created_at
//         ) VALUES ($1, $2, 'webauthn', $3, $4, $5, $6, NOW())`,
//         [
//           userId,
//           deviceId,
//           EncryptionUtils.generateHash(Buffer.from(credentialID).toString('base64')),
//           EncryptionUtils.encrypt(Buffer.from(credentialPublicKey).toString('base64')),
//           EncryptionUtils.encrypt(Buffer.from(credentialID).toString('base64')),
//           counter || 0
//         ]
//       );

//       // Clean up challenge
//       await db.query(
//         'DELETE FROM vottery_webauthn_challenges WHERE user_id = $1 AND device_id = $2',
//         [userId, deviceId]
//       );

//       logger.info(`WebAuthn registration completed successfully for user ${userId}`);
      
//       return {
//         success: true,
//         message: 'WebAuthn registration successful'
//       };

//     } catch (error) {
//       logger.error('WebAuthn finish registration error:', {
//         message: error.message,
//         stack: error.stack,
//         sngine_email,
//         sngine_phone,
//         deviceId
//       });
//       return {
//         success: false,
//         message: `Registration failed: ${error.message}`
//       };
//     }
//   }

//   static async beginAuthentication({ sngine_email, sngine_phone }) {
//     try {
//       logger.info(`WebAuthn authentication begin for email: ${sngine_email}, phone: ${sngine_phone}`);
      
//       // Find userId
//       const userResult = await db.query(
//         `SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2`,
//         [sngine_email, sngine_phone]
//       );

//       if (userResult.rows.length === 0) {
//         throw new Error('User not found for given email/phone');
//       }

//       const userId = userResult.rows[0].id;

//       // Get user's credentials
//       const credentialsResult = await db.query(
//         `SELECT credential_id FROM vottery_biometrics 
//          WHERE user_id = $1 AND biometric_type = 'webauthn' AND is_active = true`,
//         [userId]
//       );

//       if (credentialsResult.rows.length === 0) {
//         throw new Error('No WebAuthn credentials found for user');
//       }

//       const allowCredentials = credentialsResult.rows.map(row => {
//         try {
//           const decryptedCredentialId = EncryptionUtils.decrypt(row.credential_id);
//           return {
//             id: Buffer.from(decryptedCredentialId, 'base64'),
//             type: 'public-key'
//           };
//         } catch (error) {
//           logger.warn(`Failed to decrypt credential ID for user ${userId}:`, error.message);
//           return null;
//         }
//       }).filter(cred => cred !== null);

//       if (allowCredentials.length === 0) {
//         throw new Error('No valid credentials found for user');
//       }

//       const options = await generateAuthenticationOptions({
//         rpID,
//         allowCredentials,
//         userVerification: 'required'
//       });

//       // Store challenge with device_id = 0 for authentication
//       await db.query(
//         `INSERT INTO vottery_webauthn_challenges (user_id, device_id, challenge, expires_at)
//          VALUES ($1, 0, $2, $3)
//          ON CONFLICT (user_id, device_id)
//          DO UPDATE SET challenge = $2, expires_at = $3`,
//         [
//           userId,
//           options.challenge,
//           new Date(Date.now() + 5 * 60 * 1000)
//         ]
//       );

//       logger.info(`Generated WebAuthn authentication options for user ${userId}`);
//       return options;

//     } catch (error) {
//       logger.error('WebAuthn begin authentication error:', {
//         message: error.message,
//         stack: error.stack,
//         sngine_email,
//         sngine_phone
//       });
//       throw new Error(`Failed to begin WebAuthn authentication: ${error.message}`);
//     }
//   }

//   static async finishAuthentication({ sngine_email, sngine_phone, credential }) {
//     try {
//       logger.info(`WebAuthn authentication finish for email: ${sngine_email}, phone: ${sngine_phone}`);
      
//       if (!credential) {
//         return { success: false, message: 'No credential provided' };
//       }

//       // Find userId
//       const userResult = await db.query(
//         `SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2`,
//         [sngine_email, sngine_phone]
//       );

//       if (userResult.rows.length === 0) {
//         return { success: false, message: 'User not found for given email/phone' };
//       }

//       const userId = userResult.rows[0].id;

//       // Get challenge
//       const challengeResult = await db.query(
//         `SELECT challenge FROM vottery_webauthn_challenges 
//          WHERE user_id = $1 AND device_id = 0 AND expires_at > NOW()`,
//         [userId]
//       );

//       if (challengeResult.rows.length === 0) {
//         return {
//           success: false,
//           message: 'Invalid or expired challenge'
//         };
//       }

//       // Get credential by matching the rawId from the response
//       const credentialId = Buffer.from(credential.rawId, 'base64').toString('base64');
      
//       const credentialResult = await db.query(
//         `SELECT public_key, credential_id, counter FROM vottery_biometrics 
//          WHERE user_id = $1 AND biometric_type = 'webauthn' AND is_active = true`,
//         [userId]
//       );

//       if (credentialResult.rows.length === 0) {
//         return {
//           success: false,
//           message: 'No WebAuthn credentials found'
//         };
//       }

//       // Find matching credential
//       let storedCredential = null;
//       for (const row of credentialResult.rows) {
//         try {
//           const decryptedCredentialId = EncryptionUtils.decrypt(row.credential_id);
//           if (decryptedCredentialId === credentialId) {
//             storedCredential = row;
//             break;
//           }
//         } catch (error) {
//           logger.warn(`Failed to decrypt credential ID: ${error.message}`);
//         }
//       }

//       if (!storedCredential) {
//         return {
//           success: false,
//           message: 'Matching credential not found'
//         };
//       }

//       const expectedChallenge = challengeResult.rows[0].challenge;

//       const verification = await verifyAuthenticationResponse({
//         response: credential,
//         expectedChallenge,
//         expectedOrigin: origin,
//         expectedRPID: rpID,
//         authenticator: {
//           credentialID: Buffer.from(EncryptionUtils.decrypt(storedCredential.credential_id), 'base64'),
//           credentialPublicKey: Buffer.from(EncryptionUtils.decrypt(storedCredential.public_key), 'base64'),
//           counter: storedCredential.counter || 0
//         },
//         requireUserVerification: true
//       });

//       if (!verification.verified) {
//         logger.warn(`WebAuthn authentication verification failed for user ${userId}`);
//         return {
//           success: false,
//           message: 'Authentication verification failed'
//         };
//       }

//       // Update counter if provided
//       if (verification.authenticationInfo && verification.authenticationInfo.newCounter !== undefined) {
//         await db.query(
//           `UPDATE vottery_biometrics 
//            SET counter = $1, last_used_at = NOW() 
//            WHERE user_id = $2 AND credential_id = $3`,
//           [
//             verification.authenticationInfo.newCounter,
//             userId,
//             storedCredential.credential_id
//           ]
//         );
//       }

//       // Clean up challenge
//       await db.query(
//         'DELETE FROM vottery_webauthn_challenges WHERE user_id = $1 AND device_id = 0',
//         [userId]
//       );

//       logger.info(`WebAuthn authentication successful for user ${userId}`);
      
//       return {
//         success: true,
//         message: 'WebAuthn authentication successful'
//       };

//     } catch (error) {
//       logger.error('WebAuthn finish authentication error:', {
//         message: error.message,
//         stack: error.stack,
//         sngine_email,
//         sngine_phone
//       });
//       return {
//         success: false,
//         message: `Authentication failed: ${error.message}`
//       };
//     }
//   }
// }
// import { generateRegistrationOptions, verifyRegistrationResponse,
//     generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
// import { db } from '../config/database.js';
// import { EncryptionUtils } from '../utils/encryption.js';
// import { logger } from '../utils/logger.js';

// const rpName = 'Vottery';
// const rpID = process.env.RP_ID || 'localhost';
// const origin = process.env.ORIGIN || 'http://localhost:3000';

// export class WebAuthnService {
// static async beginRegistration(userId, deviceId) {
// try {
//  // Get existing credentials for this user
//  const existingCredentials = await db.query(
//    `SELECT credential_id FROM vottery_biometrics 
//     WHERE user_id = $1 AND biometric_type = 'webauthn' AND is_active = true`,
//    [userId]
//  );

//  const excludeCredentials = existingCredentials.rows.map(row => ({
//    id: Buffer.from(EncryptionUtils.decrypt(row.credential_id), 'base64'),
//    type: 'public-key'
//  }));

//  const options = await generateRegistrationOptions({
//    rpName,
//    rpID,
//    userID: userId.toString(),
//    userName: `user-${userId}`,
//    userDisplayName: `User ${userId}`,
//    attestationType: 'none',
//    excludeCredentials,
//    authenticatorSelection: {
//      authenticatorAttachment: 'platform',
//      userVerification: 'required'
//    }
//  });

//  // Store challenge temporarily
//  await db.query(
//    `INSERT INTO vottery_webauthn_challenges (user_id, device_id, challenge, expires_at)
//     VALUES ($1, $2, $3, $4)
//     ON CONFLICT (user_id, device_id) 
//     DO UPDATE SET challenge = $3, expires_at = $4`,
//    [
//      userId,
//      deviceId,
//      options.challenge,
//      new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
//    ]
//  );

//  return options;

// } catch (error) {
//  logger.error('WebAuthn begin registration error:', error);
//  throw new Error('Failed to begin WebAuthn registration');
// }
// }

// static async finishRegistration(userId, deviceId, credential) {
// try {
//  // Get stored challenge
//  const challengeResult = await db.query(
//    `SELECT challenge FROM vottery_webauthn_challenges 
//     WHERE user_id = $1 AND device_id = $2 AND expires_at > NOW()`,
//    [userId, deviceId]
//  );

//  if (challengeResult.rows.length === 0) {
//    return {
//      success: false,
//      message: 'Invalid or expired challenge'
//    };
//  }

//  const expectedChallenge = challengeResult.rows[0].challenge;

//  const verification = await verifyRegistrationResponse({
//    response: credential,
//    expectedChallenge,
//    expectedOrigin: origin,
//    expectedRPID: rpID
//  });

//  if (!verification.verified) {
//    return {
//      success: false,
//      message: 'Registration verification failed'
//    };
//  }

//  // Store the credential
//  const { credentialID, credentialPublicKey } = verification.registrationInfo;
 
//  await db.query(
//    `INSERT INTO vottery_biometrics (
//      user_id, device_id, biometric_type, biometric_hash,
//      public_key, credential_id
//    ) VALUES ($1, $2, 'webauthn', $3, $4, $5)`,
//    [
//      userId,
//      deviceId,
//      EncryptionUtils.generateHash(credentialID.toString()),
//      EncryptionUtils.encrypt(Buffer.from(credentialPublicKey).toString('base64')),
//      EncryptionUtils.encrypt(Buffer.from(credentialID).toString('base64'))
//    ]
//  );

//  // Clean up challenge
//  await db.query(
//    'DELETE FROM vottery_webauthn_challenges WHERE user_id = $1 AND device_id = $2',
//    [userId, deviceId]
//  );

//  return {
//    success: true,
//    message: 'WebAuthn registration successful'
//  };

// } catch (error) {
//  logger.error('WebAuthn finish registration error:', error);
//  throw new Error('Failed to finish WebAuthn registration');
// }
// }

// static async beginAuthentication(userId) {
// try {
//  // Get user's credentials
//  const credentialsResult = await db.query(
//    `SELECT credential_id, public_key FROM vottery_biometrics 
//     WHERE user_id = $1 AND biometric_type = 'webauthn' AND is_active = true`,
//    [userId]
//  );

//  const allowCredentials = credentialsResult.rows.map(row => ({
//    id: Buffer.from(EncryptionUtils.decrypt(row.credential_id), 'base64'),
//    type: 'public-key'
//  }));

//  const options = await generateAuthenticationOptions({
//    rpID,
//    allowCredentials,
//    userVerification: 'required'
//  });

//  // Store challenge
//  await db.query(
//    `INSERT INTO vottery_webauthn_challenges (user_id, device_id, challenge, expires_at)
//     VALUES ($1, 0, $2, $3)
//     ON CONFLICT (user_id, device_id)
//     DO UPDATE SET challenge = $2, expires_at = $3`,
//    [
//      userId,
//      options.challenge,
//      new Date(Date.now() + 5 * 60 * 1000)
//    ]
//  );

//  return options;

// } catch (error) {
//  logger.error('WebAuthn begin authentication error:', error);
//  throw new Error('Failed to begin WebAuthn authentication');
// }
// }

// static async finishAuthentication(userId, credential) {
// try {
//  // Get challenge
//  const challengeResult = await db.query(
//    `SELECT challenge FROM vottery_webauthn_challenges 
//     WHERE user_id = $1 AND device_id = 0 AND expires_at > NOW()`,
//    [userId]
//  );

//  if (challengeResult.rows.length === 0) {
//    return {
//      success: false,
//      message: 'Invalid or expired challenge'
//    };
//  }

//  // Get credential
//  const credentialResult = await db.query(
//    `SELECT public_key, credential_id FROM vottery_biometrics 
//     WHERE user_id = $1 AND biometric_type = 'webauthn' AND is_active = true`,
//    [userId]
//  );

//  if (credentialResult.rows.length === 0) {
//    return {
//      success: false,
//      message: 'No WebAuthn credentials found'
//    };
//  }

//  const storedCredential = credentialResult.rows[0];
//  const expectedChallenge = challengeResult.rows[0].challenge;

//  const verification = await verifyAuthenticationResponse({
//    response: credential,
//    expectedChallenge,
//    expectedOrigin: origin,
//    expectedRPID: rpID,
//    authenticator: {
//      credentialID: Buffer.from(EncryptionUtils.decrypt(storedCredential.credential_id), 'base64'),
//      credentialPublicKey: Buffer.from(EncryptionUtils.decrypt(storedCredential.public_key), 'base64')
//    }
//  });

//  if (!verification.verified) {
//    return {
//      success: false,
//      message: 'Authentication verification failed'
//    };
//  }

//  // Clean up challenge
//  await db.query(
//    'DELETE FROM vottery_webauthn_challenges WHERE user_id = $1 AND device_id = 0',
//    [userId]
//  );

//  return {
//    success: true,
//    message: 'WebAuthn authentication successful'
//  };

// } catch (error) {
//  logger.error('WebAuthn finish authentication error:', error);
//  throw new Error('Failed to finish WebAuthn authentication');
// }
// }
// }


//find out userId based on email and phone

// import { generateRegistrationOptions, verifyRegistrationResponse,
//   generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
// import { db } from '../config/database.js';
// import { EncryptionUtils } from '../utils/encryption.js';
// import { logger } from '../utils/logger.js';

// const rpName = 'Vottery';
// const rpID = process.env.RP_ID || 'localhost';
// const origin = process.env.ORIGIN || 'http://localhost:3000';

// export class WebAuthnService {
// static async beginRegistration({ sngine_email, sngine_phone, deviceId }) {
// try {
// // Find userId based on sngine_email and sngine_phone
// const userResult = await db.query(
//  `SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2`,
//  [sngine_email, sngine_phone]
// );

// if (userResult.rows.length === 0) {
//  throw new Error('User not found for given email/phone');
// }

// const userId = userResult.rows[0].id;

// // Get existing credentials for this user
// const existingCredentials = await db.query(
//  `SELECT credential_id FROM vottery_biometrics 
//   WHERE user_id = $1 AND biometric_type = 'webauthn' AND is_active = true`,
//  [userId]
// );

// const excludeCredentials = existingCredentials.rows.map(row => ({
//  id: Buffer.from(EncryptionUtils.decrypt(row.credential_id), 'base64'),
//  type: 'public-key'
// }));

// const options = await generateRegistrationOptions({
//  rpName,
//  rpID,
//  userID: userId.toString(),
//  userName: `user-${userId}`,
//  userDisplayName: `User ${userId}`,
//  attestationType: 'none',
//  excludeCredentials,
//  authenticatorSelection: {
//    authenticatorAttachment: 'platform',
//    userVerification: 'required'
//  }
// });

// // Store challenge temporarily
// await db.query(
//  `INSERT INTO vottery_webauthn_challenges (user_id, device_id, challenge, expires_at)
//   VALUES ($1, $2, $3, $4)
//   ON CONFLICT (user_id, device_id) 
//   DO UPDATE SET challenge = $3, expires_at = $4`,
//  [
//    userId,
//    deviceId,
//    options.challenge,
//    new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
//  ]
// );

// return options;

// } catch (error) {
// logger.error('WebAuthn begin registration error:', error);
// throw new Error('Failed to begin WebAuthn registration');
// }
// }

// static async finishRegistration({ sngine_email, sngine_phone, deviceId, credential }) {
// try {
// // Find userId
// const userResult = await db.query(
//  `SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2`,
//  [sngine_email, sngine_phone]
// );

// if (userResult.rows.length === 0) {
//  return { success: false, message: 'User not found for given email/phone' };
// }

// const userId = userResult.rows[0].id;

// // Get stored challenge
// const challengeResult = await db.query(
//  `SELECT challenge FROM vottery_webauthn_challenges 
//   WHERE user_id = $1 AND device_id = $2 AND expires_at > NOW()`,
//  [userId, deviceId]
// );

// if (challengeResult.rows.length === 0) {
//  return {
//    success: false,
//    message: 'Invalid or expired challenge'
//  };
// }

// const expectedChallenge = challengeResult.rows[0].challenge;

// const verification = await verifyRegistrationResponse({
//  response: credential,
//  expectedChallenge,
//  expectedOrigin: origin,
//  expectedRPID: rpID
// });

// if (!verification.verified) {
//  return {
//    success: false,
//    message: 'Registration verification failed'
//  };
// }

// // Store the credential
// const { credentialID, credentialPublicKey } = verification.registrationInfo;

// await db.query(
//  `INSERT INTO vottery_biometrics (
//    user_id, device_id, biometric_type, biometric_hash,
//    public_key, credential_id
//  ) VALUES ($1, $2, 'webauthn', $3, $4, $5)`,
//  [
//    userId,
//    deviceId,
//    EncryptionUtils.generateHash(credentialID.toString()),
//    EncryptionUtils.encrypt(Buffer.from(credentialPublicKey).toString('base64')),
//    EncryptionUtils.encrypt(Buffer.from(credentialID).toString('base64'))
//  ]
// );

// // Clean up challenge
// await db.query(
//  'DELETE FROM vottery_webauthn_challenges WHERE user_id = $1 AND device_id = $2',
//  [userId, deviceId]
// );

// return {
//  success: true,
//  message: 'WebAuthn registration successful'
// };

// } catch (error) {
// logger.error('WebAuthn finish registration error:', error);
// throw new Error('Failed to finish WebAuthn registration');
// }
// }

// static async beginAuthentication({ sngine_email, sngine_phone }) {
// try {
// // Find userId
// const userResult = await db.query(
//  `SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2`,
//  [sngine_email, sngine_phone]
// );

// if (userResult.rows.length === 0) {
//  throw new Error('User not found for given email/phone');
// }

// const userId = userResult.rows[0].id;

// // Get user's credentials
// const credentialsResult = await db.query(
//  `SELECT credential_id, public_key FROM vottery_biometrics 
//   WHERE user_id = $1 AND biometric_type = 'webauthn' AND is_active = true`,
//  [userId]
// );

// const allowCredentials = credentialsResult.rows.map(row => ({
//  id: Buffer.from(EncryptionUtils.decrypt(row.credential_id), 'base64'),
//  type: 'public-key'
// }));

// const options = await generateAuthenticationOptions({
//  rpID,
//  allowCredentials,
//  userVerification: 'required'
// });

// // Store challenge
// await db.query(
//  `INSERT INTO vottery_webauthn_challenges (user_id, device_id, challenge, expires_at)
//   VALUES ($1, 0, $2, $3)
//   ON CONFLICT (user_id, device_id)
//   DO UPDATE SET challenge = $2, expires_at = $3`,
//  [
//    userId,
//    options.challenge,
//    new Date(Date.now() + 5 * 60 * 1000)
//  ]
// );

// return options;

// } catch (error) {
// logger.error('WebAuthn begin authentication error:', error);
// throw new Error('Failed to begin WebAuthn authentication');
// }
// }

// static async finishAuthentication({ sngine_email, sngine_phone, credential }) {
// try {
// // Find userId
// const userResult = await db.query(
//  `SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2`,
//  [sngine_email, sngine_phone]
// );

// if (userResult.rows.length === 0) {
//  return { success: false, message: 'User not found for given email/phone' };
// }

// const userId = userResult.rows[0].id;

// // Get challenge
// const challengeResult = await db.query(
//  `SELECT challenge FROM vottery_webauthn_challenges 
//   WHERE user_id = $1 AND device_id = 0 AND expires_at > NOW()`,
//  [userId]
// );

// if (challengeResult.rows.length === 0) {
//  return {
//    success: false,
//    message: 'Invalid or expired challenge'
//  };
// }

// // Get credential
// const credentialResult = await db.query(
//  `SELECT public_key, credential_id FROM vottery_biometrics 
//   WHERE user_id = $1 AND biometric_type = 'webauthn' AND is_active = true`,
//  [userId]
// );

// if (credentialResult.rows.length === 0) {
//  return {
//    success: false,
//    message: 'No WebAuthn credentials found'
//  };
// }

// const storedCredential = credentialResult.rows[0];
// const expectedChallenge = challengeResult.rows[0].challenge;

// const verification = await verifyAuthenticationResponse({
//  response: credential,
//  expectedChallenge,
//  expectedOrigin: origin,
//  expectedRPID: rpID,
//  authenticator: {
//    credentialID: Buffer.from(EncryptionUtils.decrypt(storedCredential.credential_id), 'base64'),
//    credentialPublicKey: Buffer.from(EncryptionUtils.decrypt(storedCredential.public_key), 'base64')
//  }
// });

// if (!verification.verified) {
//  return {
//    success: false,
//    message: 'Authentication verification failed'
//  };
// }

// // Clean up challenge
// await db.query(
//  'DELETE FROM vottery_webauthn_challenges WHERE user_id = $1 AND device_id = 0',
//  [userId]
// );

// return {
//  success: true,
//  message: 'WebAuthn authentication successful'
// };

// } catch (error) {
// logger.error('WebAuthn finish authentication error:', error);
// throw new Error('Failed to finish WebAuthn authentication');
// }
// }
// }
