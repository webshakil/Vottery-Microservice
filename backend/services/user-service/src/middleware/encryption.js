import { encryptionService } from '../services/encryptionService.js';
import { keyManagementService } from '../services/keyManagementService.js';
import { auditService } from '../services/auditService.js';
import { errorResponse } from '../utils/response.js';
import crypto from 'crypto';

/**
 * Encryption Middleware
 * Handles data encryption/decryption and cryptographic operations
 */

/**
 * Auto-encrypt sensitive fields in request body
 * @param {array} fieldsToEncrypt - Fields that should be encrypted
 */
export const encryptSensitiveFields = (fieldsToEncrypt = []) => {
  return async (req, res, next) => {
    try {
      if (!req.body || typeof req.body !== 'object') {
        return next();
      }

      const userId = req.user?.id;
      if (!userId) {
        return next(); // Skip encryption if no user context
      }

      // Get user's encryption key
      const userKey = await keyManagementService.getUserEncryptionKey(userId);
      if (!userKey) {
        console.warn(`No encryption key found for user ${userId}`);
        return next();
      }

      // Encrypt specified fields
      for (const field of fieldsToEncrypt) {
        if (req.body[field] && typeof req.body[field] === 'string') {
          try {
            req.body[`${field}_encrypted`] = await encryptionService.encryptData(
              req.body[field],
              userKey.public_key
            );
            
            // Remove plain text version for security
            delete req.body[field];
            
          } catch (encryptError) {
            console.error(`Failed to encrypt field ${field}:`, encryptError);
            return errorResponse(res, 'Data encryption failed', 500);
          }
        }
      }

      req.encryptedFields = fieldsToEncrypt;
      next();

    } catch (error) {
      console.error('Encryption middleware error:', error);
      return errorResponse(res, 'Encryption processing failed', 500);
    }
  };
};

/**
 * Auto-decrypt sensitive fields in response data
 * @param {array} fieldsToDecrypt - Fields that should be decrypted
 */
export const decryptSensitiveFields = (fieldsToDecrypt = []) => {
  return async (req, res, next) => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return next();
      }

      // Store original send method
      const originalSend = res.send;

      // Override send method to decrypt data before sending
      res.send = async function(data) {
        try {
          if (typeof data === 'string') {
            try {
              data = JSON.parse(data);
            } catch (e) {
              // Not JSON, send as-is
              return originalSend.call(this, data);
            }
          }

          if (data && typeof data === 'object') {
            const decryptedData = await decryptObjectFields(data, fieldsToDecrypt, userId);
            return originalSend.call(this, JSON.stringify(decryptedData));
          }

          return originalSend.call(this, data);

        } catch (error) {
          console.error('Response decryption error:', error);
          return originalSend.call(this, data); // Send original data on error
        }
      };

      next();

    } catch (error) {
      console.error('Decryption middleware error:', error);
      next();
    }
  };
};

/**
 * End-to-end encryption for API responses
 */
export const e2eEncryption = async (req, res, next) => {
  try {
    const clientPublicKey = req.headers['x-client-public-key'];
    
    if (!clientPublicKey) {
      return next(); // Skip E2E if client doesn't support it
    }

    // Store original send method
    const originalSend = res.send;

    // Override send method to encrypt entire response
    res.send = async function(data) {
      try {
        if (res.statusCode >= 400) {
          // Don't encrypt error responses
          return originalSend.call(this, data);
        }

        const encryptedPayload = await encryptionService.encryptForClient(
          data,
          clientPublicKey
        );

        // Set encryption headers
        this.set('X-Encrypted', 'true');
        this.set('X-Encryption-Method', 'RSA-AES-256');
        
        return originalSend.call(this, JSON.stringify(encryptedPayload));

      } catch (error) {
        console.error('E2E encryption error:', error);
        return originalSend.call(this, data); // Fallback to unencrypted
      }
    };

    next();

  } catch (error) {
    console.error('E2E encryption middleware error:', error);
    next();
  }
};

/**
 * Decrypt E2E encrypted request payloads
 */
export const decryptE2ERequest = async (req, res, next) => {
  try {
    const isEncrypted = req.headers['x-encrypted'] === 'true';
    
    if (!isEncrypted || !req.body) {
      return next();
    }

    const userId = req.user?.id;
    if (!userId) {
      return errorResponse(res, 'User context required for decryption', 401);
    }

    // Get user's private key
    const userKey = await keyManagementService.getUserPrivateKey(userId);
    if (!userKey) {
      return errorResponse(res, 'Decryption key not found', 400);
    }

    // Decrypt the payload
    const decryptedPayload = await encryptionService.decryptFromClient(
      req.body,
      userKey
    );

    req.body = decryptedPayload;
    req.wasEncrypted = true;

    next();

  } catch (error) {
    console.error('E2E decryption error:', error);
    
    await auditService.log(req.user?.id || null, 'E2E_DECRYPTION_FAILED', 'security', null, {
      error: error.message,
      ip: req.ip
    }, req);

    return errorResponse(res, 'Failed to decrypt request payload', 400);
  }
};

/**
 * Generate and validate digital signatures
 */
export const digitalSignature = {
  /**
   * Sign response data
   */
  signResponse: async (req, res, next) => {
    try {
      const originalSend = res.send;

      res.send = async function(data) {
        try {
          if (res.statusCode >= 400) {
            return originalSend.call(this, data);
          }

          // Generate signature for response
          const signature = await encryptionService.signData(
            data,
            process.env.SERVER_PRIVATE_KEY
          );

          this.set('X-Signature', signature);
          this.set('X-Signature-Algorithm', 'RSA-SHA256');
          this.set('X-Signature-Timestamp', Date.now().toString());

          return originalSend.call(this, data);

        } catch (error) {
          console.error('Response signing error:', error);
          return originalSend.call(this, data);
        }
      };

      next();

    } catch (error) {
      console.error('Digital signature middleware error:', error);
      next();
    }
  },

  /**
   * Verify request signatures
   */
  verifyRequest: async (req, res, next) => {
    try {
      const signature = req.headers['x-signature'];
      const timestamp = req.headers['x-signature-timestamp'];
      const clientPublicKey = req.headers['x-client-public-key'];

      if (!signature) {
        return next(); // Skip verification if no signature provided
      }

      if (!clientPublicKey) {
        return errorResponse(res, 'Client public key required for signature verification', 400);
      }

      // Verify timestamp
      const now = Date.now();
      const signatureTime = parseInt(timestamp);
      if (Math.abs(now - signatureTime) > 300000) { // 5 minutes tolerance
        return errorResponse(res, 'Signature timestamp invalid', 401);
      }

      // Verify signature
      const payload = JSON.stringify(req.body) + timestamp;
      const isValid = await encryptionService.verifySignature(
        payload,
        signature,
        clientPublicKey
      );

      if (!isValid) {
        await auditService.log(req.user?.id || null, 'SIGNATURE_VERIFICATION_FAILED', 'security', null, {
          ip: req.ip,
          endpoint: req.originalUrl
        }, req);

        return errorResponse(res, 'Invalid request signature', 401);
      }

      req.signatureVerified = true;
      next();

    } catch (error) {
      console.error('Signature verification error:', error);
      return errorResponse(res, 'Signature verification failed', 500);
    }
  }
};

/**
 * Hash sensitive data for storage
 * @param {array} fieldsToHash - Fields that should be hashed
 */
export const hashSensitiveFields = (fieldsToHash = []) => {
  return async (req, res, next) => {
    try {
      if (!req.body || typeof req.body !== 'object') {
        return next();
      }

      for (const field of fieldsToHash) {
        if (req.body[field] && typeof req.body[field] === 'string') {
          try {
            // Use SHA-256 for hashing
            req.body[`${field}_hash`] = crypto
              .createHash('sha256')
              .update(req.body[field])
              .digest('hex');
            
            // Remove plain text version
            delete req.body[field];
            
          } catch (hashError) {
            console.error(`Failed to hash field ${field}:`, hashError);
            return errorResponse(res, 'Data hashing failed', 500);
          }
        }
      }

      req.hashedFields = fieldsToHash;
      next();

    } catch (error) {
      console.error('Hashing middleware error:', error);
      return errorResponse(res, 'Hashing processing failed', 500);
    }
  };
};

/**
 * Key rotation validation
 */
export const validateKeyRotation = async (req, res, next) => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return next();
    }

    // Check if user's keys need rotation
    const keyStatus = await keyManagementService.checkKeyRotationStatus(userId);
    
    if (keyStatus.needsRotation) {
      // Log key rotation requirement
      await auditService.log(userId, 'KEY_ROTATION_REQUIRED', 'security', null, {
        reason: keyStatus.reason,
        lastRotation: keyStatus.lastRotation,
        daysOverdue: keyStatus.daysOverdue
      }, req);

      // Add header to inform client about key rotation
      res.set('X-Key-Rotation-Required', 'true');
      res.set('X-Key-Rotation-Reason', keyStatus.reason);
      
      // For critical operations, enforce rotation
      if (keyStatus.enforceRotation && isCriticalOperation(req)) {
        return errorResponse(res, 'Key rotation required for this operation', 426, {
          keyRotationRequired: true,
          reason: keyStatus.reason
        });
      }
    }

    next();

  } catch (error) {
    console.error('Key rotation validation error:', error);
    next(); // Don't block on validation errors
  }
};

/**
 * Secure key exchange for new users
 */
export const secureKeyExchange = async (req, res, next) => {
  try {
    const isNewUser = req.path.includes('/register') || req.path.includes('/setup');
    
    if (!isNewUser) {
      return next();
    }

    // Generate ephemeral key pair for secure exchange
    const ephemeralKeys = await encryptionService.generateEphemeralKeyPair();
    
    // Store ephemeral private key temporarily
    const exchangeId = crypto.randomBytes(32).toString('hex');
    await keyManagementService.storeEphemeralKey(exchangeId, ephemeralKeys.privateKey);
    
    // Add public key to response headers
    res.set('X-Ephemeral-Public-Key', ephemeralKeys.publicKey);
    res.set('X-Key-Exchange-Id', exchangeId);
    res.set('X-Key-Exchange-Expires', (Date.now() + 300000).toString()); // 5 minutes
    
    req.keyExchange = {
      id: exchangeId,
      publicKey: ephemeralKeys.publicKey
    };

    next();

  } catch (error) {
    console.error('Secure key exchange error:', error);
    next();
  }
};

/**
 * Threshold encryption for sensitive operations
 */
export const thresholdEncryption = {
  /**
   * Encrypt data using threshold scheme
   */
  encrypt: (threshold = 3, totalShares = 5) => {
    return async (req, res, next) => {
      try {
        const sensitiveData = extractSensitiveData(req.body);
        
        if (!sensitiveData || Object.keys(sensitiveData).length === 0) {
          return next();
        }

        // Generate threshold encryption shares
        const shares = await encryptionService.createThresholdShares(
          JSON.stringify(sensitiveData),
          threshold,
          totalShares
        );

        // Store shares securely
        const shareIds = await keyManagementService.storeThresholdShares(
          req.user.id,
          shares,
          threshold
        );

        // Replace sensitive data with share references
        req.body.threshold_encrypted = {
          shareIds,
          threshold,
          algorithm: 'threshold-aes-256'
        };

        // Remove original sensitive data
        for (const field of Object.keys(sensitiveData)) {
          delete req.body[field];
        }

        next();

      } catch (error) {
        console.error('Threshold encryption error:', error);
        return errorResponse(res, 'Threshold encryption failed', 500);
      }
    };
  },

  /**
   * Decrypt data using threshold scheme
   */
  decrypt: async (req, res, next) => {
    try {
      const originalSend = res.send;

      res.send = async function(data) {
        try {
          if (typeof data === 'string') {
            data = JSON.parse(data);
          }

          if (data && data.threshold_encrypted) {
            // Reconstruct data from threshold shares
            const decryptedData = await reconstructFromThresholdShares(
              data.threshold_encrypted,
              req.user.id
            );

            // Merge decrypted data back
            Object.assign(data, decryptedData);
            delete data.threshold_encrypted;
          }

          return originalSend.call(this, JSON.stringify(data));

        } catch (error) {
          console.error('Threshold decryption error:', error);
          return originalSend.call(this, JSON.stringify(data));
        }
      };

      next();

    } catch (error) {
      console.error('Threshold decryption middleware error:', error);
      next();
    }
  }
};

/**
 * Homomorphic encryption for privacy-preserving computations
 */
export const homomorphicEncryption = {
  /**
   * Encrypt numeric data for homomorphic operations
   */
  encryptNumeric: (numericFields = []) => {
    return async (req, res, next) => {
      try {
        if (!req.body || typeof req.body !== 'object') {
          return next();
        }

        const userId = req.user?.id;
        if (!userId) {
          return next();
        }

        // Get user's homomorphic encryption key
        const homomorphicKey = await keyManagementService.getHomomorphicKey(userId);
        
        for (const field of numericFields) {
          if (req.body[field] && typeof req.body[field] === 'number') {
            try {
              req.body[`${field}_homomorphic`] = await encryptionService.homomorphicEncrypt(
                req.body[field],
                homomorphicKey
              );
              
              delete req.body[field];
              
            } catch (encryptError) {
              console.error(`Failed to homomorphically encrypt field ${field}:`, encryptError);
              return errorResponse(res, 'Homomorphic encryption failed', 500);
            }
          }
        }

        next();

      } catch (error) {
        console.error('Homomorphic encryption middleware error:', error);
        return errorResponse(res, 'Homomorphic encryption processing failed', 500);
      }
    };
  }
};

/**
 * Zero-knowledge proof validation
 */
export const zkProofValidation = async (req, res, next) => {
  try {
    const zkProof = req.headers['x-zk-proof'];
    const proofType = req.headers['x-zk-proof-type'];
    
    if (!zkProof) {
      return next(); // Skip if no ZK proof provided
    }

    // Validate zero-knowledge proof
    const isValid = await encryptionService.verifyZKProof(
      zkProof,
      proofType,
      req.body,
      req.user?.id
    );

    if (!isValid) {
      await auditService.log(req.user?.id || null, 'ZK_PROOF_VALIDATION_FAILED', 'security', null, {
        proofType,
        ip: req.ip
      }, req);

      return errorResponse(res, 'Zero-knowledge proof validation failed', 401);
    }

    req.zkProofVerified = true;
    req.zkProofType = proofType;
    next();

  } catch (error) {
    console.error('ZK proof validation error:', error);
    return errorResponse(res, 'ZK proof validation failed', 500);
  }
};

/**
 * Secure random number generation for cryptographic operations
 */
export const generateSecureRandom = (req, res, next) => {
  // Add secure random utilities to request object
  req.crypto = {
    randomBytes: (size) => crypto.randomBytes(size),
    randomInt: (min, max) => crypto.randomInt(min, max),
    randomUUID: () => crypto.randomUUID(),
    secureToken: (length = 32) => crypto.randomBytes(length).toString('hex')
  };
  
  next();
};

// Helper Functions

/**
 * Recursively decrypt object fields
 */
async function decryptObjectFields(obj, fieldsToDecrypt, userId) {
  if (!obj || typeof obj !== 'object') {
    return obj;
  }

  if (Array.isArray(obj)) {
    return Promise.all(obj.map(item => decryptObjectFields(item, fieldsToDecrypt, userId)));
  }

  const result = { ...obj };
  
  // Get user's private key
  const userKey = await keyManagementService.getUserPrivateKey(userId);
  if (!userKey) {
    return result;
  }

  for (const field of fieldsToDecrypt) {
    const encryptedField = `${field}_encrypted`;
    
    if (result[encryptedField]) {
      try {
        result[field] = await encryptionService.decryptData(
          result[encryptedField],
          userKey
        );
        delete result[encryptedField];
      } catch (decryptError) {
        console.error(`Failed to decrypt field ${field}:`, decryptError);
        // Keep encrypted field if decryption fails
      }
    }
  }

  // Recursively process nested objects
  for (const [key, value] of Object.entries(result)) {
    if (typeof value === 'object' && value !== null) {
      result[key] = await decryptObjectFields(value, fieldsToDecrypt, userId);
    }
  }

  return result;
}

/**
 * Extract sensitive data fields from request body
 */
function extractSensitiveData(body) {
  const sensitiveFields = [
    'password', 'ssn', 'credit_card', 'bank_account',
    'biometric_data', 'private_key', 'secret'
  ];
  
  const sensitiveData = {};
  
  for (const field of sensitiveFields) {
    if (body[field]) {
      sensitiveData[field] = body[field];
    }
  }
  
  return sensitiveData;
}

/**
 * Check if operation is critical and requires key rotation
 */
function isCriticalOperation(req) {
  const criticalPaths = [
    '/api/users/change-password',
    '/api/users/delete-account',
    '/api/keys/rotate',
    '/api/admin/',
    '/api/elections/create',
    '/api/votes/cast'
  ];
  
  return criticalPaths.some(path => req.originalUrl.startsWith(path));
}

/**
 * Reconstruct data from threshold shares
 */
async function reconstructFromThresholdShares(thresholdData, userId) {
  try {
    const { shareIds, threshold } = thresholdData;
    
    // Get threshold shares
    const shares = await keyManagementService.getThresholdShares(shareIds, threshold);
    
    // Reconstruct original data
    const reconstructedData = await encryptionService.reconstructFromShares(shares, threshold);
    
    return JSON.parse(reconstructedData);
    
  } catch (error) {
    console.error('Threshold reconstruction error:', error);
    throw error;
  }
}