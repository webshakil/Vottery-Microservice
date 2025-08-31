// services/signatureService.js
import DigitalSignature from '../models/DigitalSignature.js';
import { createHash, sign, verify } from 'node:crypto';
import keyManagementService from './keyManagementService.js';
import auditService from './auditService.js';
import { AppError } from '../utils/response.js';
import { SIGNATURE_ALGORITHMS } from '../utils/constants.js';

class SignatureService {
  constructor() {
    this.defaultAlgorithm = 'RSA-SHA256';
    this.supportedAlgorithms = Object.values(SIGNATURE_ALGORITHMS);
  }

  /**
   * Sign data with user's private key
   * @param {number} userId 
   * @param {string|Buffer} data 
   * @param {string} algorithm 
   * @returns {Promise<object>}
   */
  async signData(userId, data, algorithm = 'RSA-SHA256') {
    try {
      if (!this.supportedAlgorithms.includes(algorithm)) {
        throw new AppError(`Unsupported signature algorithm: ${algorithm}`, 400);
      }

      // Generate hash of the data
      const dataHash = this.generateDataHash(data);

      // Get user's private key
      const privateKey = await keyManagementService.getUserPrivateKey(userId, 'RSA');

      // Create signature
      const signature = await this.createSignature(data, privateKey, algorithm);

      // Store signature in database
      const signatureRecord = await DigitalSignature.create({
        user_id: userId,
        data_hash: dataHash,
        signature_data: signature,
        algorithm,
        verified: false
      });

      // Log signing activity
      await auditService.logActivity(
        userId,
        'DATA_SIGN',
        'digital_signature',
        signatureRecord.id,
        {
          algorithm,
          data_hash: dataHash,
          signature_length: signature.length
        }
      );

      return {
        id: signatureRecord.id,
        signature,
        dataHash,
        algorithm,
        createdAt: signatureRecord.created_at
      };
    } catch (error) {
      throw new AppError(`Signature creation failed: ${error.message}`, 500);
    }
  }

  /**
   * Verify signature
   * @param {string} signature 
   * @param {string|Buffer} originalData 
   * @param {string} publicKey 
   * @param {string} algorithm 
   * @returns {Promise<object>}
   */
  async verifySignature(signature, originalData, publicKey, algorithm = 'RSA-SHA256') {
    try {
      if (!this.supportedAlgorithms.includes(algorithm)) {
        throw new AppError(`Unsupported signature algorithm: ${algorithm}`, 400);
      }

      // Verify the signature
      const isValid = await this.performVerification(originalData, signature, publicKey, algorithm);

      // Generate hash for comparison
      const dataHash = this.generateDataHash(originalData);

      // Update signature record if it exists
      const signatureRecord = await DigitalSignature.findOne({
        where: { 
          signature_data: signature,
          data_hash: dataHash 
        }
      });

      if (signatureRecord && !signatureRecord.verified && isValid) {
        await signatureRecord.update({ verified: true });
      }

      return {
        isValid,
        dataHash,
        algorithm,
        verifiedAt: new Date(),
        signatureRecord: signatureRecord ? signatureRecord.id : null
      };
    } catch (error) {
      throw new AppError(`Signature verification failed: ${error.message}`, 500);
    }
  }

  /**
   * Verify signature by ID
   * @param {number} signatureId 
   * @param {string|Buffer} originalData 
   * @returns {Promise<object>}
   */
  async verifySignatureById(signatureId, originalData) {
    try {
      const signatureRecord = await DigitalSignature.findByPk(signatureId);
      if (!signatureRecord) {
        throw new AppError('Signature not found', 404);
      }

      // Get user's public key
      const publicKey = await keyManagementService.getUserPublicKey(
        signatureRecord.user_id, 
        'RSA'
      );

      // Verify signature
      const verification = await this.verifySignature(
        signatureRecord.signature_data,
        originalData,
        publicKey,
        signatureRecord.algorithm
      );

      // Log verification activity
      await auditService.logActivity(
        signatureRecord.user_id,
        'SIGNATURE_VERIFY',
        'digital_signature',
        signatureId,
        {
          is_valid: verification.isValid,
          verified_at: verification.verifiedAt,
          data_hash_match: verification.dataHash === signatureRecord.data_hash
        }
      );

      return {
        ...verification,
        signatureId,
        userId: signatureRecord.user_id,
        createdAt: signatureRecord.created_at
      };
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Get user's signatures
   * @param {number} userId 
   * @param {number} page 
   * @param {number} limit 
   * @returns {Promise<object>}
   */
  async getUserSignatures(userId, page = 1, limit = 10) {
    try {
      const offset = (page - 1) * limit;

      const { count, rows } = await DigitalSignature.findAndCountAll({
        where: { user_id: userId },
        limit,
        offset,
        order: [['created_at', 'DESC']]
      });

      return {
        signatures: rows,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(count / limit),
          totalCount: count,
          limit
        }
      };
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Sign multiple data items (batch signing)
   * @param {number} userId 
   * @param {array} dataItems 
   * @param {string} algorithm 
   * @returns {Promise<array>}
   */
  async batchSign(userId, dataItems, algorithm = 'RSA-SHA256') {
    try {
      const signatures = [];
      const privateKey = await keyManagementService.getUserPrivateKey(userId, 'RSA');

      for (const data of dataItems) {
        try {
          const dataHash = this.generateDataHash(data);
          const signature = await this.createSignature(data, privateKey, algorithm);

          const signatureRecord = await DigitalSignature.create({
            user_id: userId,
            data_hash: dataHash,
            signature_data: signature,
            algorithm,
            verified: false
          });

          signatures.push({
            id: signatureRecord.id,
            signature,
            dataHash,
            data: data.substring(0, 100) + '...', // First 100 chars for reference
            success: true
          });
        } catch (error) {
          signatures.push({
            data: data.substring(0, 100) + '...',
            success: false,
            error: error.message
          });
        }
      }

      // Log batch signing
      await auditService.logActivity(
        userId,
        'BATCH_SIGN',
        'digital_signature',
        null,
        {
          total_items: dataItems.length,
          successful: signatures.filter(s => s.success).length,
          failed: signatures.filter(s => !s.success).length,
          algorithm
        }
      );

      return signatures;
    } catch (error) {
      throw new AppError(`Batch signing failed: ${error.message}`, 500);
    }
  }

  /**
   * Create timestamped signature
   * @param {number} userId 
   * @param {string|Buffer} data 
   * @param {string} algorithm 
   * @returns {Promise<object>}
   */
  async createTimestampedSignature(userId, data, algorithm = 'RSA-SHA256') {
    try {
      const timestamp = new Date().toISOString();
      const timestampedData = `${data}||TIMESTAMP:${timestamp}`;

      const signature = await this.signData(userId, timestampedData, algorithm);

      return {
        ...signature,
        timestamp,
        timestampedData: timestampedData.length > 1000 ? 
          timestampedData.substring(0, 1000) + '...' : 
          timestampedData
      };
    } catch (error) {
      throw new AppError(`Timestamped signature creation failed: ${error.message}`, 500);
    }
  }

  /**
   * Generate blind signature (for anonymous voting)
   * @param {number} userId 
   * @param {string} blindedData 
   * @param {string} algorithm 
   * @returns {Promise<object>}
   */
  async createBlindSignature(userId, blindedData, algorithm = 'RSA-SHA256') {
    try {
      // For blind signatures, we sign the blinded data directly
      const privateKey = await keyManagementService.getUserPrivateKey(userId, 'RSA');
      const blindSignature = await this.createSignature(blindedData, privateKey, algorithm);

      const dataHash = this.generateDataHash(blindedData);

      const signatureRecord = await DigitalSignature.create({
        user_id: userId,
        data_hash: dataHash,
        signature_data: blindSignature,
        algorithm: `BLIND_${algorithm}`,
        verified: false
      });

      await auditService.logActivity(
        userId,
        'BLIND_SIGN',
        'digital_signature',
        signatureRecord.id,
        {
          algorithm: `BLIND_${algorithm}`,
          data_hash: dataHash
        }
      );

      return {
        id: signatureRecord.id,
        blindSignature,
        dataHash,
        algorithm: `BLIND_${algorithm}`,
        createdAt: signatureRecord.created_at
      };
    } catch (error) {
      throw new AppError(`Blind signature creation failed: ${error.message}`, 500);
    }
  }

  /**
   * Revoke signature
   * @param {number} signatureId 
   * @param {number} userId 
   * @param {string} reason 
   * @returns {Promise<boolean>}
   */
  async revokeSignature(signatureId, userId, reason = null) {
    try {
      const signatureRecord = await DigitalSignature.findByPk(signatureId);
      if (!signatureRecord) {
        throw new AppError('Signature not found', 404);
      }

      if (signatureRecord.user_id !== userId) {
        throw new AppError('Unauthorized to revoke this signature', 403);
      }

      // Mark as revoked by updating the algorithm field
      await signatureRecord.update({
        algorithm: `REVOKED_${signatureRecord.algorithm}`,
        verified: false
      });

      await auditService.logActivity(
        userId,
        'SIGNATURE_REVOKE',
        'digital_signature',
        signatureId,
        {
          reason,
          revoked_at: new Date(),
          original_algorithm: signatureRecord.algorithm.replace('REVOKED_', '')
        }
      );

      return true;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Get signature statistics
   * @returns {Promise<object>}
   */
  async getSignatureStatistics() {
    try {
      const [
        totalSignatures,
        verifiedSignatures,
        revokedSignatures,
        signaturesByAlgorithm
      ] = await Promise.all([
        DigitalSignature.count(),
        DigitalSignature.count({ where: { verified: true } }),
        DigitalSignature.count({ where: { algorithm: { [Op.like]: 'REVOKED_%' } } }),
        DigitalSignature.findAll({
          attributes: [
            'algorithm',
            [Sequelize.fn('COUNT', Sequelize.col('id')), 'count']
          ],
          group: ['algorithm']
        })
      ]);

      const algorithmDistribution = {};
      signaturesByAlgorithm.forEach(alg => {
        algorithmDistribution[alg.algorithm] = parseInt(alg.dataValues.count);
      });

      return {
        total: totalSignatures,
        verified: verifiedSignatures,
        revoked: revokedSignatures,
        pending: totalSignatures - verifiedSignatures - revokedSignatures,
        algorithmDistribution
      };
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  // Helper methods

  /**
   * Generate hash of data
   * @param {string|Buffer} data 
   * @returns {string}
   */
  generateDataHash(data) {
    return createHash('sha256').update(data).digest('hex');
  }

  /**
   * Create signature using specified algorithm
   * @param {string|Buffer} data 
   * @param {string} privateKey 
   * @param {string} algorithm 
   * @returns {Promise<string>}
   */
  async createSignature(data, privateKey, algorithm) {
    try {
      let hashAlgorithm;
      
      switch (algorithm) {
        case 'RSA-SHA256':
          hashAlgorithm = 'sha256';
          break;
        case 'RSA-SHA512':
          hashAlgorithm = 'sha512';
          break;
        default:
          throw new AppError(`Unsupported algorithm: ${algorithm}`, 400);
      }

      const signature = sign(hashAlgorithm, Buffer.from(data), {
        key: privateKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_DIGEST
      });

      return signature.toString('base64');
    } catch (error) {
      throw new AppError(`Signature creation failed: ${error.message}`, 500);
    }
  }

  /**
   * Perform signature verification
   * @param {string|Buffer} data 
   * @param {string} signature 
   * @param {string} publicKey 
   * @param {string} algorithm 
   * @returns {Promise<boolean>}
   */
  async performVerification(data, signature, publicKey, algorithm) {
    try {
      let hashAlgorithm;
      
      switch (algorithm) {
        case 'RSA-SHA256':
          hashAlgorithm = 'sha256';
          break;
        case 'RSA-SHA512':
          hashAlgorithm = 'sha512';
          break;
        default:
          throw new AppError(`Unsupported algorithm: ${algorithm}`, 400);
      }

      const signatureBuffer = Buffer.from(signature, 'base64');

      const isValid = verify(
        hashAlgorithm,
        Buffer.from(data),
        {
          key: publicKey,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST
        },
        signatureBuffer
      );

      return isValid;
    } catch (error) {
      return false;
    }
  }

  /**
   * Validate signature format
   * @param {string} signature 
   * @returns {boolean}
   */
  validateSignatureFormat(signature) {
    try {
      // Check if it's valid base64
      const decoded = Buffer.from(signature, 'base64');
      const reencoded = decoded.toString('base64');
      return reencoded === signature;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get signature info without verification
   * @param {number} signatureId 
   * @returns {Promise<object>}
   */
  async getSignatureInfo(signatureId) {
    try {
      const signatureRecord = await DigitalSignature.findByPk(signatureId);
      if (!signatureRecord) {
        throw new AppError('Signature not found', 404);
      }

      return {
        id: signatureRecord.id,
        userId: signatureRecord.user_id,
        dataHash: signatureRecord.data_hash,
        algorithm: signatureRecord.algorithm,
        verified: signatureRecord.verified,
        createdAt: signatureRecord.created_at,
        isRevoked: signatureRecord.algorithm.startsWith('REVOKED_'),
        signatureLength: signatureRecord.signature_data.length
      };
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Export signature for external verification
   * @param {number} signatureId 
   * @returns {Promise<object>}
   */
  async exportSignature(signatureId) {
    try {
      const signatureRecord = await DigitalSignature.findByPk(signatureId);
      if (!signatureRecord) {
        throw new AppError('Signature not found', 404);
      }

      // Get user's public key for verification
      const publicKey = await keyManagementService.getUserPublicKey(
        signatureRecord.user_id,
        'RSA'
      );

      return {
        signature: signatureRecord.signature_data,
        dataHash: signatureRecord.data_hash,
        algorithm: signatureRecord.algorithm,
        publicKey,
        createdAt: signatureRecord.created_at,
        verified: signatureRecord.verified,
        exportedAt: new Date()
      };
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Cleanup old signatures
   * @param {number} daysOld 
   * @returns {Promise<number>}
   */
  async cleanupOldSignatures(daysOld = 365) {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysOld);

      const oldSignatures = await DigitalSignature.findAll({
        where: {
          created_at: { [Op.lt]: cutoffDate },
          verified: true
        }
      });

      let cleaned = 0;
      for (const signature of oldSignatures) {
        await signature.destroy();
        cleaned++;
      }

      return cleaned;
    } catch (error) {
      throw new AppError(`Signature cleanup failed: ${error.message}`, 500);
    }
  }
}

export default new SignatureService();