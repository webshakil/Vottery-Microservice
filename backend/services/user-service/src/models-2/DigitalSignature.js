import { DataTypes, Model } from 'sequelize';
import crypto from 'node:crypto';

class DigitalSignature extends Model {
  static init(sequelize) {
    return super.init(
      {
        id: {
          type: DataTypes.UUID,
          defaultValue: DataTypes.UUIDV4,
          primaryKey: true,
          allowNull: false,
        },
        signature_id: {
          type: DataTypes.STRING(64),
          allowNull: false,
          unique: true,
          comment: 'Unique identifier for the signature',
        },
        signer_user_id: {
          type: DataTypes.UUID,
          allowNull: false,
        },
        organization_id: {
          type: DataTypes.UUID,
          allowNull: false,
        },
        encryption_key_id: {
          type: DataTypes.UUID,
          allowNull: false,
          comment: 'Key used for signing',
        },
        document_hash: {
          type: DataTypes.STRING(128),
          allowNull: false,
          comment: 'SHA-256 hash of the signed document/data',
        },
        document_type: {
          type: DataTypes.STRING(50),
          allowNull: false,
          comment: 'Type of document being signed (vote, contract, etc.)',
        },
        document_id: {
          type: DataTypes.UUID,
          allowNull: true,
          comment: 'ID of the document in its respective table',
        },
        signature_algorithm: {
          type: DataTypes.ENUM,
          values: ['RSA-SHA256', 'ECDSA-SHA256', 'ElGamal', 'DSA', 'EdDSA'],
          allowNull: false,
        },
        signature_value: {
          type: DataTypes.TEXT,
          allowNull: false,
          comment: 'Base64 encoded digital signature',
        },
        signature_format: {
          type: DataTypes.ENUM,
          values: ['PKCS1', 'PSS', 'DER', 'PEM', 'custom'],
          allowNull: false,
          defaultValue: 'PKCS1',
        },
        hash_algorithm: {
          type: DataTypes.ENUM,
          values: ['SHA256', 'SHA384', 'SHA512', 'SHA3-256', 'SHA3-384', 'SHA3-512'],
          allowNull: false,
          defaultValue: 'SHA256',
        },
        salt_value: {
          type: DataTypes.STRING(128),
          allowNull: true,
          comment: 'Salt used for PSS signatures',
        },
        timestamp: {
          type: DataTypes.DATE,
          allowNull: false,
          defaultValue: DataTypes.NOW,
          comment: 'When the signature was created',
        },
        trusted_timestamp: {
          type: DataTypes.TEXT,
          allowNull: true,
          comment: 'RFC 3161 trusted timestamp token',
        },
        certificate_chain: {
          type: DataTypes.JSON,
          allowNull: true,
          comment: 'X.509 certificate chain for verification',
        },
        verification_status: {
          type: DataTypes.ENUM,
          values: ['valid', 'invalid', 'expired', 'revoked', 'unknown', 'pending'],
          allowNull: false,
          defaultValue: 'pending',
        },
        verification_date: {
          type: DataTypes.DATE,
          allowNull: true,
          comment: 'When signature was last verified',
        },
        verification_details: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
          comment: 'Detailed verification results',
        },
        threshold_signature_data: {
          type: DataTypes.JSON,
          allowNull: true,
          comment: 'Data for threshold signature schemes',
        },
        multi_signature_data: {
          type: DataTypes.JSON,
          allowNull: true,
          comment: 'Data for multi-signature schemes',
        },
        signature_purpose: {
          type: DataTypes.ENUM,
          values: ['vote', 'authentication', 'document_signing', 'transaction', 'consent', 'approval', 'other'],
          allowNull: false,
        },
        signature_context: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
          comment: 'Additional context about the signature',
        },
        is_blind_signature: {
          type: DataTypes.BOOLEAN,
          defaultValue: false,
          allowNull: false,
        },
        blind_signature_data: {
          type: DataTypes.JSON,
          allowNull: true,
          comment: 'Blinding factor and related data',
        },
        witness_signatures: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Array of witness signatures',
        },
        counter_signatures: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Array of counter-signatures',
        },
        signature_policy: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
          comment: 'Policy requirements for this signature',
        },
        compliance_data: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
          comment: 'Compliance-specific metadata',
        },
        audit_trail: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Signature creation and verification history',
        },
        ip_address: {
          type: DataTypes.INET,
          allowNull: true,
          comment: 'IP address where signature was created',
        },
        user_agent: {
          type: DataTypes.TEXT,
          allowNull: true,
        },
        geolocation: {
          type: DataTypes.JSON,
          allowNull: true,
          comment: 'Geographic location data',
        },
        device_fingerprint: {
          type: DataTypes.JSON,
          allowNull: true,
          comment: 'Device identification data',
        },
        biometric_data_hash: {
          type: DataTypes.STRING(128),
          allowNull: true,
          comment: 'Hash of biometric data used for authentication',
        },
        is_revoked: {
          type: DataTypes.BOOLEAN,
          defaultValue: false,
          allowNull: false,
        },
        revocation_reason: {
          type: DataTypes.STRING(500),
          allowNull: true,
        },
        revoked_at: {
          type: DataTypes.DATE,
          allowNull: true,
        },
        revoked_by: {
          type: DataTypes.UUID,
          allowNull: true,
        },
        expires_at: {
          type: DataTypes.DATE,
          allowNull: true,
          comment: 'Signature expiration date',
        },
        legal_validity: {
          type: DataTypes.ENUM,
          values: ['legally_binding', 'evidence_only', 'internal_use', 'test'],
          allowNull: false,
          defaultValue: 'legally_binding',
        },
        archival_data: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
          comment: 'Long-term archival and preservation data',
        },
        created_by: {
          type: DataTypes.UUID,
          allowNull: true,
          comment: 'May be different from signer_user_id for system signatures',
        },
        metadata: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
        },
      },
      {
        sequelize,
        modelName: 'DigitalSignature',
        tableName: 'vottery_digital_signatures',
        paranoid: true,
        hooks: {
          beforeCreate: (signature) => {
            if (!signature.signature_id) {
              signature.signature_id = crypto.randomBytes(16).toString('hex');
            }
            signature.addAuditEntry('created', 'Signature created');
          },
        },
      }
    );
  }

  // Instance methods
  isValid() {
    return !this.is_revoked && 
           !this.isExpired() && 
           this.verification_status === 'valid';
  }

  isExpired() {
    if (!this.expires_at) {
      return false;
    }
    return new Date() > this.expires_at;
  }

  async verify(publicKey = null) {
    try {
      this.addAuditEntry('verification_attempt', 'Signature verification started');
      
      // Get the encryption key if not provided
      const encryptionKey = await this.getEncryptionKey();
      if (!encryptionKey || !encryptionKey.isValid()) {
        this.verification_status = 'invalid';
        this.verification_details = { error: 'Encryption key is invalid or revoked' };
        this.addAuditEntry('verification_failed', 'Encryption key invalid');
        await this.save();
        return false;
      }

      // Verify signature based on algorithm
      const isValidSignature = await this.performCryptographicVerification(encryptionKey);
      
      this.verification_status = isValidSignature ? 'valid' : 'invalid';
      this.verification_date = new Date();
      this.verification_details = {
        verified_at: new Date(),
        algorithm_used: this.signature_algorithm,
        key_id: encryptionKey.key_id,
        result: isValidSignature ? 'valid' : 'invalid',
      };
      
      this.addAuditEntry(
        isValidSignature ? 'verification_success' : 'verification_failed',
        `Signature verification ${isValidSignature ? 'succeeded' : 'failed'}`
      );
      
      await this.save();
      return isValidSignature;
      
    } catch (error) {
      this.verification_status = 'unknown';
      this.verification_details = { error: error.message };
      this.addAuditEntry('verification_error', `Verification error: ${error.message}`);
      await this.save();
      return false;
    }
  }

  async performCryptographicVerification(encryptionKey) {
    // This is a simplified implementation
    // In production, this would perform actual cryptographic verification
    switch (this.signature_algorithm) {
      case 'RSA-SHA256':
        return await this.verifyRSASignature(encryptionKey);
      case 'ECDSA-SHA256':
        return await this.verifyECDSASignature(encryptionKey);
      case 'ElGamal':
        return await this.verifyElGamalSignature(encryptionKey);
      default:
        throw new Error(`Unsupported signature algorithm: ${this.signature_algorithm}`);
    }
  }

  async verifyRSASignature(encryptionKey) {
    try {
      const publicKey = Buffer.from(encryptionKey.public_key, 'base64').toString('utf8');
      const signature = Buffer.from(this.signature_value, 'base64');
      const documentBuffer = Buffer.from(this.document_hash, 'hex');
      
      const verifier = crypto.createVerify(this.hash_algorithm);
      verifier.update(documentBuffer);
      
      return verifier.verify(publicKey, signature);
    } catch (error) {
      throw new Error(`RSA verification failed: ${error.message}`);
    }
  }

  async verifyECDSASignature(encryptionKey) {
    try {
      // ECDSA verification implementation
      // This is a placeholder - actual implementation would depend on curve parameters
      return true; // Placeholder
    } catch (error) {
      throw new Error(`ECDSA verification failed: ${error.message}`);
    }
  }

  async verifyElGamalSignature(encryptionKey) {
    try {
      // ElGamal verification implementation
      // This is a placeholder - actual implementation would use ElGamal parameters
      return true; // Placeholder
    } catch (error) {
      throw new Error(`ElGamal verification failed: ${error.message}`);
    }
  }

  async revoke(reason, revokedBy = null) {
    this.is_revoked = true;
    this.revocation_reason = reason;
    this.revoked_at = new Date();
    this.revoked_by = revokedBy;
    this.verification_status = 'revoked';
    
    this.addAuditEntry('revoked', `Signature revoked: ${reason}`);
    return await this.save();
  }

  // Threshold signature methods
  isThresholdSignature() {
    return !!this.threshold_signature_data;
  }

  getThresholdRequirement() {
    if (!this.isThresholdSignature()) {
      return null;
    }
    
    const { k, n } = this.threshold_signature_data;
    return `${k} of ${n}`;
  }

  addThresholdShare(share) {
    if (!this.threshold_signature_data) {
      this.threshold_signature_data = { shares: [] };
    }
    
    if (!this.threshold_signature_data.shares) {
      this.threshold_signature_data.shares = [];
    }
    
    this.threshold_signature_data.shares.push({
      ...share,
      timestamp: new Date(),
    });
    
    this.addAuditEntry('threshold_share_added', 'Threshold signature share added');
    return this;
  }

  isThresholdComplete() {
    if (!this.isThresholdSignature()) {
      return false;
    }
    
    const { k, shares = [] } = this.threshold_signature_data;
    return shares.length >= k;
  }

  // Multi-signature methods
  isMultiSignature() {
    return !!this.multi_signature_data && this.multi_signature_data.signers?.length > 1;
  }

  addCoSignature(signerUserId, signatureValue, publicKey) {
    if (!this.multi_signature_data) {
      this.multi_signature_data = { signatures: [] };
    }
    
    if (!this.multi_signature_data.signatures) {
      this.multi_signature_data.signatures = [];
    }
    
    this.multi_signature_data.signatures.push({
      signer_user_id: signerUserId,
      signature_value: signatureValue,
      public_key: publicKey,
      timestamp: new Date(),
    });
    
    this.addAuditEntry('co_signature_added', `Co-signature added by user ${signerUserId}`);
    return this;
  }

  // Witness signature methods
  addWitnessSignature(witnessUserId, signatureValue) {
    const witnessSignature = {
      witness_user_id: witnessUserId,
      signature_value: signatureValue,
      timestamp: new Date(),
    };
    
    this.witness_signatures.push(witnessSignature);
    this.addAuditEntry('witness_signature_added', `Witness signature added by user ${witnessUserId}`);
    return this;
  }

  // Counter signature methods
  addCounterSignature(counterSignerUserId, signatureValue) {
    const counterSignature = {
      counter_signer_user_id: counterSignerUserId,
      signature_value: signatureValue,
      timestamp: new Date(),
    };
    
    this.counter_signatures.push(counterSignature);
    this.addAuditEntry('counter_signature_added', `Counter signature added by user ${counterSignerUserId}`);
    return this;
  }

  // Audit trail methods
  addAuditEntry(action, description, metadata = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      action,
      description,
      metadata,
    };
    
    this.audit_trail.push(entry);
    
    // Keep only last 100 entries
    if (this.audit_trail.length > 100) {
      this.audit_trail = this.audit_trail.slice(-100);
    }
    
    return entry;
  }

  getAuditTrail(limit = 20) {
    return this.audit_trail
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, limit);
  }

  // Compliance methods
  addComplianceFlag(flag, value = true) {
    if (!this.compliance_data.flags) {
      this.compliance_data.flags = {};
    }
    
    this.compliance_data.flags[flag] = value;
    this.addAuditEntry('compliance_flag_added', `Compliance flag ${flag} set to ${value}`);
    return this;
  }

  hasComplianceFlag(flag) {
    return this.compliance_data.flags?.[flag] === true;
  }

  isLegallyBinding() {
    return this.legal_validity === 'legally_binding';
  }

  // Location and device information
  getLocation() {
    if (!this.geolocation) {
      return null;
    }
    
    const { city, country, region } = this.geolocation;
    return [city, region, country].filter(Boolean).join(', ');
  }

  getDeviceInfo() {
    if (!this.device_fingerprint) {
      return null;
    }
    
    const { browser, os, device_type } = this.device_fingerprint;
    return `${browser} on ${os} (${device_type})`;
  }

  // Archival methods
  prepareForArchival() {
    this.archival_data = {
      archived_at: new Date(),
      verification_history: this.audit_trail.filter(entry => 
        entry.action.includes('verification')
      ),
      final_verification_status: this.verification_status,
      key_fingerprint: this.encryption_key_id,
      document_hash_algorithm: this.hash_algorithm,
      signature_algorithm: this.signature_algorithm,
    };
    
    this.addAuditEntry('archived', 'Signature prepared for long-term archival');
    return this;
  }

  // Static methods
  static async createSignature(data) {
    const {
      signerUserId,
      organizationId,
      encryptionKeyId,
      documentHash,
      documentType,
      documentId = null,
      signatureAlgorithm,
      signatureValue,
      purpose,
      context = {},
      ipAddress = null,
      userAgent = null,
      deviceFingerprint = null,
      geolocation = null,
    } = data;

    const signature = await this.create({
      signer_user_id: signerUserId,
      organization_id: organizationId,
      encryption_key_id: encryptionKeyId,
      document_hash: documentHash,
      document_type: documentType,
      document_id: documentId,
      signature_algorithm: signatureAlgorithm,
      signature_value: signatureValue,
      signature_purpose: purpose,
      signature_context: context,
      ip_address: ipAddress,
      user_agent: userAgent,
      device_fingerprint: deviceFingerprint,
      geolocation: geolocation,
      created_by: signerUserId,
    });

    // Auto-verify if possible
    await signature.verify();
    
    return signature;
  }

  static async findByDocument(documentType, documentId) {
    return await this.findAll({
      where: {
        document_type: documentType,
        document_id: documentId,
        is_revoked: false,
      },
      order: [['timestamp', 'DESC']],
      include: [
        {
          model: this.sequelize.models.VotteryUser,
          as: 'signer',
        },
        {
          model: this.sequelize.models.EncryptionKey,
          as: 'encryptionKey',
        },
      ],
    });
  }

  static async findBySigner(signerUserId, options = {}) {
    const { limit = 50, offset = 0, purpose = null } = options;
    
    const whereClause = {
      signer_user_id: signerUserId,
      is_revoked: false,
    };
    
    if (purpose) {
      whereClause.signature_purpose = purpose;
    }
    
    return await this.findAll({
      where: whereClause,
      limit,
      offset,
      order: [['timestamp', 'DESC']],
    });
  }

  static async findByOrganization(organizationId, options = {}) {
    const { limit = 100, offset = 0, status = null } = options;
    
    const whereClause = {
      organization_id: organizationId,
    };
    
    if (status) {
      whereClause.verification_status = status;
    }
    
    return await this.findAll({
      where: whereClause,
      limit,
      offset,
      order: [['timestamp', 'DESC']],
      include: [
        {
          model: this.sequelize.models.VotteryUser,
          as: 'signer',
          attributes: ['id', 'username', 'first_name', 'last_name'],
        },
      ],
    });
  }

  static async findExpiredSignatures() {
    return await this.findAll({
      where: {
        expires_at: {
          [this.sequelize.Sequelize.Op.lt]: new Date(),
        },
        verification_status: {
          [this.sequelize.Sequelize.Op.ne]: 'expired',
        },
      },
    });
  }

  static async findPendingVerification() {
    return await this.findAll({
      where: {
        verification_status: 'pending',
      },
      order: [['timestamp', 'ASC']],
    });
  }

  static async findInvalidSignatures(organizationId = null) {
    const whereClause = {
      verification_status: 'invalid',
    };
    
    if (organizationId) {
      whereClause.organization_id = organizationId;
    }
    
    return await this.findAll({
      where: whereClause,
      order: [['timestamp', 'DESC']],
      include: [
        {
          model: this.sequelize.models.VotteryUser,
          as: 'signer',
        },
      ],
    });
  }

  static async verifyBatch(signatureIds) {
    const signatures = await this.findAll({
      where: {
        id: {
          [this.sequelize.Sequelize.Op.in]: signatureIds,
        },
      },
    });
    
    const results = {
      total: signatures.length,
      verified: 0,
      failed: 0,
      errors: [],
    };
    
    for (const signature of signatures) {
      try {
        const isValid = await signature.verify();
        if (isValid) {
          results.verified++;
        } else {
          results.failed++;
        }
      } catch (error) {
        results.failed++;
        results.errors.push({
          signature_id: signature.id,
          error: error.message,
        });
      }
    }
    
    return results;
  }

  static async cleanupExpiredSignatures() {
    const expiredSignatures = await this.findExpiredSignatures();
    
    const results = {
      processed: 0,
      updated: 0,
      errors: 0,
    };
    
    for (const signature of expiredSignatures) {
      try {
        signature.verification_status = 'expired';
        signature.addAuditEntry('expired', 'Signature marked as expired');
        await signature.save();
        results.updated++;
      } catch (error) {
        results.errors++;
        console.error('Error updating expired signature:', error);
      }
      results.processed++;
    }
    
    return results;
  }

  // Associations
  static associate(models) {
    // Signer user
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'signer_user_id',
      as: 'signer'
    });

    // Organization
    this.belongsTo(models.VotteryOrganization, {
      foreignKey: 'organization_id',
      as: 'organization'
    });

    // Encryption key used for signing
    this.belongsTo(models.EncryptionKey, {
      foreignKey: 'encryption_key_id',
      as: 'encryptionKey'
    });

    // Created by user
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'created_by',
      as: 'creator'
    });

    // Revoked by user
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'revoked_by',
      as: 'revoker'
    });
  }
}

export default (sequelize) => {
  return DigitalSignature.init(sequelize);
};