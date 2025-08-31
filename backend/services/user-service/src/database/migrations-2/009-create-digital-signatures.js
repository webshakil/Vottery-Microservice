import { DataTypes } from 'sequelize';

const up = async (queryInterface, Sequelize) => {
  await queryInterface.createTable('vottery_digital_signatures', {
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
      references: {
        model: 'vottery_users',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE',
    },
    organization_id: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: 'vottery_organizations',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE',
    },
    encryption_key_id: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: 'vottery_encryption_keys',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'RESTRICT',
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
      defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
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
      references: {
        model: 'vottery_users',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'SET NULL',
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
      references: {
        model: 'vottery_users',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'SET NULL',
      comment: 'May be different from signer_user_id for system signatures',
    },
    metadata: {
      type: DataTypes.JSON,
      defaultValue: {},
      allowNull: false,
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
    },
    updated_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
    },
    deleted_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
  });

  // Add indexes for performance and security
  await queryInterface.addIndex('vottery_digital_signatures', ['signature_id']);
  await queryInterface.addIndex('vottery_digital_signatures', ['signer_user_id']);
  await queryInterface.addIndex('vottery_digital_signatures', ['organization_id']);
  await queryInterface.addIndex('vottery_digital_signatures', ['encryption_key_id']);
  await queryInterface.addIndex('vottery_digital_signatures', ['document_hash']);
  await queryInterface.addIndex('vottery_digital_signatures', ['document_type']);
  await queryInterface.addIndex('vottery_digital_signatures', ['document_id']);
  await queryInterface.addIndex('vottery_digital_signatures', ['signature_algorithm']);
  await queryInterface.addIndex('vottery_digital_signatures', ['verification_status']);
  await queryInterface.addIndex('vottery_digital_signatures', ['signature_purpose']);
  await queryInterface.addIndex('vottery_digital_signatures', ['is_revoked']);
  await queryInterface.addIndex('vottery_digital_signatures', ['expires_at']);
  await queryInterface.addIndex('vottery_digital_signatures', ['timestamp']);
  await queryInterface.addIndex('vottery_digital_signatures', ['signer_user_id', 'timestamp']);
  await queryInterface.addIndex('vottery_digital_signatures', ['organization_id', 'timestamp']);
  await queryInterface.addIndex('vottery_digital_signatures', ['document_type', 'document_id']);
  await queryInterface.addIndex('vottery_digital_signatures', ['verification_status', 'timestamp']);
};

const down = async (queryInterface, Sequelize) => {
  await queryInterface.dropTable('vottery_digital_signatures');
};

export { up, down };