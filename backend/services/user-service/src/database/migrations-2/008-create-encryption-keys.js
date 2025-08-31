// // database/migrations/008-create-encryption-keys.js
// import { DataTypes } from 'sequelize';

// export default {
//   up: async (queryInterface, Sequelize) => {
//     await queryInterface.createTable('encryption_keys', {
//       id: {
//         allowNull: false,
//         autoIncrement: true,
//         primaryKey: true,
//         type: DataTypes.INTEGER
//       },
//       user_id: {
//         type: DataTypes.INTEGER,
//         allowNull: false,
//         references: {
//           model: 'vottery_users',
//           key: 'id'
//         },
//         onDelete: 'CASCADE',
//         onUpdate: 'CASCADE'
//       },
//       key_type: {
//         type: DataTypes.ENUM('rsa_public', 'rsa_private', 'elgamal_public', 'elgamal_private', 'threshold'),
//         allowNull: false
//       },
//       key_data_encrypted: {
//         type: DataTypes.TEXT,
//         allowNull: false
//       },
//       key_fingerprint: {
//         type: DataTypes.STRING(128),
//         allowNull: false,
//         unique: true
//       },
//       created_at: {
//         allowNull: false,
//         type: DataTypes.DATE,
//         defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
//       },
//       expires_at: {
//         type: DataTypes.DATE,
//         allowNull: true
//       },
//       revoked_at: {
//         type: DataTypes.DATE,
//         allowNull: true
//       }
//     });

//     // Add indexes
//     await queryInterface.addIndex('encryption_keys', ['user_id'], {
//       name: 'idx_encryption_keys_user_id'
//     });

//     await queryInterface.addIndex('encryption_keys', ['key_type'], {
//       name: 'idx_encryption_keys_key_type'
//     });

//     await queryInterface.addIndex('encryption_keys', ['key_fingerprint'], {
//       name: 'idx_encryption_keys_fingerprint',
//       unique: true
//     });

//     await queryInterface.addIndex('encryption_keys', ['created_at'], {
//       name: 'idx_encryption_keys_created_at'
//     });

//     await queryInterface.addIndex('encryption_keys', ['expires_at'], {
//       name: 'idx_encryption_keys_expires_at'
//     });

//     await queryInterface.addIndex('encryption_keys', ['revoked_at'], {
//       name: 'idx_encryption_keys_revoked_at'
//     });

//     // Composite index for user and key type
//     await queryInterface.addIndex('encryption_keys', ['user_id', 'key_type'], {
//       name: 'idx_encryption_keys_user_type'
//     });
//   },

//   down: async (queryInterface, Sequelize) => {
//     await queryInterface.dropTable('encryption_keys');
//   }
// };

import { DataTypes } from 'sequelize';

const up = async (queryInterface, Sequelize) => {
  await queryInterface.createTable('vottery_api_tokens', {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
      allowNull: false,
    },
    token_hash: {
      type: DataTypes.STRING(128),
      allowNull: false,
      unique: true,
      comment: 'SHA-256 hash of the actual token',
    },
    token_prefix: {
      type: DataTypes.STRING(10),
      allowNull: false,
      comment: 'First few characters for identification',
    },
    user_id: {
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
      allowNull: true,
      references: {
        model: 'vottery_organizations',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE',
      comment: 'Organization scope (null for personal tokens)',
    },
    name: {
      type: DataTypes.STRING(100),
      allowNull: false,
      comment: 'Human-readable token name',
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    token_type: {
      type: DataTypes.ENUM,
      values: ['personal', 'organization', 'service', 'integration', 'temporary'],
      allowNull: false,
      defaultValue: 'personal',
    },
    scopes: {
      type: DataTypes.JSON,
      defaultValue: [],
      allowNull: false,
      comment: 'Array of permission scopes',
    },
    permissions: {
      type: DataTypes.JSON,
      defaultValue: [],
      allowNull: false,
      comment: 'Specific API permissions',
    },
    rate_limit_tier: {
      type: DataTypes.ENUM,
      values: ['basic', 'standard', 'premium', 'unlimited'],
      allowNull: false,
      defaultValue: 'basic',
    },
    rate_limit_per_minute: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 60,
    },
    rate_limit_per_hour: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 1000,
    },
    rate_limit_per_day: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 10000,
    },
    allowed_ips: {
      type: DataTypes.JSON,
      defaultValue: [],
      allowNull: false,
      comment: 'IP whitelist (empty = all IPs allowed)',
    },
    allowed_domains: {
      type: DataTypes.JSON,
      defaultValue: [],
      allowNull: false,
      comment: 'Domain whitelist for CORS',
    },
    is_active: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
      allowNull: false,
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
      comment: 'Token expiration (null = never expires)',
    },
    last_used_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    last_used_ip: {
      type: DataTypes.INET,
      allowNull: true,
    },
    last_used_user_agent: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    usage_count: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
      allowNull: false,
    },
    max_usage_count: {
      type: DataTypes.INTEGER,
      allowNull: true,
      comment: 'Maximum allowed uses (null = unlimited)',
    },
    current_rate_limit_count: {
      type: DataTypes.JSON,
      defaultValue: {
        minute: 0,
        hour: 0,
        day: 0,
        last_reset: null,
      },
      allowNull: false,
    },
    webhook_url: {
      type: DataTypes.TEXT,
      allowNull: true,
      comment: 'Webhook for token events',
    },
    webhook_secret: {
      type: DataTypes.STRING(128),
      allowNull: true,
      comment: 'Secret for webhook signature verification',
    },
    security_settings: {
      type: DataTypes.JSON,
      defaultValue: {
        require_https: true,
        allow_cors: false,
        log_all_requests: false,
        alert_on_suspicious: true,
      },
      allowNull: false,
    },
    audit_log: {
      type: DataTypes.JSON,
      defaultValue: [],
      allowNull: false,
      comment: 'Recent usage and security events',
    },
    integration_metadata: {
      type: DataTypes.JSON,
      defaultValue: {},
      allowNull: false,
      comment: 'Integration-specific data',
    },
    created_by: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: 'vottery_users',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'RESTRICT',
    },
    updated_by: {
      type: DataTypes.UUID,
      allowNull: true,
      references: {
        model: 'vottery_users',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'SET NULL',
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
  await queryInterface.addIndex('vottery_api_tokens', ['token_hash']);
  await queryInterface.addIndex('vottery_api_tokens', ['token_prefix']);
  await queryInterface.addIndex('vottery_api_tokens', ['user_id']);
  await queryInterface.addIndex('vottery_api_tokens', ['organization_id']);
  await queryInterface.addIndex('vottery_api_tokens', ['token_type']);
  await queryInterface.addIndex('vottery_api_tokens', ['is_active']);
  await queryInterface.addIndex('vottery_api_tokens', ['is_revoked']);
  await queryInterface.addIndex('vottery_api_tokens', ['expires_at']);
  await queryInterface.addIndex('vottery_api_tokens', ['last_used_at']);
  await queryInterface.addIndex('vottery_api_tokens', ['user_id', 'is_active']);
  await queryInterface.addIndex('vottery_api_tokens', ['organization_id', 'is_active']);
  await queryInterface.addIndex('vottery_api_tokens', ['token_hash', 'is_active']);
};

const down = async (queryInterface, Sequelize) => {
  await queryInterface.dropTable('vottery_api_tokens');
};

export { up, down };