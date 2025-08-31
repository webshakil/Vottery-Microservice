import { DataTypes } from 'sequelize';

const up = async (queryInterface, Sequelize) => {
  await queryInterface.createTable('vottery_user_activity_logs', {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
      allowNull: false,
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
    },
    activity_type: {
      type: DataTypes.ENUM,
      values: [
        'login', 'logout', 'login_failed', 'password_change', 'password_reset',
        'profile_update', 'email_change', 'phone_change', '2fa_enable', '2fa_disable',
        'role_assigned', 'role_removed', 'permission_granted', 'permission_revoked',
        'key_generated', 'key_rotated', 'key_revoked', 'signature_created',
        'vote_cast', 'vote_updated', 'vote_deleted', 'poll_created', 'poll_updated',
        'organization_joined', 'organization_left', 'subscription_updated',
        'api_access', 'export_data', 'import_data', 'security_event',
        'system_action', 'admin_action', 'bulk_operation', 'other'
      ],
      allowNull: false,
    },
    activity_category: {
      type: DataTypes.ENUM,
      values: ['authentication', 'profile', 'security', 'voting', 'administration', 'api', 'system'],
      allowNull: false,
    },
    action_performed: {
      type: DataTypes.STRING(200),
      allowNull: false,
      comment: 'Detailed description of the action',
    },
    resource_type: {
      type: DataTypes.STRING(50),
      allowNull: true,
      comment: 'Type of resource affected (user, vote, poll, etc.)',
    },
    resource_id: {
      type: DataTypes.UUID,
      allowNull: true,
      comment: 'ID of the affected resource',
    },
    old_values: {
      type: DataTypes.JSON,
      allowNull: true,
      comment: 'Previous values before change (for updates)',
    },
    new_values: {
      type: DataTypes.JSON,
      allowNull: true,
      comment: 'New values after change (for updates)',
    },
    ip_address: {
      type: DataTypes.INET,
      allowNull: true,
    },
    user_agent: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    session_id: {
      type: DataTypes.STRING(128),
      allowNull: true,
    },
    device_info: {
      type: DataTypes.JSON,
      defaultValue: {},
      allowNull: false,
      comment: 'Device fingerprint and browser info',
    },
    geolocation: {
      type: DataTypes.JSON,
      allowNull: true,
      comment: 'Geographic location data if available',
    },
    request_method: {
      type: DataTypes.STRING(10),
      allowNull: true,
      comment: 'HTTP method for API calls',
    },
    request_path: {
      type: DataTypes.STRING(500),
      allowNull: true,
      comment: 'API endpoint or page path',
    },
    request_params: {
      type: DataTypes.JSON,
      allowNull: true,
      comment: 'Sanitized request parameters',
    },
    response_status: {
      type: DataTypes.INTEGER,
      allowNull: true,
      comment: 'HTTP response status code',
    },
    response_time_ms: {
      type: DataTypes.INTEGER,
      allowNull: true,
      comment: 'Request processing time in milliseconds',
    },
    success: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
      allowNull: false,
    },
    error_message: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    error_code: {
      type: DataTypes.STRING(50),
      allowNull: true,
    },
    risk_score: {
      type: DataTypes.INTEGER,
      allowNull: true,
      comment: 'Security risk score (0-100)',
    },
    security_flags: {
      type: DataTypes.JSON,
      defaultValue: [],
      allowNull: false,
      comment: 'Array of security-related flags',
    },
    correlation_id: {
      type: DataTypes.UUID,
      allowNull: true,
      comment: 'Links related activities together',
    },
    parent_activity_id: {
      type: DataTypes.UUID,
      allowNull: true,
      references: {
        model: 'vottery_user_activity_logs',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'SET NULL',
      comment: 'Links to parent activity for nested operations',
    },
    batch_id: {
      type: DataTypes.UUID,
      allowNull: true,
      comment: 'Groups activities from bulk operations',
    },
    performed_by: {
      type: DataTypes.UUID,
      allowNull: true,
      references: {
        model: 'vottery_users',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'SET NULL',
      comment: 'User who performed action (for admin actions)',
    },
    automated: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
      allowNull: false,
      comment: 'Whether this was an automated system action',
    },
    retention_period_days: {
      type: DataTypes.INTEGER,
      defaultValue: 2555, // 7 years
      allowNull: false,
      comment: 'How long to retain this log entry',
    },
    compliance_flags: {
      type: DataTypes.JSON,
      defaultValue: [],
      allowNull: false,
      comment: 'Compliance-related tags (GDPR, HIPAA, etc.)',
    },
    additional_data: {
      type: DataTypes.JSON,
      defaultValue: {},
      allowNull: false,
      comment: 'Additional contextual information',
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
    },
  });

  // Add indexes for performance (activity logs are heavily queried)
  await queryInterface.addIndex('vottery_user_activity_logs', ['user_id']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['organization_id']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['activity_type']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['activity_category']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['resource_type']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['resource_id']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['ip_address']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['session_id']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['success']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['correlation_id']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['batch_id']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['performed_by']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['automated']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['created_at']);
  
  // Composite indexes for common queries
  await queryInterface.addIndex('vottery_user_activity_logs', ['user_id', 'created_at']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['user_id', 'activity_type']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['organization_id', 'created_at']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['activity_type', 'created_at']);
  await queryInterface.addIndex('vottery_user_activity_logs', ['user_id', 'success', 'created_at']);
};

const down = async (queryInterface, Sequelize) => {
  await queryInterface.dropTable('vottery_user_activity_logs');
};

export { up, down };