import { DataTypes, Model } from 'sequelize';

class UserActivityLog extends Model {
  static init(sequelize) {
    return super.init(
      {
        id: {
          type: DataTypes.UUID,
          defaultValue: DataTypes.UUIDV4,
          primaryKey: true,
          allowNull: false,
        },
        user_id: {
          type: DataTypes.UUID,
          allowNull: false,
        },
        organization_id: {
          type: DataTypes.UUID,
          allowNull: true,
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
      },
      {
        sequelize,
        modelName: 'UserActivityLog',
        tableName: 'vottery_user_activity_logs',
        timestamps: true,
        paranoid: false, // Don't soft delete audit logs
        updatedAt: false, // Activity logs are immutable
        hooks: {
          beforeCreate: (log) => {
            // Sanitize sensitive data
            log.sanitizeData();
          },
        },
      }
    );
  }

  // Instance methods
  sanitizeData() {
    // Remove sensitive information from request parameters
    if (this.request_params) {
      const sensitiveFields = ['password', 'token', 'secret', 'key', 'authorization'];
      const sanitized = { ...this.request_params };
      
      sensitiveFields.forEach(field => {
        if (sanitized[field]) {
          sanitized[field] = '[REDACTED]';
        }
      });
      
      this.request_params = sanitized;
    }

    // Sanitize old/new values
    this.sanitizeValues('old_values');
    this.sanitizeValues('new_values');
  }

  sanitizeValues(field) {
    if (this[field]) {
      const sensitiveFields = ['password', 'password_hash', 'salt', 'two_factor_secret', 'backup_codes'];
      const sanitized = { ...this[field] };
      
      sensitiveFields.forEach(sensitive => {
        if (sanitized[sensitive]) {
          sanitized[sensitive] = '[REDACTED]';
        }
      });
      
      this[field] = sanitized;
    }
  }

  isSuccessful() {
    return this.success === true;
  }

  isFailed() {
    return this.success === false;
  }

  hasError() {
    return !!this.error_message || !!this.error_code;
  }

  isHighRisk() {
    return this.risk_score && this.risk_score >= 70;
  }

  isMediumRisk() {
    return this.risk_score && this.risk_score >= 40 && this.risk_score < 70;
  }

  isLowRisk() {
    return this.risk_score && this.risk_score < 40;
  }

  hasSecurityFlag(flag) {
    return this.security_flags && this.security_flags.includes(flag);
  }

  addSecurityFlag(flag) {
    if (!this.security_flags) {
      this.security_flags = [];
    }
    
    if (!this.security_flags.includes(flag)) {
      this.security_flags.push(flag);
    }
    
    return this;
  }

  hasComplianceFlag(flag) {
    return this.compliance_flags && this.compliance_flags.includes(flag);
  }

  addComplianceFlag(flag) {
    if (!this.compliance_flags) {
      this.compliance_flags = [];
    }
    
    if (!this.compliance_flags.includes(flag)) {
      this.compliance_flags.push(flag);
    }
    
    return this;
  }

  getLocation() {
    if (!this.geolocation) {
      return null;
    }
    
    const { city, country, region } = this.geolocation;
    return [city, region, country].filter(Boolean).join(', ');
  }

  getBrowserInfo() {
    if (!this.device_info || !this.device_info.browser) {
      return null;
    }
    
    const { name, version } = this.device_info.browser;
    return `${name} ${version}`;
  }

  getDeviceInfo() {
    if (!this.device_info || !this.device_info.device) {
      return null;
    }
    
    const { type, os } = this.device_info.device;
    return `${type} (${os})`;
  }

  isFromMobileDevice() {
    return this.device_info?.device?.type === 'mobile';
  }

  isFromTabletDevice() {
    return this.device_info?.device?.type === 'tablet';
  }

  isFromDesktopDevice() {
    return this.device_info?.device?.type === 'desktop';
  }

  // Change tracking helpers
  getChangedFields() {
    if (!this.old_values || !this.new_values) {
      return [];
    }
    
    const changedFields = [];
    const allFields = new Set([
      ...Object.keys(this.old_values),
      ...Object.keys(this.new_values)
    ]);
    
    allFields.forEach(field => {
      const oldVal = this.old_values[field];
      const newVal = this.new_values[field];
      
      if (JSON.stringify(oldVal) !== JSON.stringify(newVal)) {
        changedFields.push(field);
      }
    });
    
    return changedFields;
  }

  getFieldChange(field) {
    if (!this.old_values || !this.new_values) {
      return null;
    }
    
    return {
      field,
      from: this.old_values[field],
      to: this.new_values[field],
    };
  }

  // Static methods for logging
  static async logActivity(data) {
    try {
      return await this.create(data);
    } catch (error) {
      console.error('Failed to log activity:', error);
      // Don't throw - logging failures shouldn't break the application
      return null;
    }
  }

  static async logLogin(userId, data = {}) {
    return await this.logActivity({
      user_id: userId,
      activity_type: 'login',
      activity_category: 'authentication',
      action_performed: 'User logged in',
      success: true,
      ...data,
    });
  }

  static async logLoginFailure(userId, data = {}) {
    return await this.logActivity({
      user_id: userId,
      activity_type: 'login_failed',
      activity_category: 'authentication',
      action_performed: 'Failed login attempt',
      success: false,
      ...data,
    });
  }

  static async logLogout(userId, data = {}) {
    return await this.logActivity({
      user_id: userId,
      activity_type: 'logout',
      activity_category: 'authentication',
      action_performed: 'User logged out',
      success: true,
      ...data,
    });
  }

  static async logProfileUpdate(userId, oldValues, newValues, data = {}) {
    return await this.logActivity({
      user_id: userId,
      activity_type: 'profile_update',
      activity_category: 'profile',
      action_performed: 'Profile updated',
      old_values: oldValues,
      new_values: newValues,
      success: true,
      ...data,
    });
  }

  static async logPasswordChange(userId, data = {}) {
    return await this.logActivity({
      user_id: userId,
      activity_type: 'password_change',
      activity_category: 'security',
      action_performed: 'Password changed',
      success: true,
      ...data,
    });
  }

  static async logApiAccess(userId, data = {}) {
    return await this.logActivity({
      user_id: userId,
      activity_type: 'api_access',
      activity_category: 'api',
      action_performed: 'API endpoint accessed',
      success: true,
      ...data,
    });
  }

  // Query helpers
  static async findByUser(userId, options = {}) {
    const { limit = 50, offset = 0, category = null, type = null } = options;
    
    const whereClause = { user_id: userId };
    if (category) whereClause.activity_category = category;
    if (type) whereClause.activity_type = type;
    
    return await this.findAll({
      where: whereClause,
      limit,
      offset,
      order: [['created_at', 'DESC']],
    });
  }

  static async findByOrganization(organizationId, options = {}) {
    const { limit = 100, offset = 0, category = null } = options;
    
    const whereClause = { organization_id: organizationId };
    if (category) whereClause.activity_category = category;
    
    return await this.findAll({
      where: whereClause,
      limit,
      offset,
      order: [['created_at', 'DESC']],
      include: [
        {
          model: this.sequelize.models.VotteryUser,
          as: 'user',
          attributes: ['id', 'username', 'first_name', 'last_name'],
        },
      ],
    });
  }

  static async findFailedLogins(timeframe = '24 hours') {
    const timeAgo = new Date();
    timeAgo.setHours(timeAgo.getHours() - 24);
    
    return await this.findAll({
      where: {
        activity_type: 'login_failed',
        created_at: {
          [this.sequelize.Sequelize.Op.gte]: timeAgo,
        },
      },
      order: [['created_at', 'DESC']],
    });
  }

  static async findHighRiskActivities(timeframe = '1 hour') {
    const timeAgo = new Date();
    timeAgo.setHours(timeAgo.getHours() - 1);
    
    return await this.findAll({
      where: {
        risk_score: {
          [this.sequelize.Sequelize.Op.gte]: 70,
        },
        created_at: {
          [this.sequelize.Sequelize.Op.gte]: timeAgo,
        },
      },
      order: [['risk_score', 'DESC'], ['created_at', 'DESC']],
    });
  }

  static async findByCorrelationId(correlationId) {
    return await this.findAll({
      where: {
        correlation_id: correlationId,
      },
      order: [['created_at', 'ASC']],
    });
  }

  static async cleanupOldLogs() {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - 2555); // 7 years default retention
    
    return await this.destroy({
      where: {
        created_at: {
          [this.sequelize.Sequelize.Op.lt]: cutoffDate,
        },
      },
      force: true, // Hard delete
    });
  }

  // Associations
  static associate(models) {
    // User who performed the activity
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'user_id',
      as: 'user'
    });

    // Organization context
    this.belongsTo(models.VotteryOrganization, {
      foreignKey: 'organization_id',
      as: 'organization'
    });

    // User who performed the action (for admin actions)
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'performed_by',
      as: 'performer'
    });

    // Parent activity (for nested operations)
    this.belongsTo(models.UserActivityLog, {
      foreignKey: 'parent_activity_id',
      as: 'parentActivity'
    });

    // Child activities
    this.hasMany(models.UserActivityLog, {
      foreignKey: 'parent_activity_id',
      as: 'childActivities'
    });
  }
}

export default (sequelize) => {
  return UserActivityLog.init(sequelize);
};