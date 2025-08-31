import { DataTypes, Model } from 'sequelize';

class OrganizationMember extends Model {
  static init(sequelize) {
    return super.init(
      {
        id: {
          type: DataTypes.UUID,
          defaultValue: DataTypes.UUIDV4,
          primaryKey: true,
          allowNull: false,
        },
        organization_id: {
          type: DataTypes.UUID,
          allowNull: false,
        },
        user_id: {
          type: DataTypes.UUID,
          allowNull: false,
        },
        membership_type: {
          type: DataTypes.ENUM,
          values: ['owner', 'admin', 'member', 'guest', 'contractor'],
          allowNull: false,
          defaultValue: 'member',
        },
        status: {
          type: DataTypes.ENUM,
          values: ['active', 'pending', 'suspended', 'inactive'],
          allowNull: false,
          defaultValue: 'pending',
        },
        joined_at: {
          type: DataTypes.DATE,
          allowNull: true,
          comment: 'When the member accepted the invitation',
        },
        invited_at: {
          type: DataTypes.DATE,
          allowNull: false,
          defaultValue: DataTypes.NOW,
        },
        invited_by: {
          type: DataTypes.UUID,
          allowNull: true,
        },
        invitation_token: {
          type: DataTypes.STRING(128),
          allowNull: true,
          comment: 'Token for invitation acceptance',
        },
        invitation_expires_at: {
          type: DataTypes.DATE,
          allowNull: true,
        },
        is_active: {
          type: DataTypes.BOOLEAN,
          defaultValue: true,
          allowNull: false,
        },
        access_level: {
          type: DataTypes.INTEGER,
          defaultValue: 0,
          allowNull: false,
          comment: 'Numeric access level for quick comparisons',
        },
        permissions: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Organization-specific permissions',
        },
        department: {
          type: DataTypes.STRING(100),
          allowNull: true,
        },
        position: {
          type: DataTypes.STRING(100),
          allowNull: true,
        },
        employee_id: {
          type: DataTypes.STRING(50),
          allowNull: true,
          comment: 'Internal employee/member identifier',
        },
        cost_center: {
          type: DataTypes.STRING(50),
          allowNull: true,
        },
        manager_id: {
          type: DataTypes.UUID,
          allowNull: true,
          comment: 'References another organization member',
        },
        work_location: {
          type: DataTypes.STRING(100),
          allowNull: true,
        },
        timezone: {
          type: DataTypes.STRING(50),
          allowNull: true,
        },
        work_hours: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
          comment: 'Standard work hours configuration',
        },
        notification_preferences: {
          type: DataTypes.JSON,
          defaultValue: {
            email: true,
            in_app: true,
            sms: false,
            desktop: false,
          },
          allowNull: false,
        },
        billing_role: {
          type: DataTypes.ENUM,
          values: ['none', 'viewer', 'admin', 'owner'],
          allowNull: false,
          defaultValue: 'none',
        },
        emergency_contact: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
        },
        onboarding_completed: {
          type: DataTypes.BOOLEAN,
          defaultValue: false,
          allowNull: false,
        },
        onboarding_step: {
          type: DataTypes.INTEGER,
          defaultValue: 0,
          allowNull: false,
        },
        last_activity_at: {
          type: DataTypes.DATE,
          allowNull: true,
        },
        suspension_reason: {
          type: DataTypes.TEXT,
          allowNull: true,
        },
        suspended_by: {
          type: DataTypes.UUID,
          allowNull: true,
        },
        suspended_at: {
          type: DataTypes.DATE,
          allowNull: true,
        },
        notes: {
          type: DataTypes.TEXT,
          allowNull: true,
          comment: 'Internal notes about the member',
        },
        custom_fields: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
          comment: 'Organization-specific custom fields',
        },
        metadata: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
        },
      },
      {
        sequelize,
        modelName: 'OrganizationMember',
        tableName: 'organization_members',
        paranoid: true,
        indexes: [
          {
            unique: true,
            fields: ['organization_id', 'user_id'],
            name: 'unique_org_user_membership',
          },
          {
            fields: ['invitation_token'],
            name: 'idx_invitation_token',
          },
        ],
        hooks: {
          beforeCreate: (member) => {
            member.setAccessLevelFromType();
          },
          beforeUpdate: (member) => {
            if (member.changed('membership_type')) {
              member.setAccessLevelFromType();
            }
          },
        },
      }
    );
  }

  // Instance methods
  setAccessLevelFromType() {
    const levelMap = {
      owner: 1000,
      admin: 800,
      member: 400,
      guest: 200,
      contractor: 100,
    };
    this.access_level = levelMap[this.membership_type] || 0;
  }

  isOwner() {
    return this.membership_type === 'owner';
  }

  isAdmin() {
    return this.membership_type === 'admin';
  }

  isMember() {
    return this.membership_type === 'member';
  }

  isGuest() {
    return this.membership_type === 'guest';
  }

  isContractor() {
    return this.membership_type === 'contractor';
  }

  isPending() {
    return this.status === 'pending';
  }

  isActive() {
    return this.status === 'active' && this.is_active;
  }

  isSuspended() {
    return this.status === 'suspended';
  }

  hasHigherAccessThan(otherMember) {
    return this.access_level > otherMember.access_level;
  }

  hasLowerAccessThan(otherMember) {
    return this.access_level < otherMember.access_level;
  }

  hasSameAccessAs(otherMember) {
    return this.access_level === otherMember.access_level;
  }

  canManageMember(otherMember) {
    if (this.isOwner()) {
      return true;
    }
    
    if (this.isAdmin()) {
      return !otherMember.isOwner();
    }
    
    return false;
  }

  // Permission methods
  hasPermission(permission) {
    if (!this.permissions || !Array.isArray(this.permissions)) {
      return false;
    }

    // Owner has all permissions
    if (this.isOwner()) {
      return true;
    }

    return this.permissions.includes(permission) || this.permissions.includes('*');
  }

  addPermission(permission) {
    if (!this.permissions) {
      this.permissions = [];
    }

    if (!this.permissions.includes(permission)) {
      this.permissions.push(permission);
    }

    return this;
  }

  removePermission(permission) {
    if (!this.permissions || !Array.isArray(this.permissions)) {
      return this;
    }

    this.permissions = this.permissions.filter(perm => perm !== permission);
    return this;
  }

  // Invitation methods
  async generateInvitationToken() {
    const crypto = await import('node:crypto');
    this.invitation_token = crypto.randomBytes(32).toString('hex');
    
    // Set expiration to 7 days from now
    this.invitation_expires_at = new Date();
    this.invitation_expires_at.setDate(this.invitation_expires_at.getDate() + 7);
    
    return this.invitation_token;
  }

  isInvitationValid() {
    if (!this.invitation_token || !this.invitation_expires_at) {
      return false;
    }

    return new Date() < this.invitation_expires_at;
  }

  async acceptInvitation() {
    if (!this.isInvitationValid()) {
      throw new Error('Invitation has expired or is invalid');
    }

    this.status = 'active';
    this.joined_at = new Date();
    this.invitation_token = null;
    this.invitation_expires_at = null;
    
    return await this.save();
  }

  async rejectInvitation() {
    this.status = 'inactive';
    this.invitation_token = null;
    this.invitation_expires_at = null;
    
    return await this.save();
  }

  // Status management
  async activate() {
    this.status = 'active';
    this.is_active = true;
    
    if (!this.joined_at) {
      this.joined_at = new Date();
    }
    
    return await this.save();
  }

  async suspend(reason = null, suspendedBy = null) {
    this.status = 'suspended';
    this.suspension_reason = reason;
    this.suspended_by = suspendedBy;
    this.suspended_at = new Date();
    
    return await this.save();
  }

  async unsuspend() {
    this.status = 'active';
    this.suspension_reason = null;
    this.suspended_by = null;
    this.suspended_at = null;
    
    return await this.save();
  }

  async deactivate() {
    this.status = 'inactive';
    this.is_active = false;
    
    return await this.save();
  }

  // Onboarding methods
  async completeOnboardingStep(step = null) {
    if (step !== null) {
      this.onboarding_step = step;
    } else {
      this.onboarding_step += 1;
    }
    
    return await this.save();
  }

  async completeOnboarding() {
    this.onboarding_completed = true;
    this.onboarding_step = -1; // Mark as fully completed
    
    return await this.save();
  }

  isOnboardingComplete() {
    return this.onboarding_completed;
  }

  // Activity tracking
  async updateLastActivity() {
    this.last_activity_at = new Date();
    return await this.save();
  }

  getDaysSinceLastActivity() {
    if (!this.last_activity_at) {
      return null;
    }
    
    const now = new Date();
    const diffTime = now - this.last_activity_at;
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  }

  isInactive(days = 30) {
    const daysSince = this.getDaysSinceLastActivity();
    return daysSince !== null && daysSince > days;
  }

  // Notification preferences
  updateNotificationPreference(type, enabled) {
    if (!this.notification_preferences) {
      this.notification_preferences = {};
    }
    
    this.notification_preferences[type] = enabled;
    return this;
  }

  getNotificationPreference(type) {
    return this.notification_preferences?.[type] || false;
  }

  // Custom fields management
  setCustomField(key, value) {
    if (!this.custom_fields) {
      this.custom_fields = {};
    }
    
    this.custom_fields[key] = value;
    return this;
  }

  getCustomField(key) {
    return this.custom_fields?.[key];
  }

  removeCustomField(key) {
    if (this.custom_fields && this.custom_fields[key]) {
      delete this.custom_fields[key];
    }
    return this;
  }

  // Static methods
  static async findByInvitationToken(token) {
    return await this.findOne({
      where: {
        invitation_token: token,
        invitation_expires_at: {
          [this.sequelize.Sequelize.Op.gt]: new Date(),
        },
      },
    });
  }

  static async findActiveMembers(organizationId) {
    return await this.findAll({
      where: {
        organization_id: organizationId,
        status: 'active',
        is_active: true,
      },
      include: [
        {
          model: this.sequelize.models.VotteryUser,
          as: 'user',
        },
      ],
      order: [['access_level', 'DESC'], ['joined_at', 'ASC']],
    });
  }

  static async findPendingInvitations(organizationId) {
    return await this.findAll({
      where: {
        organization_id: organizationId,
        status: 'pending',
        invitation_expires_at: {
          [this.sequelize.Sequelize.Op.gt]: new Date(),
        },
      },
      include: [
        {
          model: this.sequelize.models.VotteryUser,
          as: 'user',
        },
      ],
    });
  }

  static async findExpiredInvitations() {
    return await this.findAll({
      where: {
        status: 'pending',
        invitation_expires_at: {
          [this.sequelize.Sequelize.Op.lt]: new Date(),
        },
      },
    });
  }

  static async findInactiveMembers(organizationId, days = 30) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);

    return await this.findAll({
      where: {
        organization_id: organizationId,
        status: 'active',
        last_activity_at: {
          [this.sequelize.Sequelize.Op.lt]: cutoffDate,
        },
      },
      include: [
        {
          model: this.sequelize.models.VotteryUser,
          as: 'user',
        },
      ],
    });
  }

  static async findByMembershipType(organizationId, membershipType) {
    return await this.findAll({
      where: {
        organization_id: organizationId,
        membership_type: membershipType,
        status: 'active',
        is_active: true,
      },
      include: [
        {
          model: this.sequelize.models.VotteryUser,
          as: 'user',
        },
      ],
    });
  }

  static async findOwners(organizationId) {
    return await this.findByMembershipType(organizationId, 'owner');
  }

  static async findAdmins(organizationId) {
    return await this.findByMembershipType(organizationId, 'admin');
  }

  static async inviteUser(organizationId, userId, options = {}) {
    const {
      membershipType = 'member',
      invitedBy = null,
      permissions = [],
      department = null,
      position = null,
      customFields = {},
    } = options;

    // Check if membership already exists
    const existingMembership = await this.findOne({
      where: {
        organization_id: organizationId,
        user_id: userId,
      },
    });

    if (existingMembership) {
      if (existingMembership.status === 'active') {
        throw new Error('User is already a member of this organization');
      }
      
      if (existingMembership.status === 'pending') {
        // Refresh the invitation
        await existingMembership.generateInvitationToken();
        return await existingMembership.save();
      }
    }

    // Create new membership
    const membership = await this.create({
      organization_id: organizationId,
      user_id: userId,
      membership_type: membershipType,
      status: 'pending',
      invited_by: invitedBy,
      permissions,
      department,
      position,
      custom_fields: customFields,
    });

    await membership.generateInvitationToken();
    return await membership.save();
  }

  static async cleanupExpiredInvitations() {
    const expiredInvitations = await this.findExpiredInvitations();
    
    const results = {
      processed: 0,
      cleaned: 0,
      errors: 0,
    };

    for (const membership of expiredInvitations) {
      try {
        membership.status = 'inactive';
        membership.invitation_token = null;
        membership.invitation_expires_at = null;
        await membership.save();
        results.cleaned++;
      } catch (error) {
        results.errors++;
        console.error('Error cleaning up expired invitation:', error);
      }
      results.processed++;
    }

    return results;
  }

  // Associations
  static associate(models) {
    // User
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'user_id',
      as: 'user'
    });

    // Organization
    this.belongsTo(models.VotteryOrganization, {
      foreignKey: 'organization_id',
      as: 'organization'
    });

    // Invited by user
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'invited_by',
      as: 'inviter'
    });

    // Suspended by user
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'suspended_by',
      as: 'suspender'
    });

    // Manager (self-referencing to another organization member)
    this.belongsTo(models.OrganizationMember, {
      foreignKey: 'manager_id',
      as: 'manager'
    });

    // Direct reports (self-referencing)
    this.hasMany(models.OrganizationMember, {
      foreignKey: 'manager_id',
      as: 'directReports'
    });
  }
}

export default (sequelize) => {
  return OrganizationMember.init(sequelize);
};