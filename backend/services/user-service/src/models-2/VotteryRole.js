import { DataTypes, Model } from 'sequelize';

class VotteryRole extends Model {
  static init(sequelize) {
    return super.init(
      {
        id: {
          type: DataTypes.UUID,
          defaultValue: DataTypes.UUIDV4,
          primaryKey: true,
          allowNull: false,
        },
        name: {
          type: DataTypes.STRING(50),
          allowNull: false,
          unique: true,
          validate: {
            len: [2, 50],
          },
        },
        slug: {
          type: DataTypes.STRING(50),
          allowNull: false,
          unique: true,
          validate: {
            is: /^[a-z0-9-_]+$/,
          },
        },
        description: {
          type: DataTypes.TEXT,
          allowNull: true,
        },
        level: {
          type: DataTypes.INTEGER,
          allowNull: false,
          defaultValue: 0,
          comment: 'Higher level = higher priority/authority',
        },
        permissions: {
          type: DataTypes.JSON,
          allowNull: false,
          defaultValue: [],
          comment: 'Array of permission strings',
        },
        is_system_role: {
          type: DataTypes.BOOLEAN,
          defaultValue: false,
          allowNull: false,
          comment: 'System roles cannot be deleted',
        },
        is_active: {
          type: DataTypes.BOOLEAN,
          defaultValue: true,
          allowNull: false,
        },
        max_users: {
          type: DataTypes.INTEGER,
          allowNull: true,
          comment: 'Maximum users allowed for this role (null = unlimited)',
        },
        role_metadata: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
        },
        created_by: {
          type: DataTypes.UUID,
          allowNull: true,
        },
        updated_by: {
          type: DataTypes.UUID,
          allowNull: true,
        },
      },
      {
        sequelize,
        modelName: 'VotteryRole',
        tableName: 'vottery_roles',
        paranoid: true,
        hooks: {
          beforeCreate: (role) => {
            if (!role.slug) {
              role.slug = role.name.toLowerCase().replace(/[^a-z0-9]/g, '-');
            }
          },
          beforeUpdate: (role) => {
            if (role.changed('name') && !role.changed('slug')) {
              role.slug = role.name.toLowerCase().replace(/[^a-z0-9]/g, '-');
            }
          },
        },
      }
    );
  }

  // Instance methods
  hasPermission(permission) {
    if (!this.permissions || !Array.isArray(this.permissions)) {
      return false;
    }

    // Check for wildcard permission
    if (this.permissions.includes('*')) {
      return true;
    }

    // Check for exact permission match
    if (this.permissions.includes(permission)) {
      return true;
    }

    // Check for wildcard patterns (e.g., 'user.*' matches 'user.read')
    return this.permissions.some(perm => {
      if (perm.endsWith('.*')) {
        const prefix = perm.slice(0, -2);
        return permission.startsWith(prefix + '.');
      }
      return false;
    });
  }

  hasAnyPermission(permissions) {
    if (!Array.isArray(permissions)) {
      return false;
    }

    return permissions.some(permission => this.hasPermission(permission));
  }

  hasAllPermissions(permissions) {
    if (!Array.isArray(permissions)) {
      return false;
    }

    return permissions.every(permission => this.hasPermission(permission));
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

  setPermissions(permissions) {
    this.permissions = Array.isArray(permissions) ? permissions : [];
    return this;
  }

  async getUserCount() {
    const UserRole = this.sequelize.models.VotteryUserRole;
    return await UserRole.count({
      where: {
        role_id: this.id,
        is_active: true,
      },
    });
  }

  async isAtMaxCapacity() {
    if (!this.max_users) {
      return false;
    }

    const currentCount = await this.getUserCount();
    return currentCount >= this.max_users;
  }

  canBeDeleted() {
    return !this.is_system_role;
  }

  canBeModified() {
    // System roles can be modified but not deleted
    return true;
  }

  getHierarchyLevel() {
    return this.level;
  }

  isHigherThan(otherRole) {
    return this.level > otherRole.level;
  }

  isLowerThan(otherRole) {
    return this.level < otherRole.level;
  }

  isSameLevelAs(otherRole) {
    return this.level === otherRole.level;
  }

  // Static methods
  static async findBySlug(slug) {
    return await this.findOne({
      where: {
        slug,
        is_active: true,
      },
    });
  }

  static async findSystemRoles() {
    return await this.findAll({
      where: {
        is_system_role: true,
        is_active: true,
      },
      order: [['level', 'DESC']],
    });
  }

  static async findCustomRoles() {
    return await this.findAll({
      where: {
        is_system_role: false,
        is_active: true,
      },
      order: [['level', 'DESC']],
    });
  }

  static async findByLevel(level) {
    return await this.findAll({
      where: {
        level,
        is_active: true,
      },
    });
  }

  static async findByMinLevel(minLevel) {
    return await this.findAll({
      where: {
        level: {
          [this.sequelize.Sequelize.Op.gte]: minLevel,
        },
        is_active: true,
      },
      order: [['level', 'DESC']],
    });
  }

  static async findByMaxLevel(maxLevel) {
    return await this.findAll({
      where: {
        level: {
          [this.sequelize.Sequelize.Op.lte]: maxLevel,
        },
        is_active: true,
      },
      order: [['level', 'DESC']],
    });
  }

  static async findByPermission(permission) {
    const roles = await this.findAll({
      where: {
        is_active: true,
      },
    });

    return roles.filter(role => role.hasPermission(permission));
  }

  // Standard role creation helpers
  static createSuperAdminRole() {
    return {
      name: 'Super Admin',
      slug: 'super-admin',
      description: 'Full system access with all permissions',
      level: 1000,
      permissions: ['*'],
      is_system_role: true,
    };
  }

  static createAdminRole() {
    return {
      name: 'Admin',
      slug: 'admin',
      description: 'Administrative access to manage users and system',
      level: 800,
      permissions: [
        'user.read', 'user.create', 'user.update', 'user.delete',
        'role.read', 'role.create', 'role.update',
        'organization.read', 'organization.create', 'organization.update',
        'system.read', 'analytics.read',
      ],
      is_system_role: true,
    };
  }

  static createUserRole() {
    return {
      name: 'User',
      slug: 'user',
      description: 'Standard user with basic voting permissions',
      level: 200,
      permissions: [
        'profile.read', 'profile.update',
        'voting.participate',
        'notification.read',
      ],
      is_system_role: true,
    };
  }

  // Associations
  static associate(models) {
    // Role users (many-to-many through user_roles)
    this.belongsToMany(models.VotteryUser, {
      through: models.VotteryUserRole,
      foreignKey: 'role_id',
      otherKey: 'user_id',
      as: 'users'
    });

    // User role assignments
    this.hasMany(models.VotteryUserRole, {
      foreignKey: 'role_id',
      as: 'userRoles'
    });

    // Created by user
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'created_by',
      as: 'creator'
    });

    // Updated by user
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'updated_by',
      as: 'updater'
    });
  }
}

export default (sequelize) => {
  return VotteryRole.init(sequelize);
};