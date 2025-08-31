// models/UserRole.js
import { DataTypes, Model, Op } from 'sequelize';

class UserRole extends Model {
  static init(sequelize) {
    return super.init(
      {
        id: {
          type: DataTypes.INTEGER,
          primaryKey: true,
          autoIncrement: true
        },
        user_id: {
          type: DataTypes.INTEGER,
          allowNull: false,
          references: {
            model: 'vottery_users',
            key: 'id'
          },
          onDelete: 'CASCADE'
        },
        role_id: {
          type: DataTypes.INTEGER,
          allowNull: false,
          references: {
            model: 'roles',
            key: 'id'
          },
          onDelete: 'CASCADE'
        },
        assigned_by: {
          type: DataTypes.INTEGER,
          allowNull: true,
          references: {
            model: 'vottery_users',
            key: 'id'
          }
        },
        assigned_at: {
          type: DataTypes.DATE,
          allowNull: false,
          defaultValue: DataTypes.NOW
        },
        expires_at: {
          type: DataTypes.DATE,
          allowNull: true,
          validate: {
            isAfterAssigned(value) {
              if (value && this.assigned_at && new Date(value) <= new Date(this.assigned_at)) {
                throw new Error('Expiration date must be after assignment date');
              }
            }
          }
        },
        // Virtual field to check if role is active
        isActive: {
          type: DataTypes.VIRTUAL,
          get() {
            if (!this.expires_at) return true;
            return new Date() < new Date(this.expires_at);
          }
        },
        // Virtual field to check if role is expired
        isExpired: {
          type: DataTypes.VIRTUAL,
          get() {
            if (!this.expires_at) return false;
            return new Date() >= new Date(this.expires_at);
          }
        }
      },
      {
        sequelize,
        modelName: 'UserRole',
        tableName: 'user_roles',
        timestamps: false,
        indexes: [
          {
            unique: true,
            fields: ['user_id', 'role_id'],
            name: 'unique_user_role'
          },
          {
            fields: ['user_id']
          },
          {
            fields: ['role_id']
          },
          {
            fields: ['expires_at']
          },
          {
            fields: ['assigned_at']
          }
        ]
      }
    );
  }

  // Instance method to check if assignment is currently valid
  isCurrentlyActive() {
    return this.isActive;
  }

  // Instance method to extend expiration
  async extendExpiration(newExpirationDate) {
    try {
      if (newExpirationDate <= new Date()) {
        throw new Error('New expiration date must be in the future');
      }

      this.expires_at = newExpirationDate;
      await this.save();
      return this;
    } catch (error) {
      throw new Error(`Failed to extend expiration: ${error.message}`);
    }
  }

  // Instance method to revoke role (set expiration to now)
  async revoke() {
    try {
      this.expires_at = new Date();
      await this.save();
      return this;
    } catch (error) {
      throw new Error(`Failed to revoke role: ${error.message}`);
    }
  }

  // Static method to assign role to user
  static async assignRole(userId, roleId, assignedBy = null, expiresAt = null) {
    try {
      // Check if assignment already exists and is active
      const existingAssignment = await this.findOne({
        where: {
          user_id: userId,
          role_id: roleId,
          [Op.or]: [
            { expires_at: null },
            { expires_at: { [Op.gt]: new Date() } }
          ]
        }
      });

      if (existingAssignment) {
        throw new Error('User already has this role assigned');
      }

      const userRole = await this.create({
        user_id: userId,
        role_id: roleId,
        assigned_by: assignedBy,
        expires_at: expiresAt
      });

      return userRole;
    } catch (error) {
      if (error.name === 'SequelizeUniqueConstraintError') {
        throw new Error('User role assignment already exists');
      }
      throw new Error(`Failed to assign role: ${error.message}`);
    }
  }

  // Static method to get user's active roles
  static async getUserActiveRoles(userId) {
    try {
      return await this.findAll({
        where: {
          user_id: userId,
          [Op.or]: [
            { expires_at: null },
            { expires_at: { [Op.gt]: new Date() } }
          ]
        },
        include: [
          {
            model: this.sequelize.models.Role,
            as: 'role'
          }
        ],
        order: [
          [{ model: this.sequelize.models.Role, as: 'role' }, 'level', 'DESC']
        ]
      });
    } catch (error) {
      throw new Error(`Failed to get user roles: ${error.message}`);
    }
  }

  // Static method to get user's highest role
  static async getUserHighestRole(userId) {
    try {
      const userRole = await this.findOne({
        where: {
          user_id: userId,
          [Op.or]: [
            { expires_at: null },
            { expires_at: { [Op.gt]: new Date() } }
          ]
        },
        include: [
          {
            model: this.sequelize.models.Role,
            as: 'role'
          }
        ],
        order: [
          [{ model: this.sequelize.models.Role, as: 'role' }, 'level', 'DESC']
        ]
      });

      return userRole ? userRole.role : null;
    } catch (error) {
      throw new Error(`Failed to get user's highest role: ${error.message}`);
    }
  }

  // Static method to check if user has permission
  static async userHasPermission(userId, module, action) {
    try {
      const userRoles = await this.getUserActiveRoles(userId);
      
      for (const userRole of userRoles) {
        if (userRole.role.hasPermission(module, action)) {
          return true;
        }
      }
      
      return false;
    } catch (error) {
      throw new Error(`Failed to check user permission: ${error.message}`);
    }
  }

  // Static method to get all user permissions
  static async getUserPermissions(userId) {
    try {
      const userRoles = await this.getUserActiveRoles(userId);
      const permissions = new Set();
      
      for (const userRole of userRoles) {
        const rolePermissions = userRole.role.getAllPermissions();
        rolePermissions.forEach(permission => permissions.add(permission));
      }
      
      return Array.from(permissions);
    } catch (error) {
      throw new Error(`Failed to get user permissions: ${error.message}`);
    }
  }

  // Static method to remove user from role
  static async removeUserFromRole(userId, roleId) {
    try {
      const userRole = await this.findOne({
        where: {
          user_id: userId,
          role_id: roleId,
          [Op.or]: [
            { expires_at: null },
            { expires_at: { [Op.gt]: new Date() } }
          ]
        }
      });

      if (!userRole) {
        throw new Error('User role assignment not found or already expired');
      }

      await userRole.revoke();
      return true;
    } catch (error) {
      throw new Error(`Failed to remove user from role: ${error.message}`);
    }
  }

  // Static method to get expired roles (for cleanup)
  static async getExpiredRoles() {
    try {
      return await this.findAll({
        where: {
          expires_at: {
            [Op.lte]: new Date()
          }
        },
        include: [
          {
            model: this.sequelize.models.Role,
            as: 'role'
          }
        ]
      });
    } catch (error) {
      throw new Error(`Failed to get expired roles: ${error.message}`);
    }
  }

  // Static method to cleanup expired roles
  static async cleanupExpiredRoles() {
    try {
      const expiredRoles = await this.getExpiredRoles();
      const cleanedCount = expiredRoles.length;
      
      // You might want to archive these instead of deleting
      await this.destroy({
        where: {
          expires_at: {
            [Op.lte]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // 30 days old
          }
        }
      });

      return cleanedCount;
    } catch (error) {
      throw new Error(`Failed to cleanup expired roles: ${error.message}`);
    }
  }

  // Static method to get role assignment history for user
  static async getUserRoleHistory(userId, limit = 50) {
    try {
      return await this.findAll({
        where: { user_id: userId },
        include: [
          {
            model: this.sequelize.models.Role,
            as: 'role'
          }
        ],
        order: [['assigned_at', 'DESC']],
        limit
      });
    } catch (error) {
      throw new Error(`Failed to get user role history: ${error.message}`);
    }
  }

  // Static method to assign default role to new user
  static async assignDefaultRole(userId, userType = 'voter') {
    try {
      let defaultRoleName;
      
      switch (userType) {
        case 'individual_creator':
          defaultRoleName = 'Individual Election Creator';
          break;
        case 'organization_creator':
          defaultRoleName = 'Organization Election Creator';
          break;
        case 'free_user':
          defaultRoleName = 'Free User';
          break;
        case 'subscribed_user':
          defaultRoleName = 'Subscribed User';
          break;
        default:
          defaultRoleName = 'Voter';
      }

      const role = await this.sequelize.models.Role.findOne({
        where: { name: defaultRoleName }
      });

      if (!role) {
        throw new Error(`Default role ${defaultRoleName} not found`);
      }

      return await this.assignRole(userId, role.id);
    } catch (error) {
      throw new Error(`Failed to assign default role: ${error.message}`);
    }
  }

  // Define associations
  static associate(models) {
    UserRole.belongsTo(models.VotteryUser, {
      foreignKey: 'user_id',
      as: 'user'
    });

    UserRole.belongsTo(models.Role, {
      foreignKey: 'role_id',
      as: 'role'
    });

    UserRole.belongsTo(models.VotteryUser, {
      foreignKey: 'assigned_by',
      as: 'assignedBy'
    });
  }
}

export default UserRole;