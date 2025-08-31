// services/roleService.js
import Role from '../models/Role.js';
import UserRole from '../models/UserRole.js';
import VotteryUser from '../models/VotteryUser.js';
import auditService from './auditService.js';
import { AppError } from '../utils/response.js';
import { PERMISSIONS } from '../config/roles.js';

class RoleService {
  /**
   * Create a new role
   * @param {object} roleData 
   * @param {object} createdBy 
   * @returns {Promise<object>}
   */
  async createRole(roleData, createdBy) {
    try {
      const { name, category, level, permissions } = roleData;

      // Check if role already exists
      const existingRole = await Role.findOne({ where: { name } });
      if (existingRole) {
        throw new AppError('Role with this name already exists', 400);
      }

      // Validate permissions
      this.validatePermissions(permissions);

      // Create role
      const role = await Role.create({
        name,
        category,
        level,
        permissions
      });

      // Log activity
      await auditService.logActivity(
        createdBy.id,
        'ROLE_CREATE',
        'role',
        role.id,
        {
          role_name: name,
          category,
          level,
          permissions_count: Object.keys(permissions).length
        }
      );

      return role;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Get all roles with optional filtering
   * @param {object} filters 
   * @returns {Promise<array>}
   */
  async getAllRoles(filters = {}) {
    try {
      const whereClause = {};

      if (filters.category) {
        whereClause.category = filters.category;
      }

      if (filters.level) {
        whereClause.level = filters.level;
      }

      const roles = await Role.findAll({
        where: whereClause,
        order: [['level', 'DESC'], ['name', 'ASC']]
      });

      return roles;
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Get role by ID
   * @param {number} roleId 
   * @returns {Promise<object>}
   */
  async getRoleById(roleId) {
    try {
      const role = await Role.findByPk(roleId);
      if (!role) {
        throw new AppError('Role not found', 404);
      }

      return role;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Update role
   * @param {number} roleId 
   * @param {object} updateData 
   * @param {object} updatedBy 
   * @returns {Promise<object>}
   */
  async updateRole(roleId, updateData, updatedBy) {
    try {
      const role = await Role.findByPk(roleId);
      if (!role) {
        throw new AppError('Role not found', 404);
      }

      // Validate permissions if being updated
      if (updateData.permissions) {
        this.validatePermissions(updateData.permissions);
      }

      const oldData = { ...role.toJSON() };
      
      await role.update(updateData);

      // Log activity
      await auditService.logActivity(
        updatedBy.id,
        'ROLE_UPDATE',
        'role',
        roleId,
        {
          old_data: oldData,
          new_data: updateData,
          role_name: role.name
        }
      );

      return role;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Delete role (only if not assigned to users)
   * @param {number} roleId 
   * @param {object} deletedBy 
   * @returns {Promise<boolean>}
   */
  async deleteRole(roleId, deletedBy) {
    try {
      const role = await Role.findByPk(roleId);
      if (!role) {
        throw new AppError('Role not found', 404);
      }

      // Check if role is assigned to any users
      const userRoleCount = await UserRole.count({ where: { role_id: roleId } });
      if (userRoleCount > 0) {
        throw new AppError(
          `Cannot delete role. It is assigned to ${userRoleCount} user(s)`,
          400
        );
      }

      const roleName = role.name;
      await role.destroy();

      // Log activity
      await auditService.logActivity(
        deletedBy.id,
        'ROLE_DELETE',
        'role',
        roleId,
        {
          deleted_role_name: roleName,
          deleted_by: deletedBy.id
        }
      );

      return true;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Assign role to user
   * @param {number} userId 
   * @param {number} roleId 
   * @param {object} assignedBy 
   * @param {Date} expiresAt 
   * @returns {Promise<object>}
   */
  async assignRoleToUser(userId, roleId, assignedBy, expiresAt = null) {
    try {
      // Check if user exists
      const user = await VotteryUser.findByPk(userId);
      if (!user) {
        throw new AppError('User not found', 404);
      }

      // Check if role exists
      const role = await Role.findByPk(roleId);
      if (!role) {
        throw new AppError('Role not found', 404);
      }

      // Check if assignment already exists
      const existingAssignment = await UserRole.findOne({
        where: { user_id: userId, role_id: roleId }
      });

      if (existingAssignment) {
        throw new AppError('User already has this role assigned', 400);
      }

      // Create assignment
      const userRole = await UserRole.create({
        user_id: userId,
        role_id: roleId,
        assigned_by: assignedBy.id,
        expires_at: expiresAt
      });

      // Log activity
      await auditService.logActivity(
        assignedBy.id,
        'ROLE_ASSIGN',
        'user_role',
        userRole.id,
        {
          user_id: userId,
          role_id: roleId,
          role_name: role.name,
          expires_at: expiresAt,
          assigned_by: assignedBy.id
        }
      );

      return await this.getUserRoleById(userRole.id);
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Remove role from user
   * @param {number} userId 
   * @param {number} roleId 
   * @param {object} removedBy 
   * @returns {Promise<boolean>}
   */
  async removeRoleFromUser(userId, roleId, removedBy) {
    try {
      const userRole = await UserRole.findOne({
        where: { user_id: userId, role_id: roleId },
        include: [{ model: Role, as: 'role' }]
      });

      if (!userRole) {
        throw new AppError('Role assignment not found', 404);
      }

      const roleName = userRole.role.name;
      await userRole.destroy();

      // Log activity
      await auditService.logActivity(
        removedBy.id,
        'ROLE_REMOVE',
        'user_role',
        userRole.id,
        {
          user_id: userId,
          role_id: roleId,
          role_name: roleName,
          removed_by: removedBy.id
        }
      );

      return true;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Get user roles
   * @param {number} userId 
   * @returns {Promise<array>}
   */
  async getUserRoles(userId) {
    try {
      const userRoles = await UserRole.findAll({
        where: { user_id: userId },
        include: [{
          model: Role,
          as: 'role'
        }]
      });

      return userRoles.filter(ur => {
        // Filter out expired roles
        return !ur.expires_at || ur.expires_at > new Date();
      });
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Get user role by ID
   * @param {number} userRoleId 
   * @returns {Promise<object>}
   */
  async getUserRoleById(userRoleId) {
    try {
      const userRole = await UserRole.findByPk(userRoleId, {
        include: [{
          model: Role,
          as: 'role'
        }, {
          model: VotteryUser,
          as: 'user',
          attributes: ['id', 'email', 'username']
        }]
      });

      if (!userRole) {
        throw new AppError('User role assignment not found', 404);
      }

      return userRole;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Check if user has permission
   * @param {number} userId 
   * @param {string} permission 
   * @returns {Promise<boolean>}
   */
  async userHasPermission(userId, permission) {
    try {
      const userRoles = await this.getUserRoles(userId);
      
      for (const userRole of userRoles) {
        const rolePermissions = userRole.role.permissions;
        if (this.checkPermission(rolePermissions, permission)) {
          return true;
        }
      }

      return false;
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Get all permissions for user
   * @param {number} userId 
   * @returns {Promise<array>}
   */
  async getUserPermissions(userId) {
    try {
      const userRoles = await this.getUserRoles(userId);
      const allPermissions = new Set();

      for (const userRole of userRoles) {
        const rolePermissions = userRole.role.permissions;
        const permissionsList = this.flattenPermissions(rolePermissions);
        permissionsList.forEach(perm => allPermissions.add(perm));
      }

      return Array.from(allPermissions);
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Get users by role
   * @param {number} roleId 
   * @param {number} page 
   * @param {number} limit 
   * @returns {Promise<object>}
   */
  async getUsersByRole(roleId, page = 1, limit = 10) {
    try {
      const offset = (page - 1) * limit;

      const { count, rows } = await UserRole.findAndCountAll({
        where: { role_id: roleId },
        include: [{
          model: VotteryUser,
          as: 'user',
          attributes: ['id', 'email', 'username', 'status', 'created_at']
        }, {
          model: Role,
          as: 'role'
        }],
        limit,
        offset,
        order: [['assigned_at', 'DESC']]
      });

      return {
        userRoles: rows.filter(ur => !ur.expires_at || ur.expires_at > new Date()),
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
   * Get role statistics
   * @returns {Promise<object>}
   */
  async getRoleStatistics() {
    try {
      const [roles, userRoles] = await Promise.all([
        Role.findAll(),
        UserRole.findAll({
          include: [{ model: Role, as: 'role' }],
          where: {
            [Op.or]: [
              { expires_at: null },
              { expires_at: { [Op.gt]: new Date() } }
            ]
          }
        })
      ]);

      const stats = {
        totalRoles: roles.length,
        rolesByCategory: {},
        usersByRole: {},
        totalAssignments: userRoles.length
      };

      // Count roles by category
      for (const role of roles) {
        stats.rolesByCategory[role.category] = (stats.rolesByCategory[role.category] || 0) + 1;
      }

      // Count users by role
      for (const userRole of userRoles) {
        const roleName = userRole.role.name;
        stats.usersByRole[roleName] = (stats.usersByRole[roleName] || 0) + 1;
      }

      return stats;
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Bulk assign roles to users
   * @param {array} assignments Array of {userId, roleId} objects
   * @param {object} assignedBy 
   * @returns {Promise<array>}
   */
  async bulkAssignRoles(assignments, assignedBy) {
    try {
      const results = [];

      for (const assignment of assignments) {
        try {
          const userRole = await this.assignRoleToUser(
            assignment.userId,
            assignment.roleId,
            assignedBy,
            assignment.expiresAt || null
          );
          results.push({ success: true, userRole });
        } catch (error) {
          results.push({ 
            success: false, 
            error: error.message,
            userId: assignment.userId,
            roleId: assignment.roleId
          });
        }
      }

      return results;
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Check if user has sufficient level for action
   * @param {number} userId 
   * @param {number} requiredLevel 
   * @returns {Promise<boolean>}
   */
  async userHasLevel(userId, requiredLevel) {
    try {
      const userRoles = await this.getUserRoles(userId);
      
      const maxLevel = Math.max(...userRoles.map(ur => ur.role.level));
      return maxLevel >= requiredLevel;
    } catch (error) {
      return false;
    }
  }

  /**
   * Validate permissions object
   * @param {object} permissions 
   */
  validatePermissions(permissions) {
    if (!permissions || typeof permissions !== 'object') {
      throw new AppError('Permissions must be an object', 400);
    }

    const validPermissions = this.flattenPermissions(PERMISSIONS);
    const providedPermissions = this.flattenPermissions(permissions);

    for (const permission of providedPermissions) {
      if (!validPermissions.includes(permission)) {
        throw new AppError(`Invalid permission: ${permission}`, 400);
      }
    }
  }

  /**
   * Check if permissions object contains a specific permission
   * @param {object} permissions 
   * @param {string} permission 
   * @returns {boolean}
   */
  checkPermission(permissions, permission) {
    const flatPermissions = this.flattenPermissions(permissions);
    return flatPermissions.includes(permission);
  }

  /**
   * Flatten nested permissions object to array
   * @param {object} permissions 
   * @returns {array}
   */
  flattenPermissions(permissions) {
    const result = [];

    const flatten = (obj, prefix = '') => {
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string') {
          result.push(value);
        } else if (typeof value === 'object' && value !== null) {
          flatten(value, prefix ? `${prefix}.${key}` : key);
        }
      }
    };

    flatten(permissions);
    return result;
  }
}

export default new RoleService();