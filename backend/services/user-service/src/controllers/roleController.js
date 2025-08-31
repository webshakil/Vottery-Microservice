import { Op } from 'sequelize';
import db from '../models/index.js';
const { Role, UserRole, VotteryUser } = db;
import  auditService  from '../services/auditService.js';
import  roleService  from '../services/roleService.js';
import { ResponseBuilder } from '../utils/response.js';
import  validateInput  from '../utils/validators.js';
import { PERMISSIONS, ROLE_CATEGORIES, ADMIN_ROLES } from '../config/roles.js';

/**
 * Role Controller - Manages role-based access control
 * Handles role creation, assignment, permissions management
 */
class RoleController {

  /**
   * Get all roles with filtering and pagination
   * GET /api/roles
   */
  async getAllRoles(req, res) {
    try {
      const { category, level, page = 1, limit = 20, search } = req.query;
      
      const filters = {};
      if (category) filters.category = category;
      if (level) filters.level = level;
      if (search) {
        filters.name = { [Op.iLike]: `%${search}%` };
      }

      const offset = (page - 1) * limit;
      
      const { rows: roles, count } = await Role.findAndCountAll({
        where: filters,
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [['level', 'DESC'], ['name', 'ASC']],
        include: [{
          model: UserRole,
          attributes: ['id'],
          separate: true,
          required: false
        }]
      });

      // Add user count to each role
      const rolesWithCounts = roles.map(role => ({
        ...role.toJSON(),
        userCount: role.UserRoles ? role.UserRoles.length : 0
      }));

      await auditService.log(req.user.id, 'ROLE_LIST_VIEWED', 'role', null, {
        filters,
        resultCount: count
      }, req);

      return ResponseBuilder.success(res, {
        roles: rolesWithCounts,
        pagination: {
          total: count,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(count / limit)
        }
      });

    } catch (error) {
      console.error('Get roles error:', error);
      return ResponseBuilder.internalError(res, 'Failed to fetch roles', error);
    }
  }

  /**
   * Get single role by ID
   * GET /api/roles/:id
   */
  async getRoleById(req, res) {
    try {
      const { id } = req.params;

      const role = await Role.findByPk(id, {
        include: [{
          model: UserRole,
          include: [{
            model: VotteryUser,
            attributes: ['id', 'email', 'username', 'created_at']
          }]
        }]
      });

      if (!role) {
        return ResponseBuilder.notFound(res, 'Role not found');
      }

      await auditService.log(req.user.id, 'ROLE_VIEWED', 'role', id, {
        roleName: role.name
      }, req);

      return ResponseBuilder.success(res, { role });

    } catch (error) {
      console.error('Get role error:', error);
      return ResponseBuilder.internalError(res, 'Failed to fetch role', error);
    }
  }

  /**
   * Create new role
   * POST /api/roles
   */
  async createRole(req, res) {
    try {
      const { name, category, level, permissions, description } = req.body;

      // Validate input
      const validation = validateInput({
        name: { value: name, required: true, minLength: 2, maxLength: 50 },
        category: { value: category, required: true, enum: Object.values(ROLE_CATEGORIES) },
        level: { value: level, required: true, type: 'number', min: 1, max: 100 },
        permissions: { value: permissions, required: true, type: 'array' }
      });

      if (!validation.isValid) {
        return ResponseBuilder.validationError(res, validation.errors, validation.errors.join(', '));
      }

      // Check if role name already exists
      const existingRole = await Role.findOne({ where: { name } });
      if (existingRole) {
        return ResponseBuilder.conflict(res, 'Role name already exists');
      }

      // Validate permissions
      const validPermissions = Object.values(PERMISSIONS).flatMap(group => Object.values(group));
      const invalidPermissions = permissions.filter(perm => !validPermissions.includes(perm));
      
      if (invalidPermissions.length > 0) {
        return ResponseBuilder.validationError(res, [{ 
          field: 'permissions', 
          message: `Invalid permissions: ${invalidPermissions.join(', ')}` 
        }]);
      }

      // Create role
      const role = await Role.create({
        name,
        category,
        level,
        permissions: JSON.stringify(permissions),
        description,
        created_by: req.user.id
      });

      await auditService.log(req.user.id, 'ROLE_CREATED', 'role', role.id, {
        roleName: name,
        category,
        level,
        permissionCount: permissions.length
      }, req);

      return ResponseBuilder.created(res, { role }, 'Role created successfully');

    } catch (error) {
      console.error('Create role error:', error);
      return ResponseBuilder.internalError(res, 'Failed to create role', error);
    }
  }

  /**
   * Update existing role
   * PUT /api/roles/:id
   */
  async updateRole(req, res) {
    try {
      const { id } = req.params;
      const { name, category, level, permissions, description } = req.body;

      const role = await Role.findByPk(id);
      if (!role) {
        return ResponseBuilder.notFound(res, 'Role not found');
      }

      // Prevent modification of system roles
      if (ADMIN_ROLES.includes(role.name)) {
        return ResponseBuilder.forbidden(res, 'System roles cannot be modified');
      }

      // Validate permissions if provided
      if (permissions) {
        const validPermissions = Object.values(PERMISSIONS).flatMap(group => Object.values(group));
        const invalidPermissions = permissions.filter(perm => !validPermissions.includes(perm));
        
        if (invalidPermissions.length > 0) {
          return ResponseBuilder.validationError(res, [{ 
            field: 'permissions', 
            message: `Invalid permissions: ${invalidPermissions.join(', ')}` 
          }]);
        }
      }

      const oldData = { ...role.toJSON() };

      // Update role
      await role.update({
        ...(name && { name }),
        ...(category && { category }),
        ...(level && { level }),
        ...(permissions && { permissions: JSON.stringify(permissions) }),
        ...(description && { description })
      });

      await auditService.log(req.user.id, 'ROLE_UPDATED', 'role', id, {
        oldData,
        newData: role.toJSON(),
        changes: Object.keys(req.body)
      }, req);

      return ResponseBuilder.updated(res, { role }, 'Role updated successfully');

    } catch (error) {
      console.error('Update role error:', error);
      return ResponseBuilder.internalError(res, 'Failed to update role', error);
    }
  }

  /**
   * Delete role
   * DELETE /api/roles/:id
   */
  async deleteRole(req, res) {
    try {
      const { id } = req.params;

      const role = await Role.findByPk(id, {
        include: [{ model: UserRole }]
      });

      if (!role) {
        return ResponseBuilder.notFound(res, 'Role not found');
      }

      // Prevent deletion of system roles
      if (ADMIN_ROLES.includes(role.name)) {
        return ResponseBuilder.forbidden(res, 'System roles cannot be deleted');
      }

      // Check if role is assigned to users
      if (role.UserRoles && role.UserRoles.length > 0) {
        return ResponseBuilder.conflict(res, `Cannot delete role. It is assigned to ${role.UserRoles.length} user(s)`);
      }

      await role.destroy();

      await auditService.log(req.user.id, 'ROLE_DELETED', 'role', id, {
        roleName: role.name,
        category: role.category,
        level: role.level
      }, req);

      return ResponseBuilder.deleted(res, 'Role deleted successfully');

    } catch (error) {
      console.error('Delete role error:', error);
      return ResponseBuilder.internalError(res, 'Failed to delete role', error);
    }
  }

  /**
   * Assign role to user
   * POST /api/roles/:roleId/assign
   */
  async assignRole(req, res) {
    try {
      const { roleId } = req.params;
      const { userId, expiresAt } = req.body;

      // Validate input
      if (!userId) {
        return ResponseBuilder.validationError(res, [{ 
          field: 'userId', 
          message: 'User ID is required' 
        }]);
      }

      // Check if role exists
      const role = await Role.findByPk(roleId);
      if (!role) {
        return ResponseBuilder.notFound(res, 'Role not found');
      }

      // Check if user exists
      const user = await VotteryUser.findByPk(userId);
      if (!user) {
        return ResponseBuilder.notFound(res, 'User not found');
      }

      // Check if user already has this role
      const existingAssignment = await UserRole.findOne({
        where: { user_id: userId, role_id: roleId }
      });

      if (existingAssignment) {
        return ResponseBuilder.conflict(res, 'User already has this role');
      }

      // Create role assignment
      const userRole = await UserRole.create({
        user_id: userId,
        role_id: roleId,
        assigned_by: req.user.id,
        expires_at: expiresAt || null
      });

      await auditService.log(req.user.id, 'ROLE_ASSIGNED', 'user_role', userRole.id, {
        userId,
        roleId,
        roleName: role.name,
        assignedTo: user.email,
        expiresAt
      }, req);

      return ResponseBuilder.created(res, { userRole }, 'Role assigned successfully');

    } catch (error) {
      console.error('Assign role error:', error);
      return ResponseBuilder.internalError(res, 'Failed to assign role', error);
    }
  }

  /**
   * Remove role from user
   * DELETE /api/roles/:roleId/users/:userId
   */
  async removeRole(req, res) {
    try {
      const { roleId, userId } = req.params;

      const userRole = await UserRole.findOne({
        where: { user_id: userId, role_id: roleId },
        include: [
          { model: Role, attributes: ['name'] },
          { model: VotteryUser, attributes: ['email'] }
        ]
      });

      if (!userRole) {
        return ResponseBuilder.notFound(res, 'Role assignment not found');
      }

      await userRole.destroy();

      await auditService.log(req.user.id, 'ROLE_REMOVED', 'user_role', userRole.id, {
        userId,
        roleId,
        roleName: userRole.Role.name,
        removedFrom: userRole.VotteryUser.email
      }, req);

      return ResponseBuilder.deleted(res, 'Role removed successfully');

    } catch (error) {
      console.error('Remove role error:', error);
      return ResponseBuilder.internalError(res, 'Failed to remove role', error);
    }
  }

  /**
   * Get user's roles
   * GET /api/users/:userId/roles
   */
  async getUserRoles(req, res) {
    try {
      const { userId } = req.params;

      const user = await VotteryUser.findByPk(userId);
      if (!user) {
        return ResponseBuilder.notFound(res, 'User not found');
      }

      const userRoles = await UserRole.findAll({
        where: { user_id: userId },
        include: [{
          model: Role,
          attributes: ['id', 'name', 'category', 'level', 'permissions']
        }],
        order: [[Role, 'level', 'DESC']]
      });

      const roles = userRoles.map(ur => ({
        ...ur.Role.toJSON(),
        assignedAt: ur.assigned_at,
        expiresAt: ur.expires_at,
        assignedBy: ur.assigned_by
      }));

      await auditService.log(req.user.id, 'USER_ROLES_VIEWED', 'user', userId, {
        roleCount: roles.length
      }, req);

      return ResponseBuilder.success(res, { roles });

    } catch (error) {
      console.error('Get user roles error:', error);
      return ResponseBuilder.internalError(res, 'Failed to fetch user roles', error);
    }
  }

  /**
   * Check user permissions
   * POST /api/roles/check-permission
   */
  async checkPermission(req, res) {
    try {
      const { userId, permission } = req.body;

      if (!userId || !permission) {
        return ResponseBuilder.validationError(res, [
          ...((!userId) ? [{ field: 'userId', message: 'User ID is required' }] : []),
          ...((!permission) ? [{ field: 'permission', message: 'Permission is required' }] : [])
        ]);
      }

      const hasPermission = await roleService.checkUserPermission(userId, permission);

      return ResponseBuilder.success(res, { 
        userId, 
        permission, 
        hasPermission 
      });

    } catch (error) {
      console.error('Check permission error:', error);
      return ResponseBuilder.internalError(res, 'Failed to check permission', error);
    }
  }

  /**
   * Get role statistics
   * GET /api/roles/stats
   */
  async getRoleStats(req, res) {
    try {
      const stats = await roleService.getRoleStatistics();

      await auditService.log(req.user.id, 'ROLE_STATS_VIEWED', 'system', null, {
        statsRequested: Object.keys(stats)
      }, req);

      return ResponseBuilder.success(res, { stats });

    } catch (error) {
      console.error('Get role stats error:', error);
      return ResponseBuilder.internalError(res, 'Failed to fetch role statistics', error);
    }
  }

}

export default new RoleController();
// //import { Role, UserRole, VotteryUser } from '../models/index.js';
// import db from '../models/index.js';
// const { Role, UserRole, VotteryUser } = db;
// import  auditService  from '../services/auditService.js';
// import { roleService } from '../services/roleService.js';
// import { successResponse, errorResponse  } from '../utils/response.js';
// import { validateInput } from '../utils/validators.js';
// import { PERMISSIONS, ROLE_CATEGORIES, ADMIN_ROLES } from '../config/roles.js';

// /**
//  * Role Controller - Manages role-based access control
//  * Handles role creation, assignment, permissions management
//  */
// class RoleController {

//   /**
//    * Get all roles with filtering and pagination
//    * GET /api/roles
//    */
//   async getAllRoles(req, res) {
//     try {
//       const { category, level, page = 1, limit = 20, search } = req.query;
      
//       const filters = {};
//       if (category) filters.category = category;
//       if (level) filters.level = level;
//       if (search) {
//         filters.name = { [Op.iLike]: `%${search}%` };
//       }

//       const offset = (page - 1) * limit;
      
//       const { rows: roles, count } = await Role.findAndCountAll({
//         where: filters,
//         limit: parseInt(limit),
//         offset: parseInt(offset),
//         order: [['level', 'DESC'], ['name', 'ASC']],
//         include: [{
//           model: UserRole,
//           attributes: ['id'],
//           separate: true,
//           required: false
//         }]
//       });

//       // Add user count to each role
//       const rolesWithCounts = roles.map(role => ({
//         ...role.toJSON(),
//         userCount: role.UserRoles ? role.UserRoles.length : 0
//       }));

//       await auditService.log(req.user.id, 'ROLE_LIST_VIEWED', 'role', null, {
//         filters,
//         resultCount: count
//       }, req);

//       return successResponse(res, {
//         roles: rolesWithCounts,
//         pagination: {
//           total: count,
//           page: parseInt(page),
//           limit: parseInt(limit),
//           totalPages: Math.ceil(count / limit)
//         }
//       });

//     } catch (error) {
//       console.error('Get roles error:', error);
//       return errorResponse(res, 'Failed to fetch roles', 500);
//     }
//   }

//   /**
//    * Get single role by ID
//    * GET /api/roles/:id
//    */
//   async getRoleById(req, res) {
//     try {
//       const { id } = req.params;

//       const role = await Role.findByPk(id, {
//         include: [{
//           model: UserRole,
//           include: [{
//             model: VotteryUser,
//             attributes: ['id', 'email', 'username', 'created_at']
//           }]
//         }]
//       });

//       if (!role) {
//         return errorResponse(res, 'Role not found', 404);
//       }

//       await auditService.log(req.user.id, 'ROLE_VIEWED', 'role', id, {
//         roleName: role.name
//       }, req);

//       return successResponse(res, { role });

//     } catch (error) {
//       console.error('Get role error:', error);
//       return errorResponse(res, 'Failed to fetch role', 500);
//     }
//   }

//   /**
//    * Create new role
//    * POST /api/roles
//    */
//   async createRole(req, res) {
//     try {
//       const { name, category, level, permissions, description } = req.body;

//       // Validate input
//       const validation = validateInput({
//         name: { value: name, required: true, minLength: 2, maxLength: 50 },
//         category: { value: category, required: true, enum: Object.values(ROLE_CATEGORIES) },
//         level: { value: level, required: true, type: 'number', min: 1, max: 100 },
//         permissions: { value: permissions, required: true, type: 'array' }
//       });

//       if (!validation.isValid) {
//         return errorResponse(res, validation.errors.join(', '), 400);
//       }

//       // Check if role name already exists
//       const existingRole = await Role.findOne({ where: { name } });
//       if (existingRole) {
//         return errorResponse(res, 'Role name already exists', 409);
//       }

//       // Validate permissions
//       const validPermissions = Object.values(PERMISSIONS).flatMap(group => Object.values(group));
//       const invalidPermissions = permissions.filter(perm => !validPermissions.includes(perm));
      
//       if (invalidPermissions.length > 0) {
//         return errorResponse(res, `Invalid permissions: ${invalidPermissions.join(', ')}`, 400);
//       }

//       // Create role
//       const role = await Role.create({
//         name,
//         category,
//         level,
//         permissions: JSON.stringify(permissions),
//         description,
//         created_by: req.user.id
//       });

//       await auditService.log(req.user.id, 'ROLE_CREATED', 'role', role.id, {
//         roleName: name,
//         category,
//         level,
//         permissionCount: permissions.length
//       }, req);

//       return successResponse(res, { role }, 'Role created successfully', 201);

//     } catch (error) {
//       console.error('Create role error:', error);
//       return errorResponse(res, 'Failed to create role', 500);
//     }
//   }

//   /**
//    * Update existing role
//    * PUT /api/roles/:id
//    */
//   async updateRole(req, res) {
//     try {
//       const { id } = req.params;
//       const { name, category, level, permissions, description } = req.body;

//       const role = await Role.findByPk(id);
//       if (!role) {
//         return errorResponse(res, 'Role not found', 404);
//       }

//       // Prevent modification of system roles
//       if (ADMIN_ROLES.includes(role.name)) {
//         return errorResponse(res, 'System roles cannot be modified', 403);
//       }

//       // Validate permissions if provided
//       if (permissions) {
//         const validPermissions = Object.values(PERMISSIONS).flatMap(group => Object.values(group));
//         const invalidPermissions = permissions.filter(perm => !validPermissions.includes(perm));
        
//         if (invalidPermissions.length > 0) {
//           return errorResponse(res, `Invalid permissions: ${invalidPermissions.join(', ')}`, 400);
//         }
//       }

//       const oldData = { ...role.toJSON() };

//       // Update role
//       await role.update({
//         ...(name && { name }),
//         ...(category && { category }),
//         ...(level && { level }),
//         ...(permissions && { permissions: JSON.stringify(permissions) }),
//         ...(description && { description })
//       });

//       await auditService.log(req.user.id, 'ROLE_UPDATED', 'role', id, {
//         oldData,
//         newData: role.toJSON(),
//         changes: Object.keys(req.body)
//       }, req);

//       return successResponse(res, { role }, 'Role updated successfully');

//     } catch (error) {
//       console.error('Update role error:', error);
//       return errorResponse(res, 'Failed to update role', 500);
//     }
//   }

//   /**
//    * Delete role
//    * DELETE /api/roles/:id
//    */
//   async deleteRole(req, res) {
//     try {
//       const { id } = req.params;

//       const role = await Role.findByPk(id, {
//         include: [{ model: UserRole }]
//       });

//       if (!role) {
//         return errorResponse(res, 'Role not found', 404);
//       }

//       // Prevent deletion of system roles
//       if (ADMIN_ROLES.includes(role.name)) {
//         return errorResponse(res, 'System roles cannot be deleted', 403);
//       }

//       // Check if role is assigned to users
//       if (role.UserRoles && role.UserRoles.length > 0) {
//         return errorResponse(res, `Cannot delete role. It is assigned to ${role.UserRoles.length} user(s)`, 409);
//       }

//       await role.destroy();

//       await auditService.log(req.user.id, 'ROLE_DELETED', 'role', id, {
//         roleName: role.name,
//         category: role.category,
//         level: role.level
//       }, req);

//       return successResponse(res, null, 'Role deleted successfully');

//     } catch (error) {
//       console.error('Delete role error:', error);
//       return errorResponse(res, 'Failed to delete role', 500);
//     }
//   }

//   /**
//    * Assign role to user
//    * POST /api/roles/:roleId/assign
//    */
//   async assignRole(req, res) {
//     try {
//       const { roleId } = req.params;
//       const { userId, expiresAt } = req.body;

//       // Validate input
//       if (!userId) {
//         return errorResponse(res, 'User ID is required', 400);
//       }

//       // Check if role exists
//       const role = await Role.findByPk(roleId);
//       if (!role) {
//         return errorResponse(res, 'Role not found', 404);
//       }

//       // Check if user exists
//       const user = await VotteryUser.findByPk(userId);
//       if (!user) {
//         return errorResponse(res, 'User not found', 404);
//       }

//       // Check if user already has this role
//       const existingAssignment = await UserRole.findOne({
//         where: { user_id: userId, role_id: roleId }
//       });

//       if (existingAssignment) {
//         return errorResponse(res, 'User already has this role', 409);
//       }

//       // Create role assignment
//       const userRole = await UserRole.create({
//         user_id: userId,
//         role_id: roleId,
//         assigned_by: req.user.id,
//         expires_at: expiresAt || null
//       });

//       await auditService.log(req.user.id, 'ROLE_ASSIGNED', 'user_role', userRole.id, {
//         userId,
//         roleId,
//         roleName: role.name,
//         assignedTo: user.email,
//         expiresAt
//       }, req);

//       return successResponse(res, { userRole }, 'Role assigned successfully', 201);

//     } catch (error) {
//       console.error('Assign role error:', error);
//       return errorResponse(res, 'Failed to assign role', 500);
//     }
//   }

//   /**
//    * Remove role from user
//    * DELETE /api/roles/:roleId/users/:userId
//    */
//   async removeRole(req, res) {
//     try {
//       const { roleId, userId } = req.params;

//       const userRole = await UserRole.findOne({
//         where: { user_id: userId, role_id: roleId },
//         include: [
//           { model: Role, attributes: ['name'] },
//           { model: VotteryUser, attributes: ['email'] }
//         ]
//       });

//       if (!userRole) {
//         return errorResponse(res, 'Role assignment not found', 404);
//       }

//       await userRole.destroy();

//       await auditService.log(req.user.id, 'ROLE_REMOVED', 'user_role', userRole.id, {
//         userId,
//         roleId,
//         roleName: userRole.Role.name,
//         removedFrom: userRole.VotteryUser.email
//       }, req);

//       return successResponse(res, null, 'Role removed successfully');

//     } catch (error) {
//       console.error('Remove role error:', error);
//       return errorResponse(res, 'Failed to remove role', 500);
//     }
//   }

//   /**
//    * Get user's roles
//    * GET /api/users/:userId/roles
//    */
//   async getUserRoles(req, res) {
//     try {
//       const { userId } = req.params;

//       const user = await VotteryUser.findByPk(userId);
//       if (!user) {
//         return errorResponse(res, 'User not found', 404);
//       }

//       const userRoles = await UserRole.findAll({
//         where: { user_id: userId },
//         include: [{
//           model: Role,
//           attributes: ['id', 'name', 'category', 'level', 'permissions']
//         }],
//         order: [[Role, 'level', 'DESC']]
//       });

//       const roles = userRoles.map(ur => ({
//         ...ur.Role.toJSON(),
//         assignedAt: ur.assigned_at,
//         expiresAt: ur.expires_at,
//         assignedBy: ur.assigned_by
//       }));

//       await auditService.log(req.user.id, 'USER_ROLES_VIEWED', 'user', userId, {
//         roleCount: roles.length
//       }, req);

//       return successResponse(res, { roles });

//     } catch (error) {
//       console.error('Get user roles error:', error);
//       return errorResponse(res, 'Failed to fetch user roles', 500);
//     }
//   }

//   /**
//    * Check user permissions
//    * POST /api/roles/check-permission
//    */
//   async checkPermission(req, res) {
//     try {
//       const { userId, permission } = req.body;

//       if (!userId || !permission) {
//         return errorResponse(res, 'User ID and permission are required', 400);
//       }

//       const hasPermission = await roleService.checkUserPermission(userId, permission);

//       return successResponse(res, { 
//         userId, 
//         permission, 
//         hasPermission 
//       });

//     } catch (error) {
//       console.error('Check permission error:', error);
//       return errorResponse(res, 'Failed to check permission', 500);
//     }
//   }

//   /**
//    * Get role statistics
//    * GET /api/roles/stats
//    */
//   async getRoleStats(req, res) {
//     try {
//       const stats = await roleService.getRoleStatistics();

//       await auditService.log(req.user.id, 'ROLE_STATS_VIEWED', 'system', null, {
//         statsRequested: Object.keys(stats)
//       }, req);

//       return successResponse(res, { stats });

//     } catch (error) {
//       console.error('Get role stats error:', error);
//       return errorResponse(res, 'Failed to fetch role statistics', 500);
//     }
//   }

// }

// export default new RoleController();