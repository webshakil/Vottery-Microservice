// models/Role.js
import { DataTypes, Model } from 'sequelize';

class Role extends Model {
  static init(sequelize) {
    return super.init(
      {
        id: {
          type: DataTypes.INTEGER,
          primaryKey: true,
          autoIncrement: true
        },
        name: {
          type: DataTypes.STRING(50),
          allowNull: false,
          unique: true,
          validate: {
            notEmpty: {
              msg: 'Role name cannot be empty'
            },
            len: {
              args: [2, 50],
              msg: 'Role name must be between 2 and 50 characters'
            }
          }
        },
        category: {
          type: DataTypes.ENUM('admin', 'user'),
          allowNull: false,
          validate: {
            isIn: {
              args: [['admin', 'user']],
              msg: 'Category must be either admin or user'
            }
          }
        },
        level: {
          type: DataTypes.INTEGER,
          allowNull: false,
          validate: {
            min: {
              args: [0],
              msg: 'Level must be non-negative'
            },
            max: {
              args: [100],
              msg: 'Level cannot exceed 100'
            }
          },
          comment: 'Higher number = more permissions'
        },
        permissions: {
          type: DataTypes.JSON,
          allowNull: false,
          validate: {
            isValidPermissions(value) {
              if (!value || typeof value !== 'object') {
                throw new Error('Permissions must be a valid object');
              }
              
              // Validate permission structure
              const validModules = ['users', 'elections', 'analytics', 'system', 'organizations'];
              const validActions = ['view', 'create', 'edit', 'delete', 'moderate', 'export', 'config', 'audit', 'security', 'suspend'];
              
              for (const [module, actions] of Object.entries(value)) {
                if (!validModules.includes(module)) {
                  throw new Error(`Invalid permission module: ${module}`);
                }
                
                if (!Array.isArray(actions)) {
                  throw new Error(`Permissions for ${module} must be an array`);
                }
                
                for (const action of actions) {
                  if (!validActions.includes(action)) {
                    throw new Error(`Invalid action ${action} for module ${module}`);
                  }
                }
              }
            }
          }
        }
      },
      {
        sequelize,
        modelName: 'Role',
        tableName: 'roles',
        timestamps: true,
        createdAt: 'created_at',
        updatedAt: false,
        indexes: [
          {
            unique: true,
            fields: ['name']
          },
          {
            fields: ['category']
          },
          {
            fields: ['level']
          }
        ]
      }
    );
  }

  // Check if role has specific permission
  hasPermission(module, action) {
    try {
      const permissions = this.permissions;
      return permissions[module] && permissions[module].includes(action);
    } catch (error) {
      console.error('Error checking permission:', error);
      return false;
    }
  }

  // Get all permissions as flat array
  getAllPermissions() {
    const flatPermissions = [];
    const permissions = this.permissions;
    
    for (const [module, actions] of Object.entries(permissions)) {
      for (const action of actions) {
        flatPermissions.push(`${module}:${action}`);
      }
    }
    
    return flatPermissions;
  }

  // Check if this role has higher level than another role
  isHigherThan(otherRole) {
    return this.level > otherRole.level;
  }

  // Check if this role can assign another role
  canAssignRole(targetRole) {
    // Can only assign roles with lower or equal level
    return this.level >= targetRole.level;
  }

  // Static method to get default admin roles
  static getDefaultAdminRoles() {
    return [
      {
        name: 'Manager',
        category: 'admin',
        level: 100,
        permissions: {
          users: ['view', 'edit', 'delete', 'suspend'],
          elections: ['view', 'create', 'edit', 'delete', 'moderate'],
          analytics: ['view', 'export', 'advanced'],
          system: ['config', 'audit', 'security'],
          organizations: ['view', 'edit', 'delete']
        }
      },
      {
        name: 'Admin',
        category: 'admin',
        level: 90,
        permissions: {
          users: ['view', 'edit', 'suspend'],
          elections: ['view', 'edit', 'moderate'],
          analytics: ['view', 'export'],
          system: ['audit'],
          organizations: ['view', 'edit']
        }
      },
      {
        name: 'Moderator',
        category: 'admin',
        level: 80,
        permissions: {
          users: ['view'],
          elections: ['view', 'moderate'],
          analytics: ['view'],
          organizations: ['view']
        }
      },
      {
        name: 'Auditor',
        category: 'admin',
        level: 70,
        permissions: {
          users: ['view'],
          elections: ['view'],
          analytics: ['view', 'export'],
          system: ['audit'],
          organizations: ['view']
        }
      },
      {
        name: 'Editor',
        category: 'admin',
        level: 60,
        permissions: {
          elections: ['view', 'edit'],
          analytics: ['view'],
          organizations: ['view']
        }
      },
      {
        name: 'Advertiser',
        category: 'admin',
        level: 50,
        permissions: {
          elections: ['view'],
          analytics: ['view'],
          organizations: ['view']
        }
      },
      {
        name: 'Analyst',
        category: 'admin',
        level: 40,
        permissions: {
          analytics: ['view', 'export'],
          elections: ['view'],
          organizations: ['view']
        }
      }
    ];
  }

  // Static method to get default user roles
  static getDefaultUserRoles() {
    return [
      {
        name: 'Individual Election Creator',
        category: 'user',
        level: 30,
        permissions: {
          elections: ['view', 'create', 'edit'],
          analytics: ['view'],
          users: ['view']
        }
      },
      {
        name: 'Organization Election Creator',
        category: 'user',
        level: 35,
        permissions: {
          elections: ['view', 'create', 'edit'],
          analytics: ['view'],
          users: ['view'],
          organizations: ['view', 'create', 'edit']
        }
      },
      {
        name: 'Voter',
        category: 'user',
        level: 10,
        permissions: {
          elections: ['view'],
          users: ['view']
        }
      },
      {
        name: 'Free User',
        category: 'user',
        level: 5,
        permissions: {
          elections: ['view'],
          users: ['view']
        }
      },
      {
        name: 'Subscribed User',
        category: 'user',
        level: 20,
        permissions: {
          elections: ['view', 'create'],
          analytics: ['view'],
          users: ['view']
        }
      }
    ];
  }

  // Static method to create default roles
  static async createDefaultRoles() {
    try {
      const adminRoles = this.getDefaultAdminRoles();
      const userRoles = this.getDefaultUserRoles();
      const allRoles = [...adminRoles, ...userRoles];

      const createdRoles = [];
      
      for (const roleData of allRoles) {
        const [role, created] = await this.findOrCreate({
          where: { name: roleData.name },
          defaults: roleData
        });
        
        if (created) {
          createdRoles.push(role);
        }
      }

      return createdRoles;
    } catch (error) {
      throw new Error(`Failed to create default roles: ${error.message}`);
    }
  }

  // Static method to find roles by category
  static async findByCategory(category) {
    try {
      return await this.findAll({
        where: { category },
        order: [['level', 'DESC']]
      });
    } catch (error) {
      throw new Error(`Failed to find roles by category: ${error.message}`);
    }
  }

  // Static method to find roles by minimum level
  static async findByMinLevel(minLevel) {
    try {
      return await this.findAll({
        where: {
          level: {
            [Op.gte]: minLevel
          }
        },
        order: [['level', 'DESC']]
      });
    } catch (error) {
      throw new Error(`Failed to find roles by level: ${error.message}`);
    }
  }

  // Instance method to add permission
  addPermission(module, action) {
    const permissions = { ...this.permissions };
    
    if (!permissions[module]) {
      permissions[module] = [];
    }
    
    if (!permissions[module].includes(action)) {
      permissions[module].push(action);
      this.permissions = permissions;
    }
  }

  // Instance method to remove permission
  removePermission(module, action) {
    const permissions = { ...this.permissions };
    
    if (permissions[module]) {
      permissions[module] = permissions[module].filter(a => a !== action);
      
      if (permissions[module].length === 0) {
        delete permissions[module];
      }
      
      this.permissions = permissions;
    }
  }

  // Define associations
  static associate(models) {
    Role.hasMany(models.UserRole, {
      foreignKey: 'role_id',
      as: 'userRoles'
    });
  }
}

export default Role;