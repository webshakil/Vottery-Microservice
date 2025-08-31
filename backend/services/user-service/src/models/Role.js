import { DataTypes, Model } from 'sequelize';

export default class Role extends Model {
  static init(sequelize) {
    return super.init({
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      name: {
        type: DataTypes.STRING(50),
        allowNull: false,
        unique: true
      },
      category: {
        type: DataTypes.ENUM('admin', 'user'),
        allowNull: false
      },
      level: {
        type: DataTypes.INTEGER,
        allowNull: false,
        comment: 'Higher number = more permissions'
      },
      permissions: {
        type: DataTypes.JSON,
        allowNull: false
      },
      description: {
        type: DataTypes.TEXT
      },
      is_system_role: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        comment: 'System roles cannot be deleted'
      }
    }, {
      sequelize,
      modelName: 'Role',
      tableName: 'vottery_roles',
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at'
    });
  }

  static associate(models) {
    // Many-to-Many with VotteryUsers through UserRoles
    this.belongsToMany(models.VotteryUser, {
      through: models.UserRole,
      foreignKey: 'role_id',
      otherKey: 'user_id',
      as: 'users'
    });

    // One-to-Many with UserRoles
    this.hasMany(models.UserRole, {
      foreignKey: 'role_id',
      as: 'userRoles'
    });
  }

  // Check if role has specific permission
  hasPermission(permission) {
    return this.permissions.includes(permission);
  }

  // Check if role has any of the specified permissions
  hasAnyPermission(permissions) {
    return permissions.some(permission => this.permissions.includes(permission));
  }

  // Check if role has all specified permissions
  hasAllPermissions(permissions) {
    return permissions.every(permission => this.permissions.includes(permission));
  }
}

// const { DataTypes, Model } = require('sequelize');

// class Role extends Model {
//   static init(sequelize) {
//     return super.init({
//       id: {
//         type: DataTypes.INTEGER,
//         primaryKey: true,
//         autoIncrement: true
//       },
//       name: {
//         type: DataTypes.STRING(50),
//         allowNull: false,
//         unique: true
//       },
//       category: {
//         type: DataTypes.ENUM('admin', 'user'),
//         allowNull: false
//       },
//       level: {
//         type: DataTypes.INTEGER,
//         allowNull: false,
//         comment: 'Higher number = more permissions'
//       },
//       permissions: {
//         type: DataTypes.JSON,
//         allowNull: false
//       },
//       description: {
//         type: DataTypes.TEXT
//       },
//       is_system_role: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: false,
//         comment: 'System roles cannot be deleted'
//       }
//     }, {
//       sequelize,
//       modelName: 'Role',
//       tableName: 'vottery_roles',
//       timestamps: true,
//       createdAt: 'created_at',
//       updatedAt: 'updated_at'
//     });
//   }

//   static associate(models) {
//     // Many-to-Many with VotteryUsers through UserRoles
//     this.belongsToMany(models.VotteryUser, {
//       through: models.UserRole,
//       foreignKey: 'role_id',
//       otherKey: 'user_id',
//       as: 'users'
//     });

//     // One-to-Many with UserRoles
//     this.hasMany(models.UserRole, {
//       foreignKey: 'role_id',
//       as: 'userRoles'
//     });
//   }

//   // Check if role has specific permission
//   hasPermission(permission) {
//     return this.permissions.includes(permission);
//   }

//   // Check if role has any of the specified permissions
//   hasAnyPermission(permissions) {
//     return permissions.some(permission => this.permissions.includes(permission));
//   }

//   // Check if role has all specified permissions
//   hasAllPermissions(permissions) {
//     return permissions.every(permission => this.permissions.includes(permission));
//   }
// }

// module.exports = Role;