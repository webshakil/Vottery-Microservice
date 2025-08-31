import { DataTypes, Model } from 'sequelize';

export default class UserRole extends Model {
  static init(sequelize) {
    return super.init({
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      user_id: {
        type: DataTypes.INTEGER,
        allowNull: false
      },
      role_id: {
        type: DataTypes.INTEGER,
        allowNull: false
      },
      assigned_by: {
        type: DataTypes.INTEGER
      },
      assigned_at: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW
      },
      expires_at: {
        type: DataTypes.DATE
      },
      is_active: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
      }
    }, {
      sequelize,
      modelName: 'UserRole',
      tableName: 'vottery_user_roles',
      timestamps: false,
      indexes: [
        {
          unique: true,
          fields: ['user_id', 'role_id'],
          name: 'unique_user_role'
        }
      ]
    });
  }

  static associate(models) {
    // Belongs to VotteryUser
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'user_id',
      as: 'user'
    });

    // Belongs to Role
    this.belongsTo(models.Role, {
      foreignKey: 'role_id',
      as: 'role'
    });

    // Belongs to VotteryUser (assigned by)
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'assigned_by',
      as: 'assignedBy'
    });
  }

  // Check if role assignment is currently valid
  isValid() {
    if (!this.is_active) return false;
    if (this.expires_at && new Date() > this.expires_at) return false;
    return true;
  }

  // Deactivate role assignment
  async deactivate() {
    this.is_active = false;
    await this.save();
  }
}

// const { DataTypes, Model } = require('sequelize');

// class UserRole extends Model {
//   static init(sequelize) {
//     return super.init({
//       id: {
//         type: DataTypes.INTEGER,
//         primaryKey: true,
//         autoIncrement: true
//       },
//       user_id: {
//         type: DataTypes.INTEGER,
//         allowNull: false
//       },
//       role_id: {
//         type: DataTypes.INTEGER,
//         allowNull: false
//       },
//       assigned_by: {
//         type: DataTypes.INTEGER
//       },
//       assigned_at: {
//         type: DataTypes.DATE,
//         defaultValue: DataTypes.NOW
//       },
//       expires_at: {
//         type: DataTypes.DATE
//       },
//       is_active: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: true
//       }
//     }, {
//       sequelize,
//       modelName: 'UserRole',
//       tableName: 'vottery_user_roles',
//       timestamps: false,
//       indexes: [
//         {
//           unique: true,
//           fields: ['user_id', 'role_id'],
//           name: 'unique_user_role'
//         }
//       ]
//     });
//   }

//   static associate(models) {
//     // Belongs to VotteryUser
//     this.belongsTo(models.VotteryUser, {
//       foreignKey: 'user_id',
//       as: 'user'
//     });

//     // Belongs to Role
//     this.belongsTo(models.Role, {
//       foreignKey: 'role_id',
//       as: 'role'
//     });

//     // Belongs to VotteryUser (assigned by)
//     this.belongsTo(models.VotteryUser, {
//       foreignKey: 'assigned_by',
//       as: 'assignedBy'
//     });
//   }

//   // Check if role assignment is currently valid
//   isValid() {
//     if (!this.is_active) return false;
//     if (this.expires_at && new Date() > this.expires_at) return false;
//     return true;
//   }

//   // Deactivate role assignment
//   async deactivate() {
//     this.is_active = false;
//     await this.save();
//   }
// }

// module.exports = UserRole;