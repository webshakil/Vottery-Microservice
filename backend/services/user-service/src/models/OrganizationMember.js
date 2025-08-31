
import { DataTypes, Model } from 'sequelize';

class OrganizationMember extends Model {
  static init(sequelize) {
    return super.init({
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      organization_id: {
        type: DataTypes.INTEGER,
        allowNull: false
      },
      user_id: {
        type: DataTypes.INTEGER,
        allowNull: false
      },
      role: {
        type: DataTypes.ENUM('owner', 'admin', 'member'),
        defaultValue: 'member'
      },
      permissions: {
        type: DataTypes.JSON,
        defaultValue: []
      },
      invited_by: {
        type: DataTypes.INTEGER
      },
      invitation_status: {
        type: DataTypes.ENUM('pending', 'accepted', 'declined'),
        defaultValue: 'accepted'
      },
      joined_at: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW
      }
    }, {
      sequelize,
      modelName: 'OrganizationMember',
      tableName: 'vottery_organization_members',
      timestamps: false,
      indexes: [
        {
          unique: true,
          fields: ['organization_id', 'user_id'],
          name: 'unique_organization_user'
        }
      ]
    });
  }

  static associate(models) {
    // Belongs to Organization
    this.belongsTo(models.Organization, {
      foreignKey: 'organization_id',
      as: 'organization'
    });

    // Belongs to VotteryUser
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'user_id',
      as: 'user'
    });

    // Belongs to VotteryUser (invited by)
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'invited_by',
      as: 'invitedBy'
    });
  }

  // Check if member has specific permission
  hasPermission(permission) {
    return this.permissions.includes(permission);
  }

  // Check if member can manage other members
  canManageMembers() {
    return ['owner', 'admin'].includes(this.role);
  }

  // Check if member is owner
  isOwner() {
    return this.role === 'owner';
  }
}

export default OrganizationMember;

// const { DataTypes, Model } = require('sequelize');

// class OrganizationMember extends Model {
//   static init(sequelize) {
//     return super.init({
//       id: {
//         type: DataTypes.INTEGER,
//         primaryKey: true,
//         autoIncrement: true
//       },
//       organization_id: {
//         type: DataTypes.INTEGER,
//         allowNull: false
//       },
//       user_id: {
//         type: DataTypes.INTEGER,
//         allowNull: false
//       },
//       role: {
//         type: DataTypes.ENUM('owner', 'admin', 'member'),
//         defaultValue: 'member'
//       },
//       permissions: {
//         type: DataTypes.JSON,
//         defaultValue: []
//       },
//       invited_by: {
//         type: DataTypes.INTEGER
//       },
//       invitation_status: {
//         type: DataTypes.ENUM('pending', 'accepted', 'declined'),
//         defaultValue: 'accepted'
//       },
//       joined_at: {
//         type: DataTypes.DATE,
//         defaultValue: DataTypes.NOW
//       }
//     }, {
//       sequelize,
//       modelName: 'OrganizationMember',
//       tableName: 'vottery_organization_members',
//       timestamps: false,
//       indexes: [
//         {
//           unique: true,
//           fields: ['organization_id', 'user_id'],
//           name: 'unique_organization_user'
//         }
//       ]
//     });
//   }

//   static associate(models) {
//     // Belongs to Organization
//     this.belongsTo(models.Organization, {
//       foreignKey: 'organization_id',
//       as: 'organization'
//     });

//     // Belongs to VotteryUser
//     this.belongsTo(models.VotteryUser, {
//       foreignKey: 'user_id',
//       as: 'user'
//     });

//     // Belongs to VotteryUser (invited by)
//     this.belongsTo(models.VotteryUser, {
//       foreignKey: 'invited_by',
//       as: 'invitedBy'
//     });
//   }

//   // Check if member has specific permission
//   hasPermission(permission) {
//     return this.permissions.includes(permission);
//   }

//   // Check if member can manage other members
//   canManageMembers() {
//     return ['owner', 'admin'].includes(this.role);
//   }

//   // Check if member is owner
//   isOwner() {
//     return this.role === 'owner';
//   }
// }

// module.exports = OrganizationMember;