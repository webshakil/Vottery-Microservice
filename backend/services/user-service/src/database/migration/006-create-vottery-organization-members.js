import { DataTypes } from 'sequelize';

export default {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_organization_members', {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      organization_id: {
        type: DataTypes.INTEGER,
        allowNull: false,
        references: {
          model: 'vottery_organizations',
          key: 'id'
        },
        onDelete: 'CASCADE'
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
      role: {
        type: DataTypes.ENUM('owner', 'admin', 'member'),
        defaultValue: 'member'
      },
      permissions: {
        type: DataTypes.JSON,
        defaultValue: []
      },
      invited_by: {
        type: DataTypes.INTEGER,
        references: {
          model: 'vottery_users',
          key: 'id'
        }
      },
      invitation_status: {
        type: DataTypes.ENUM('pending', 'accepted', 'declined'),
        defaultValue: 'accepted'
      },
      joined_at: {
        type: DataTypes.DATE,
        defaultValue: Sequelize.fn('NOW')
      }
    });

    // Add unique constraint
    await queryInterface.addConstraint('vottery_organization_members', {
      fields: ['organization_id', 'user_id'],
      type: 'unique',
      name: 'unique_organization_user'
    });

    // Add indexes
    await queryInterface.addIndex('vottery_organization_members', ['organization_id']);
    await queryInterface.addIndex('vottery_organization_members', ['user_id']);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_organization_members');
  }
};



// const { DataTypes } = require('sequelize');

// module.exports = {
//   async up(queryInterface, Sequelize) {
//     await queryInterface.createTable('vottery_organization_members', {
//       id: {
//         type: DataTypes.INTEGER,
//         primaryKey: true,
//         autoIncrement: true
//       },
//       organization_id: {
//         type: DataTypes.INTEGER,
//         allowNull: false,
//         references: {
//           model: 'vottery_organizations',
//           key: 'id'
//         },
//         onDelete: 'CASCADE'
//       },
//       user_id: {
//         type: DataTypes.INTEGER,
//         allowNull: false,
//         references: {
//           model: 'vottery_users',
//           key: 'id'
//         },
//         onDelete: 'CASCADE'
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
//         type: DataTypes.INTEGER,
//         references: {
//           model: 'vottery_users',
//           key: 'id'
//         }
//       },
//       invitation_status: {
//         type: DataTypes.ENUM('pending', 'accepted', 'declined'),
//         defaultValue: 'accepted'
//       },
//       joined_at: {
//         type: DataTypes.DATE,
//         defaultValue: Sequelize.fn('NOW')
//       }
//     });

//     // Add unique constraint
//     await queryInterface.addConstraint('vottery_organization_members', {
//       fields: ['organization_id', 'user_id'],
//       type: 'unique',
//       name: 'unique_organization_user'
//     });

//     // Add indexes
//     await queryInterface.addIndex('vottery_organization_members', ['organization_id']);
//     await queryInterface.addIndex('vottery_organization_members', ['user_id']);
//   },

//   async down(queryInterface, Sequelize) {
//     await queryInterface.dropTable('vottery_organization_members');
//   }
// };