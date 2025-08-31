import { DataTypes } from 'sequelize';

export default {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_user_roles', {
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
          model: 'vottery_roles',
          key: 'id'
        },
        onDelete: 'CASCADE'
      },
      assigned_by: {
        type: DataTypes.INTEGER,
        references: {
          model: 'vottery_users',
          key: 'id'
        }
      },
      assigned_at: {
        type: DataTypes.DATE,
        defaultValue: Sequelize.fn('NOW')
      },
      expires_at: {
        type: DataTypes.DATE
      },
      is_active: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
      }
    });

    // Add unique constraint
    await queryInterface.addConstraint('vottery_user_roles', {
      fields: ['user_id', 'role_id'],
      type: 'unique',
      name: 'unique_user_role'
    });

    // Add indexes
    await queryInterface.addIndex('vottery_user_roles', ['user_id']);
    await queryInterface.addIndex('vottery_user_roles', ['role_id']);
    await queryInterface.addIndex('vottery_user_roles', ['assigned_by']);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_user_roles');
  }
};

// const { DataTypes } = require('sequelize');

// module.exports = {
//   async up(queryInterface, Sequelize) {
//     await queryInterface.createTable('vottery_user_roles', {
//       id: {
//         type: DataTypes.INTEGER,
//         primaryKey: true,
//         autoIncrement: true
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
//       role_id: {
//         type: DataTypes.INTEGER,
//         allowNull: false,
//         references: {
//           model: 'vottery_roles',
//           key: 'id'
//         },
//         onDelete: 'CASCADE'
//       },
//       assigned_by: {
//         type: DataTypes.INTEGER,
//         references: {
//           model: 'vottery_users',
//           key: 'id'
//         }
//       },
//       assigned_at: {
//         type: DataTypes.DATE,
//         defaultValue: Sequelize.fn('NOW')
//       },
//       expires_at: {
//         type: DataTypes.DATE
//       },
//       is_active: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: true
//       }
//     });

//     // Add unique constraint
//     await queryInterface.addConstraint('vottery_user_roles', {
//       fields: ['user_id', 'role_id'],
//       type: 'unique',
//       name: 'unique_user_role'
//     });

//     // Add indexes
//     await queryInterface.addIndex('vottery_user_roles', ['user_id']);
//     await queryInterface.addIndex('vottery_user_roles', ['role_id']);
//     await queryInterface.addIndex('vottery_user_roles', ['assigned_by']);
//   },

//   async down(queryInterface, Sequelize) {
//     await queryInterface.dropTable('vottery_user_roles');
//   }
// };