import { DataTypes } from 'sequelize';

export default {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_roles', {
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
      },
      created_at: {
        type: DataTypes.DATE,
        defaultValue: Sequelize.fn('NOW')
      },
      updated_at: {
        type: DataTypes.DATE,
        defaultValue: Sequelize.fn('NOW')
      }
    });

    // Add indexes
    await queryInterface.addIndex('vottery_roles', ['category']);
    await queryInterface.addIndex('vottery_roles', ['level']);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_roles');
  }
};

// const { DataTypes } = require('sequelize');

// module.exports = {
//   async up(queryInterface, Sequelize) {
//     await queryInterface.createTable('vottery_roles', {
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
//       },
//       created_at: {
//         type: DataTypes.DATE,
//         defaultValue: Sequelize.fn('NOW')
//       },
//       updated_at: {
//         type: DataTypes.DATE,
//         defaultValue: Sequelize.fn('NOW')
//       }
//     });

//     // Add indexes
//     await queryInterface.addIndex('vottery_roles', ['category']);
//     await queryInterface.addIndex('vottery_roles', ['level']);
//   },

//   async down(queryInterface, Sequelize) {
//     await queryInterface.dropTable('vottery_roles');
//   }
// };