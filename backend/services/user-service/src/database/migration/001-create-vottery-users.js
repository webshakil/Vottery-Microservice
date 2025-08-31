import { DataTypes } from 'sequelize';

export default {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_users', {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      email: {
        type: DataTypes.STRING(255),
        allowNull: false,
        unique: true
      },
      email_verified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      phone: {
        type: DataTypes.STRING(20)
      },
      phone_verified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      password_hash: {
        type: DataTypes.TEXT
      },
      status: {
        type: DataTypes.ENUM('active', 'inactive', 'suspended', 'deleted'),
        defaultValue: 'active'
      },
      last_login_at: {
        type: DataTypes.DATE
      },
      login_attempts: {
        type: DataTypes.INTEGER,
        defaultValue: 0
      },
      locked_until: {
        type: DataTypes.DATE
      },
      two_factor_enabled: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      two_factor_secret: {
        type: DataTypes.TEXT
      },
      recovery_codes: {
        type: DataTypes.JSON
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
    await queryInterface.addIndex('vottery_users', ['email']);
    await queryInterface.addIndex('vottery_users', ['status']);
    await queryInterface.addIndex('vottery_users', ['created_at']);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_users');
  }
};

// const { DataTypes } = require('sequelize');

// module.exports = {
//   async up(queryInterface, Sequelize) {
//     await queryInterface.createTable('vottery_users', {
//       id: {
//         type: DataTypes.INTEGER,
//         primaryKey: true,
//         autoIncrement: true
//       },
//       email: {
//         type: DataTypes.STRING(255),
//         allowNull: false,
//         unique: true
//       },
//       email_verified: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: false
//       },
//       phone: {
//         type: DataTypes.STRING(20)
//       },
//       phone_verified: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: false
//       },
//       password_hash: {
//         type: DataTypes.TEXT
//       },
//       status: {
//         type: DataTypes.ENUM('active', 'inactive', 'suspended', 'deleted'),
//         defaultValue: 'active'
//       },
//       last_login_at: {
//         type: DataTypes.DATE
//       },
//       login_attempts: {
//         type: DataTypes.INTEGER,
//         defaultValue: 0
//       },
//       locked_until: {
//         type: DataTypes.DATE
//       },
//       two_factor_enabled: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: false
//       },
//       two_factor_secret: {
//         type: DataTypes.TEXT
//       },
//       recovery_codes: {
//         type: DataTypes.JSON
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
//     await queryInterface.addIndex('vottery_users', ['email']);
//     await queryInterface.addIndex('vottery_users', ['status']);
//     await queryInterface.addIndex('vottery_users', ['created_at']);
//   },

//   async down(queryInterface, Sequelize) {
//     await queryInterface.dropTable('vottery_users');
//   }
// };