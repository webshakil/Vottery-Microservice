import { DataTypes } from 'sequelize';

export default {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_organizations', {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      name_encrypted: {
        type: DataTypes.TEXT,
        allowNull: false
      },
      type_encrypted: {
        type: DataTypes.TEXT,
        comment: 'company, nonprofit, government, etc.'
      },
      registration_number_encrypted: {
        type: DataTypes.TEXT
      },
      website: {
        type: DataTypes.STRING(255)
      },
      verification_status: {
        type: DataTypes.ENUM('pending', 'verified', 'rejected'),
        defaultValue: 'pending'
      },
      verification_documents: {
        type: DataTypes.JSON
      },
      settings: {
        type: DataTypes.JSON,
        defaultValue: {}
      },
      created_by: {
        type: DataTypes.INTEGER,
        references: {
          model: 'vottery_users',
          key: 'id'
        }
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
    await queryInterface.addIndex('vottery_organizations', ['created_by']);
    await queryInterface.addIndex('vottery_organizations', ['verification_status']);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_organizations');
  }
};

// // migrations/005-create-vottery-organizations.js
// const { DataTypes } = require('sequelize');

// module.exports = {
//   async up(queryInterface, Sequelize) {
//     await queryInterface.createTable('vottery_organizations', {
//       id: {
//         type: DataTypes.INTEGER,
//         primaryKey: true,
//         autoIncrement: true
//       },
//       name_encrypted: {
//         type: DataTypes.TEXT,
//         allowNull: false
//       },
//       type_encrypted: {
//         type: DataTypes.TEXT,
//         comment: 'company, nonprofit, government, etc.'
//       },
//       registration_number_encrypted: {
//         type: DataTypes.TEXT
//       },
//       website: {
//         type: DataTypes.STRING(255)
//       },
//       verification_status: {
//         type: DataTypes.ENUM('pending', 'verified', 'rejected'),
//         defaultValue: 'pending'
//       },
//       verification_documents: {
//         type: DataTypes.JSON
//       },
//       settings: {
//         type: DataTypes.JSON,
//         defaultValue: {}
//       },
//       created_by: {
//         type: DataTypes.INTEGER,
//         references: {
//           model: 'vottery_users',
//           key: 'id'
//         }
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
//     await queryInterface.addIndex('vottery_organizations', ['created_by']);
//     await queryInterface.addIndex('vottery_organizations', ['verification_status']);
//   },

//   async down(queryInterface, Sequelize) {
//     await queryInterface.dropTable('vottery_organizations');
//   }
// };