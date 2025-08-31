import { DataTypes } from 'sequelize';

export default {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_digital_signatures', {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      user_id: {
        type: DataTypes.INTEGER,
        references: {
          model: 'vottery_users',
          key: 'id'
        },
        onDelete: 'CASCADE'
      },
      data_hash: {
        type: DataTypes.STRING(64),
        allowNull: false,
        comment: 'SHA-256 hash of signed data'
      },
      signature_data: {
        type: DataTypes.TEXT,
        allowNull: false
      },
      algorithm: {
        type: DataTypes.STRING(20),
        defaultValue: 'RSA-SHA256'
      },
      key_fingerprint: {
        type: DataTypes.STRING(128),
        allowNull: false
      },
      document_type: {
        type: DataTypes.STRING(50),
        comment: 'vote, profile_update, etc.'
      },
      document_id: {
        type: DataTypes.INTEGER,
        comment: 'ID of the signed document'
      },
      verified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      verification_timestamp: {
        type: DataTypes.DATE
      },
      created_at: {
        type: DataTypes.DATE,
        defaultValue: Sequelize.fn('NOW')
      }
    });

    // Add indexes
    await queryInterface.addIndex('vottery_digital_signatures', ['user_id']);
    await queryInterface.addIndex('vottery_digital_signatures', ['data_hash']);
    await queryInterface.addIndex('vottery_digital_signatures', ['key_fingerprint']);
    await queryInterface.addIndex('vottery_digital_signatures', ['document_type', 'document_id']);
    await queryInterface.addIndex('vottery_digital_signatures', ['verified']);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_digital_signatures');
  }
};

// const { DataTypes } = require('sequelize');

// module.exports = {
//   async up(queryInterface, Sequelize) {
//     await queryInterface.createTable('vottery_digital_signatures', {
//       id: {
//         type: DataTypes.INTEGER,
//         primaryKey: true,
//         autoIncrement: true
//       },
//       user_id: {
//         type: DataTypes.INTEGER,
//         references: {
//           model: 'vottery_users',
//           key: 'id'
//         },
//         onDelete: 'CASCADE'
//       },
//       data_hash: {
//         type: DataTypes.STRING(64),
//         allowNull: false,
//         comment: 'SHA-256 hash of signed data'
//       },
//       signature_data: {
//         type: DataTypes.TEXT,
//         allowNull: false
//       },
//       algorithm: {
//         type: DataTypes.STRING(20),
//         defaultValue: 'RSA-SHA256'
//       },
//       key_fingerprint: {
//         type: DataTypes.STRING(128),
//         allowNull: false
//       },
//       document_type: {
//         type: DataTypes.STRING(50),
//         comment: 'vote, profile_update, etc.'
//       },
//       document_id: {
//         type: DataTypes.INTEGER,
//         comment: 'ID of the signed document'
//       },
//       verified: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: false
//       },
//       verification_timestamp: {
//         type: DataTypes.DATE
//       },
//       created_at: {
//         type: DataTypes.DATE,
//         defaultValue: Sequelize.fn('NOW')
//       }
//     });

//     // Add indexes
//     await queryInterface.addIndex('vottery_digital_signatures', ['user_id']);
//     await queryInterface.addIndex('vottery_digital_signatures', ['data_hash']);
//     await queryInterface.addIndex('vottery_digital_signatures', ['key_fingerprint']);
//     await queryInterface.addIndex('vottery_digital_signatures', ['document_type', 'document_id']);
//     await queryInterface.addIndex('vottery_digital_signatures', ['verified']);
//   },

//   async down(queryInterface, Sequelize) {
//     await queryInterface.dropTable('vottery_digital_signatures');
//   }
// };