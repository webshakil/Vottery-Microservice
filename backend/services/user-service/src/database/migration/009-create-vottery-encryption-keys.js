import { DataTypes } from 'sequelize';

export default {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_encryption_keys', {
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
      key_type: {
        type: DataTypes.ENUM('rsa_public', 'rsa_private', 'elgamal_public', 'elgamal_private', 'threshold', 'aes'),
        allowNull: false
      },
      key_data_encrypted: {
        type: DataTypes.TEXT,
        allowNull: false
      },
      key_fingerprint: {
        type: DataTypes.STRING(128),
        allowNull: false,
        unique: true
      },
      algorithm: {
        type: DataTypes.STRING(50),
        defaultValue: 'RSA-2048'
      },
      key_size: {
        type: DataTypes.INTEGER,
        defaultValue: 2048
      },
      purpose: {
        type: DataTypes.ENUM('voting', 'profile', 'communication', 'signature'),
        defaultValue: 'voting'
      },
      is_active: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
      },
      created_at: {
        type: DataTypes.DATE,
        defaultValue: Sequelize.fn('NOW')
      },
      expires_at: {
        type: DataTypes.DATE
      },
      revoked_at: {
        type: DataTypes.DATE
      }
    });

    // Add indexes
    await queryInterface.addIndex('vottery_encryption_keys', ['user_id']);
    await queryInterface.addIndex('vottery_encryption_keys', ['key_type']);
    await queryInterface.addIndex('vottery_encryption_keys', ['key_fingerprint']);
    await queryInterface.addIndex('vottery_encryption_keys', ['purpose']);
    await queryInterface.addIndex('vottery_encryption_keys', ['is_active']);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_encryption_keys');
  }
};

// const { DataTypes } = require('sequelize');

// module.exports = {
//   async up(queryInterface, Sequelize) {
//     await queryInterface.createTable('vottery_encryption_keys', {
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
//       key_type: {
//         type: DataTypes.ENUM('rsa_public', 'rsa_private', 'elgamal_public', 'elgamal_private', 'threshold', 'aes'),
//         allowNull: false
//       },
//       key_data_encrypted: {
//         type: DataTypes.TEXT,
//         allowNull: false
//       },
//       key_fingerprint: {
//         type: DataTypes.STRING(128),
//         allowNull: false,
//         unique: true
//       },
//       algorithm: {
//         type: DataTypes.STRING(50),
//         defaultValue: 'RSA-2048'
//       },
//       key_size: {
//         type: DataTypes.INTEGER,
//         defaultValue: 2048
//       },
//       purpose: {
//         type: DataTypes.ENUM('voting', 'profile', 'communication', 'signature'),
//         defaultValue: 'voting'
//       },
//       is_active: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: true
//       },
//       created_at: {
//         type: DataTypes.DATE,
//         defaultValue: Sequelize.fn('NOW')
//       },
//       expires_at: {
//         type: DataTypes.DATE
//       },
//       revoked_at: {
//         type: DataTypes.DATE
//       }
//     });

//     // Add indexes
//     await queryInterface.addIndex('vottery_encryption_keys', ['user_id']);
//     await queryInterface.addIndex('vottery_encryption_keys', ['key_type']);
//     await queryInterface.addIndex('vottery_encryption_keys', ['key_fingerprint']);
//     await queryInterface.addIndex('vottery_encryption_keys', ['purpose']);
//     await queryInterface.addIndex('vottery_encryption_keys', ['is_active']);
//   },

//   async down(queryInterface, Sequelize) {
//     await queryInterface.dropTable('vottery_encryption_keys');
//   }
// };