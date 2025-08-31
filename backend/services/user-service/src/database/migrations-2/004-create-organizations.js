// database/migrations/004-create-organizations.js
import { DataTypes } from 'sequelize';

export default {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('vottery_organizations', {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: DataTypes.INTEGER
      },
      name_encrypted: {
        type: DataTypes.TEXT,
        allowNull: false
      },
      type_encrypted: {
        type: DataTypes.TEXT,
        allowNull: true,
        comment: 'company, nonprofit, government, etc.'
      },
      registration_number_encrypted: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      website: {
        type: DataTypes.STRING(255),
        allowNull: true
      },
      verification_status: {
        type: DataTypes.ENUM('pending', 'verified', 'rejected'),
        allowNull: false,
        defaultValue: 'pending'
      },
      created_by: {
        type: DataTypes.INTEGER,
        allowNull: false,
        references: {
          model: 'vottery_users',
          key: 'id'
        }
      },
      created_at: {
        allowNull: false,
        type: DataTypes.DATE,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
      },
      updated_at: {
        allowNull: false,
        type: DataTypes.DATE,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
      }
    });

    // Add indexes
    await queryInterface.addIndex('organizations', ['created_by'], {
      name: 'idx_organizations_created_by'
    });

    await queryInterface.addIndex('organizations', ['verification_status'], {
      name: 'idx_organizations_verification_status'
    });

    await queryInterface.addIndex('organizations', ['created_at'], {
      name: 'idx_organizations_created_at'
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('organizations');
  }
};