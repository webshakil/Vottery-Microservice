// database/migrations/005-create-organization-members.js
import { DataTypes } from 'sequelize';

export default {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('organization_members', {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: DataTypes.INTEGER
      },
      organization_id: {
        type: DataTypes.INTEGER,
        allowNull: false,
        references: {
          model: 'organizations',
          key: 'id'
        },
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE'
      },
      user_id: {
        type: DataTypes.INTEGER,
        allowNull: false,
        references: {
          model: 'vottery_users',
          key: 'id'
        },
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE'
      },
      role: {
        type: DataTypes.ENUM('owner', 'admin', 'member'),
        allowNull: false,
        defaultValue: 'member'
      },
      joined_at: {
        allowNull: false,
        type: DataTypes.DATE,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
      }
    });

    // Add unique constraint and indexes
    await queryInterface.addConstraint('organization_members', {
      fields: ['organization_id', 'user_id'],
      type: 'unique',
      name: 'unique_organization_member'
    });

    await queryInterface.addIndex('organization_members', ['organization_id'], {
      name: 'idx_org_members_organization_id'
    });

    await queryInterface.addIndex('organization_members', ['user_id'], {
      name: 'idx_org_members_user_id'
    });

    await queryInterface.addIndex('organization_members', ['role'], {
      name: 'idx_org_members_role'
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('organization_members');
  }
};