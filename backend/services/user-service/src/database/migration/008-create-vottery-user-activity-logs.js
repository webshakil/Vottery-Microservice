import { DataTypes } from 'sequelize';

export default {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_user_activity_logs', {
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
        onDelete: 'SET NULL'
      },
      action: {
        type: DataTypes.STRING(100),
        allowNull: false
      },
      resource_type: {
        type: DataTypes.STRING(50)
      },
      resource_id: {
        type: DataTypes.INTEGER
      },
      details: {
        type: DataTypes.JSON
      },
      ip_address: {
        type: DataTypes.INET
      },
      user_agent: {
        type: DataTypes.TEXT
      },
      service_name: {
        type: DataTypes.STRING(50),
        defaultValue: 'user-service'
      },
      session_id: {
        type: DataTypes.STRING(128)
      },
      severity: {
        type: DataTypes.ENUM('low', 'medium', 'high', 'critical'),
        defaultValue: 'low'
      },
      created_at: {
        type: DataTypes.DATE,
        defaultValue: Sequelize.fn('NOW')
      }
    });

    // Add indexes
    await queryInterface.addIndex('vottery_user_activity_logs', ['user_id', 'created_at']);
    await queryInterface.addIndex('vottery_user_activity_logs', ['action']);
    await queryInterface.addIndex('vottery_user_activity_logs', ['resource_type', 'resource_id']);
    await queryInterface.addIndex('vottery_user_activity_logs', ['severity']);
    await queryInterface.addIndex('vottery_user_activity_logs', ['created_at']);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_user_activity_logs');
  }
};

// const { DataTypes } = require('sequelize');

// module.exports = {
//   async up(queryInterface, Sequelize) {
//     await queryInterface.createTable('vottery_user_activity_logs', {
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
//         onDelete: 'SET NULL'
//       },
//       action: {
//         type: DataTypes.STRING(100),
//         allowNull: false
//       },
//       resource_type: {
//         type: DataTypes.STRING(50)
//       },
//       resource_id: {
//         type: DataTypes.INTEGER
//       },
//       details: {
//         type: DataTypes.JSON
//       },
//       ip_address: {
//         type: DataTypes.INET
//       },
//       user_agent: {
//         type: DataTypes.TEXT
//       },
//       service_name: {
//         type: DataTypes.STRING(50),
//         defaultValue: 'user-service'
//       },
//       session_id: {
//         type: DataTypes.STRING(128)
//       },
//       severity: {
//         type: DataTypes.ENUM('low', 'medium', 'high', 'critical'),
//         defaultValue: 'low'
//       },
//       created_at: {
//         type: DataTypes.DATE,
//         defaultValue: Sequelize.fn('NOW')
//       }
//     });

//     // Add indexes
//     await queryInterface.addIndex('vottery_user_activity_logs', ['user_id', 'created_at']);
//     await queryInterface.addIndex('vottery_user_activity_logs', ['action']);
//     await queryInterface.addIndex('vottery_user_activity_logs', ['resource_type', 'resource_id']);
//     await queryInterface.addIndex('vottery_user_activity_logs', ['severity']);
//     await queryInterface.addIndex('vottery_user_activity_logs', ['created_at']);
//   },

//   async down(queryInterface, Sequelize) {
//     await queryInterface.dropTable('vottery_user_activity_logs');
//   }
// };