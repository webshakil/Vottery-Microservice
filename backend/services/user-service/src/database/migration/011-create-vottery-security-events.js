import { DataTypes } from 'sequelize';

export default {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_security_events', {
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
      event_type: {
        type: DataTypes.ENUM('login_attempt', 'password_change', 'email_change', 'suspicious_activity', 'account_locked', 'key_generated', 'key_revoked'),
        allowNull: false
      },
      severity: {
        type: DataTypes.ENUM('info', 'warning', 'error', 'critical'),
        defaultValue: 'info'
      },
      description: {
        type: DataTypes.TEXT
      },
      metadata: {
        type: DataTypes.JSON
      },
      ip_address: {
        type: DataTypes.INET
      },
      user_agent: {
        type: DataTypes.TEXT
      },
      resolved: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      resolved_by: {
        type: DataTypes.INTEGER,
        references: {
          model: 'vottery_users',
          key: 'id'
        }
      },
      resolved_at: {
        type: DataTypes.DATE
      },
      created_at: {
        type: DataTypes.DATE,
        defaultValue: Sequelize.fn('NOW')
      }
    });

    // Add indexes
    await queryInterface.addIndex('vottery_security_events', ['user_id']);
    await queryInterface.addIndex('vottery_security_events', ['event_type']);
    await queryInterface.addIndex('vottery_security_events', ['severity']);
    await queryInterface.addIndex('vottery_security_events', ['resolved']);
    await queryInterface.addIndex('vottery_security_events', ['created_at']);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_security_events');
  }
};

// const { DataTypes } = require('sequelize');

// module.exports = {
//   async up(queryInterface, Sequelize) {
//     await queryInterface.createTable('vottery_security_events', {
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
//       event_type: {
//         type: DataTypes.ENUM('login_attempt', 'password_change', 'email_change', 'suspicious_activity', 'account_locked', 'key_generated', 'key_revoked'),
//         allowNull: false
//       },
//       severity: {
//         type: DataTypes.ENUM('info', 'warning', 'error', 'critical'),
//         defaultValue: 'info'
//       },
//       description: {
//         type: DataTypes.TEXT
//       },
//       metadata: {
//         type: DataTypes.JSON
//       },
//       ip_address: {
//         type: DataTypes.INET
//       },
//       user_agent: {
//         type: DataTypes.TEXT
//       },
//       resolved: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: false
//       },
//       resolved_by: {
//         type: DataTypes.INTEGER,
//         references: {
//           model: 'vottery_users',
//           key: 'id'
//         }
//       },
//       resolved_at: {
//         type: DataTypes.DATE
//       },
//       created_at: {
//         type: DataTypes.DATE,
//         defaultValue: Sequelize.fn('NOW')
//       }
//     });

//     // Add indexes
//     await queryInterface.addIndex('vottery_security_events', ['user_id']);
//     await queryInterface.addIndex('vottery_security_events', ['event_type']);
//     await queryInterface.addIndex('vottery_security_events', ['severity']);
//     await queryInterface.addIndex('vottery_security_events', ['resolved']);
//     await queryInterface.addIndex('vottery_security_events', ['created_at']);
//   },

//   async down(queryInterface, Sequelize) {
//     await queryInterface.dropTable('vottery_security_events');
//   }
// };