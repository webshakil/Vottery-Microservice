import { DataTypes } from 'sequelize';

export default {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_subscriptions', {
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
      plan_type: {
        type: DataTypes.ENUM('free', 'pay_as_you_go', 'monthly', '3_month', '6_month', 'yearly'),
        defaultValue: 'free'
      },
      status: {
        type: DataTypes.ENUM('active', 'cancelled', 'expired', 'suspended'),
        defaultValue: 'active'
      },
      limits_json: {
        type: DataTypes.JSON,
        comment: 'voting limits, election creation limits, etc.'
      },
      usage_tracking: {
        type: DataTypes.JSON,
        defaultValue: {
          elections_created: 0,
          votes_cast: 0,
          monthly_usage: {}
        }
      },
      stripe_subscription_id: {
        type: DataTypes.STRING(100)
      },
      paddle_subscription_id: {
        type: DataTypes.STRING(100)
      },
      payment_method: {
        type: DataTypes.ENUM('stripe', 'paddle', 'manual'),
        defaultValue: 'stripe'
      },
      starts_at: {
        type: DataTypes.DATE,
        defaultValue: Sequelize.fn('NOW')
      },
      expires_at: {
        type: DataTypes.DATE
      },
      auto_renew: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
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
    await queryInterface.addIndex('vottery_subscriptions', ['user_id']);
    await queryInterface.addIndex('vottery_subscriptions', ['plan_type']);
    await queryInterface.addIndex('vottery_subscriptions', ['status']);
    await queryInterface.addIndex('vottery_subscriptions', ['stripe_subscription_id']);
    await queryInterface.addIndex('vottery_subscriptions', ['paddle_subscription_id']);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_subscriptions');
  }
};


// const { DataTypes } = require('sequelize');

// module.exports = {
//   async up(queryInterface, Sequelize) {
//     await queryInterface.createTable('vottery_subscriptions', {
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
//       plan_type: {
//         type: DataTypes.ENUM('free', 'pay_as_you_go', 'monthly', '3_month', '6_month', 'yearly'),
//         defaultValue: 'free'
//       },
//       status: {
//         type: DataTypes.ENUM('active', 'cancelled', 'expired', 'suspended'),
//         defaultValue: 'active'
//       },
//       limits_json: {
//         type: DataTypes.JSON,
//         comment: 'voting limits, election creation limits, etc.'
//       },
//       usage_tracking: {
//         type: DataTypes.JSON,
//         defaultValue: {
//           elections_created: 0,
//           votes_cast: 0,
//           monthly_usage: {}
//         }
//       },
//       stripe_subscription_id: {
//         type: DataTypes.STRING(100)
//       },
//       paddle_subscription_id: {
//         type: DataTypes.STRING(100)
//       },
//       payment_method: {
//         type: DataTypes.ENUM('stripe', 'paddle', 'manual'),
//         defaultValue: 'stripe'
//       },
//       starts_at: {
//         type: DataTypes.DATE,
//         defaultValue: Sequelize.fn('NOW')
//       },
//       expires_at: {
//         type: DataTypes.DATE
//       },
//       auto_renew: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: false
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
//     await queryInterface.addIndex('vottery_subscriptions', ['user_id']);
//     await queryInterface.addIndex('vottery_subscriptions', ['plan_type']);
//     await queryInterface.addIndex('vottery_subscriptions', ['status']);
//     await queryInterface.addIndex('vottery_subscriptions', ['stripe_subscription_id']);
//     await queryInterface.addIndex('vottery_subscriptions', ['paddle_subscription_id']);
//   },

//   async down(queryInterface, Sequelize) {
//     await queryInterface.dropTable('vottery_subscriptions');
//   }
// };