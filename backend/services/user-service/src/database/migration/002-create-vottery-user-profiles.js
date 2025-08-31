import { DataTypes } from 'sequelize';

export default {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_user_profiles', {
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
        onDelete: 'CASCADE',
        unique: true
      },
      first_name_encrypted: {
        type: DataTypes.TEXT
      },
      last_name_encrypted: {
        type: DataTypes.TEXT
      },
      age_encrypted: {
        type: DataTypes.TEXT
      },
      gender_encrypted: {
        type: DataTypes.TEXT
      },
      country_encrypted: {
        type: DataTypes.TEXT
      },
      city_encrypted: {
        type: DataTypes.TEXT
      },
      preferences_encrypted: {
        type: DataTypes.TEXT
      },
      avatar_url: {
        type: DataTypes.STRING(500)
      },
      bio_encrypted: {
        type: DataTypes.TEXT
      },
      privacy_settings: {
        type: DataTypes.JSON,
        defaultValue: {
          profile_visibility: 'public',
          email_visibility: 'private',
          activity_visibility: 'friends'
        }
      },
      notification_preferences: {
        type: DataTypes.JSON,
        defaultValue: {
          email_notifications: true,
          push_notifications: true,
          sms_notifications: false
        }
      },
      profile_completion_score: {
        type: DataTypes.INTEGER,
        defaultValue: 0
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
    await queryInterface.addIndex('vottery_user_profiles', ['user_id']);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_user_profiles');
  }
};

// const { DataTypes } = require('sequelize');

// module.exports = {
//   async up(queryInterface, Sequelize) {
//     await queryInterface.createTable('vottery_user_profiles', {
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
//         onDelete: 'CASCADE',
//         unique: true
//       },
//       first_name_encrypted: {
//         type: DataTypes.TEXT
//       },
//       last_name_encrypted: {
//         type: DataTypes.TEXT
//       },
//       age_encrypted: {
//         type: DataTypes.TEXT
//       },
//       gender_encrypted: {
//         type: DataTypes.TEXT
//       },
//       country_encrypted: {
//         type: DataTypes.TEXT
//       },
//       city_encrypted: {
//         type: DataTypes.TEXT
//       },
//       preferences_encrypted: {
//         type: DataTypes.TEXT
//       },
//       avatar_url: {
//         type: DataTypes.STRING(500)
//       },
//       bio_encrypted: {
//         type: DataTypes.TEXT
//       },
//       privacy_settings: {
//         type: DataTypes.JSON,
//         defaultValue: {
//           profile_visibility: 'public',
//           email_visibility: 'private',
//           activity_visibility: 'friends'
//         }
//       },
//       notification_preferences: {
//         type: DataTypes.JSON,
//         defaultValue: {
//           email_notifications: true,
//           push_notifications: true,
//           sms_notifications: false
//         }
//       },
//       profile_completion_score: {
//         type: DataTypes.INTEGER,
//         defaultValue: 0
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
//     await queryInterface.addIndex('vottery_user_profiles', ['user_id']);
//   },

//   async down(queryInterface, Sequelize) {
//     await queryInterface.dropTable('vottery_user_profiles');
//   }
// };