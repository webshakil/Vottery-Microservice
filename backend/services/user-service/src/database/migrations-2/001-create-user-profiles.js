// // database/migrations/001-create-user-profiles.js
// import { DataTypes } from 'sequelize';

// export default {
//   up: async (queryInterface, Sequelize) => {
//     await queryInterface.createTable('user_profiles', {
//       id: {
//         allowNull: false,
//         autoIncrement: true,
//         primaryKey: true,
//         type: DataTypes.INTEGER
//       },
//       user_id: {
//         type: DataTypes.INTEGER,
//         allowNull: false,
//         references: {
//           model: 'vottery_users',
//           key: 'id'
//         },
//         onDelete: 'CASCADE',
//         onUpdate: 'CASCADE'
//       },
//       first_name_encrypted: {
//         type: DataTypes.TEXT,
//         allowNull: true
//       },
//       last_name_encrypted: {
//         type: DataTypes.TEXT,
//         allowNull: true
//       },
//       age_encrypted: {
//         type: DataTypes.TEXT,
//         allowNull: true
//       },
//       gender_encrypted: {
//         type: DataTypes.TEXT,
//         allowNull: true
//       },
//       country_encrypted: {
//         type: DataTypes.TEXT,
//         allowNull: true
//       },
//       city_encrypted: {
//         type: DataTypes.TEXT,
//         allowNull: true
//       },
//       preferences_encrypted: {
//         type: DataTypes.TEXT,
//         allowNull: true
//       },
//       avatar_url: {
//         type: DataTypes.STRING(500),
//         allowNull: true
//       },
//       bio_encrypted: {
//         type: DataTypes.TEXT,
//         allowNull: true
//       },
//       created_at: {
//         allowNull: false,
//         type: DataTypes.DATE,
//         defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
//       },
//       updated_at: {
//         allowNull: false,
//         type: DataTypes.DATE,
//         defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
//       }
//     });

//     // Add indexes for performance
//     await queryInterface.addIndex('user_profiles', ['user_id'], {
//       name: 'idx_user_profiles_user_id',
//       unique: true
//     });

//     await queryInterface.addIndex('user_profiles', ['created_at'], {
//       name: 'idx_user_profiles_created_at'
//     });
//   },

//   down: async (queryInterface, Sequelize) => {
//     await queryInterface.dropTable('user_profiles');
//   }
// };


//vottery prefixed version
// database/migrations/001-create-user-profiles.js
import { DataTypes } from 'sequelize';

export default {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('vottery_user_profiles', {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: DataTypes.INTEGER
      },
      user_id: {
        type: DataTypes.INTEGER,
        allowNull: false,
        references: {
          model: 'vottery_users', // already prefixed table
          key: 'id'
        },
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE'
      },
      first_name_encrypted: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      last_name_encrypted: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      age_encrypted: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      gender_encrypted: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      country_encrypted: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      city_encrypted: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      preferences_encrypted: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      avatar_url: {
        type: DataTypes.STRING(500),
        allowNull: true
      },
      bio_encrypted: {
        type: DataTypes.TEXT,
        allowNull: true
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

    // Add indexes for performance
    await queryInterface.addIndex('vottery_user_profiles', ['user_id'], {
      name: 'idx_vottery_user_profiles_user_id',
      unique: true
    });

    await queryInterface.addIndex('vottery_user_profiles', ['created_at'], {
      name: 'idx_vottery_user_profiles_created_at'
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('vottery_user_profiles');
  }
};
