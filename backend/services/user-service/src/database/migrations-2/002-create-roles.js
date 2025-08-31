// database/migrations/002-create-roles.js. vottery version
import { DataTypes } from 'sequelize';

export default {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('vottery_roles', {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: DataTypes.INTEGER
      },
      name: {
        type: DataTypes.STRING(50),
        allowNull: false,
        unique: true
      },
      category: {
        type: DataTypes.ENUM('admin', 'user'),
        allowNull: false
      },
      level: {
        type: DataTypes.INTEGER,
        allowNull: false,
        comment: 'Higher number = more permissions'
      },
      permissions: {
        type: DataTypes.JSON,
        allowNull: false
      },
      created_at: {
        allowNull: false,
        type: DataTypes.DATE,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
      }
    });

    // Add indexes
    await queryInterface.addIndex('vottery_roles', ['name'], {
      name: 'idx_vottery_roles_name',
      unique: true
    });

    await queryInterface.addIndex('vottery_roles', ['category'], {
      name: 'idx_vottery_roles_category'
    });

    await queryInterface.addIndex('vottery_roles', ['level'], {
      name: 'idx_vottery_roles_level'
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('vottery_roles');
  }
};


//non vottery version
// database/migrations/002-create-roles.js
// import { DataTypes } from 'sequelize';

// export default {
//   up: async (queryInterface, Sequelize) => {
//     await queryInterface.createTable('roles', {
//       id: {
//         allowNull: false,
//         autoIncrement: true,
//         primaryKey: true,
//         type: DataTypes.INTEGER
//       },
//       name: {
//         type: DataTypes.STRING(50),
//         allowNull: false,
//         unique: true
//       },
//       category: {
//         type: DataTypes.ENUM('admin', 'user'),
//         allowNull: false
//       },
//       level: {
//         type: DataTypes.INTEGER,
//         allowNull: false,
//         comment: 'Higher number = more permissions'
//       },
//       permissions: {
//         type: DataTypes.JSON,
//         allowNull: false
//       },
//       created_at: {
//         allowNull: false,
//         type: DataTypes.DATE,
//         defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
//       }
//     });

//     // Add indexes
//     await queryInterface.addIndex('roles', ['name'], {
//       name: 'idx_roles_name',
//       unique: true
//     });

//     await queryInterface.addIndex('roles', ['category'], {
//       name: 'idx_roles_category'
//     });

//     await queryInterface.addIndex('roles', ['level'], {
//       name: 'idx_roles_level'
//     });
//   },

//   down: async (queryInterface, Sequelize) => {
//     await queryInterface.dropTable('roles');
//   }
// };
