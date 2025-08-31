import { PERMISSIONS } from '../config/roles.js';

export default {
  async up(queryInterface, Sequelize) {
    const roles = [
      // Admin Roles
      {
        name: 'manager',
        category: 'admin',
        level: 100,
        description: 'Highest level admin with full system access',
        is_system_role: true,
        permissions: JSON.stringify([
          PERMISSIONS.USERS.VIEW,
          PERMISSIONS.USERS.EDIT,
          PERMISSIONS.USERS.DELETE,
          PERMISSIONS.USERS.SUSPEND,
          PERMISSIONS.ELECTIONS.CREATE,
          PERMISSIONS.ELECTIONS.VIEW,
          PERMISSIONS.ELECTIONS.EDIT,
          PERMISSIONS.ELECTIONS.DELETE,
          PERMISSIONS.ELECTIONS.MODERATE,
          PERMISSIONS.ANALYTICS.VIEW,
          PERMISSIONS.ANALYTICS.EXPORT,
          PERMISSIONS.ANALYTICS.ADVANCED,
          PERMISSIONS.SYSTEM.CONFIG,
          PERMISSIONS.SYSTEM.AUDIT,
          PERMISSIONS.SYSTEM.SECURITY
        ]),
        created_at: new Date(),
        updated_at: new Date()
      },
      {
        name: 'admin',
        category: 'admin',
        level: 90,
        description: 'System administrator with broad permissions',
        is_system_role: true,
        permissions: JSON.stringify([
          PERMISSIONS.USERS.VIEW,
          PERMISSIONS.USERS.EDIT,
          PERMISSIONS.USERS.SUSPEND,
          PERMISSIONS.ELECTIONS.CREATE,
          PERMISSIONS.ELECTIONS.VIEW,
          PERMISSIONS.ELECTIONS.EDIT,
          PERMISSIONS.ELECTIONS.MODERATE,
          PERMISSIONS.ANALYTICS.VIEW,
          PERMISSIONS.ANALYTICS.EXPORT,
          PERMISSIONS.SYSTEM.CONFIG,
          PERMISSIONS.SYSTEM.AUDIT
        ]),
        created_at: new Date(),
        updated_at: new Date()
      },
      {
        name: 'moderator',
        category: 'admin',
        level: 80,
        description: 'Content and election moderator',
        is_system_role: true,
        permissions: JSON.stringify([
          PERMISSIONS.USERS.VIEW,
          PERMISSIONS.ELECTIONS.VIEW,
          PERMISSIONS.ELECTIONS.MODERATE,
          PERMISSIONS.ANALYTICS.VIEW
        ]),
        created_at: new Date(),
        updated_at: new Date()
      },
      {
        name: 'auditor',
        category: 'admin',
        level: 70,
        description: 'System auditor with read-only access to sensitive data',
        is_system_role: true,
        permissions: JSON.stringify([
          PERMISSIONS.USERS.VIEW,
          PERMISSIONS.ELECTIONS.VIEW,
          PERMISSIONS.ANALYTICS.VIEW,
          PERMISSIONS.ANALYTICS.EXPORT,
          PERMISSIONS.SYSTEM.AUDIT
        ]),
        created_at: new Date(),
        updated_at: new Date()
      },
      {
        name: 'editor',
        category: 'admin',
        level: 60,
        description: 'Content editor with limited admin access',
        is_system_role: true,
        permissions: JSON.stringify([
          PERMISSIONS.ELECTIONS.VIEW,
          PERMISSIONS.ELECTIONS.EDIT,
          PERMISSIONS.ANALYTICS.VIEW
        ]),
        created_at: new Date(),
        updated_at: new Date()
      },
      {
        name: 'advertiser',
        category: 'admin',
        level: 50,
        description: 'Advertising and promotion manager',
        is_system_role: true,
        permissions: JSON.stringify([
          PERMISSIONS.ELECTIONS.VIEW,
          PERMISSIONS.ANALYTICS.VIEW,
          PERMISSIONS.ANALYTICS.EXPORT
        ]),
        created_at: new Date(),
        updated_at: new Date()
      },
      {
        name: 'analyst',
        category: 'admin',
        level: 40,
        description: 'Data analyst with analytics access',
        is_system_role: true,
        permissions: JSON.stringify([
          PERMISSIONS.ANALYTICS.VIEW,
          PERMISSIONS.ANALYTICS.EXPORT,
          PERMISSIONS.ANALYTICS.ADVANCED
        ]),
        created_at: new Date(),
        updated_at: new Date()
      },

      // User Roles
      {
        name: 'individual_election_creator',
        category: 'user',
        level: 30,
        description: 'Individual user who can create elections',
        is_system_role: true,
        permissions: JSON.stringify([
          PERMISSIONS.ELECTIONS.CREATE,
          PERMISSIONS.ELECTIONS.VIEW,
          PERMISSIONS.ELECTIONS.EDIT
        ]),
        created_at: new Date(),
        updated_at: new Date()
      },
      {
        name: 'organization_election_creator',
        category: 'user',
        level: 35,
        description: 'Organization member who can create elections',
        is_system_role: true,
        permissions: JSON.stringify([
          PERMISSIONS.ELECTIONS.CREATE,
          PERMISSIONS.ELECTIONS.VIEW,
          PERMISSIONS.ELECTIONS.EDIT,
          PERMISSIONS.ANALYTICS.VIEW
        ]),
        created_at: new Date(),
        updated_at: new Date()
      },
      {
        name: 'voter',
        category: 'user',
        level: 10,
        description: 'Basic user who can participate in elections',
        is_system_role: true,
        permissions: JSON.stringify([
          PERMISSIONS.ELECTIONS.VIEW
        ]),
        created_at: new Date(),
        updated_at: new Date()
      },
      {
        name: 'free_user',
        category: 'user',
        level: 15,
        description: 'Free tier user with limited features',
        is_system_role: true,
        permissions: JSON.stringify([
          PERMISSIONS.ELECTIONS.VIEW,
          PERMISSIONS.ELECTIONS.CREATE
        ]),
        created_at: new Date(),
        updated_at: new Date()
      },
      {
        name: 'subscribed_user',
        category: 'user',
        level: 25,
        description: 'Paid subscriber with unlimited features',
        is_system_role: true,
        permissions: JSON.stringify([
          PERMISSIONS.ELECTIONS.CREATE,
          PERMISSIONS.ELECTIONS.VIEW,
          PERMISSIONS.ELECTIONS.EDIT,
          PERMISSIONS.ANALYTICS.VIEW
        ]),
        created_at: new Date(),
        updated_at: new Date()
      }
    ];

    await queryInterface.bulkInsert('vottery_roles', roles);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.bulkDelete('vottery_roles', {
      is_system_role: true
    });
  }
};

// const { PERMISSIONS } = require('../config/roles');

// module.exports = {
//   async up(queryInterface, Sequelize) {
//     const roles = [
//       // Admin Roles (as per Master Technical Specification)
//       {
//         name: 'manager',
//         category: 'admin',
//         level: 100,
//         description: 'Highest level admin with full system access',
//         is_system_role: true,
//         permissions: JSON.stringify([
//           PERMISSIONS.USERS.VIEW,
//           PERMISSIONS.USERS.EDIT,
//           PERMISSIONS.USERS.DELETE,
//           PERMISSIONS.USERS.SUSPEND,
//           PERMISSIONS.ELECTIONS.CREATE,
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ELECTIONS.EDIT,
//           PERMISSIONS.ELECTIONS.DELETE,
//           PERMISSIONS.ELECTIONS.MODERATE,
//           PERMISSIONS.ANALYTICS.VIEW,
//           PERMISSIONS.ANALYTICS.EXPORT,
//           PERMISSIONS.ANALYTICS.ADVANCED,
//           PERMISSIONS.SYSTEM.CONFIG,
//           PERMISSIONS.SYSTEM.AUDIT,
//           PERMISSIONS.SYSTEM.SECURITY
//         ]),
//         created_at: new Date(),
//         updated_at: new Date()
//       },
//       {
//         name: 'admin',
//         category: 'admin',
//         level: 90,
//         description: 'System administrator with broad permissions',
//         is_system_role: true,
//         permissions: JSON.stringify([
//           PERMISSIONS.USERS.VIEW,
//           PERMISSIONS.USERS.EDIT,
//           PERMISSIONS.USERS.SUSPEND,
//           PERMISSIONS.ELECTIONS.CREATE,
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ELECTIONS.EDIT,
//           PERMISSIONS.ELECTIONS.MODERATE,
//           PERMISSIONS.ANALYTICS.VIEW,
//           PERMISSIONS.ANALYTICS.EXPORT,
//           PERMISSIONS.SYSTEM.CONFIG,
//           PERMISSIONS.SYSTEM.AUDIT
//         ]),
//         created_at: new Date(),
//         updated_at: new Date()
//       },
//       {
//         name: 'moderator',
//         category: 'admin',
//         level: 80,
//         description: 'Content and election moderator',
//         is_system_role: true,
//         permissions: JSON.stringify([
//           PERMISSIONS.USERS.VIEW,
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ELECTIONS.MODERATE,
//           PERMISSIONS.ANALYTICS.VIEW
//         ]),
//         created_at: new Date(),
//         updated_at: new Date()
//       },
//       {
//         name: 'auditor',
//         category: 'admin',
//         level: 70,
//         description: 'System auditor with read-only access to sensitive data',
//         is_system_role: true,
//         permissions: JSON.stringify([
//           PERMISSIONS.USERS.VIEW,
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ANALYTICS.VIEW,
//           PERMISSIONS.ANALYTICS.EXPORT,
//           PERMISSIONS.SYSTEM.AUDIT
//         ]),
//         created_at: new Date(),
//         updated_at: new Date()
//       },
//       {
//         name: 'editor',
//         category: 'admin',
//         level: 60,
//         description: 'Content editor with limited admin access',
//         is_system_role: true,
//         permissions: JSON.stringify([
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ELECTIONS.EDIT,
//           PERMISSIONS.ANALYTICS.VIEW
//         ]),
//         created_at: new Date(),
//         updated_at: new Date()
//       },
//       {
//         name: 'advertiser',
//         category: 'admin',
//         level: 50,
//         description: 'Advertising and promotion manager',
//         is_system_role: true,
//         permissions: JSON.stringify([
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ANALYTICS.VIEW,
//           PERMISSIONS.ANALYTICS.EXPORT
//         ]),
//         created_at: new Date(),
//         updated_at: new Date()
//       },
//       {
//         name: 'analyst',
//         category: 'admin',
//         level: 40,
//         description: 'Data analyst with analytics access',
//         is_system_role: true,
//         permissions: JSON.stringify([
//           PERMISSIONS.ANALYTICS.VIEW,
//           PERMISSIONS.ANALYTICS.EXPORT,
//           PERMISSIONS.ANALYTICS.ADVANCED
//         ]),
//         created_at: new Date(),
//         updated_at: new Date()
//       },

//       // User Roles (as per Master Technical Specification)
//       {
//         name: 'individual_election_creator',
//         category: 'user',
//         level: 30,
//         description: 'Individual user who can create elections',
//         is_system_role: true,
//         permissions: JSON.stringify([
//           PERMISSIONS.ELECTIONS.CREATE,
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ELECTIONS.EDIT
//         ]),
//         created_at: new Date(),
//         updated_at: new Date()
//       },
//       {
//         name: 'organization_election_creator',
//         category: 'user',
//         level: 35,
//         description: 'Organization member who can create elections',
//         is_system_role: true,
//         permissions: JSON.stringify([
//           PERMISSIONS.ELECTIONS.CREATE,
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ELECTIONS.EDIT,
//           PERMISSIONS.ANALYTICS.VIEW
//         ]),
//         created_at: new Date(),
//         updated_at: new Date()
//       },
//       {
//         name: 'voter',
//         category: 'user',
//         level: 10,
//         description: 'Basic user who can participate in elections',
//         is_system_role: true,
//         permissions: JSON.stringify([
//           PERMISSIONS.ELECTIONS.VIEW
//         ]),
//         created_at: new Date(),
//         updated_at: new Date()
//       },
//       {
//         name: 'free_user',
//         category: 'user',
//         level: 15,
//         description: 'Free tier user with limited features',
//         is_system_role: true,
//         permissions: JSON.stringify([
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ELECTIONS.CREATE
//         ]),
//         created_at: new Date(),
//         updated_at: new Date()
//       },
//       {
//         name: 'subscribed_user',
//         category: 'user',
//         level: 25,
//         description: 'Paid subscriber with unlimited features',
//         is_system_role: true,
//         permissions: JSON.stringify([
//           PERMISSIONS.ELECTIONS.CREATE,
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ELECTIONS.EDIT,
//           PERMISSIONS.ANALYTICS.VIEW
//         ]),
//         created_at: new Date(),
//         updated_at: new Date()
//       }
//     ];

//     await queryInterface.bulkInsert('vottery_roles', roles);
//   },

//   async down(queryInterface, Sequelize) {
//     await queryInterface.bulkDelete('vottery_roles', {
//       is_system_role: true
//     });
//   }
// };