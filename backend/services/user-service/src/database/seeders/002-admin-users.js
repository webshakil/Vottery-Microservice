import bcrypt from 'bcrypt';

export default {
  async up(queryInterface, Sequelize) {
    // Create default admin user
    const adminUsers = [
      {
        email: 'admin@vottery.com',
        email_verified: true,
        password_hash: await bcrypt.hash('Admin@123!Vottery', 12),
        status: 'active',
        two_factor_enabled: false,
        created_at: new Date(),
        updated_at: new Date()
      },
      {
        email: 'manager@vottery.com',
        email_verified: true,
        password_hash: await bcrypt.hash('Manager@123!Vottery', 12),
        status: 'active',
        two_factor_enabled: false,
        created_at: new Date(),
        updated_at: new Date()
      }
    ];

    const users = await queryInterface.bulkInsert('vottery_users', adminUsers, {
      returning: true
    });

    // Create profiles for admin users
    const profiles = [
      {
        user_id: users[0].id,
        first_name_encrypted: 'System',
        last_name_encrypted: 'Administrator',
        profile_completion_score: 100,
        privacy_settings: JSON.stringify({
          profile_visibility: 'private',
          email_visibility: 'private',
          activity_visibility: 'private'
        }),
        notification_preferences: JSON.stringify({
          email_notifications: true,
          push_notifications: false,
          sms_notifications: false
        }),
        created_at: new Date(),
        updated_at: new Date()
      },
      {
        user_id: users[1].id,
        first_name_encrypted: 'System',
        last_name_encrypted: 'Manager',
        profile_completion_score: 100,
        privacy_settings: JSON.stringify({
          profile_visibility: 'private',
          email_visibility: 'private',
          activity_visibility: 'private'
        }),
        notification_preferences: JSON.stringify({
          email_notifications: true,
          push_notifications: false,
          sms_notifications: false
        }),
        created_at: new Date(),
        updated_at: new Date()
      }
    ];

    await queryInterface.bulkInsert('vottery_user_profiles', profiles);

    // Assign admin roles
    const roleAssignments = [
      {
        user_id: users[0].id,
        role_id: 2, // admin role
        assigned_by: users[0].id,
        assigned_at: new Date(),
        is_active: true
      },
      {
        user_id: users[1].id,
        role_id: 1, // manager role
        assigned_by: users[1].id,
        assigned_at: new Date(),
        is_active: true
      }
    ];

    await queryInterface.bulkInsert('vottery_user_roles', roleAssignments);

    // Create default subscriptions
    const subscriptions = [
      {
        user_id: users[0].id,
        plan_type: 'yearly',
        status: 'active',
        limits_json: JSON.stringify({}),
        usage_tracking: JSON.stringify({
          elections_created: 0,
          votes_cast: 0,
          monthly_usage: {}
        }),
        payment_method: 'manual',
        starts_at: new Date(),
        auto_renew: false,
        created_at: new Date(),
        updated_at: new Date()
      },
      {
        user_id: users[1].id,
        plan_type: 'yearly',
        status: 'active',
        limits_json: JSON.stringify({}),
        usage_tracking: JSON.stringify({
          elections_created: 0,
          votes_cast: 0,
          monthly_usage: {}
        }),
        payment_method: 'manual',
        starts_at: new Date(),
        auto_renew: false,
        created_at: new Date(),
        updated_at: new Date()
      }
    ];

    await queryInterface.bulkInsert('vottery_subscriptions', subscriptions);
  },

  async down(queryInterface, Sequelize) {
    // Remove admin users and associated data
    await queryInterface.bulkDelete('vottery_users', {
      email: {
        [Sequelize.Op.in]: ['admin@vottery.com', 'manager@vottery.com']
      }
    });
  }
};

// const bcrypt = require('bcrypt');

// module.exports = {
//   async up(queryInterface, Sequelize) {
//     // Create default admin user
//     const adminUsers = [
//       {
//         email: 'admin@vottery.com',
//         email_verified: true,
//         password_hash: await bcrypt.hash('Admin@123!Vottery', 12),
//         status: 'active',
//         two_factor_enabled: false,
//         created_at: new Date(),
//         updated_at: new Date()
//       },
//       {
//         email: 'manager@vottery.com',
//         email_verified: true,
//         password_hash: await bcrypt.hash('Manager@123!Vottery', 12),
//         status: 'active',
//         two_factor_enabled: false,
//         created_at: new Date(),
//         updated_at: new Date()
//       }
//     ];

//     const users = await queryInterface.bulkInsert('vottery_users', adminUsers, {
//       returning: true
//     });

//     // Create profiles for admin users
//     const profiles = [
//       {
//         user_id: users[0].id,
//         first_name_encrypted: 'System', // Would be encrypted in real implementation
//         last_name_encrypted: 'Administrator',
//         profile_completion_score: 100,
//         privacy_settings: JSON.stringify({
//           profile_visibility: 'private',
//           email_visibility: 'private',
//           activity_visibility: 'private'
//         }),
//         notification_preferences: JSON.stringify({
//           email_notifications: true,
//           push_notifications: false,
//           sms_notifications: false
//         }),
//         created_at: new Date(),
//         updated_at: new Date()
//       },
//       {
//         user_id: users[1].id,
//         first_name_encrypted: 'System', // Would be encrypted in real implementation
//         last_name_encrypted: 'Manager',
//         profile_completion_score: 100,
//         privacy_settings: JSON.stringify({
//           profile_visibility: 'private',
//           email_visibility: 'private',
//           activity_visibility: 'private'
//         }),
//         notification_preferences: JSON.stringify({
//           email_notifications: true,
//           push_notifications: false,
//           sms_notifications: false
//         }),
//         created_at: new Date(),
//         updated_at: new Date()
//       }
//     ];

//     await queryInterface.bulkInsert('vottery_user_profiles', profiles);

//     // Assign admin roles
//     const roleAssignments = [
//       {
//         user_id: users[0].id,
//         role_id: 2, // admin role
//         assigned_by: users[0].id,
//         assigned_at: new Date(),
//         is_active: true
//       },
//       {
//         user_id: users[1].id,
//         role_id: 1, // manager role
//         assigned_by: users[1].id,
//         assigned_at: new Date(),
//         is_active: true
//       }
//     ];

//     await queryInterface.bulkInsert('vottery_user_roles', roleAssignments);

//     // Create default subscriptions
//     const subscriptions = [
//       {
//         user_id: users[0].id,
//         plan_type: 'yearly',
//         status: 'active',
//         limits_json: JSON.stringify({}), // Unlimited
//         usage_tracking: JSON.stringify({
//           elections_created: 0,
//           votes_cast: 0,
//           monthly_usage: {}
//         }),
//         payment_method: 'manual',
//         starts_at: new Date(),
//         auto_renew: false,
//         created_at: new Date(),
//         updated_at: new Date()
//       },
//       {
//         user_id: users[1].id,
//         plan_type: 'yearly',
//         status: 'active',
//         limits_json: JSON.stringify({}), // Unlimited
//         usage_tracking: JSON.stringify({
//           elections_created: 0,
//           votes_cast: 0,
//           monthly_usage: {}
//         }),
//         payment_method: 'manual',
//         starts_at: new Date(),
//         auto_renew: false,
//         created_at: new Date(),
//         updated_at: new Date()
//       }
//     ];

//     await queryInterface.bulkInsert('vottery_subscriptions', subscriptions);
//   },

//   async down(queryInterface, Sequelize) {
//     // Remove admin users and associated data
//     await queryInterface.bulkDelete('vottery_users', {
//       email: {
//         [Sequelize.Op.in]: ['admin@vottery.com', 'manager@vottery.com']
//       }
//     });
//   }
// };