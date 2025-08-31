// database/migrations/001-create-user-profiles.js
'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_user_profiles', {
      id: {
        allowNull: false,
        primaryKey: true,
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4
      },
      user_id: {
        type: Sequelize.UUID,
        allowNull: false,
        unique: true,
        references: {
          model: 'vottery_users', // From auth service
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
      },
      encrypted_personal_data: {
        type: Sequelize.TEXT,
        allowNull: false,
        comment: 'Encrypted JSON containing sensitive user data'
      },
      public_display_name: {
        type: Sequelize.STRING(100),
        allowNull: false
      },
      avatar_url: {
        type: Sequelize.TEXT,
        allowNull: true
      },
      country: {
        type: Sequelize.STRING(3),
        allowNull: true,
        comment: 'ISO 3166-1 alpha-3 country code'
      },
      timezone: {
        type: Sequelize.STRING(50),
        allowNull: true,
        defaultValue: 'UTC'
      },
      preferred_language: {
        type: Sequelize.STRING(5),
        allowNull: false,
        defaultValue: 'en-US'
      },
      account_type: {
        type: Sequelize.ENUM('individual', 'organization'),
        allowNull: false,
        defaultValue: 'individual'
      },
      subscription_status: {
        type: Sequelize.ENUM('free', 'subscribed'),
        allowNull: false,
        defaultValue: 'free'
      },
      verification_status: {
        type: Sequelize.ENUM('unverified', 'email_verified', 'phone_verified', 'fully_verified'),
        allowNull: false,
        defaultValue: 'unverified'
      },
      privacy_settings: {
        type: Sequelize.JSONB,
        allowNull: false,
        defaultValue: {
          profile_visibility: 'public',
          show_voting_history: false,
          allow_friend_requests: true,
          show_online_status: true
        }
      },
      notification_preferences: {
        type: Sequelize.JSONB,
        allowNull: false,
        defaultValue: {
          email_notifications: true,
          push_notifications: true,
          election_updates: true,
          lottery_results: true,
          friend_activities: true
        }
      },
      demographics: {
        type: Sequelize.JSONB,
        allowNull: true,
        comment: 'Non-PII demographic data for analytics'
      },
      last_active_at: {
        allowNull: true,
        type: Sequelize.DATE
      },
      profile_completion_score: {
        type: Sequelize.INTEGER,
        allowNull: false,
        defaultValue: 20,
        validate: {
          min: 0,
          max: 100
        }
      },
      is_active: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: true
      },
      created_at: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      },
      updated_at: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      }
    });

    // Add indexes
    await queryInterface.addIndex('vottery_user_profiles', ['user_id']);
    await queryInterface.addIndex('vottery_user_profiles', ['country']);
    await queryInterface.addIndex('vottery_user_profiles', ['account_type']);
    await queryInterface.addIndex('vottery_user_profiles', ['subscription_status']);
    await queryInterface.addIndex('vottery_user_profiles', ['verification_status']);
    await queryInterface.addIndex('vottery_user_profiles', ['is_active']);
    await queryInterface.addIndex('vottery_user_profiles', ['last_active_at']);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_user_profiles');
  }
};

// database/migrations/002-create-roles.js
'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_roles', {
      id: {
        allowNull: false,
        primaryKey: true,
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4
      },
      name: {
        type: Sequelize.STRING(50),
        allowNull: false,
        unique: true
      },
      slug: {
        type: Sequelize.STRING(50),
        allowNull: false,
        unique: true
      },
      description: {
        type: Sequelize.TEXT,
        allowNull: true
      },
      category: {
        type: Sequelize.ENUM('admin', 'user'),
        allowNull: false
      },
      permissions: {
        type: Sequelize.JSONB,
        allowNull: false,
        defaultValue: []
      },
      priority_level: {
        type: Sequelize.INTEGER,
        allowNull: false,
        defaultValue: 0,
        comment: 'Higher number = higher priority'
      },
      is_system_role: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: false,
        comment: 'Cannot be deleted if true'
      },
      is_active: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: true
      },
      created_at: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      },
      updated_at: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      }
    });

    // Add indexes
    await queryInterface.addIndex('vottery_roles', ['category']);
    await queryInterface.addIndex('vottery_roles', ['priority_level']);
    await queryInterface.addIndex('vottery_roles', ['is_active']);
    await queryInterface.addIndex('vottery_roles', ['slug']);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_roles');
  }
};

// database/migrations/003-create-user-roles.js
'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_user_roles', {
      id: {
        allowNull: false,
        primaryKey: true,
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4
      },
      user_id: {
        type: Sequelize.UUID,
        allowNull: false,
        references: {
          model: 'vottery_users', // From auth service
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
      },
      role_id: {
        type: Sequelize.UUID,
        allowNull: false,
        references: {
          model: 'vottery_roles',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
      },
      assigned_by: {
        type: Sequelize.UUID,
        allowNull: false,
        references: {
          model: 'vottery_users',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'RESTRICT'
      },
      assigned_at: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      },
      expires_at: {
        allowNull: true,
        type: Sequelize.DATE,
        comment: 'Role expires at this time, null for permanent'
      },
      is_active: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: true
      },
      metadata: {
        type: Sequelize.JSONB,
        allowNull: true,
        comment: 'Additional role-specific data'
      },
      created_at: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      },
      updated_at: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      }
    });

    // Add indexes and constraints
    await queryInterface.addIndex('vottery_user_roles', ['user_id']);
    await queryInterface.addIndex('vottery_user_roles', ['role_id']);
    await queryInterface.addIndex('vottery_user_roles', ['assigned_by']);
    await queryInterface.addIndex('vottery_user_roles', ['expires_at']);
    await queryInterface.addIndex('vottery_user_roles', ['is_active']);
    
    // Unique constraint to prevent duplicate active role assignments
    await queryInterface.addConstraint('vottery_user_roles', {
      fields: ['user_id', 'role_id'],
      type: 'unique',
      name: 'unique_active_user_role',
      where: {
        is_active: true
      }
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_user_roles');
  }
};

// database/migrations/004-create-organizations.js
'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_organizations', {
      id: {
        allowNull: false,
        primaryKey: true,
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4
      },
      name: {
        type: Sequelize.STRING(200),
        allowNull: false
      },
      slug: {
        type: Sequelize.STRING(100),
        allowNull: false,
        unique: true
      },
      description: {
        type: Sequelize.TEXT,
        allowNull: true
      },
      logo_url: {
        type: Sequelize.TEXT,
        allowNull: true
      },
      website: {
        type: Sequelize.STRING(500),
        allowNull: true
      },
      industry: {
        type: Sequelize.STRING(100),
        allowNull: true
      },
      organization_type: {
        type: Sequelize.ENUM('corporate', 'non_profit', 'government', 'educational', 'political', 'other'),
        allowNull: false,
        defaultValue: 'corporate'
      },
      encrypted_contact_info: {
        type: Sequelize.TEXT,
        allowNull: true,
        comment: 'Encrypted JSON containing contact details'
      },
      country: {
        type: Sequelize.STRING(3),
        allowNull: true,
        comment: 'ISO 3166-1 alpha-3 country code'
      },
      timezone: {
        type: Sequelize.STRING(50),
        allowNull: true,
        defaultValue: 'UTC'
      },
      subscription_status: {
        type: Sequelize.ENUM('free', 'basic', 'premium', 'enterprise'),
        allowNull: false,
        defaultValue: 'free'
      },
      verification_status: {
        type: Sequelize.ENUM('unverified', 'pending', 'verified', 'rejected'),
        allowNull: false,
        defaultValue: 'unverified'
      },
      settings: {
        type: Sequelize.JSONB,
        allowNull: false,
        defaultValue: {
          branding: {
            primary_color: '#007bff',
            secondary_color: '#6c757d',
            custom_css: null
          },
          privacy: {
            member_list_visible: false,
            elections_public: true
          },
          notifications: {
            member_join: true,
            election_created: true,
            voting_complete: true
          }
        }
      },
      member_count: {
        type: Sequelize.INTEGER,
        allowNull: false,
        defaultValue: 0
      },
      max_members: {
        type: Sequelize.INTEGER,
        allowNull: true,
        comment: 'Subscription-based member limit, null for unlimited'
      },
      created_by: {
        type: Sequelize.UUID,
        allowNull: false,
        references: {
          model: 'vottery_users',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'RESTRICT'
      },
      is_active: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: true
      },
      created_at: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      },
      updated_at: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      }
    });

    // Add indexes
    await queryInterface.addIndex('vottery_organizations', ['slug']);
    await queryInterface.addIndex('vottery_organizations', ['organization_type']);
    await queryInterface.addIndex('vottery_organizations', ['country']);
    await queryInterface.addIndex('vottery_organizations', ['subscription_status']);
    await queryInterface.addIndex('vottery_organizations', ['verification_status']);
    await queryInterface.addIndex('vottery_organizations', ['created_by']);
    await queryInterface.addIndex('vottery_organizations', ['is_active']);
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_organizations');
  }
};

// database/migrations/005-create-organization-members.js
'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_organization_members', {
      id: {
        allowNull: false,
        primaryKey: true,
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4
      },
      organization_id: {
        type: Sequelize.UUID,
        allowNull: false,
        references: {
          model: 'vottery_organizations',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
      },
      user_id: {
        type: Sequelize.UUID,
        allowNull: false,
        references: {
          model: 'vottery_users',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
      },
      role: {
        type: Sequelize.ENUM('owner', 'admin', 'moderator', 'member', 'viewer'),
        allowNull: false,
        defaultValue: 'member'
      },
      status: {
        type: Sequelize.ENUM('active', 'inactive', 'pending', 'banned'),
        allowNull: false,
        defaultValue: 'pending'
      },
      invited_by: {
        type: Sequelize.UUID,
        allowNull: true,
        references: {
          model: 'vottery_users',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'SET NULL'
      },
      joined_at: {
        allowNull: true,
        type: Sequelize.DATE
      },
      left_at: {
        allowNull: true,
        type: Sequelize.DATE
      },
      permissions: {
        type: Sequelize.JSONB,
        allowNull: false,
        defaultValue: {
          can_create_elections: false,
          can_invite_members: false,
          can_manage_settings: false,
          can_view_analytics: false
        }
      },
      metadata: {
        type: Sequelize.JSONB,
        allowNull: true,
        comment: 'Additional member-specific data'
      },
      created_at: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      },
      updated_at: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      }
    });

    // Add indexes and constraints
    await queryInterface.addIndex('vottery_organization_members', ['organization_id']);
    await queryInterface.addIndex('vottery_organization_members', ['user_id']);
    await queryInterface.addIndex('vottery_organization_members', ['role']);
    await queryInterface.addIndex('vottery_organization_members', ['status']);
    await queryInterface.addIndex('vottery_organization_members', ['invited_by']);
    
    // Unique constraint to prevent duplicate memberships
    await queryInterface.addConstraint('vottery_organization_members', {
      fields: ['organization_id', 'user_id'],
      type: 'unique',
      name: 'unique_organization_member'
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_organization_members');
  }
};

// database/migrations/006-create-subscriptions.js
'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('vottery_subscriptions', {
      id: {
        allowNull: false,
        primaryKey: true,
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4
      },
      user_id: {
        type: Sequelize.UUID,
        allowNull: true,
        references: {
          model: 'vottery_users',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
      },
      organization_id: {
        type: Sequelize.UUID,
        allowNull: true,
        references: {
          model: 'vottery_organizations',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
      },
      subscription_type: {
        type: Sequelize.ENUM('individual', 'organization'),
        allowNull: false
      },
      plan_name: {
        type: Sequelize.ENUM('free', 'pay_as_you_go', 'monthly', '3_month', '6_month', 'yearly', 'enterprise'),
        allowNull: false
      },
      status: {
        type: Sequelize.ENUM('active', 'cancelled', 'expired', 'suspended', 'pending'),
        allowNull: false,
        defaultValue: 'pending'
      },
      billing_cycle: {
        type: Sequelize.ENUM('one_time', 'monthly', 'quarterly', 'semi_annual', 'annual'),
        allowNull: true
      },
      price_per_cycle: {
        type: Sequelize.DECIMAL(10, 2),
        allowNull: true
      },
      currency: {
        type: Sequelize.STRING(3),
        allowNull: false,
        defaultValue: 'USD'
      },
      payment_method: {
        type: Sequelize.ENUM('stripe', 'paddle', 'wallet'),
        allowNull: true
      },
      external_subscription_id: {
        type: Sequelize.STRING(255),
        allowNull: true,
        comment: 'Stripe/Paddle subscription ID'
      },
      trial_starts_at: {
        allowNull: true,
        type: Sequelize.DATE
      },
      trial_ends_at: {
        allowNull: true,
        type: Sequelize.DATE
      },
      starts_at: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      },
      ends_at: {
        allowNull: true,
        type: Sequelize.DATE
      },
      cancelled_at: {
        allowNull: true,
        type: Sequelize.DATE
      },
      features: {
        type: Sequelize.JSONB,
        allowNull: false,
        defaultValue: {
          unlimited_elections: false,
          custom_branding: false,
          advanced_analytics: false,
          priority_support: false,
          api_access: false
        }
      },
      usage_limits: {
        type: Sequelize.JSONB,
        allowNull: false,
        defaultValue: {
          elections_per_month: 5,
          votes_per_election: 1000,
          storage_gb: 1
        }
      },
      auto_renew: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
        defaultValue: true
      },
      created_at: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      },
      updated_at: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      }
    });

    // Add indexes and constraints
    await queryInterface.addIndex('vottery_subscriptions', ['user_id']);
    await queryInterface.addIndex('vottery_subscriptions', ['organization_id']);
    await queryInterface.addIndex('vottery_subscriptions', ['subscription_type']);
    await queryInterface.addIndex('vottery_subscriptions', ['status']);
    await queryInterface.addIndex('vottery_subscriptions', ['plan_name']);
    await queryInterface.addIndex('vottery_subscriptions', ['external_subscription_id']);
    await queryInterface.addIndex('vottery_subscriptions', ['ends_at']);
    
    // Ensure either user_id or organization_id is set, but not both
    await queryInterface.addConstraint('vottery_subscriptions', {
      fields: ['user_id', 'organization_id'],
      type: 'check',
      name: 'check_subscription_owner',
      where: Sequelize.literal('(user_id IS NOT NULL AND organization_id IS NULL) OR (user_id IS NULL AND organization_id IS NOT NULL)')
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('vottery_subscriptions');
  }
};