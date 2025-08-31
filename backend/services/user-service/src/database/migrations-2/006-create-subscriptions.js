import { DataTypes } from 'sequelize';

const up = async (queryInterface, Sequelize) => {
  await queryInterface.createTable('vottery_subscriptions', {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
      allowNull: false,
    },
    organization_id: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: 'vottery_organizations',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE',
    },
    subscription_tier: {
      type: DataTypes.ENUM,
      values: ['trial', 'basic', 'professional', 'enterprise', 'custom'],
      allowNull: false,
    },
    plan_name: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    plan_description: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    billing_cycle: {
      type: DataTypes.ENUM,
      values: ['monthly', 'quarterly', 'annual', 'custom'],
      allowNull: false,
      defaultValue: 'monthly',
    },
    price_amount: {
      type: DataTypes.DECIMAL(10, 2),
      allowNull: false,
      comment: 'Price in the billing currency',
    },
    currency: {
      type: DataTypes.STRING(3),
      allowNull: false,
      defaultValue: 'USD',
      validate: {
        len: [3, 3],
        isUppercase: true,
      },
    },
    discount_amount: {
      type: DataTypes.DECIMAL(10, 2),
      defaultValue: 0.00,
      allowNull: false,
    },
    discount_type: {
      type: DataTypes.ENUM,
      values: ['fixed', 'percentage', 'none'],
      allowNull: false,
      defaultValue: 'none',
    },
    tax_amount: {
      type: DataTypes.DECIMAL(10, 2),
      defaultValue: 0.00,
      allowNull: false,
    },
    tax_rate: {
      type: DataTypes.DECIMAL(5, 4),
      defaultValue: 0.0000,
      allowNull: false,
      comment: 'Tax rate as decimal (0.0825 for 8.25%)',
    },
    total_amount: {
      type: DataTypes.DECIMAL(10, 2),
      allowNull: false,
      comment: 'Final amount after discounts and taxes',
    },
    status: {
      type: DataTypes.ENUM,
      values: ['trial', 'active', 'past_due', 'canceled', 'suspended', 'expired'],
      allowNull: false,
      defaultValue: 'trial',
    },
    payment_status: {
      type: DataTypes.ENUM,
      values: ['pending', 'paid', 'failed', 'refunded', 'partially_refunded'],
      allowNull: false,
      defaultValue: 'pending',
    },
    payment_method: {
      type: DataTypes.ENUM,
      values: ['credit_card', 'bank_transfer', 'paypal', 'crypto', 'invoice', 'other'],
      allowNull: true,
    },
    external_subscription_id: {
      type: DataTypes.STRING(200),
      allowNull: true,
      comment: 'ID from external payment processor (Stripe, PayPal, etc.)',
    },
    external_customer_id: {
      type: DataTypes.STRING(200),
      allowNull: true,
      comment: 'Customer ID from external payment processor',
    },
    trial_start_date: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    trial_end_date: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    subscription_start_date: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
    },
    subscription_end_date: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    current_period_start: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
    },
    current_period_end: {
      type: DataTypes.DATE,
      allowNull: false,
    },
    next_billing_date: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    last_payment_date: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    failed_payment_count: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
      allowNull: false,
    },
    auto_renew: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
      allowNull: false,
    },
    cancellation_requested: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
      allowNull: false,
    },
    cancellation_date: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    cancellation_reason: {
      type: DataTypes.STRING(500),
      allowNull: true,
    },
    features_included: {
      type: DataTypes.JSON,
      defaultValue: [],
      allowNull: false,
      comment: 'Array of included features',
    },
    usage_limits: {
      type: DataTypes.JSON,
      defaultValue: {
        max_users: null,
        max_votes_per_month: null,
        max_organizations: 1,
        max_storage_gb: 5,
        api_calls_per_day: 10000,
      },
      allowNull: false,
    },
    current_usage: {
      type: DataTypes.JSON,
      defaultValue: {
        users_count: 0,
        votes_this_month: 0,
        storage_used_gb: 0,
        api_calls_today: 0,
      },
      allowNull: false,
    },
    overage_charges: {
      type: DataTypes.JSON,
      defaultValue: {},
      allowNull: false,
      comment: 'Charges for usage beyond limits',
    },
    promo_code: {
      type: DataTypes.STRING(50),
      allowNull: true,
    },
    promo_discount: {
      type: DataTypes.DECIMAL(10, 2),
      defaultValue: 0.00,
      allowNull: false,
    },
    billing_address: {
      type: DataTypes.JSON,
      allowNull: true,
      defaultValue: {},
    },
    payment_details: {
      type: DataTypes.JSON,
      allowNull: true,
      defaultValue: {},
      comment: 'Encrypted payment method details',
    },
    invoice_settings: {
      type: DataTypes.JSON,
      defaultValue: {
        send_invoices: true,
        invoice_email: null,
        billing_contact: null,
      },
      allowNull: false,
    },
    notifications_sent: {
      type: DataTypes.JSON,
      defaultValue: [],
      allowNull: false,
      comment: 'History of billing notifications sent',
    },
    subscription_metadata: {
      type: DataTypes.JSON,
      defaultValue: {},
      allowNull: false,
    },
    created_by: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: 'vottery_users',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'RESTRICT',
    },
    updated_by: {
      type: DataTypes.UUID,
      allowNull: true,
      references: {
        model: 'vottery_users',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'SET NULL',
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
    },
    updated_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
    },
    deleted_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
  });

  // Add indexes for performance
  await queryInterface.addIndex('vottery_subscriptions', ['organization_id']);
  await queryInterface.addIndex('vottery_subscriptions', ['subscription_tier']);
  await queryInterface.addIndex('vottery_subscriptions', ['status']);
  await queryInterface.addIndex('vottery_subscriptions', ['payment_status']);
  await queryInterface.addIndex('vottery_subscriptions', ['external_subscription_id']);
  await queryInterface.addIndex('vottery_subscriptions', ['trial_end_date']);
  await queryInterface.addIndex('vottery_subscriptions', ['subscription_end_date']);
  await queryInterface.addIndex('vottery_subscriptions', ['current_period_end']);
  await queryInterface.addIndex('vottery_subscriptions', ['next_billing_date']);
  await queryInterface.addIndex('vottery_subscriptions', ['auto_renew']);
  await queryInterface.addIndex('vottery_subscriptions', ['organization_id', 'status']);
};

const down = async (queryInterface, Sequelize) => {
  await queryInterface.dropTable('vottery_subscriptions');
};

export { up, down };