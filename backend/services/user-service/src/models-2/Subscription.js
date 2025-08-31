// models/Subscription.js
import { DataTypes, Model, Op } from 'sequelize';

class Subscription extends Model {
  static init(sequelize) {
    return super.init(
      {
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
          allowNull: false,
          defaultValue: 'free',
          validate: {
            isIn: {
              args: [['free', 'pay_as_you_go', 'monthly', '3_month', '6_month', 'yearly']],
              msg: 'Plan type must be valid subscription plan'
            }
          }
        },
        status: {
          type: DataTypes.ENUM('active', 'cancelled', 'expired', 'suspended'),
          allowNull: false,
          defaultValue: 'active',
          validate: {
            isIn: {
              args: [['active', 'cancelled', 'expired', 'suspended']],
              msg: 'Status must be active, cancelled, expired, or suspended'
            }
          }
        },
        limits_json: {
          type: DataTypes.JSON,
          allowNull: true,
          validate: {
            isValidLimits(value) {
              if (value && typeof value !== 'object') {
                throw new Error('Limits must be a valid JSON object');
              }
            }
          }
        },
        starts_at: {
          type: DataTypes.DATE,
          allowNull: false,
          defaultValue: DataTypes.NOW
        },
        expires_at: {
          type: DataTypes.DATE,
          allowNull: true,
          validate: {
            isAfterStart(value) {
              if (value && this.starts_at && new Date(value) <= new Date(this.starts_at)) {
                throw new Error('Expiration date must be after start date');
              }
            }
          }
        },
        auto_renew: {
          type: DataTypes.BOOLEAN,
          allowNull: false,
          defaultValue: false
        },
        // Virtual fields for subscription status
        isActive: {
          type: DataTypes.VIRTUAL,
          get() {
            if (this.status !== 'active') return false;
            if (!this.expires_at) return true;
            return new Date() < new Date(this.expires_at);
          }
        },
        isExpired: {
          type: DataTypes.VIRTUAL,
          get() {
            if (this.status === 'expired') return true;
            if (!this.expires_at) return false;
            return new Date() >= new Date(this.expires_at);
          }
        },
        isPaid: {
          type: DataTypes.VIRTUAL,
          get() {
            return this.plan_type !== 'free';
          }
        },
        daysRemaining: {
          type: DataTypes.VIRTUAL,
          get() {
            if (!this.expires_at || !this.isActive) return null;
            const diffTime = new Date(this.expires_at) - new Date();
            return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
          }
        }
      },
      {
        sequelize,
        modelName: 'Subscription',
        tableName: 'subscriptions',
        timestamps: true,
        createdAt: 'created_at',
        updatedAt: false,
        indexes: [
          {
            fields: ['user_id']
          },
          {
            fields: ['plan_type']
          },
          {
            fields: ['status']
          },
          {
            fields: ['expires_at']
          },
          {
            fields: ['auto_renew']
          }
        ]
      }
    );
  }

  // Instance method to get subscription limits
  getLimits() {
    return this.limits_json || this.getDefaultLimits();
  }

  // Instance method to get default limits based on plan type
  getDefaultLimits() {
    const defaultLimits = {
      free: {
        electionsPerMonth: 1,
        votesPerElection: 100,
        electionDuration: 7, // days
        customBranding: false,
        analytics: false,
        exportResults: false
      },
      pay_as_you_go: {
        electionsPerMonth: null, // unlimited but pay per use
        votesPerElection: null,
        electionDuration: 365,
        customBranding: true,
        analytics: true,
        exportResults: true
      },
      monthly: {
        electionsPerMonth: 10,
        votesPerElection: null,
        electionDuration: 365,
        customBranding: true,
        analytics: true,
        exportResults: true
      },
      '3_month': {
        electionsPerMonth: 15,
        votesPerElection: null,
        electionDuration: 365,
        customBranding: true,
        analytics: true,
        exportResults: true
      },
      '6_month': {
        electionsPerMonth: 20,
        votesPerElection: null,
        electionDuration: 365,
        customBranding: true,
        analytics: true,
        exportResults: true
      },
      yearly: {
        electionsPerMonth: null, // unlimited
        votesPerElection: null,
        electionDuration: 365,
        customBranding: true,
        analytics: true,
        exportResults: true
      }
    };

    return defaultLimits[this.plan_type] || defaultLimits.free;
  }

  // Instance method to check if feature is allowed
  hasFeature(featureName) {
    const limits = this.getLimits();
    return limits[featureName] === true || limits[featureName] === null;
  }

  // Instance method to check usage against limits
  async checkUsageLimit(limitType, currentUsage) {
    const limits = this.getLimits();
    const limit = limits[limitType];
    
    if (limit === null || limit === undefined) return true; // unlimited
    return currentUsage < limit;
  }

  // Instance method to cancel subscription
  async cancel() {
    try {
      this.status = 'cancelled';
      this.auto_renew = false;
      await this.save();
      return this;
    } catch (error) {
      throw new Error(`Subscription cancellation failed: ${error.message}`);
    }
  }

  // Instance method to suspend subscription
  async suspend() {
    try {
      this.status = 'suspended';
      await this.save();
      return this;
    } catch (error) {
      throw new Error(`Subscription suspension failed: ${error.message}`);
    }
  }

  // Instance method to reactivate subscription
  async reactivate() {
    try {
      if (this.isExpired) {
        throw new Error('Cannot reactivate expired subscription');
      }
      this.status = 'active';
      await this.save();
      return this;
    } catch (error) {
      throw new Error(`Subscription reactivation failed: ${error.message}`);
    }
  }

  // Instance method to renew subscription
  async renew(newExpiryDate = null) {
    try {
      if (!newExpiryDate) {
        // Calculate new expiry based on plan type
        const now = new Date();
        const durations = {
          monthly: 30,
          '3_month': 90,
          '6_month': 180,
          yearly: 365
        };
        
        const duration = durations[this.plan_type] || 30;
        newExpiryDate = new Date(now.getTime() + (duration * 24 * 60 * 60 * 1000));
      }

      this.expires_at = newExpiryDate;
      this.status = 'active';
      await this.save();
      return this;
    } catch (error) {
      throw new Error(`Subscription renewal failed: ${error.message}`);
    }
  }

  // Instance method to upgrade subscription
  async upgrade(newPlanType) {
    try {
      const validPlans = ['free', 'pay_as_you_go', 'monthly', '3_month', '6_month', 'yearly'];
      if (!validPlans.includes(newPlanType)) {
        throw new Error('Invalid plan type');
      }

      this.plan_type = newPlanType;
      this.limits_json = null; // Reset to use default limits
      await this.save();
      return this;
    } catch (error) {
      throw new Error(`Subscription upgrade failed: ${error.message}`);
    }
  }

  // Static method to create subscription
  static async createSubscription(userId, planType = 'free', options = {}) {
    try {
      const {
        customLimits = null,
        autoRenew = false,
        startDate = new Date(),
        duration = null
      } = options;

      let expiryDate = null;
      if (duration) {
        expiryDate = new Date(startDate.getTime() + (duration * 24 * 60 * 60 * 1000));
      } else if (planType !== 'free') {
        const durations = {
          monthly: 30,
          '3_month': 90,
          '6_month': 180,
          yearly: 365
        };
        const planDuration = durations[planType];
        if (planDuration) {
          expiryDate = new Date(startDate.getTime() + (planDuration * 24 * 60 * 60 * 1000));
        }
      }

      const subscription = await this.create({
        user_id: userId,
        plan_type: planType,
        limits_json: customLimits,
        starts_at: startDate,
        expires_at: expiryDate,
        auto_renew: autoRenew
      });

      return subscription;
    } catch (error) {
      throw new Error(`Subscription creation failed: ${error.message}`);
    }
  }

  // Static method to get user's active subscription
  static async getUserActiveSubscription(userId) {
    try {
      return await this.findOne({
        where: {
          user_id: userId,
          status: 'active',
          [Op.or]: [
            { expires_at: null },
            { expires_at: { [Op.gt]: new Date() } }
          ]
        },
        order: [['created_at', 'DESC']]
      });
    } catch (error) {
      throw new Error(`Failed to get user subscription: ${error.message}`);
    }
  }

  // Static method to get expiring subscriptions for renewal
  static async getExpiringSubscriptions(daysAhead = 7) {
    try {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + daysAhead);

      return await this.findAll({
        where: {
          status: 'active',
          auto_renew: true,
          expires_at: {
            [Op.between]: [new Date(), futureDate]
          }
        },
        include: [
          {
            model: this.sequelize.models.VotteryUser,
            as: 'user'
          }
        ]
      });
    } catch (error) {
      throw new Error(`Failed to get expiring subscriptions: ${error.message}`);
    }
  }

  // Static method to expire old subscriptions
  static async expireOldSubscriptions() {
    try {
      const [updatedCount] = await this.update(
        { status: 'expired' },
        {
          where: {
            status: 'active',
            expires_at: { [Op.lt]: new Date() }
          }
        }
      );

      return updatedCount;
    } catch (error) {
      throw new Error(`Failed to expire subscriptions: ${error.message}`);
    }
  }

  // Static method to get subscription analytics
  static async getSubscriptionAnalytics(dateFrom = null, dateTo = null) {
    try {
      const whereClause = {};
      
      if (dateFrom || dateTo) {
        whereClause.created_at = {};
        if (dateFrom) whereClause.created_at[Op.gte] = dateFrom;
        if (dateTo) whereClause.created_at[Op.lte] = dateTo;
      }

      const analytics = await this.findAll({
        attributes: [
          'plan_type',
          [this.sequelize.fn('COUNT', '*'), 'count'],
          [this.sequelize.fn('COUNT', this.sequelize.where(this.sequelize.col('status'), 'active')), 'active_count']
        ],
        where: whereClause,
        group: ['plan_type']
      });

      return analytics;
    } catch (error) {
      throw new Error(`Failed to get subscription analytics: ${error.message}`);
    }
  }

  // Define associations
  static associate(models) {
    Subscription.belongsTo(models.VotteryUser, {
      foreignKey: 'user_id',
      as: 'user'
    });
  }
}

export default Subscription;