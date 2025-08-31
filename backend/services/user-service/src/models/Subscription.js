import { DataTypes, Model } from 'sequelize';

class Subscription extends Model {
  static init(sequelize) {
    return super.init({
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      user_id: {
        type: DataTypes.INTEGER,
        allowNull: false
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
        type: DataTypes.JSON
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
        defaultValue: DataTypes.NOW
      },
      expires_at: {
        type: DataTypes.DATE
      },
      auto_renew: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      }
    }, {
      sequelize,
      modelName: 'Subscription',
      tableName: 'vottery_subscriptions',
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at'
    });
  }

  static associate(models) {
    // Belongs to VotteryUser
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'user_id',
      as: 'user'
    });
  }

  // Check if subscription is currently active
  isActive() {
    if (this.status !== 'active') return false;
    if (this.expires_at && new Date() > this.expires_at) return false;
    return true;
  }

  // Check if user has reached usage limits
  hasReachedLimit(resource) {
    if (!this.limits_json || this.plan_type === 'yearly') return false;
    
    const limits = this.limits_json;
    const usage = this.usage_tracking;
    
    if (limits[resource] && usage[resource] >= limits[resource]) {
      return true;
    }
    
    return false;
  }

  // Increment usage counter
  async incrementUsage(resource, amount = 1) {
    if (!this.usage_tracking[resource]) {
      this.usage_tracking[resource] = 0;
    }
    
    this.usage_tracking[resource] += amount;
    
    // Track monthly usage
    const currentMonth = new Date().toISOString().substr(0, 7); // YYYY-MM
    if (!this.usage_tracking.monthly_usage[currentMonth]) {
      this.usage_tracking.monthly_usage[currentMonth] = {};
    }
    if (!this.usage_tracking.monthly_usage[currentMonth][resource]) {
      this.usage_tracking.monthly_usage[currentMonth][resource] = 0;
    }
    this.usage_tracking.monthly_usage[currentMonth][resource] += amount;
    
    await this.save();
  }

  // Get remaining quota for a resource
  getRemainingQuota(resource) {
    if (!this.limits_json || this.plan_type === 'yearly') return -1; // Unlimited
    
    const limits = this.limits_json;
    const usage = this.usage_tracking;
    
    if (!limits[resource]) return -1; // Unlimited
    
    return Math.max(0, limits[resource] - (usage[resource] || 0));
  }
}

export default Subscription;

// const { DataTypes, Model } = require('sequelize');

// class Subscription extends Model {
//   static init(sequelize) {
//     return super.init({
//       id: {
//         type: DataTypes.INTEGER,
//         primaryKey: true,
//         autoIncrement: true
//       },
//       user_id: {
//         type: DataTypes.INTEGER,
//         allowNull: false
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
//         type: DataTypes.JSON
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
//         defaultValue: DataTypes.NOW
//       },
//       expires_at: {
//         type: DataTypes.DATE
//       },
//       auto_renew: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: false
//       }
//     }, {
//       sequelize,
//       modelName: 'Subscription',
//       tableName: 'vottery_subscriptions',
//       timestamps: true,
//       createdAt: 'created_at',
//       updatedAt: 'updated_at'
//     });
//   }

//   static associate(models) {
//     // Belongs to VotteryUser
//     this.belongsTo(models.VotteryUser, {
//       foreignKey: 'user_id',
//       as: 'user'
//     });
//   }

//   // Check if subscription is currently active
//   isActive() {
//     if (this.status !== 'active') return false;
//     if (this.expires_at && new Date() > this.expires_at) return false;
//     return true;
//   }

//   // Check if user has reached usage limits
//   hasReachedLimit(resource) {
//     if (!this.limits_json || this.plan_type === 'yearly') return false;
    
//     const limits = this.limits_json;
//     const usage = this.usage_tracking;
    
//     if (limits[resource] && usage[resource] >= limits[resource]) {
//       return true;
//     }
    
//     return false;
//   }

//   // Increment usage counter
//   async incrementUsage(resource, amount = 1) {
//     if (!this.usage_tracking[resource]) {
//       this.usage_tracking[resource] = 0;
//     }
    
//     this.usage_tracking[resource] += amount;
    
//     // Track monthly usage
//     const currentMonth = new Date().toISOString().substr(0, 7); // YYYY-MM
//     if (!this.usage_tracking.monthly_usage[currentMonth]) {
//       this.usage_tracking.monthly_usage[currentMonth] = {};
//     }
//     if (!this.usage_tracking.monthly_usage[currentMonth][resource]) {
//       this.usage_tracking.monthly_usage[currentMonth][resource] = 0;
//     }
//     this.usage_tracking.monthly_usage[currentMonth][resource] += amount;
    
//     await this.save();
//   }

//   // Get remaining quota for a resource
//   getRemainingQuota(resource) {
//     if (!this.limits_json || this.plan_type === 'yearly') return -1; // Unlimited
    
//     const limits = this.limits_json;
//     const usage = this.usage_tracking;
    
//     if (!limits[resource]) return -1; // Unlimited
    
//     return Math.max(0, limits[resource] - (usage[resource] || 0));
//   }
// }

// module.exports = Subscription;