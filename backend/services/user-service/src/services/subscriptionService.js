// services/subscriptionService.js
import Subscription from '../models/Subscription.js';
import VotteryUser from '../models/VotteryUser.js';
import auditService from './auditService.js';
import { AppError } from '../utils/response.js';
import { SUBSCRIPTION_PLANS, SUBSCRIPTION_STATUS } from '../utils/constants.js';

class SubscriptionService {
  /**
   * Create new subscription
   * @param {number} userId 
   * @param {string} planType 
   * @param {object} limits 
   * @param {Date} expiresAt 
   * @returns {Promise<object>}
   */
  async createSubscription(userId, planType, limits = null, expiresAt = null) {
    try {
      // Check if user exists
      const user = await VotteryUser.findByPk(userId);
      if (!user) {
        throw new AppError('User not found', 404);
      }

      // Check for existing active subscription
      const existingSubscription = await Subscription.findOne({
        where: {
          user_id: userId,
          status: SUBSCRIPTION_STATUS.ACTIVE
        }
      });

      if (existingSubscription) {
        throw new AppError('User already has an active subscription', 400);
      }

      // Validate plan type
      if (!Object.values(SUBSCRIPTION_PLANS).includes(planType)) {
        throw new AppError('Invalid subscription plan', 400);
      }

      // Get default limits for plan if not provided
      const planLimits = limits || this.getDefaultLimits(planType);

      // Create subscription
      const subscription = await Subscription.create({
        user_id: userId,
        plan_type: planType,
        status: SUBSCRIPTION_STATUS.ACTIVE,
        limits_json: planLimits,
        expires_at: expiresAt,
        auto_renew: planType !== SUBSCRIPTION_PLANS.PAY_AS_YOU_GO
      });

      // Log activity
      await auditService.logActivity(
        userId,
        'SUBSCRIPTION_CREATE',
        'subscription',
        subscription.id,
        {
          plan_type: planType,
          expires_at: expiresAt,
          limits: planLimits
        }
      );

      return subscription;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Get user's current subscription
   * @param {number} userId 
   * @returns {Promise<object|null>}
   */
  async getUserSubscription(userId) {
    try {
      const subscription = await Subscription.findOne({
        where: {
          user_id: userId,
          status: SUBSCRIPTION_STATUS.ACTIVE
        },
        order: [['created_at', 'DESC']]
      });

      // Check if subscription is expired
      if (subscription && subscription.expires_at && subscription.expires_at < new Date()) {
        await this.expireSubscription(subscription.id);
        return null;
      }

      return subscription;
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Update subscription plan
   * @param {number} userId 
   * @param {string} newPlanType 
   * @param {Date} newExpiresAt 
   * @returns {Promise<object>}
   */
  async updateSubscriptionPlan(userId, newPlanType, newExpiresAt = null) {
    try {
      const subscription = await this.getUserSubscription(userId);
      if (!subscription) {
        throw new AppError('No active subscription found', 404);
      }

      // Validate new plan type
      if (!Object.values(SUBSCRIPTION_PLANS).includes(newPlanType)) {
        throw new AppError('Invalid subscription plan', 400);
      }

      const oldPlan = subscription.plan_type;
      const newLimits = this.getDefaultLimits(newPlanType);

      // Update subscription
      await subscription.update({
        plan_type: newPlanType,
        limits_json: newLimits,
        expires_at: newExpiresAt,
        updated_at: new Date()
      });

      // Log activity
      await auditService.logActivity(
        userId,
        'SUBSCRIPTION_UPGRADE',
        'subscription',
        subscription.id,
        {
          old_plan: oldPlan,
          new_plan: newPlanType,
          old_expires_at: subscription.expires_at,
          new_expires_at: newExpiresAt
        }
      );

      return subscription;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Cancel subscription
   * @param {number} userId 
   * @param {string} reason 
   * @returns {Promise<object>}
   */
  async cancelSubscription(userId, reason = null) {
    try {
      const subscription = await this.getUserSubscription(userId);
      if (!subscription) {
        throw new AppError('No active subscription found', 404);
      }

      await subscription.update({
        status: SUBSCRIPTION_STATUS.CANCELLED,
        auto_renew: false,
        updated_at: new Date()
      });

      // Log activity
      await auditService.logActivity(
        userId,
        'SUBSCRIPTION_CANCEL',
        'subscription',
        subscription.id,
        {
          plan_type: subscription.plan_type,
          reason,
          cancelled_at: new Date()
        }
      );

      return subscription;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Reactivate cancelled subscription
   * @param {number} userId 
   * @param {Date} newExpiresAt 
   * @returns {Promise<object>}
   */
  async reactivateSubscription(userId, newExpiresAt = null) {
    try {
      const subscription = await Subscription.findOne({
        where: {
          user_id: userId,
          status: SUBSCRIPTION_STATUS.CANCELLED
        },
        order: [['updated_at', 'DESC']]
      });

      if (!subscription) {
        throw new AppError('No cancelled subscription found', 404);
      }

      await subscription.update({
        status: SUBSCRIPTION_STATUS.ACTIVE,
        expires_at: newExpiresAt,
        auto_renew: true,
        updated_at: new Date()
      });

      // Log activity
      await auditService.logActivity(
        userId,
        'SUBSCRIPTION_REACTIVATE',
        'subscription',
        subscription.id,
        {
          plan_type: subscription.plan_type,
          new_expires_at: newExpiresAt
        }
      );

      return subscription;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Expire subscription
   * @param {number} subscriptionId 
   * @returns {Promise<object>}
   */
  async expireSubscription(subscriptionId) {
    try {
      const subscription = await Subscription.findByPk(subscriptionId);
      if (!subscription) {
        throw new AppError('Subscription not found', 404);
      }

      await subscription.update({
        status: SUBSCRIPTION_STATUS.EXPIRED,
        auto_renew: false,
        updated_at: new Date()
      });

      // Log activity
      await auditService.logActivity(
        subscription.user_id,
        'SUBSCRIPTION_EXPIRE',
        'subscription',
        subscriptionId,
        {
          plan_type: subscription.plan_type,
          expired_at: new Date()
        }
      );

      return subscription;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }

  /**
   * Check if user has feature access
   * @param {number} userId 
   * @param {string} feature 
   * @returns {Promise<boolean>}
   */
  async userHasFeatureAccess(userId, feature) {
    try {
      const subscription = await this.getUserSubscription(userId);
      
      // Free users have limited access
      if (!subscription) {
        const freeLimits = this.getDefaultLimits(SUBSCRIPTION_PLANS.FREE);
        return freeLimits.features && freeLimits.features.includes(feature);
      }

      // Check subscription limits
      const limits = subscription.limits_json;
      if (!limits.features) {
        return false;
      }

      return limits.features.includes(feature) || limits.features.includes('all');
    } catch (error) {
      return false;
    }
  }

  /**
   * Check usage limit
   * @param {number} userId 
   * @param {string} limitType 
   * @param {number} currentUsage 
   * @returns {Promise<object>}
   */
  async checkUsageLimit(userId, limitType, currentUsage = 0) {
    try {
      const subscription = await this.getUserSubscription(userId);
      
      let limits;
      if (!subscription) {
        limits = this.getDefaultLimits(SUBSCRIPTION_PLANS.FREE);
      } else {
        limits = subscription.limits_json;
      }

      const limit = limits[limitType];
      
      if (limit === -1 || limit === 'unlimited') {
        return {
          hasAccess: true,
          remaining: -1,
          limit: 'unlimited'
        };
      }

      const remaining = Math.max(0, limit - currentUsage);
      
      return {
        hasAccess: currentUsage < limit,
        remaining,
        limit,
        currentUsage
      };
    } catch (error) {
      return {
        hasAccess: false,
        remaining: 0,
        limit: 0,
        error: error.message
      };
    }
  }

  /**
   * Get subscription history for user
   * @param {number} userId 
   * @returns {Promise<array>}
   */
  async getSubscriptionHistory(userId) {
    try {
      const subscriptions = await Subscription.findAll({
        where: { user_id: userId },
        order: [['created_at', 'DESC']]
      });

      return subscriptions;
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Get subscriptions expiring soon
   * @param {number} days Days ahead to check
   * @returns {Promise<array>}
   */
  async getExpiringSoonSubscriptions(days = 7) {
    try {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + days);

      const subscriptions = await Subscription.findAll({
        where: {
          status: SUBSCRIPTION_STATUS.ACTIVE,
          expires_at: {
            [Op.lte]: futureDate,
            [Op.gt]: new Date()
          }
        },
        include: [{
          model: VotteryUser,
          as: 'user',
          attributes: ['id', 'email', 'username']
        }],
        order: [['expires_at', 'ASC']]
      });

      return subscriptions;
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Process expired subscriptions
   * @returns {Promise<number>}
   */
  async processExpiredSubscriptions() {
    try {
      const expiredSubscriptions = await Subscription.findAll({
        where: {
          status: SUBSCRIPTION_STATUS.ACTIVE,
          expires_at: {
            [Op.lt]: new Date()
          }
        }
      });

      let processed = 0;
      for (const subscription of expiredSubscriptions) {
        try {
          await this.expireSubscription(subscription.id);
          processed++;
        } catch (error) {
          console.error(`Error expiring subscription ${subscription.id}:`, error);
        }
      }

      return processed;
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Get subscription statistics
   * @returns {Promise<object>}
   */
  async getSubscriptionStatistics() {
    try {
      const [
        totalSubscriptions,
        activeSubscriptions,
        subscriptionsByPlan,
        recentSubscriptions
      ] = await Promise.all([
        Subscription.count(),
        Subscription.count({ where: { status: SUBSCRIPTION_STATUS.ACTIVE } }),
        Subscription.findAll({
          attributes: [
            'plan_type',
            [Sequelize.fn('COUNT', Sequelize.col('id')), 'count']
          ],
          where: { status: SUBSCRIPTION_STATUS.ACTIVE },
          group: ['plan_type']
        }),
        Subscription.count({
          where: {
            created_at: {
              [Op.gte]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
            }
          }
        })
      ]);

      const planDistribution = {};
      subscriptionsByPlan.forEach(plan => {
        planDistribution[plan.plan_type] = parseInt(plan.dataValues.count);
      });

      return {
        total: totalSubscriptions,
        active: activeSubscriptions,
        planDistribution,
        recent: recentSubscriptions
      };
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Get default limits for subscription plan
   * @param {string} planType 
   * @returns {object}
   */
  getDefaultLimits(planType) {
    const limits = {
      [SUBSCRIPTION_PLANS.FREE]: {
        elections_per_month: 2,
        votes_per_election: 100,
        features: ['basic_voting', 'plurality_voting'],
        storage_mb: 10,
        analytics_days: 7
      },
      [SUBSCRIPTION_PLANS.PAY_AS_YOU_GO]: {
        elections_per_month: -1,
        votes_per_election: -1,
        features: ['all'],
        storage_mb: -1,
        analytics_days: -1,
        cost_per_vote: 0.01
      },
      [SUBSCRIPTION_PLANS.MONTHLY]: {
        elections_per_month: -1,
        votes_per_election: -1,
        features: ['all'],
        storage_mb: -1,
        analytics_days: -1
      },
      [SUBSCRIPTION_PLANS.QUARTERLY]: {
        elections_per_month: -1,
        votes_per_election: -1,
        features: ['all'],
        storage_mb: -1,
        analytics_days: -1,
        discount_percentage: 10
      },
      [SUBSCRIPTION_PLANS.SEMI_ANNUAL]: {
        elections_per_month: -1,
        votes_per_election: -1,
        features: ['all'],
        storage_mb: -1,
        analytics_days: -1,
        discount_percentage: 15
      },
      [SUBSCRIPTION_PLANS.YEARLY]: {
        elections_per_month: -1,
        votes_per_election: -1,
        features: ['all'],
        storage_mb: -1,
        analytics_days: -1,
        discount_percentage: 20
      }
    };

    return limits[planType] || limits[SUBSCRIPTION_PLANS.FREE];
  }

  /**
   * Update subscription limits
   * @param {number} subscriptionId 
   * @param {object} newLimits 
   * @returns {Promise<object>}
   */
  async updateSubscriptionLimits(subscriptionId, newLimits) {
    try {
      const subscription = await Subscription.findByPk(subscriptionId);
      if (!subscription) {
        throw new AppError('Subscription not found', 404);
      }

      const oldLimits = subscription.limits_json;
      await subscription.update({
        limits_json: { ...oldLimits, ...newLimits },
        updated_at: new Date()
      });

      // Log activity
      await auditService.logActivity(
        subscription.user_id,
        'SUBSCRIPTION_LIMITS_UPDATE',
        'subscription',
        subscriptionId,
        {
          old_limits: oldLimits,
          new_limits: newLimits
        }
      );

      return subscription;
    } catch (error) {
      throw new AppError(error.message, error.statusCode || 500);
    }
  }
}

export default new SubscriptionService();