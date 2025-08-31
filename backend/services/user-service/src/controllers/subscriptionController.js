//import { Subscription, VotteryUser, UserActivityLog } from '../models/index.js';
import models from '../models/index.js';

const { Subscription, VotteryUser, UserActivityLog } = models;

import  subscriptionService  from '../services/subscriptionService.js';
import  auditService  from '../services/auditService.js';
import { successResponse, errorResponse } from '../utils/response.js';
import  validateInput  from '../utils/validators.js';
import { SUBSCRIPTION_PLANS, SUBSCRIPTION_STATUS } from '../config/constants.js';
import { Op } from 'sequelize';

/**
 * Subscription Controller - Manages user subscriptions and billing
 * Handles subscription creation, updates, cancellations, and usage tracking
 */
class SubscriptionController {

  /**
   * Get current user's subscription
   * GET /api/subscriptions/me
   */
  async getCurrentSubscription(req, res) {
    try {
      const subscription = await subscriptionService.getUserActiveSubscription(req.user.id);
      
      if (!subscription) {
        // Return default free subscription structure
        const freeSubscription = {
          id: null,
          plan_type: 'free',
          status: 'active',
          limits_json: await subscriptionService.getDefaultLimits('free'),
          starts_at: req.user.created_at,
          expires_at: null,
          auto_renew: false,
          usage: await subscriptionService.getCurrentUsage(req.user.id)
        };

        return successResponse(res, { subscription: freeSubscription });
      }

      // Get current usage
      const usage = await subscriptionService.getCurrentUsage(req.user.id);
      const subscriptionWithUsage = {
        ...subscription.toJSON(),
        usage
      };

      await auditService.log(req.user.id, 'SUBSCRIPTION_VIEWED', 'subscription', subscription.id, {
        planType: subscription.plan_type,
        status: subscription.status
      }, req);

      return successResponse(res, { subscription: subscriptionWithUsage });

    } catch (error) {
      console.error('Get current subscription error:', error);
      return errorResponse(res, 'Failed to fetch subscription', 500);
    }
  }

  /**
   * Get all subscriptions (admin only)
   * GET /api/subscriptions
   */
  async getAllSubscriptions(req, res) {
    try {
      const { 
        page = 1, 
        limit = 20, 
        plan_type, 
        status, 
        search,
        sort_by = 'created_at',
        sort_order = 'DESC'
      } = req.query;

      const filters = {};
      if (plan_type) filters.plan_type = plan_type;
      if (status) filters.status = status;

      const searchCondition = search ? {
        [Op.or]: [
          { '$VotteryUser.email$': { [Op.iLike]: `%${search}%` } },
          { '$VotteryUser.username$': { [Op.iLike]: `%${search}%` } }
        ]
      } : {};

      const offset = (page - 1) * limit;

      const { rows: subscriptions, count } = await Subscription.findAndCountAll({
        where: { ...filters, ...searchCondition },
        include: [{
          model: VotteryUser,
          attributes: ['id', 'email', 'username', 'created_at']
        }],
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [[sort_by, sort_order.toUpperCase()]],
        distinct: true
      });

      await auditService.log(req.user.id, 'SUBSCRIPTIONS_LIST_VIEWED', 'subscription', null, {
        filters,
        resultCount: count,
        page: parseInt(page)
      }, req);

      return successResponse(res, {
        subscriptions,
        pagination: {
          total: count,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(count / limit)
        }
      });

    } catch (error) {
      console.error('Get all subscriptions error:', error);
      return errorResponse(res, 'Failed to fetch subscriptions', 500);
    }
  }

  /**
   * Create or upgrade subscription
   * POST /api/subscriptions
   */
  async createSubscription(req, res) {
    try {
      const { plan_type, payment_method, auto_renew = false } = req.body;

      // Basic validation
      if (!plan_type) {
        return errorResponse(res, 'Plan type is required', 400);
      }

      if (!payment_method) {
        return errorResponse(res, 'Payment method is required', 400);
      }

      // Check if user already has an active subscription
      const existingSubscription = await subscriptionService.getUserActiveSubscription(req.user.id);
      
      if (existingSubscription && existingSubscription.plan_type !== 'free') {
        return errorResponse(res, 'User already has an active subscription. Use upgrade endpoint instead.', 409);
      }

      // Create subscription through service
      const result = await subscriptionService.createSubscription({
        userId: req.user.id,
        planType: plan_type,
        paymentMethod: payment_method,
        autoRenew: auto_renew
      });

      if (!result.success) {
        return errorResponse(res, result.error, 400);
      }

      await auditService.log(req.user.id, 'SUBSCRIPTION_CREATED', 'subscription', result.subscription.id, {
        planType: plan_type,
        paymentMethod: payment_method,
        autoRenew: auto_renew,
        amount: result.paymentAmount
      }, req);

      return successResponse(res, {
        subscription: result.subscription,
        payment: result.payment
      }, 'Subscription created successfully', 201);

    } catch (error) {
      console.error('Create subscription error:', error);
      return errorResponse(res, 'Failed to create subscription', 500);
    }
  }

  /**
   * Update subscription
   * PUT /api/subscriptions/:id
   */
  async updateSubscription(req, res) {
    try {
      const { id } = req.params;
      const { auto_renew, plan_type } = req.body;

      const subscription = await Subscription.findOne({
        where: { id, user_id: req.user.id }
      });

      if (!subscription) {
        return errorResponse(res, 'Subscription not found', 404);
      }

      if (subscription.status !== 'active') {
        return errorResponse(res, 'Cannot modify inactive subscription', 400);
      }

      const oldData = { ...subscription.toJSON() };

      // Handle plan upgrade/downgrade
      if (plan_type && plan_type !== subscription.plan_type) {
        const result = await subscriptionService.changeSubscriptionPlan(
          subscription.id, 
          plan_type
        );

        if (!result.success) {
          return errorResponse(res, result.error, 400);
        }
      }

      // Update auto-renew setting
      if (typeof auto_renew === 'boolean') {
        await subscription.update({ auto_renew });
      }

      await subscription.reload();

      await auditService.log(req.user.id, 'SUBSCRIPTION_UPDATED', 'subscription', id, {
        oldData,
        newData: subscription.toJSON(),
        changes: Object.keys(req.body)
      }, req);

      return successResponse(res, { subscription }, 'Subscription updated successfully');

    } catch (error) {
      console.error('Update subscription error:', error);
      return errorResponse(res, 'Failed to update subscription', 500);
    }
  }

  /**
   * Cancel subscription
   * DELETE /api/subscriptions/:id
   */
  async cancelSubscription(req, res) {
    try {
      const { id } = req.params;
      const { cancel_at_period_end = true, reason } = req.body;

      const subscription = await Subscription.findOne({
        where: { id, user_id: req.user.id }
      });

      if (!subscription) {
        return errorResponse(res, 'Subscription not found', 404);
      }

      if (subscription.status === 'cancelled') {
        return errorResponse(res, 'Subscription is already cancelled', 400);
      }

      const result = await subscriptionService.cancelSubscription(
        subscription.id,
        cancel_at_period_end,
        reason
      );

      if (!result.success) {
        return errorResponse(res, result.error, 400);
      }

      await auditService.log(req.user.id, 'SUBSCRIPTION_CANCELLED', 'subscription', id, {
        planType: subscription.plan_type,
        cancelAtPeriodEnd: cancel_at_period_end,
        reason,
        refundAmount: result.refundAmount
      }, req);

      return successResponse(res, {
        subscription: result.subscription,
        refund: result.refund
      }, 'Subscription cancelled successfully');

    } catch (error) {
      console.error('Cancel subscription error:', error);
      return errorResponse(res, 'Failed to cancel subscription', 500);
    }
  }

  /**
   * Get subscription usage and limits
   * GET /api/subscriptions/usage
   */
  async getUsage(req, res) {
    try {
      const subscription = await subscriptionService.getUserActiveSubscription(req.user.id);
      const usage = await subscriptionService.getCurrentUsage(req.user.id);
      
      const limits = subscription 
        ? JSON.parse(subscription.limits_json || '{}')
        : await subscriptionService.getDefaultLimits('free');

      const usageData = {
        current_usage: usage,
        limits: limits,
        plan_type: subscription ? subscription.plan_type : 'free',
        usage_percentage: subscriptionService.calculateUsagePercentage(usage, limits)
      };

      return successResponse(res, { usage: usageData });

    } catch (error) {
      console.error('Get usage error:', error);
      return errorResponse(res, 'Failed to fetch usage data', 500);
    }
  }

  /**
   * Get available subscription plans
   * GET /api/subscriptions/plans
   */
  async getAvailablePlans(req, res) {
    try {
      const plans = await subscriptionService.getAvailablePlans();
      
      // Add current user's plan info
      const currentSubscription = await subscriptionService.getUserActiveSubscription(req.user.id);
      const currentPlan = currentSubscription ? currentSubscription.plan_type : 'free';

      const plansWithStatus = plans.map(plan => ({
        ...plan,
        is_current: plan.type === currentPlan,
        can_upgrade: subscriptionService.canUpgradeToPlan(currentPlan, plan.type),
        can_downgrade: subscriptionService.canDowngradeToPlan(currentPlan, plan.type)
      }));

      return successResponse(res, { plans: plansWithStatus });

    } catch (error) {
      console.error('Get plans error:', error);
      return errorResponse(res, 'Failed to fetch subscription plans', 500);
    }
  }

  /**
   * Process webhook from payment providers
   * POST /api/subscriptions/webhook/:provider
   */
  async processWebhook(req, res) {
    try {
      const { provider } = req.params;
      const webhookData = req.body;
      const signature = req.headers['stripe-signature'] || req.headers['paddle-signature'];

      if (!['stripe', 'paddle'].includes(provider)) {
        return errorResponse(res, 'Invalid payment provider', 400);
      }

      const result = await subscriptionService.processWebhook(provider, webhookData, signature);

      if (!result.success) {
        console.error('Webhook processing failed:', result.error);
        return res.status(400).send('Webhook processing failed');
      }

      // Log webhook processing
      await auditService.log(null, 'WEBHOOK_PROCESSED', 'subscription', null, {
        provider,
        eventType: result.eventType,
        subscriptionId: result.subscriptionId,
        success: true
      }, req);

      return res.status(200).send('Webhook processed successfully');

    } catch (error) {
      console.error('Webhook processing error:', error);
      
      // Log failed webhook
      await auditService.log(null, 'WEBHOOK_FAILED', 'subscription', null, {
        provider: req.params.provider,
        error: error.message
      }, req);

      return res.status(500).send('Webhook processing error');
    }
  }

  /**
   * Get subscription analytics (admin only)
   * GET /api/subscriptions/analytics
   */
  async getSubscriptionAnalytics(req, res) {
    try {
      const { period = '30d', metrics = 'all' } = req.query;

      const analytics = await subscriptionService.getSubscriptionAnalytics({
        period,
        metrics: metrics === 'all' ? null : metrics.split(',')
      });

      await auditService.log(req.user.id, 'SUBSCRIPTION_ANALYTICS_VIEWED', 'system', null, {
        period,
        metrics,
        analyticsKeys: Object.keys(analytics)
      }, req);

      return successResponse(res, { analytics });

    } catch (error) {
      console.error('Get analytics error:', error);
      return errorResponse(res, 'Failed to fetch subscription analytics', 500);
    }
  }

  /**
   * Get subscription history
   * GET /api/subscriptions/history
   */
  async getSubscriptionHistory(req, res) {
    try {
      const { page = 1, limit = 10 } = req.query;
      const offset = (page - 1) * limit;

      const { rows: subscriptions, count } = await Subscription.findAndCountAll({
        where: { user_id: req.user.id },
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [['created_at', 'DESC']]
      });

      return successResponse(res, {
        subscriptions,
        pagination: {
          total: count,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(count / limit)
        }
      });

    } catch (error) {
      console.error('Get subscription history error:', error);
      return errorResponse(res, 'Failed to fetch subscription history', 500);
    }
  }

  /**
   * Check subscription limits before action
   * POST /api/subscriptions/check-limit
   */
  async checkLimit(req, res) {
    try {
      const { action, quantity = 1 } = req.body;

      if (!action) {
        return errorResponse(res, 'Action type is required', 400);
      }

      const canPerform = await subscriptionService.checkUsageLimit(
        req.user.id, 
        action, 
        quantity
      );

      const usage = await subscriptionService.getCurrentUsage(req.user.id);
      const subscription = await subscriptionService.getUserActiveSubscription(req.user.id);
      
      const limits = subscription 
        ? JSON.parse(subscription.limits_json || '{}')
        : await subscriptionService.getDefaultLimits('free');

      return successResponse(res, {
        can_perform: canPerform.allowed,
        reason: canPerform.reason,
        current_usage: usage,
        limits: limits,
        remaining: canPerform.remaining
      });

    } catch (error) {
      console.error('Check limit error:', error);
      return errorResponse(res, 'Failed to check subscription limit', 500);
    }
  }

}

export default new SubscriptionController();