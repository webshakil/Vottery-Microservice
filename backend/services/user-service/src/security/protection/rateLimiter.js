// src/security/protection/rateLimiter.js
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { createClient } from 'redis';

/**
 * Advanced Rate Limiting Service for Vottery User Service
 * Implements multiple rate limiting strategies with Redis backend
 */
class RateLimiter {
  constructor() {
    this.redisClient = null;
    this.isRedisAvailable = false;
    this.initializeRedis();
  }

  /**
   * Initialize Redis connection for distributed rate limiting
   */
  async initializeRedis() {
    try {
      if (process.env.REDIS_URL) {
        this.redisClient = createClient({
          url: process.env.REDIS_URL,
          retry_strategy: (options) => {
            if (options.error && options.error.code === 'ECONNREFUSED') {
              console.warn('Redis connection refused, falling back to memory store');
              return undefined; // Stop retrying
            }
            return Math.min(options.attempt * 100, 3000);
          }
        });

        await this.redisClient.connect();
        this.isRedisAvailable = true;
        console.log('Redis connected for rate limiting');
      }
    } catch (error) {
      console.warn('Redis not available, using memory store for rate limiting:', error.message);
      this.isRedisAvailable = false;
    }
  }

  /**
   * Create store for rate limiting (Redis or memory)
   * @returns {Object} Rate limit store
   */
  createStore() {
    if (this.isRedisAvailable && this.redisClient) {
      return new RedisStore({
        sendCommand: (...args) => this.redisClient.sendCommand(args),
        prefix: 'vottery_rl:'
      });
    }
    // Fallback to default memory store
    return undefined;
  }

  /**
   * Authentication rate limiter (stricter limits)
   * @param {Object} options - Custom options
   * @returns {Function} Rate limiting middleware
   */
  createAuthLimiter(options = {}) {
    return rateLimit({
      store: this.createStore(),
      windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
      max: options.max || 5, // 5 attempts per window
      message: {
        error: 'Too many authentication attempts',
        retryAfter: '15 minutes',
        type: 'auth_rate_limit'
      },
      standardHeaders: true,
      legacyHeaders: false,
      skipSuccessfulRequests: false,
      skipFailedRequests: false,
      keyGenerator: (req) => {
        // Use both IP and email/username for more precise limiting
        const identifier = req.body?.email || req.body?.username || req.ip;
        return `auth_${identifier}`;
      },
      handler: (req, res) => {
        const remaining = Math.round((Date.now() + (options.windowMs || 15 * 60 * 1000)) / 1000);
        res.status(429).json({
          error: 'Authentication rate limit exceeded',
          message: 'Too many login attempts. Please try again later.',
          retryAfter: remaining,
          type: 'auth_rate_limit'
        });
      },
      ...options
    });
  }

  /**
   * API rate limiter (general API usage)
   * @param {Object} options - Custom options
   * @returns {Function} Rate limiting middleware
   */
  createApiLimiter(options = {}) {
    return rateLimit({
      store: this.createStore(),
      windowMs: options.windowMs || 60 * 1000, // 1 minute
      max: options.max || 60, // 60 requests per minute
      message: {
        error: 'API rate limit exceeded',
        retryAfter: '1 minute',
        type: 'api_rate_limit'
      },
      standardHeaders: true,
      legacyHeaders: false,
      skipSuccessfulRequests: false,
      keyGenerator: (req) => {
        // Use API key if available, otherwise IP
        return req.user?.id ? `api_user_${req.user.id}` : `api_ip_${req.ip}`;
      },
      handler: (req, res) => {
        res.status(429).json({
          error: 'API rate limit exceeded',
          message: 'You have exceeded the API rate limit.',
          limit: options.max || 60,
          window: '1 minute',
          type: 'api_rate_limit'
        });
      },
      ...options
    });
  }

  /**
   * Election creation rate limiter
   * @param {Object} options - Custom options
   * @returns {Function} Rate limiting middleware
   */
  createElectionLimiter(options = {}) {
    return rateLimit({
      store: this.createStore(),
      windowMs: options.windowMs || 60 * 60 * 1000, // 1 hour
      max: options.max || 10, // 10 elections per hour
      message: {
        error: 'Election creation limit exceeded',
        retryAfter: '1 hour',
        type: 'election_rate_limit'
      },
      skipSuccessfulRequests: false,
      keyGenerator: (req) => `election_${req.user?.id || req.ip}`,
      skip: (req) => {
        // Skip rate limiting for premium users
        return req.user?.subscription?.type === 'premium';
      },
      handler: (req, res) => {
        res.status(429).json({
          error: 'Election creation rate limit exceeded',
          message: 'You have reached your hourly election creation limit.',
          suggestion: 'Consider upgrading to premium for unlimited elections',
          type: 'election_rate_limit'
        });
      },
      ...options
    });
  }

  /**
   * Vote casting rate limiter
   * @param {Object} options - Custom options
   * @returns {Function} Rate limiting middleware
   */
  createVotingLimiter(options = {}) {
    return rateLimit({
      store: this.createStore(),
      windowMs: options.windowMs || 60 * 1000, // 1 minute
      max: options.max || 30, // 30 votes per minute
      message: {
        error: 'Voting rate limit exceeded',
        retryAfter: '1 minute',
        type: 'voting_rate_limit'
      },
      keyGenerator: (req) => `vote_${req.user?.id || req.ip}`,
      handler: (req, res) => {
        res.status(429).json({
          error: 'Voting rate limit exceeded',
          message: 'Please slow down your voting activity.',
          type: 'voting_rate_limit'
        });
      },
      ...options
    });
  }

  /**
   * File upload rate limiter
   * @param {Object} options - Custom options
   * @returns {Function} Rate limiting middleware
   */
  createUploadLimiter(options = {}) {
    return rateLimit({
      store: this.createStore(),
      windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
      max: options.max || 20, // 20 uploads per 15 minutes
      message: {
        error: 'Upload rate limit exceeded',
        retryAfter: '15 minutes',
        type: 'upload_rate_limit'
      },
      keyGenerator: (req) => `upload_${req.user?.id || req.ip}`,
      handler: (req, res) => {
        res.status(429).json({
          error: 'Upload rate limit exceeded',
          message: 'Too many file uploads. Please wait before uploading more files.',
          type: 'upload_rate_limit'
        });
      },
      ...options
    });
  }

  /**
   * Search rate limiter (prevent search abuse)
   * @param {Object} options - Custom options
   * @returns {Function} Rate limiting middleware
   */
  createSearchLimiter(options = {}) {
    return rateLimit({
      store: this.createStore(),
      windowMs: options.windowMs || 60 * 1000, // 1 minute
      max: options.max || 100, // 100 searches per minute
      message: {
        error: 'Search rate limit exceeded',
        retryAfter: '1 minute',
        type: 'search_rate_limit'
      },
      keyGenerator: (req) => `search_${req.user?.id || req.ip}`,
      handler: (req, res) => {
        res.status(429).json({
          error: 'Search rate limit exceeded',
          message: 'Too many search requests. Please wait before searching again.',
          type: 'search_rate_limit'
        });
      },
      ...options
    });
  }

  /**
   * Adaptive rate limiter that adjusts based on user behavior
   * @param {Object} options - Custom options
   * @returns {Function} Rate limiting middleware
   */
  createAdaptiveLimiter(options = {}) {
    return rateLimit({
      store: this.createStore(),
      windowMs: options.windowMs || 60 * 1000, // 1 minute
      max: (req) => {
        // Adjust limits based on user type and behavior
        if (req.user?.subscription?.type === 'premium') return 200;
        if (req.user?.verified) return 120;
        if (req.user) return 60;
        return 30; // Anonymous users get lowest limit
      },
      keyGenerator: (req) => `adaptive_${req.user?.id || req.ip}`,
      handler: (req, res) => {
        const userType = req.user?.subscription?.type || 'free';
        res.status(429).json({
          error: 'Rate limit exceeded',
          message: `Rate limit exceeded for ${userType} users`,
          suggestion: userType === 'free' ? 'Consider upgrading for higher limits' : null,
          type: 'adaptive_rate_limit'
        });
      },
      ...options
    });
  }

  /**
   * Burst limiter for handling traffic spikes
   * @param {Object} options - Custom options
   * @returns {Function} Rate limiting middleware
   */
  createBurstLimiter(options = {}) {
    return rateLimit({
      store: this.createStore(),
      windowMs: options.windowMs || 1000, // 1 second
      max: options.max || 10, // 10 requests per second
      message: {
        error: 'Burst rate limit exceeded',
        retryAfter: '1 second',
        type: 'burst_rate_limit'
      },
      keyGenerator: (req) => `burst_${req.user?.id || req.ip}`,
      handler: (req, res) => {
        res.status(429).json({
          error: 'Too many requests too quickly',
          message: 'Please slow down your request rate.',
          type: 'burst_rate_limit'
        });
      },
      ...options
    });
  }

  /**
   * Create custom rate limiter with specific configuration
   * @param {Object} config - Rate limiter configuration
   * @returns {Function} Rate limiting middleware
   */
  createCustomLimiter(config) {
    return rateLimit({
      store: this.createStore(),
      windowMs: config.windowMs,
      max: config.max,
      keyGenerator: config.keyGenerator || ((req) => req.ip),
      skip: config.skip,
      handler: config.handler || ((req, res) => {
        res.status(429).json({
          error: 'Rate limit exceeded',
          message: config.message || 'Too many requests',
          type: 'custom_rate_limit'
        });
      }),
      ...config
    });
  }

  /**
   * Get current rate limit status for a key
   * @param {string} key - Rate limit key
   * @param {Object} limiterConfig - Limiter configuration
   * @returns {Promise<Object>} Rate limit status
   */
  async getRateLimitStatus(key, limiterConfig) {
    try {
      if (!this.isRedisAvailable) {
        return { available: true, remaining: limiterConfig.max };
      }

      const current = await this.redisClient.get(`vottery_rl:${key}`);
      const remaining = Math.max(0, limiterConfig.max - (parseInt(current) || 0));

      return {
        available: remaining > 0,
        remaining,
        total: limiterConfig.max,
        resetTime: Date.now() + limiterConfig.windowMs
      };
    } catch (error) {
      console.error('Error getting rate limit status:', error);
      return { available: true, remaining: limiterConfig.max };
    }
  }

  /**
   * Reset rate limit for a specific key (admin function)
   * @param {string} key - Rate limit key to reset
   * @returns {Promise<boolean>} Success status
   */
  async resetRateLimit(key) {
    try {
      if (!this.isRedisAvailable) {
        return true; // Memory store resets automatically
      }

      await this.redisClient.del(`vottery_rl:${key}`);
      return true;
    } catch (error) {
      console.error('Error resetting rate limit:', error);
      return false;
    }
  }

  /**
   * Create middleware stack with multiple rate limiters
   * @param {Object} options - Configuration for different limiters
   * @returns {Array} Array of rate limiting middleware
   */
  createMiddlewareStack(options = {}) {
    const middlewares = [];

    // Add burst protection (first line of defense)
    if (options.burst !== false) {
      middlewares.push(this.createBurstLimiter(options.burst));
    }

    // Add general API limiting
    if (options.api !== false) {
      middlewares.push(this.createApiLimiter(options.api));
    }

    // Add adaptive limiting based on user type
    if (options.adaptive !== false) {
      middlewares.push(this.createAdaptiveLimiter(options.adaptive));
    }

    return middlewares;
  }
}

export default RateLimiter;