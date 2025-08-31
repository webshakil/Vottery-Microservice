import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import redisClient from '../config/redis.js';
import { ResponseBuilder } from '../utils/response.js';
import auditService from '../services/auditService.js';

/**
 * Rate Limiting Middleware
 * Comprehensive rate limiting for API endpoints, authentication, and user actions
 * Milestone 1: Rate limiting and DDoS protection
 */

/**
 * Helper function to create unique RedisStore instances
 */
const createRedisStore = (prefix) => {
  return new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
    prefix: `rl:${prefix}:`
  });
};

/**
 * IPv6-safe key generator helper using the proper ipKeyGenerator
 */
const createKeyGenerator = (keyFn) => {
  return (req, res) => {
    const baseKey = keyFn(req);
    // Use the built-in ipKeyGenerator for IPv6 safety
    if (req.ip && baseKey.includes(req.ip)) {
      const { ipKeyGenerator } = rateLimit;
      const safeIp = ipKeyGenerator(req, res);
      return baseKey.replace(req.ip, safeIp);
    }
    return baseKey;
  };
};

/**
 * General API rate limiter
 */
export const generalRateLimit = rateLimit({
  store: createRedisStore('general'),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: {
    error: 'Too many requests from this IP, please try again later',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: createKeyGenerator((req) => {
    // Use user ID if authenticated, otherwise IP
    return req.user ? `user:${req.user.id}` : `ip:${req.ip}`;
  }),
  handler: async (req, res) => {
    // Log rate limit exceeded
    await auditService.log(req.user?.id || null, 'RATE_LIMIT_EXCEEDED', 'security', null, {
      type: 'general_api',
      ip: req.ip,
      endpoint: req.originalUrl,
      userAgent: req.headers['user-agent']
    }, req);

    return ResponseBuilder(res, 'Too many requests, please try again later', 429, {
      retryAfter: 900 // 15 minutes in seconds
    });
  }
});

/**
 * Standard rate limiter for normal operations
 */
export const standardRateLimit = rateLimit({
  store: createRedisStore('standard'),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  keyGenerator: createKeyGenerator((req) => req.user ? `user:${req.user.id}` : `ip:${req.ip}`),
  handler: async (req, res) => {
    await auditService.log(req.user?.id || null, 'STANDARD_RATE_LIMIT_EXCEEDED', 'security', null, {
      ip: req.ip,
      endpoint: req.originalUrl
    }, req);

    return ResponseBuilder(res, 'Too many requests, please try again later', 429, {
      retryAfter: 900
    });
  }
});

/**
 * Strict rate limiter for sensitive operations
 */
export const strictRateLimit = rateLimit({
  store: createRedisStore('strict'),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 requests per window
  keyGenerator: createKeyGenerator((req) => req.user ? `user:${req.user.id}` : `ip:${req.ip}`),
  handler: async (req, res) => {
    await auditService.log(req.user?.id || null, 'STRICT_RATE_LIMIT_EXCEEDED', 'security', null, {
      ip: req.ip,
      endpoint: req.originalUrl
    }, req);

    return ResponseBuilder(res, 'Too many requests for this sensitive operation', 429, {
      retryAfter: 900
    });
  }
});

/**
 * Authentication rate limiter
 */
export const authRateLimit = rateLimit({
  store: createRedisStore('auth'),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 login attempts per window
  skipSuccessfulRequests: true,
  keyGenerator: createKeyGenerator((req) => `auth:${req.ip}:${req.body.email || 'unknown'}`),
  handler: async (req, res) => {
    // Log failed authentication attempts
    await auditService.log(null, 'AUTH_RATE_LIMIT_EXCEEDED', 'security', null, {
      ip: req.ip,
      email: req.body.email,
      endpoint: req.originalUrl,
      attempts: 5,
      userAgent: req.headers['user-agent']
    }, req);

    return ResponseBuilder(res, 'Too many login attempts, please try again later', 429, {
      retryAfter: 900,
      lockoutTime: '15 minutes'
    });
  }
});

/**
 * Password reset rate limiter
 */
export const passwordResetRateLimit = rateLimit({
  store: createRedisStore('pwd_reset'),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 password reset attempts per hour
  keyGenerator: createKeyGenerator((req) => `pwd_reset:${req.body.email || req.ip}`),
  handler: async (req, res) => {
    await auditService.log(null, 'PASSWORD_RESET_RATE_LIMIT_EXCEEDED', 'security', null, {
      email: req.body.email,
      ip: req.ip,
      attempts: 3
    }, req);

    return ResponseBuilder(res, 'Too many password reset attempts, please try again in 1 hour', 429, {
      retryAfter: 3600
    });
  }
});

/**
 * Registration rate limiter
 */
export const registrationRateLimit = rateLimit({
  store: createRedisStore('register'),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 registrations per IP per hour
  keyGenerator: createKeyGenerator((req) => `register:${req.ip}`),
  handler: async (req, res) => {
    await auditService.log(null, 'REGISTRATION_RATE_LIMIT_EXCEEDED', 'security', null, {
      ip: req.ip,
      email: req.body.email,
      attempts: 3
    }, req);

    return ResponseBuilder(res, 'Too many registration attempts, please try again later', 429, {
      retryAfter: 3600
    });
  }
});

/**
 * File upload rate limiter
 */
export const uploadRateLimit = rateLimit({
  store: createRedisStore('upload'),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // 20 uploads per hour per user
  keyGenerator: createKeyGenerator((req) => `upload:${req.user?.id || req.ip}`),
  handler: async (req, res) => {
    await auditService.log(req.user?.id || null, 'UPLOAD_RATE_LIMIT_EXCEEDED', 'security', null, {
      ip: req.ip,
      attempts: 20
    }, req);

    return ResponseBuilder(res, 'Too many file uploads, please try again later', 429, {
      retryAfter: 3600
    });
  }
});

/**
 * Email sending rate limiter
 */
export const emailRateLimit = rateLimit({
  store: createRedisStore('email'),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 emails per hour per user
  keyGenerator: createKeyGenerator((req) => `email:${req.user?.id || req.ip}`),
  handler: async (req, res) => {
    await auditService.log(req.user?.id || null, 'EMAIL_RATE_LIMIT_EXCEEDED', 'security', null, {
      ip: req.ip,
      attempts: 10
    }, req);

    return ResponseBuilder(res, 'Too many emails sent, please try again later', 429, {
      retryAfter: 3600
    });
  }
});

/**
 * Admin actions rate limiter
 */
export const adminRateLimit = rateLimit({
  store: createRedisStore('admin'),
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 50, // 50 admin actions per 5 minutes
  keyGenerator: createKeyGenerator((req) => `admin:${req.user?.id}`),
  handler: async (req, res) => {
    await auditService.log(req.user?.id || null, 'ADMIN_RATE_LIMIT_EXCEEDED', 'security', null, {
      ip: req.ip,
      endpoint: req.originalUrl,
      attempts: 50
    }, req);

    return ResponseBuilder(res, 'Too many admin actions, please slow down', 429, {
      retryAfter: 300
    });
  }
});

/**
 * Emergency rate limiter for critical security operations
 * More restrictive than strict for emergency procedures
 */
export const emergencyRateLimit = rateLimit({
  store: createRedisStore('emergency'),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 2, // Only 2 emergency operations per hour
  keyGenerator: createKeyGenerator((req) => `emergency:${req.user?.id || req.ip}`),
  handler: async (req, res) => {
    await auditService.log(req.user?.id || null, 'EMERGENCY_RATE_LIMIT_EXCEEDED', 'security', null, {
      ip: req.ip,
      endpoint: req.originalUrl,
      attempts: 2
    }, req);

    return ResponseBuilder(res, 'Too many emergency operations attempted', 429, {
      retryAfter: 3600,
      emergencyContact: true
    });
  }
});

/**
 * API key rate limiter for external integrations
 */
export const apiKeyRateLimit = rateLimit({
  store: createRedisStore('api_key'),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 1000, // 1000 requests per hour per API key
  keyGenerator: (req) => {
    const apiKey = req.headers['x-api-key'];
    return `api_key:${apiKey}`;
  },
  skip: (req) => !req.headers['x-api-key'],
  handler: async (req, res) => {
    await auditService.log(null, 'API_KEY_RATE_LIMIT_EXCEEDED', 'security', null, {
      apiKey: req.headers['x-api-key'],
      ip: req.ip,
      endpoint: req.originalUrl
    }, req);

    return ResponseBuilder(res, 'API key rate limit exceeded', 429, {
      retryAfter: 3600
    });
  }
});

/**
 * Dynamic rate limiter based on user subscription
 */
export const subscriptionBasedRateLimit = async (req, res, next) => {
  try {
    if (!req.user) {
      return generalRateLimit(req, res, next);
    }

    // Get user's subscription tier
    const subscription = await getUserSubscription(req.user.id);
    const tier = subscription?.plan_type || 'free';

    // Define limits based on subscription tier
    const tierLimits = {
      free: { windowMs: 60 * 60 * 1000, max: 50 },
      pay_as_you_go: { windowMs: 60 * 60 * 1000, max: 200 },
      monthly: { windowMs: 60 * 60 * 1000, max: 500 },
      '3_month': { windowMs: 60 * 60 * 1000, max: 750 },
      '6_month': { windowMs: 60 * 60 * 1000, max: 1000 },
      yearly: { windowMs: 60 * 60 * 1000, max: 1500 }
    };

    const limits = tierLimits[tier] || tierLimits.free;

    const dynamicLimiter = rateLimit({
      store: createRedisStore(`sub_${tier}`),
      windowMs: limits.windowMs,
      max: limits.max,
      keyGenerator: createKeyGenerator((req) => `sub:${tier}:${req.user.id}`),
      handler: async (req, res) => {
        await auditService.log(req.user.id, 'SUBSCRIPTION_RATE_LIMIT_EXCEEDED', 'security', null, {
          tier,
          limit: limits.max,
          window: limits.windowMs,
          ip: req.ip
        }, req);

        return ResponseBuilder(res, 'Subscription rate limit exceeded. Consider upgrading your plan.', 429, {
          retryAfter: Math.floor(limits.windowMs / 1000),
          upgradeRequired: tier === 'free'
        });
      }
    });

    return dynamicLimiter(req, res, next);

  } catch (error) {
    console.error('Subscription rate limit error:', error);
    // Fallback to general rate limit
    return generalRateLimit(req, res, next);
  }
};

/**
 * Burst rate limiter for high-frequency actions
 */
export const burstRateLimit = rateLimit({
  store: createRedisStore('burst'),
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 requests per minute
  keyGenerator: createKeyGenerator((req) => `burst:${req.user?.id || req.ip}`),
  handler: async (req, res) => {
    await auditService.log(req.user?.id || null, 'BURST_RATE_LIMIT_EXCEEDED', 'security', null, {
      ip: req.ip,
      endpoint: req.originalUrl
    }, req);

    return ResponseBuilder(res, 'Too many rapid requests, please slow down', 429, {
      retryAfter: 60
    });
  }
});

/**
 * Check if IP is in blocked list
 */
export const checkBlockedIP = async (req, res, next) => {
  try {
    const isBlocked = await redisClient.sismember('blocked_ips', req.ip);
    
    if (isBlocked) {
      await auditService.log(null, 'BLOCKED_IP_ACCESS_ATTEMPT', 'security', null, {
        ip: req.ip,
        endpoint: req.originalUrl,
        userAgent: req.headers['user-agent']
      }, req);

      return ResponseBuilder(res, 'Access denied from this IP address', 403, {
        blocked: true,
        contactSupport: true
      });
    }

    next();

  } catch (error) {
    console.error('IP block check error:', error);
    next(); // Don't block on error
  }
};

/**
 * Custom rate limiter factory
 * @param {object} options - Rate limiting options
 */
export const createCustomRateLimit = (options = {}) => {
  const {
    windowMs = 15 * 60 * 1000,
    max = 100,
    keyGenerator = (req) => req.user?.id || req.ip,
    message = 'Too many requests',
    logAction = 'CUSTOM_RATE_LIMIT_EXCEEDED',
    prefix = 'custom'
  } = options;

  return rateLimit({
    store: createRedisStore(prefix),
    windowMs,
    max,
    keyGenerator: createKeyGenerator((req) => `custom:${keyGenerator(req)}`),
    handler: async (req, res) => {
      await auditService.log(req.user?.id || null, logAction, 'security', null, {
        ip: req.ip,
        endpoint: req.originalUrl,
        limit: max,
        window: windowMs
      }, req);

      return ResponseBuilder(res, message, 429, {
        retryAfter: Math.floor(windowMs / 1000)
      });
    }
  });
};

// Helper Functions

/**
 * Get user's subscription information
 */
async function getUserSubscription(userId) {
  try {
    // This would integrate with your subscription service
    // Placeholder for now - will be implemented in Milestone 3
    return null;
  } catch (error) {
    console.error('Get subscription error:', error);
    return null;
  }
}

/**
 * Reset rate limit violations for a user/IP
 */
export const resetRateLimitViolations = async (identifier) => {
  try {
    const violationKey = `violations:${identifier}`;
    await redisClient.del(violationKey);
    return true;
  } catch (error) {
    console.error('Reset violations error:', error);
    return false;
  }
};

// Export rateLimiting object to match the import pattern in routes
export const rateLimiting = {
  global: generalRateLimit,
  standard: standardRateLimit,
  strict: strictRateLimit,
  general: generalRateLimit,
  auth: authRateLimit,
  passwordReset: passwordResetRateLimit,
  registration: registrationRateLimit,
  upload: uploadRateLimit,
  email: emailRateLimit,
  admin: adminRateLimit,
  emergency: emergencyRateLimit, // Added the missing emergency rate limiter
  apiKey: apiKeyRateLimit,
  subscriptionBased: subscriptionBasedRateLimit,
  burst: burstRateLimit,
  createCustom: createCustomRateLimit,
  checkBlockedIP,
  resetViolations: resetRateLimitViolations
};

// Also export individual functions for flexibility
export default rateLimiting;
// import rateLimit from 'express-rate-limit';
// import RedisStore from 'rate-limit-redis';
// import redisClient from '../config/redis.js';
// import { ResponseBuilder } from '../utils/response.js';
// import auditService from '../services/auditService.js';

// /**
//  * Rate Limiting Middleware
//  * Comprehensive rate limiting for API endpoints, authentication, and user actions
//  * Milestone 1: Rate limiting and DDoS protection
//  */

// /**
//  * Helper function to create unique RedisStore instances
//  */
// const createRedisStore = (prefix) => {
//   return new RedisStore({
//     sendCommand: (...args) => redisClient.call(...args),
//     prefix: `rl:${prefix}:`
//   });
// };

// /**
//  * IPv6-safe key generator helper using the proper ipKeyGenerator
//  */
// const createKeyGenerator = (keyFn) => {
//   return (req, res) => {
//     const baseKey = keyFn(req);
//     // Use the built-in ipKeyGenerator for IPv6 safety
//     if (req.ip && baseKey.includes(req.ip)) {
//       const { ipKeyGenerator } = rateLimit;
//       const safeIp = ipKeyGenerator(req, res);
//       return baseKey.replace(req.ip, safeIp);
//     }
//     return baseKey;
//   };
// };

// /**
//  * General API rate limiter
//  */
// export const generalRateLimit = rateLimit({
//   store: createRedisStore('general'),
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 100, // 100 requests per window
//   message: {
//     error: 'Too many requests from this IP, please try again later',
//     retryAfter: '15 minutes'
//   },
//   standardHeaders: true,
//   legacyHeaders: false,
//   keyGenerator: createKeyGenerator((req) => {
//     // Use user ID if authenticated, otherwise IP
//     return req.user ? `user:${req.user.id}` : `ip:${req.ip}`;
//   }),
//   handler: async (req, res) => {
//     // Log rate limit exceeded
//     await auditService.log(req.user?.id || null, 'RATE_LIMIT_EXCEEDED', 'security', null, {
//       type: 'general_api',
//       ip: req.ip,
//       endpoint: req.originalUrl,
//       userAgent: req.headers['user-agent']
//     }, req);

//     return ResponseBuilder(res, 'Too many requests, please try again later', 429, {
//       retryAfter: 900 // 15 minutes in seconds
//     });
//   }
// });

// /**
//  * Standard rate limiter for normal operations
//  */
// export const standardRateLimit = rateLimit({
//   store: createRedisStore('standard'),
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 100, // 100 requests per window
//   keyGenerator: createKeyGenerator((req) => req.user ? `user:${req.user.id}` : `ip:${req.ip}`),
//   handler: async (req, res) => {
//     await auditService.log(req.user?.id || null, 'STANDARD_RATE_LIMIT_EXCEEDED', 'security', null, {
//       ip: req.ip,
//       endpoint: req.originalUrl
//     }, req);

//     return ResponseBuilder(res, 'Too many requests, please try again later', 429, {
//       retryAfter: 900
//     });
//   }
// });

// /**
//  * Strict rate limiter for sensitive operations
//  */
// export const strictRateLimit = rateLimit({
//   store: createRedisStore('strict'),
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 10, // 10 requests per window
//   keyGenerator: createKeyGenerator((req) => req.user ? `user:${req.user.id}` : `ip:${req.ip}`),
//   handler: async (req, res) => {
//     await auditService.log(req.user?.id || null, 'STRICT_RATE_LIMIT_EXCEEDED', 'security', null, {
//       ip: req.ip,
//       endpoint: req.originalUrl
//     }, req);

//     return ResponseBuilder(res, 'Too many requests for this sensitive operation', 429, {
//       retryAfter: 900
//     });
//   }
// });

// /**
//  * Authentication rate limiter
//  */
// export const authRateLimit = rateLimit({
//   store: createRedisStore('auth'),
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 5, // 5 login attempts per window
//   skipSuccessfulRequests: true,
//   keyGenerator: createKeyGenerator((req) => `auth:${req.ip}:${req.body.email || 'unknown'}`),
//   handler: async (req, res) => {
//     // Log failed authentication attempts
//     await auditService.log(null, 'AUTH_RATE_LIMIT_EXCEEDED', 'security', null, {
//       ip: req.ip,
//       email: req.body.email,
//       endpoint: req.originalUrl,
//       attempts: 5,
//       userAgent: req.headers['user-agent']
//     }, req);

//     return ResponseBuilder(res, 'Too many login attempts, please try again later', 429, {
//       retryAfter: 900,
//       lockoutTime: '15 minutes'
//     });
//   }
// });

// /**
//  * Password reset rate limiter
//  */
// export const passwordResetRateLimit = rateLimit({
//   store: createRedisStore('pwd_reset'),
//   windowMs: 60 * 60 * 1000, // 1 hour
//   max: 3, // 3 password reset attempts per hour
//   keyGenerator: createKeyGenerator((req) => `pwd_reset:${req.body.email || req.ip}`),
//   handler: async (req, res) => {
//     await auditService.log(null, 'PASSWORD_RESET_RATE_LIMIT_EXCEEDED', 'security', null, {
//       email: req.body.email,
//       ip: req.ip,
//       attempts: 3
//     }, req);

//     return ResponseBuilder(res, 'Too many password reset attempts, please try again in 1 hour', 429, {
//       retryAfter: 3600
//     });
//   }
// });

// /**
//  * Registration rate limiter
//  */
// export const registrationRateLimit = rateLimit({
//   store: createRedisStore('register'),
//   windowMs: 60 * 60 * 1000, // 1 hour
//   max: 3, // 3 registrations per IP per hour
//   keyGenerator: createKeyGenerator((req) => `register:${req.ip}`),
//   handler: async (req, res) => {
//     await auditService.log(null, 'REGISTRATION_RATE_LIMIT_EXCEEDED', 'security', null, {
//       ip: req.ip,
//       email: req.body.email,
//       attempts: 3
//     }, req);

//     return ResponseBuilder(res, 'Too many registration attempts, please try again later', 429, {
//       retryAfter: 3600
//     });
//   }
// });

// /**
//  * File upload rate limiter
//  */
// export const uploadRateLimit = rateLimit({
//   store: createRedisStore('upload'),
//   windowMs: 60 * 60 * 1000, // 1 hour
//   max: 20, // 20 uploads per hour per user
//   keyGenerator: createKeyGenerator((req) => `upload:${req.user?.id || req.ip}`),
//   handler: async (req, res) => {
//     await auditService.log(req.user?.id || null, 'UPLOAD_RATE_LIMIT_EXCEEDED', 'security', null, {
//       ip: req.ip,
//       attempts: 20
//     }, req);

//     return ResponseBuilder(res, 'Too many file uploads, please try again later', 429, {
//       retryAfter: 3600
//     });
//   }
// });

// /**
//  * Email sending rate limiter
//  */
// export const emailRateLimit = rateLimit({
//   store: createRedisStore('email'),
//   windowMs: 60 * 60 * 1000, // 1 hour
//   max: 10, // 10 emails per hour per user
//   keyGenerator: createKeyGenerator((req) => `email:${req.user?.id || req.ip}`),
//   handler: async (req, res) => {
//     await auditService.log(req.user?.id || null, 'EMAIL_RATE_LIMIT_EXCEEDED', 'security', null, {
//       ip: req.ip,
//       attempts: 10
//     }, req);

//     return ResponseBuilder(res, 'Too many emails sent, please try again later', 429, {
//       retryAfter: 3600
//     });
//   }
// });

// /**
//  * Admin actions rate limiter
//  */
// export const adminRateLimit = rateLimit({
//   store: createRedisStore('admin'),
//   windowMs: 5 * 60 * 1000, // 5 minutes
//   max: 50, // 50 admin actions per 5 minutes
//   keyGenerator: createKeyGenerator((req) => `admin:${req.user?.id}`),
//   handler: async (req, res) => {
//     await auditService.log(req.user?.id || null, 'ADMIN_RATE_LIMIT_EXCEEDED', 'security', null, {
//       ip: req.ip,
//       endpoint: req.originalUrl,
//       attempts: 50
//     }, req);

//     return ResponseBuilder(res, 'Too many admin actions, please slow down', 429, {
//       retryAfter: 300
//     });
//   }
// });

// /**
//  * API key rate limiter for external integrations
//  */
// export const apiKeyRateLimit = rateLimit({
//   store: createRedisStore('api_key'),
//   windowMs: 60 * 60 * 1000, // 1 hour
//   max: 1000, // 1000 requests per hour per API key
//   keyGenerator: (req) => {
//     const apiKey = req.headers['x-api-key'];
//     return `api_key:${apiKey}`;
//   },
//   skip: (req) => !req.headers['x-api-key'],
//   handler: async (req, res) => {
//     await auditService.log(null, 'API_KEY_RATE_LIMIT_EXCEEDED', 'security', null, {
//       apiKey: req.headers['x-api-key'],
//       ip: req.ip,
//       endpoint: req.originalUrl
//     }, req);

//     return ResponseBuilder(res, 'API key rate limit exceeded', 429, {
//       retryAfter: 3600
//     });
//   }
// });

// /**
//  * Dynamic rate limiter based on user subscription
//  */
// export const subscriptionBasedRateLimit = async (req, res, next) => {
//   try {
//     if (!req.user) {
//       return generalRateLimit(req, res, next);
//     }

//     // Get user's subscription tier
//     const subscription = await getUserSubscription(req.user.id);
//     const tier = subscription?.plan_type || 'free';

//     // Define limits based on subscription tier
//     const tierLimits = {
//       free: { windowMs: 60 * 60 * 1000, max: 50 },
//       pay_as_you_go: { windowMs: 60 * 60 * 1000, max: 200 },
//       monthly: { windowMs: 60 * 60 * 1000, max: 500 },
//       '3_month': { windowMs: 60 * 60 * 1000, max: 750 },
//       '6_month': { windowMs: 60 * 60 * 1000, max: 1000 },
//       yearly: { windowMs: 60 * 60 * 1000, max: 1500 }
//     };

//     const limits = tierLimits[tier] || tierLimits.free;

//     const dynamicLimiter = rateLimit({
//       store: createRedisStore(`sub_${tier}`),
//       windowMs: limits.windowMs,
//       max: limits.max,
//       keyGenerator: createKeyGenerator((req) => `sub:${tier}:${req.user.id}`),
//       handler: async (req, res) => {
//         await auditService.log(req.user.id, 'SUBSCRIPTION_RATE_LIMIT_EXCEEDED', 'security', null, {
//           tier,
//           limit: limits.max,
//           window: limits.windowMs,
//           ip: req.ip
//         }, req);

//         return ResponseBuilder(res, 'Subscription rate limit exceeded. Consider upgrading your plan.', 429, {
//           retryAfter: Math.floor(limits.windowMs / 1000),
//           upgradeRequired: tier === 'free'
//         });
//       }
//     });

//     return dynamicLimiter(req, res, next);

//   } catch (error) {
//     console.error('Subscription rate limit error:', error);
//     // Fallback to general rate limit
//     return generalRateLimit(req, res, next);
//   }
// };

// /**
//  * Burst rate limiter for high-frequency actions
//  */
// export const burstRateLimit = rateLimit({
//   store: createRedisStore('burst'),
//   windowMs: 60 * 1000, // 1 minute
//   max: 10, // 10 requests per minute
//   keyGenerator: createKeyGenerator((req) => `burst:${req.user?.id || req.ip}`),
//   handler: async (req, res) => {
//     await auditService.log(req.user?.id || null, 'BURST_RATE_LIMIT_EXCEEDED', 'security', null, {
//       ip: req.ip,
//       endpoint: req.originalUrl
//     }, req);

//     return ResponseBuilder(res, 'Too many rapid requests, please slow down', 429, {
//       retryAfter: 60
//     });
//   }
// });

// /**
//  * Check if IP is in blocked list
//  */
// export const checkBlockedIP = async (req, res, next) => {
//   try {
//     const isBlocked = await redisClient.sismember('blocked_ips', req.ip);
    
//     if (isBlocked) {
//       await auditService.log(null, 'BLOCKED_IP_ACCESS_ATTEMPT', 'security', null, {
//         ip: req.ip,
//         endpoint: req.originalUrl,
//         userAgent: req.headers['user-agent']
//       }, req);

//       return ResponseBuilder(res, 'Access denied from this IP address', 403, {
//         blocked: true,
//         contactSupport: true
//       });
//     }

//     next();

//   } catch (error) {
//     console.error('IP block check error:', error);
//     next(); // Don't block on error
//   }
// };

// /**
//  * Custom rate limiter factory
//  * @param {object} options - Rate limiting options
//  */
// export const createCustomRateLimit = (options = {}) => {
//   const {
//     windowMs = 15 * 60 * 1000,
//     max = 100,
//     keyGenerator = (req) => req.user?.id || req.ip,
//     message = 'Too many requests',
//     logAction = 'CUSTOM_RATE_LIMIT_EXCEEDED',
//     prefix = 'custom'
//   } = options;

//   return rateLimit({
//     store: createRedisStore(prefix),
//     windowMs,
//     max,
//     keyGenerator: createKeyGenerator((req) => `custom:${keyGenerator(req)}`),
//     handler: async (req, res) => {
//       await auditService.log(req.user?.id || null, logAction, 'security', null, {
//         ip: req.ip,
//         endpoint: req.originalUrl,
//         limit: max,
//         window: windowMs
//       }, req);

//       return ResponseBuilder(res, message, 429, {
//         retryAfter: Math.floor(windowMs / 1000)
//       });
//     }
//   });
// };

// // Helper Functions

// /**
//  * Get user's subscription information
//  */
// async function getUserSubscription(userId) {
//   try {
//     // This would integrate with your subscription service
//     // Placeholder for now - will be implemented in Milestone 3
//     return null;
//   } catch (error) {
//     console.error('Get subscription error:', error);
//     return null;
//   }
// }

// /**
//  * Reset rate limit violations for a user/IP
//  */
// export const resetRateLimitViolations = async (identifier) => {
//   try {
//     const violationKey = `violations:${identifier}`;
//     await redisClient.del(violationKey);
//     return true;
//   } catch (error) {
//     console.error('Reset violations error:', error);
//     return false;
//   }
// };

// // Export rateLimiting object to match the import pattern in routes
// export const rateLimiting = {
//   standard: standardRateLimit,
//   strict: strictRateLimit,
//   general: generalRateLimit,
//   auth: authRateLimit,
//   passwordReset: passwordResetRateLimit,
//   registration: registrationRateLimit,
//   upload: uploadRateLimit,
//   email: emailRateLimit,
//   admin: adminRateLimit,
//   apiKey: apiKeyRateLimit,
//   subscriptionBased: subscriptionBasedRateLimit,
//   burst: burstRateLimit,
//   createCustom: createCustomRateLimit,
//   checkBlockedIP,
//   resetViolations: resetRateLimitViolations
// };

// // Also export individual functions for flexibility
// export default rateLimiting;