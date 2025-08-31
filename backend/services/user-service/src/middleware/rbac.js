import VotteryUser from '../models/index.js';
import { ResponseBuilder } from '../utils/response.js';
import auditService from '../services/auditService.js';
import redisClient from '../config/redis.js';

/**
 * Role-Based Access Control (RBAC) Middleware
 * Milestone 1: Role-based access control middleware with comprehensive role system
 * 
 * Role System:
 * Admin Roles: Manager, Admin, Moderator, Auditor, Editor, Advertiser, Analyst
 * User Types: Individual Election Creators, Organization Election Creators, Voters
 * Subscription Status: Free Users (limited), Subscribed Users (unlimited)
 */

// Define role hierarchy and permissions
const ROLE_HIERARCHY = {
  // Admin roles (highest to lowest privilege)
  'manager': 100,
  'admin': 90,
  'moderator': 80,
  'auditor': 70,
  'editor': 60,
  'advertiser': 50,
  'analyst': 40,
  
  // User types
  'organization_creator': 30,
  'individual_creator': 20,
  'voter': 10
};

const PERMISSIONS = {
  // User management permissions
  'users:view': ['manager', 'admin', 'moderator', 'auditor'],
  'users:edit': ['manager', 'admin', 'moderator'],
  'users:suspend': ['manager', 'admin', 'moderator'],
  'users:delete': ['manager', 'admin'],
  'users:create': ['manager', 'admin'],
  
  // Election management permissions
  'elections:view': ['manager', 'admin', 'moderator', 'auditor', 'analyst'],
  'elections:create': ['manager', 'admin', 'moderator', 'editor', 'organization_creator', 'individual_creator'],
  'elections:edit': ['manager', 'admin', 'moderator', 'editor'],
  'elections:delete': ['manager', 'admin'],
  'elections:moderate': ['manager', 'admin', 'moderator'],
  'elections:audit': ['manager', 'admin', 'auditor'],
  
  // Voting permissions
  'voting:participate': ['manager', 'admin', 'moderator', 'auditor', 'editor', 'advertiser', 'analyst', 'organization_creator', 'individual_creator', 'voter'],
  'voting:verify': ['manager', 'admin', 'auditor'],
  'voting:audit': ['manager', 'admin', 'auditor'],
  
  // Analytics permissions
  'analytics:view': ['manager', 'admin', 'analyst', 'auditor'],
  'analytics:export': ['manager', 'admin', 'analyst'],
  'analytics:advanced': ['manager', 'admin'],
  
  // Content management
  'content:create': ['manager', 'admin', 'editor'],
  'content:edit': ['manager', 'admin', 'editor'],
  'content:delete': ['manager', 'admin'],
  'content:moderate': ['manager', 'admin', 'moderator'],
  
  // Advertising permissions
  'ads:create': ['manager', 'admin', 'advertiser'],
  'ads:edit': ['manager', 'admin', 'advertiser'],
  'ads:view': ['manager', 'admin', 'advertiser', 'analyst'],
  
  // Financial permissions
  'finance:view': ['manager', 'admin'],
  'finance:manage': ['manager'],
  'subscriptions:manage': ['manager', 'admin'],
  
  // System permissions
  'system:configure': ['manager'],
  'system:monitor': ['manager', 'admin'],
  'audit:view': ['manager', 'admin', 'auditor'],
  'audit:export': ['manager', 'admin']
};

/**
 * Check if user has specific permission
 */
export const hasPermission = (userRole, permission) => {
  const allowedRoles = PERMISSIONS[permission];
  return allowedRoles && allowedRoles.includes(userRole);
};

/**
 * Check if user has sufficient role level
 */
export const hasRoleLevel = (userRole, requiredRole) => {
  const userLevel = ROLE_HIERARCHY[userRole] || 0;
  const requiredLevel = ROLE_HIERARCHY[requiredRole] || 0;
  return userLevel >= requiredLevel;
};

/**
 * Get user's effective permissions
 */
export const getUserPermissions = async (userId) => {
  try {
    // Check cache first
    const cached = await redisClient.get(`user_permissions:${userId}`);
    if (cached) {
      return JSON.parse(cached);
    }

    // Get user from database with role information
    const user = await VotteryUser.findByPk(userId, {
      attributes: ['id', 'role', 'user_type', 'subscription_status', 'status']
    });

    if (!user) {
      return [];
    }

    // Get all permissions for user's role
    const userPermissions = [];
    const userRole = user.role || user.user_type || 'voter';

    for (const [permission, allowedRoles] of Object.entries(PERMISSIONS)) {
      if (allowedRoles.includes(userRole)) {
        userPermissions.push(permission);
      }
    }

    // Cache permissions for 15 minutes
    await redisClient.setex(`user_permissions:${userId}`, 900, JSON.stringify(userPermissions));

    return userPermissions;

  } catch (error) {
    console.error('Get user permissions error:', error);
    return [];
  }
};

/**
 * Require specific permission middleware
 */
export const requirePermission = (permission) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return ResponseBuilder(res, 'Authentication required', 401);
      }

      const userRole = req.user.role || req.user.user_type || 'voter';
      
      if (!hasPermission(userRole, permission)) {
        // Log unauthorized access attempt
        await auditService.log(req.user.id, 'UNAUTHORIZED_ACCESS_ATTEMPT', 'security', null, {
          permission,
          userRole,
          endpoint: req.originalUrl,
          ip: req.ip
        }, req);

        return ResponseBuilder(res, 'Insufficient permissions', 403, {
          required_permission: permission,
          user_role: userRole
        });
      }

      // Log successful permission check
      await auditService.log(req.user.id, 'PERMISSION_CHECK_SUCCESS', 'access', null, {
        permission,
        userRole,
        endpoint: req.originalUrl
      }, req);

      next();

    } catch (error) {
      console.error('Permission check error:', error);
      return ResponseBuilder(res, 'Permission check failed', 500);
    }
  };
};

/**
 * Require specific role or higher middleware
 */
export const requireRole = (requiredRole) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return ResponseBuilder(res, 'Authentication required', 401);
      }

      const userRole = req.user.role || req.user.user_type || 'voter';
      
      if (!hasRoleLevel(userRole, requiredRole)) {
        await auditService.log(req.user.id, 'INSUFFICIENT_ROLE_ACCESS', 'security', null, {
          requiredRole,
          userRole,
          endpoint: req.originalUrl,
          ip: req.ip
        }, req);

        return ResponseBuilder(res, 'Insufficient role level', 403, {
          required_role: requiredRole,
          user_role: userRole
        });
      }

      next();

    } catch (error) {
      console.error('Role check error:', error);
      return ResponseBuilder(res, 'Role check failed', 500);
    }
  };
};

/**
 * Check if user is admin (any admin role)
 */
export const requireAdmin = async (req, res, next) => {
  try {
    if (!req.user) {
      return ResponseBuilder(res, 'Authentication required', 401);
    }

    const userRole = req.user.role || req.user.user_type || 'voter';
    const adminRoles = ['manager', 'admin', 'moderator', 'auditor', 'editor', 'advertiser', 'analyst'];
    
    if (!adminRoles.includes(userRole)) {
      await auditService.log(req.user.id, 'NON_ADMIN_ACCESS_ATTEMPT', 'security', null, {
        userRole,
        endpoint: req.originalUrl,
        ip: req.ip
      }, req);

      return ResponseBuilder(res, 'Admin access required', 403, {
        user_role: userRole
      });
    }

    next();

  } catch (error) {
    console.error('Admin check error:', error);
    return ResponseBuilder(res, 'Admin check failed', 500);
  }
};

/**
 * Check subscription status for premium features
 */
export const requireSubscription = (requiredTier = 'basic') => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return ResponseBuilder(res, 'Authentication required', 401);
      }

      const subscriptionStatus = req.user.subscription_status || 'free';
      
      // Define subscription hierarchy
      const subscriptionHierarchy = {
        'free': 0,
        'pay_as_you_go': 10,
        'monthly': 20,
        '3_month': 30,
        '6_month': 40,
        'yearly': 50
      };

      const userLevel = subscriptionHierarchy[subscriptionStatus] || 0;
      const requiredLevel = subscriptionHierarchy[requiredTier] || 0;

      if (userLevel < requiredLevel) {
        await auditService.log(req.user.id, 'SUBSCRIPTION_UPGRADE_REQUIRED', 'access', null, {
          currentTier: subscriptionStatus,
          requiredTier,
          endpoint: req.originalUrl
        }, req);

        return ResponseBuilder(res, 'Subscription upgrade required', 402, {
          current_subscription: subscriptionStatus,
          required_subscription: requiredTier,
          upgrade_url: '/subscription/upgrade'
        });
      }

      next();

    } catch (error) {
      console.error('Subscription check error:', error);
      return ResponseBuilder(res, 'Subscription check failed', 500);
    }
  };
};

/**
 * Check if user owns resource or has admin privileges
 */
export const requireOwnershipOrAdmin = (resourceIdParam = 'id', resourceType = 'resource') => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return ResponseBuilder(res, 'Authentication required', 401);
      }

      const resourceId = req.params[resourceIdParam];
      const userRole = req.user.role || req.user.user_type || 'voter';
      const adminRoles = ['manager', 'admin', 'moderator'];

      // Admins can access any resource
      if (adminRoles.includes(userRole)) {
        return next();
      }

      // Check if user owns the resource
      const isOwner = await checkResourceOwnership(req.user.id, resourceId, resourceType);
      
      if (!isOwner) {
        await auditService.log(req.user.id, 'UNAUTHORIZED_RESOURCE_ACCESS', 'security', null, {
          resourceId,
          resourceType,
          endpoint: req.originalUrl,
          ip: req.ip
        }, req);

        return ResponseBuilder(res, 'Access denied - resource not owned', 403, {
          resource_type: resourceType,
          resource_id: resourceId
        });
      }

      next();

    } catch (error) {
      console.error('Ownership check error:', error);
      return ResponseBuilder(res, 'Ownership check failed', 500);
    }
  };
};

/**
 * Rate limit based on user role
 */
export const roleBasedRateLimit = async (req, res, next) => {
  try {
    if (!req.user) {
      return next();
    }

    const userRole = req.user.role || req.user.user_type || 'voter';
    const subscriptionStatus = req.user.subscription_status || 'free';
    
    // Define role-based limits
    const roleLimits = {
      'manager': { requests: 1000, window: 3600 },
      'admin': { requests: 800, window: 3600 },
      'moderator': { requests: 600, window: 3600 },
      'auditor': { requests: 400, window: 3600 },
      'editor': { requests: 300, window: 3600 },
      'advertiser': { requests: 300, window: 3600 },
      'analyst': { requests: 300, window: 3600 },
      'organization_creator': subscriptionStatus === 'free' ? { requests: 100, window: 3600 } : { requests: 500, window: 3600 },
      'individual_creator': subscriptionStatus === 'free' ? { requests: 50, window: 3600 } : { requests: 200, window: 3600 },
      'voter': subscriptionStatus === 'free' ? { requests: 20, window: 3600 } : { requests: 100, window: 3600 }
    };

    const limits = roleLimits[userRole] || roleLimits['voter'];
    
    // Store limit info for other middleware to use
    req.roleBasedLimits = limits;
    
    next();

  } catch (error) {
    console.error('Role-based rate limit error:', error);
    next();
  }
};

/**
 * Check resource ownership
 */
async function checkResourceOwnership(userId, resourceId, resourceType) {
  try {
    // This would be implemented based on your database schema
    // For now, return true as placeholder
    // In real implementation:
    // - Check elections table for election ownership
    // - Check user_resources table for generic resource ownership
    // - etc.
    
    return true; // Placeholder
    
  } catch (error) {
    console.error('Resource ownership check error:', error);
    return false;
  }
}

/**
 * Clear user permissions cache
 */
export const clearUserPermissionsCache = async (userId) => {
  try {
    await redisClient.del(`user_permissions:${userId}`);
    return true;
  } catch (error) {
    console.error('Clear permissions cache error:', error);
    return false;
  }
};

/**
 * Audit permission changes
 */
export const auditPermissionChange = async (adminUserId, targetUserId, oldRole, newRole, req) => {
  try {
    await auditService.log(adminUserId, 'ROLE_CHANGE', 'admin', targetUserId, {
      oldRole,
      newRole,
      timestamp: new Date().toISOString()
    }, req);

    // Clear target user's permissions cache
    await clearUserPermissionsCache(targetUserId);

  } catch (error) {
    console.error('Audit permission change error:', error);
  }
};

// Export rbac object to match the import pattern in routes
export const rbac = {
  requirePermission,
  requireRole,
  requireAdmin,
  requireSubscription,
  requireOwnershipOrAdmin,
  roleBasedRateLimit,
  hasPermission,
  hasRoleLevel,
  getUserPermissions,
  clearUserPermissionsCache,
  auditPermissionChange
};

export default rbac;
// import jwt from 'jsonwebtoken';
// import  VotteryUser  from '../models/index.js';
// import  errorResponse  from '../utils/response.js';
// import  auditService  from '../services/auditService.js';
// import redisClient  from '../config/redis.js';

// /**
//  * Authentication Middleware
//  * Handles JWT token validation, session management, and user authentication
//  */

// /**
//  * Verify JWT token and authenticate user
//  */
// export const authenticate = async (req, res, next) => {
//   try {
//     const token = extractToken(req);
    
//     if (!token) {
//       return errorResponse(res, 'Access token is required', 401);
//     }

//     // Verify JWT token
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
//     // Check if token is blacklisted
//     const isBlacklisted = await redisClient.get(`blacklist:${token}`);
//     if (isBlacklisted) {
//       return errorResponse(res, 'Token has been revoked', 401);
//     }

//     // Get user from database
//     const user = await VotteryUser.findByPk(decoded.userId, {
//       attributes: ['id', 'email', 'username', 'status', 'last_login', 'created_at']
//     });

//     if (!user) {
//       return errorResponse(res, 'User not found', 401);
//     }

//     if (user.status !== 'active') {
//       return errorResponse(res, 'Account is not active', 401);
//     }

//     // Check token expiration
//     if (decoded.exp < Date.now() / 1000) {
//       return errorResponse(res, 'Token has expired', 401);
//     }

//     // Attach user to request
//     req.user = user;
//     req.token = token;
//     req.tokenPayload = decoded;

//     next();

//   } catch (error) {
//     if (error.name === 'JsonWebTokenError') {
//       return errorResponse(res, 'Invalid token', 401);
//     }
//     if (error.name === 'TokenExpiredError') {
//       return errorResponse(res, 'Token has expired', 401);
//     }
    
//     console.error('Authentication error:', error);
//     return errorResponse(res, 'Authentication failed', 401);
//   }
// };

// /**
//  * Optional authentication - doesn't fail if no token provided
//  */
// export const optionalAuth = async (req, res, next) => {
//   try {
//     const token = extractToken(req);
    
//     if (!token) {
//       req.user = null;
//       return next();
//     }

//     // Try to authenticate but don't fail if it doesn't work
//     await new Promise((resolve) => {
//       authenticate(req, res, (err) => {
//         if (err) {
//           req.user = null;
//         }
//         resolve();
//       });
//     });

//     next();

//   } catch (error) {
//     req.user = null;
//     next();
//   }
// };

// /**
//  * Refresh token middleware
//  */
// export const refreshToken = async (req, res, next) => {
//   try {
//     const refreshToken = req.body.refresh_token || req.headers['x-refresh-token'];
    
//     if (!refreshToken) {
//       return errorResponse(res, 'Refresh token is required', 400);
//     }

//     // Verify refresh token
//     const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
//     // Check if refresh token exists in database/redis
//     const storedToken = await redisClient.get(`refresh:${decoded.userId}`);
//     if (!storedToken || storedToken !== refreshToken) {
//       return errorResponse(res, 'Invalid refresh token', 401);
//     }

//     // Get user
//     const user = await VotteryUser.findByPk(decoded.userId);
//     if (!user || user.status !== 'active') {
//       return errorResponse(res, 'User not found or inactive', 401);
//     }

//     // Generate new access token
//     const newAccessToken = jwt.sign(
//       { 
//         userId: user.id, 
//         email: user.email,
//         type: 'access'
//       },
//       process.env.JWT_SECRET,
//       { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
//     );

//     // Generate new refresh token
//     const newRefreshToken = jwt.sign(
//       { 
//         userId: user.id, 
//         type: 'refresh'
//       },
//       process.env.JWT_REFRESH_SECRET,
//       { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
//     );

//     // Store new refresh token
//     await redisClient.setex(
//       `refresh:${user.id}`, 
//       7 * 24 * 60 * 60, // 7 days
//       newRefreshToken
//     );

//     // Blacklist old refresh token
//     await redisClient.setex(
//       `blacklist:${refreshToken}`, 
//       7 * 24 * 60 * 60,
//       'revoked'
//     );

//     req.newTokens = {
//       access_token: newAccessToken,
//       refresh_token: newRefreshToken
//     };
//     req.user = user;

//     next();

//   } catch (error) {
//     if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
//       return errorResponse(res, 'Invalid or expired refresh token', 401);
//     }
    
//     console.error('Refresh token error:', error);
//     return errorResponse(res, 'Token refresh failed', 500);
//   }
// };

// /**
//  * Validate session middleware
//  */
// export const validateSession = async (req, res, next) => {
//   try {
//     if (!req.user) {
//       return errorResponse(res, 'User not authenticated', 401);
//     }

//     const sessionKey = `session:${req.user.id}`;
//     const session = await redisClient.get(sessionKey);
    
//     if (!session) {
//       return errorResponse(res, 'Session has expired', 401);
//     }

//     const sessionData = JSON.parse(session);
    
//     // Check if session is still valid
//     if (sessionData.expiresAt < Date.now()) {
//       await redisClient.del(sessionKey);
//       return errorResponse(res, 'Session has expired', 401);
//     }

//     // Update session activity
//     sessionData.lastActivity = Date.now();
//     await redisClient.setex(sessionKey, 24 * 60 * 60, JSON.stringify(sessionData)); // 24 hours

//     req.session = sessionData;
//     next();

//   } catch (error) {
//     console.error('Session validation error:', error);
//     return errorResponse(res, 'Session validation failed', 500);
//   }
// };

// /**
//  * Check if user account is verified
//  */
// export const requireVerified = async (req, res, next) => {
//   try {
//     if (!req.user) {
//       return errorResponse(res, 'User not authenticated', 401);
//     }

//     // Check if user is verified (assuming you have email_verified field)
//     if (!req.user.email_verified) {
//       return errorResponse(res, 'Email verification required', 403);
//     }

//     next();

//   } catch (error) {
//     console.error('Verification check error:', error);
//     return errorResponse(res, 'Verification check failed', 500);
//   }
// };

// /**
//  * Biometric authentication validation
//  */
// export const validateBiometric = async (req, res, next) => {
//   try {
//     const { biometric_data, device_id } = req.body;
    
//     if (!biometric_data || !device_id) {
//       return errorResponse(res, 'Biometric data and device ID required', 400);
//     }

//     // Call biometric service for validation
//     const response = await fetch(`${process.env.BIOMETRIC_SERVICE_URL}/validate`, {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//         'Authorization': `Bearer ${process.env.SERVICE_TOKEN}`
//       },
//       body: JSON.stringify({
//         user_id: req.user.id,
//         biometric_data,
//         device_id
//       })
//     });

//     if (!response.ok) {
//       return errorResponse(res, 'Biometric validation failed', 401);
//     }

//     const result = await response.json();
    
//     if (!result.valid) {
//       await auditService.log(req.user.id, 'BIOMETRIC_AUTH_FAILED', 'auth', null, {
//         device_id,
//         reason: result.reason
//       }, req);
      
//       return errorResponse(res, 'Biometric authentication failed', 401);
//     }

//     req.biometricVerified = true;
//     next();

//   } catch (error) {
//     console.error('Biometric validation error:', error);
//     return errorResponse(res, 'Biometric validation error', 500);
//   }
// };

// /**
//  * Multi-factor authentication check
//  */
// export const requireMFA = async (req, res, next) => {
//   try {
//     if (!req.user) {
//       return errorResponse(res, 'User not authenticated', 401);
//     }

//     // Check if MFA is enabled for user
//     const mfaEnabled = req.user.mfa_enabled;
//     if (!mfaEnabled) {
//       return next(); // MFA not required
//     }

//     const mfaToken = req.headers['x-mfa-token'];
//     if (!mfaToken) {
//       return errorResponse(res, 'MFA token required', 403);
//     }

//     // Verify MFA token (TOTP)
//     const isValidMFA = await verifyMFAToken(req.user.id, mfaToken);
//     if (!isValidMFA) {
//       return errorResponse(res, 'Invalid MFA token', 403);
//     }

//     req.mfaVerified = true;
//     next();

//   } catch (error) {
//     console.error('MFA validation error:', error);
//     return errorResponse(res, 'MFA validation failed', 500);
//   }
// };

// /**
//  * Device trust validation
//  */
// export const validateTrustedDevice = async (req, res, next) => {
//   try {
//     const deviceFingerprint = req.headers['x-device-fingerprint'];
    
//     if (!deviceFingerprint) {
//       return errorResponse(res, 'Device fingerprint required', 400);
//     }

//     const trustedDevices = await redisClient.smembers(`trusted_devices:${req.user.id}`);
    
//     if (!trustedDevices.includes(deviceFingerprint)) {
//       // Log suspicious device access
//       await auditService.log(req.user.id, 'UNTRUSTED_DEVICE_ACCESS', 'security', null, {
//         deviceFingerprint,
//         userAgent: req.headers['user-agent'],
//         ip: req.ip
//       }, req);
      
//       return errorResponse(res, 'Device not trusted', 403);
//     }

//     next();

//   } catch (error) {
//     console.error('Device validation error:', error);
//     return errorResponse(res, 'Device validation failed', 500);
//   }
// };

// /**
//  * Extract token from request headers
//  */
// const extractToken = (req) => {
//   const authHeader = req.headers.authorization;
  
//   if (authHeader && authHeader.startsWith('Bearer ')) {
//     return authHeader.substring(7);
//   }
  
//   // Check for token in cookies
//   if (req.cookies && req.cookies.access_token) {
//     return req.cookies.access_token;
//   }
  
//   // Check for token in query parameter (less secure, for specific cases)
//   if (req.query.token) {
//     return req.query.token;
//   }
  
//   return null;
// };

// /**
//  * Verify MFA TOTP token
//  */
// const verifyMFAToken = async (userId, token) => {
//   try {
//     // Implementation would depend on your MFA library (e.g., speakeasy)
//     // This is a placeholder for the actual MFA verification logic
//     const userMFASecret = await redisClient.get(`mfa_secret:${userId}`);
    
//     if (!userMFASecret) {
//       return false;
//     }
    
//     // Verify TOTP token using your preferred library
//     // Example with speakeasy:
//     // const verified = speakeasy.totp.verify({
//     //   secret: userMFASecret,
//     //   encoding: 'base32',
//     //   token: token,
//     //   window: 1
//     // });
    
//     return true; // Placeholder
    
//   } catch (error) {
//     console.error('MFA verification error:', error);
//     return false;
//   }
// };