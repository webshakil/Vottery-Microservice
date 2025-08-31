import jwt from 'jsonwebtoken';
import VotteryUser from '../models/index.js';
import errorResponse from '../utils/response.js';
import auditService from '../services/auditService.js';
import redisClient from '../config/redis.js';

/**
 * Authentication Middleware
 * Handles JWT token validation, session management, and user authentication
 * Milestone 1: Core Authentication & User Management Microservices
 */

/**
 * Verify JWT token and authenticate user
 */
export const authenticate = async (req, res, next) => {
  try {
    const token = extractToken(req);
    
    if (!token) {
      return errorResponse(res, 'Access token is required', 401);
    }

    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if token is blacklisted
    const isBlacklisted = await redisClient.get(`blacklist:${token}`);
    if (isBlacklisted) {
      return errorResponse(res, 'Token has been revoked', 401);
    }

    // Get user from database
    const user = await VotteryUser.findByPk(decoded.userId, {
      attributes: ['id', 'email', 'username', 'status', 'last_login', 'created_at', 'email_verified', 'mfa_enabled']
    });

    if (!user) {
      return errorResponse(res, 'User not found', 401);
    }

    if (user.status !== 'active') {
      return errorResponse(res, 'Account is not active', 401);
    }

    // Check token expiration
    if (decoded.exp < Date.now() / 1000) {
      return errorResponse(res, 'Token has expired', 401);
    }

    // Attach user to request
    req.user = user;
    req.token = token;
    req.tokenPayload = decoded;

    next();

  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return errorResponse(res, 'Invalid token', 401);
    }
    if (error.name === 'TokenExpiredError') {
      return errorResponse(res, 'Token has expired', 401);
    }
    
    console.error('Authentication error:', error);
    return errorResponse(res, 'Authentication failed', 401);
  }
};

/**
 * Optional authentication - doesn't fail if no token provided
 */
export const optionalAuth = async (req, res, next) => {
  try {
    const token = extractToken(req);
    
    if (!token) {
      req.user = null;
      return next();
    }

    // Try to authenticate but don't fail if it doesn't work
    await new Promise((resolve) => {
      authenticate(req, res, (err) => {
        if (err) {
          req.user = null;
        }
        resolve();
      });
    });

    next();

  } catch (error) {
    req.user = null;
    next();
  }
};

/**
 * Refresh token middleware
 */
export const refreshToken = async (req, res, next) => {
  try {
    const refreshToken = req.body.refresh_token || req.headers['x-refresh-token'];
    
    if (!refreshToken) {
      return errorResponse(res, 'Refresh token is required', 400);
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // Check if refresh token exists in database/redis
    const storedToken = await redisClient.get(`refresh:${decoded.userId}`);
    if (!storedToken || storedToken !== refreshToken) {
      return errorResponse(res, 'Invalid refresh token', 401);
    }

    // Get user
    const user = await VotteryUser.findByPk(decoded.userId);
    if (!user || user.status !== 'active') {
      return errorResponse(res, 'User not found or inactive', 401);
    }

    // Generate new access token
    const newAccessToken = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        type: 'access'
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );

    // Generate new refresh token
    const newRefreshToken = jwt.sign(
      { 
        userId: user.id, 
        type: 'refresh'
      },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
    );

    // Store new refresh token
    await redisClient.setex(
      `refresh:${user.id}`, 
      7 * 24 * 60 * 60, // 7 days
      newRefreshToken
    );

    // Blacklist old refresh token
    await redisClient.setex(
      `blacklist:${refreshToken}`, 
      7 * 24 * 60 * 60,
      'revoked'
    );

    req.newTokens = {
      access_token: newAccessToken,
      refresh_token: newRefreshToken
    };
    req.user = user;

    next();

  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return errorResponse(res, 'Invalid or expired refresh token', 401);
    }
    
    console.error('Refresh token error:', error);
    return errorResponse(res, 'Token refresh failed', 500);
  }
};

/**
 * Validate session middleware
 */
export const validateSession = async (req, res, next) => {
  try {
    if (!req.user) {
      return errorResponse(res, 'User not authenticated', 401);
    }

    const sessionKey = `session:${req.user.id}`;
    const session = await redisClient.get(sessionKey);
    
    if (!session) {
      return errorResponse(res, 'Session has expired', 401);
    }

    const sessionData = JSON.parse(session);
    
    // Check if session is still valid
    if (sessionData.expiresAt < Date.now()) {
      await redisClient.del(sessionKey);
      return errorResponse(res, 'Session has expired', 401);
    }

    // Update session activity
    sessionData.lastActivity = Date.now();
    await redisClient.setex(sessionKey, 24 * 60 * 60, JSON.stringify(sessionData)); // 24 hours

    req.session = sessionData;
    next();

  } catch (error) {
    console.error('Session validation error:', error);
    return errorResponse(res, 'Session validation failed', 500);
  }
};

/**
 * Check if user account is verified
 */
export const requireVerified = async (req, res, next) => {
  try {
    if (!req.user) {
      return errorResponse(res, 'User not authenticated', 401);
    }

    // Check if user is verified (assuming you have email_verified field)
    if (!req.user.email_verified) {
      return errorResponse(res, 'Email verification required', 403);
    }

    next();

  } catch (error) {
    console.error('Verification check error:', error);
    return errorResponse(res, 'Verification check failed', 500);
  }
};

/**
 * Biometric authentication validation
 * Milestone 1: Biometric Authentication API Infrastructure
 */
export const validateBiometric = async (req, res, next) => {
  try {
    const { biometric_data, device_id } = req.body;
    
    if (!biometric_data || !device_id) {
      return errorResponse(res, 'Biometric data and device ID required', 400);
    }

    // Call biometric service for validation
    const response = await fetch(`${process.env.BIOMETRIC_SERVICE_URL}/validate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.SERVICE_TOKEN}`
      },
      body: JSON.stringify({
        user_id: req.user.id,
        biometric_data,
        device_id
      })
    });

    if (!response.ok) {
      return errorResponse(res, 'Biometric validation failed', 401);
    }

    const result = await response.json();
    
    if (!result.valid) {
      await auditService.log(req.user.id, 'BIOMETRIC_AUTH_FAILED', 'auth', null, {
        device_id,
        reason: result.reason
      }, req);
      
      return errorResponse(res, 'Biometric authentication failed', 401);
    }

    req.biometricVerified = true;
    next();

  } catch (error) {
    console.error('Biometric validation error:', error);
    return errorResponse(res, 'Biometric validation error', 500);
  }
};

/**
 * Multi-factor authentication check
 * Milestone 1: 2FA/OTP Implementation
 */
export const requireMFA = async (req, res, next) => {
  try {
    if (!req.user) {
      return errorResponse(res, 'User not authenticated', 401);
    }

    // Check if MFA is enabled for user
    const mfaEnabled = req.user.mfa_enabled;
    if (!mfaEnabled) {
      return next(); // MFA not required
    }

    const mfaToken = req.headers['x-mfa-token'];
    if (!mfaToken) {
      return errorResponse(res, 'MFA token required', 403);
    }

    // Verify MFA token (TOTP)
    const isValidMFA = await verifyMFAToken(req.user.id, mfaToken);
    if (!isValidMFA) {
      return errorResponse(res, 'Invalid MFA token', 403);
    }

    req.mfaVerified = true;
    next();

  } catch (error) {
    console.error('MFA validation error:', error);
    return errorResponse(res, 'MFA validation failed', 500);
  }
};

/**
 * Device trust validation
 * Milestone 1: Device compatibility detection and registration system
 */
export const validateTrustedDevice = async (req, res, next) => {
  try {
    const deviceFingerprint = req.headers['x-device-fingerprint'];
    
    if (!deviceFingerprint) {
      return errorResponse(res, 'Device fingerprint required', 400);
    }

    const trustedDevices = await redisClient.smembers(`trusted_devices:${req.user.id}`);
    
    if (!trustedDevices.includes(deviceFingerprint)) {
      // Log suspicious device access
      await auditService.log(req.user.id, 'UNTRUSTED_DEVICE_ACCESS', 'security', null, {
        deviceFingerprint,
        userAgent: req.headers['user-agent'],
        ip: req.ip
      }, req);
      
      return errorResponse(res, 'Device not trusted', 403);
    }

    next();

  } catch (error) {
    console.error('Device validation error:', error);
    return errorResponse(res, 'Device validation failed', 500);
  }
};

/**
 * Extract token from request headers
 */
const extractToken = (req) => {
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  
  // Check for token in cookies
  if (req.cookies && req.cookies.access_token) {
    return req.cookies.access_token;
  }
  
  // Check for token in query parameter (less secure, for specific cases)
  if (req.query.token) {
    return req.query.token;
  }
  
  return null;
};

/**
 * Verify MFA TOTP token
 */
const verifyMFAToken = async (userId, token) => {
  try {
    // Implementation would depend on your MFA library (e.g., speakeasy)
    // This is a placeholder for the actual MFA verification logic
    const userMFASecret = await redisClient.get(`mfa_secret:${userId}`);
    
    if (!userMFASecret) {
      return false;
    }
    
    // Verify TOTP token using your preferred library
    // Example with speakeasy:
    // const verified = speakeasy.totp.verify({
    //   secret: userMFASecret,
    //   encoding: 'base32',
    //   token: token,
    //   window: 1
    // });
    
    return true; // Placeholder - implement actual TOTP verification
    
  } catch (error) {
    console.error('MFA verification error:', error);
    return false;
  }
};

// Export auth object to match the import pattern in routes
export const auth = {
  verifyToken: authenticate,
  authenticate,
  optionalAuth,
  refreshToken,
  validateSession,
  requireVerified,
  validateBiometric,
  requireMFA,
  validateTrustedDevice
};

// Also export individual functions for flexibility
export default auth;
// import jwt from 'jsonwebtoken';
// import  VotteryUser  from '../models/index.js';
// import  errorResponse  from '../utils/response.js';
// import auditService  from '../services/auditService.js';
// import  redisClient from '../config/redis.js';

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