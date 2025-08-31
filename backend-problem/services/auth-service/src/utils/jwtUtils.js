import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import logger from './logger.js';

export class JwtUtils {
  constructor() {
    this.accessTokenSecret = process.env.JWT_SECRET;
    this.refreshTokenSecret = process.env.JWT_REFRESH_SECRET;
    this.accessTokenExpiry = process.env.JWT_EXPIRES_IN || '1h';
    this.refreshTokenExpiry = process.env.JWT_REFRESH_EXPIRES_IN || '7d';
  }

  // Generate access token
  generateAccessToken(payload) {
    const jti = uuidv4(); // JWT ID for token tracking
    const tokenPayload = {
      ...payload,
      jti,
      type: 'access',
      iat: Math.floor(Date.now() / 1000)
    };

    const token = jwt.sign(tokenPayload, this.accessTokenSecret, {
      expiresIn: this.accessTokenExpiry,
      issuer: 'vottery-auth-service',
      audience: 'vottery-platform'
    });

    // Calculate expiration timestamp
    const decoded = jwt.decode(token);
    const expiresAt = new Date(decoded.exp * 1000);

    return {
      token,
      jti,
      expiresAt,
      expiresIn: this.accessTokenExpiry
    };
  }

  // Generate refresh token
  generateRefreshToken(payload) {
    const jti = uuidv4();
    const tokenPayload = {
      userId: payload.userId,
      deviceId: payload.deviceId,
      jti,
      type: 'refresh',
      iat: Math.floor(Date.now() / 1000)
    };

    const token = jwt.sign(tokenPayload, this.refreshTokenSecret, {
      expiresIn: this.refreshTokenExpiry,
      issuer: 'vottery-auth-service',
      audience: 'vottery-platform'
    });

    const decoded = jwt.decode(token);
    const expiresAt = new Date(decoded.exp * 1000);

    return {
      token,
      jti,
      expiresAt,
      expiresIn: this.refreshTokenExpiry
    };
  }

  // Generate token pair (access + refresh)
  generateTokenPair(payload) {
    const sessionId = uuidv4(); // Shared session ID
    
    const accessToken = this.generateAccessToken({
      ...payload,
      sessionId
    });

    const refreshToken = this.generateRefreshToken({
      ...payload,
      sessionId
    });

    return {
      accessToken: accessToken.token,
      refreshToken: refreshToken.token,
      sessionId,
      jti: accessToken.jti,
      expiresAt: accessToken.expiresAt,
      refreshExpiresAt: refreshToken.expiresAt
    };
  }

  // Verify access token
  verifyAccessToken(token) {
    try {
      const decoded = jwt.verify(token, this.accessTokenSecret, {
        issuer: 'vottery-auth-service',
        audience: 'vottery-platform'
      });

      if (decoded.type !== 'access') {
        throw new Error('Invalid token type');
      }

      return {
        valid: true,
        payload: decoded,
        expired: false
      };
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return {
          valid: false,
          payload: null,
          expired: true,
          error: 'Token expired'
        };
      }

      return {
        valid: false,
        payload: null,
        expired: false,
        error: error.message
      };
    }
  }

  // Verify refresh token
  verifyRefreshToken(token) {
    try {
      const decoded = jwt.verify(token, this.refreshTokenSecret, {
        issuer: 'vottery-auth-service',
        audience: 'vottery-platform'
      });

      if (decoded.type !== 'refresh') {
        throw new Error('Invalid token type');
      }

      return {
        valid: true,
        payload: decoded,
        expired: false
      };
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return {
          valid: false,
          payload: null,
          expired: true,
          error: 'Refresh token expired'
        };
      }

      return {
        valid: false,
        payload: null,
        expired: false,
        error: error.message
      };
    }
  }

  // Decode token without verification (for logging/debugging)
  decodeToken(token) {
    try {
      return jwt.decode(token, { complete: true });
    } catch (error) {
      logger.error('Error decoding token:', error);
      return null;
    }
  }

  // Extract token from Authorization header
  extractTokenFromHeader(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    return authHeader.substring(7);
  }

  // Generate token for email verification (different from auth tokens)
  generateEmailVerificationToken(email, userId) {
    const payload = {
      email,
      userId,
      purpose: 'email_verification',
      jti: uuidv4()
    };

    return jwt.sign(payload, this.accessTokenSecret, {
      expiresIn: '24h',
      issuer: 'vottery-auth-service'
    });
  }

  // Verify email verification token
  verifyEmailVerificationToken(token) {
    try {
      const decoded = jwt.verify(token, this.accessTokenSecret);
      
      if (decoded.purpose !== 'email_verification') {
        throw new Error('Invalid token purpose');
      }

      return {
        valid: true,
        payload: decoded
      };
    } catch (error) {
      return {
        valid: false,
        error: error.message
      };
    }
  }
}