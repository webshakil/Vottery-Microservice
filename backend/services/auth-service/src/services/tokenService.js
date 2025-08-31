import jwt from 'jsonwebtoken';
import { JWT_CONFIG } from '../utils/constants.js';
import { logger } from '../utils/logger.js';
import dotenv from 'dotenv';

dotenv.config();

export class TokenService {
  static generateTokenPair(payload) {
    try {
      const accessToken = jwt.sign(
        payload,
        process.env.JWT_PRIVATE_KEY.replace(/\\n/g, '\n'),
        {
          algorithm: JWT_CONFIG.ALGORITHM,
          expiresIn: JWT_CONFIG.ACCESS_TOKEN_EXPIRY,
          issuer: 'vottery-auth-service',
          audience: 'vottery-client'
        }
      );

      const refreshToken = jwt.sign(
        { userId: payload.userId, tokenType: 'refresh' },
        process.env.JWT_REFRESH_SECRET,
        {
          expiresIn: JWT_CONFIG.REFRESH_TOKEN_EXPIRY
        }
      );

      return { accessToken, refreshToken };
    } catch (error) {
      logger.error('Token generation failed:', error);
      throw new Error('Token generation failed');
    }
  }

  static verifyAccessToken(token) {
    try {
      return jwt.verify(
        token,
        process.env.JWT_PUBLIC_KEY.replace(/\\n/g, '\n'),
        {
          algorithm: JWT_CONFIG.ALGORITHM,
          issuer: 'vottery-auth-service',
          audience: 'vottery-client'
        }
      );
    } catch (error) {
      logger.error('Access token verification failed:', error);
      throw new Error('Invalid access token');
    }
  }

  static verifyRefreshToken(token) {
    try {
      return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    } catch (error) {
      logger.error('Refresh token verification failed:', error);
      throw new Error('Invalid refresh token');
    }
  }
}