import { TokenService } from '../services/tokenService.js';
import { Session } from '../models/Session.js';
import { logger } from '../utils/logger.js';

export const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Access token is required'
      });
    }

    const token = authHeader.substring(7);

    // Verify JWT token
    const decoded = TokenService.verifyAccessToken(token);
    
    // Check if session exists and is active
    const session = await Session.getByToken(token);
    
    if (!session || !session.is_active) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired session'
      });
    }

    // Check if session is expired
    if (new Date() > new Date(session.expires_at)) {
      return res.status(401).json({
        success: false,
        message: 'Session expired'
      });
    }

    // Check if user is active
    if (session.status === 'suspended') {
      return res.status(403).json({
        success: false,
        message: 'User account is suspended'
      });
    }

    // Add user info to request
    req.user = {
      userId: decoded.userId,
      email: decoded.email,
      phone: decoded.phone,
      deviceId: decoded.deviceId,
      sessionId: session.id
    };

    next();

  } catch (error) {
    logger.error('Token authentication error:', error);
    
    if (error.message.includes('expired') || error.message.includes('invalid')) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Authentication failed'
    });
  }
};