import express from 'express';
import userRoutes from './userRoutes.js';
import profileRoutes from './profileRoutes.js';
//import roleRoutes from './roleRoutes.js';
//import subscriptionRoutes from './subscriptionRoutes.js';
//import organizationRoutes from './organizationRoutes.js';
import securityRoutes from './securityRoutes.js';
import { auth } from '../middleware/auth.js';
import { errorHandler } from '../middleware/errorHandler.js';
import { rateLimiting } from '../middleware/rateLimiting.js';
import logger from '../utils/logger.js';

const router = express.Router();

// Apply global rate limiting
router.use(rateLimiting.global);

// Health check endpoint
router.get('/health', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'User Service is healthy',
    timestamp: new Date().toISOString(),
    service: 'user-service',
    version: '1.0.0'
  });
});

// API documentation endpoint
router.get('/docs', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Vottery User Service API',
    version: '1.0.0',
    endpoints: {
      users: '/api/users',
      profiles: '/api/profiles',
      roles: '/api/roles',
      subscriptions: '/api/subscriptions',
      organizations: '/api/organizations',
      security: '/api/security'
    },
    authentication: 'Bearer token required for protected routes',
    documentation: 'https://docs.vottery.com/user-service'
  });
});

// Mount route modules with proper middleware
router.use('/users', userRoutes);
router.use('/profiles', profileRoutes);
//router.use('/roles', roleRoutes);
//router.use('/subscriptions', subscriptionRoutes);
//router.use('/organizations', organizationRoutes);
router.use('/security', securityRoutes);

// 404 handler for API routes
router.use('*', (req, res) => {
  logger.warn(`404 - Route not found: ${req.method} ${req.originalUrl}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  res.status(404).json({
    status: 'error',
    message: 'API route not found',
    path: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

// Apply error handling middleware
router.use(errorHandler);

export default router;