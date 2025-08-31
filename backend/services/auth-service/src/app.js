// app.js
import express from 'express';
import dotenv from 'dotenv';
import morgan from 'morgan'; // lightweight logging
import { securityMiddleware } from './middleware/security.js';
import authRoutes from './routes/authRoutes.js';
import { generalRateLimit } from './middleware/rateLimit.js';
import cors from 'cors'

// Load environment variables quietly
//dotenv.config({ quiet: true });
dotenv.config()

const app = express();
const PORT = process.env.PORT || 3001;
// CORS configuration
// const corsOptions = {
// origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:5173'],
// credentials: true,
// methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
// allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
// exposedHeaders: ['X-Token-Expires-At']
//  };
//  app.use(cors(corsOptions));

const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:5173'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'x-referrer'],
  exposedHeaders: ['X-Token-Expires-At']
};
app.use(cors(corsOptions));

// Apply security middleware
app.use(securityMiddleware);

// Apply general rate limiting
app.use(generalRateLimit);

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev')); // logs incoming requests

// Health check route
 app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Auth service is healthy',
     timestamp: new Date().toISOString(),
     service: 'vottery-auth-service',
     version: '1.0.0'
   });
 });

 // API routes
app.use('/api/auth', authRoutes);




//404 handler (must be placed after all routes)
app.all('*', (req, res) => {
res.status(404).json({
success: false,
message: 'Route not found'
});
});

// Start server
app.listen(PORT, () => {
  console.log(`Auth service running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});







// //latest
// import express from 'express';
// import dotenv from 'dotenv';
// // import { logger } from './utils/logger.js';
// // import { securityMiddleware } from './middleware/security.js';
// // import { generalRateLimit } from './middleware/rateLimit.js';
// // import authRoutes from './routes/authRoutes.js';
// // import { OTP } from './models/OTP.js';
// // import { Session } from './models/Session.js';

// // Load environment variables
// dotenv.config();

// const app = express();
// const PORT = process.env.PORT || 3001;

// // // Apply security middleware
// // app.use(securityMiddleware);

// // // Parse JSON bodies
// // app.use(express.json({ limit: '10mb' }));
// // app.use(express.urlencoded({ extended: true }));

// // // Apply general rate limiting
// // app.use(generalRateLimit);

// // // Health check endpoint
// // app.get('/health', (req, res) => {
// //   res.json({
// //     success: true,
// //     message: 'Auth service is healthy',
// //     timestamp: new Date().toISOString(),
// //     service: 'vottery-auth-service',
// //     version: '1.0.0'
// //   });
// // });

// // // API routes
// // app.use('/api/auth', authRoutes);

// // // // 404 handler
// // // app.use('*', (req, res) => {
// // //   res.status(404).json({
// // //     success: false,
// // //     message: 'Route not found'
// // //   });
// // // });
// // // 404 handler (must be placed after all routes)
// // app.all('*', (req, res) => {
// //   res.status(404).json({
// //     success: false,
// //     message: 'Route not found'
// //   });
// // });

// // // Global error handler
// // app.use((err, req, res, next) => {
// //   logger.error('Unhandled error:', err);
  
// //   res.status(err.status || 500).json({
// //     success: false,
// //     message: import.meta.env.VITE_NODE_ENV === 'production' 
// //       ? 'Internal server error' 
// //       : err.message,
// //     ...(import.meta.env.VITE_NODE_ENV !== 'production' && { stack: err.stack })
// //   });
// // });

// // // Cleanup function for expired records
// // const startCleanupJobs = () => {
// //   // Clean expired OTPs every 10 minutes
// //   setInterval(async () => {
// //     try {
// //       await OTP.cleanExpired();
// //     } catch (error) {
// //       logger.error('OTP cleanup job failed:', error);
// //     }
// //   }, 10 * 60 * 1000);

// //   // Clean expired sessions every hour
// //   setInterval(async () => {
// //     try {
// //       await Session.cleanExpired();
// //     } catch (error) {
// //       logger.error('Session cleanup job failed:', error);
// //     }
// //   }, 60 * 60 * 1000);
// // };

// // Start server
// app.listen(PORT, () => {
//   logger.info(`Auth service running on port ${PORT}`);
//   logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  
//   // Start cleanup jobs
//   startCleanupJobs();
  
//   // Graceful shutdown
//   process.on('SIGTERM', () => {
//     logger.info('SIGTERM received, shutting down gracefully');
//     process.exit(0);
//   });
  
//   process.on('SIGINT', () => {
//     logger.info('SIGINT received, shutting down gracefully');
//     process.exit(0);
//   });
// });






// import express from 'express';
// import helmet from 'helmet';
// import cors from 'cors';
// import compression from 'compression';
// import morgan from 'morgan';
// import dotenv from 'dotenv';
// import { createServer } from 'http';

// // Import routes
// import authRoutes from './routes/authRoutes.js';
// import otpRoutes from './routes/otpRoutes.js';
// import biometricRoutes from './routes/biometricRoutes.js';

// // Import middleware
// import { errorHandler } from './middleware/errorHandler.js';
// import { rateLimitMiddleware } from './middleware/rateLimitMiddleware.js';
// import logger from './utils/logger.js';

// // Load environment variables
// dotenv.config();

// const app = express();
// const PORT = process.env.AUTH_SERVICE_PORT || 3001;

// // Security middleware
// app.use(helmet({
//   contentSecurityPolicy: {
//     directives: {
//       defaultSrc: ["'self'"],
//       styleSrc: ["'self'", "'unsafe-inline'"],
//       scriptSrc: ["'self'"],
//       imgSrc: ["'self'", "data:", "https:"],
//     },
//   },
//   hsts: {
//     maxAge: 31536000,
//     includeSubDomains: true,
//     preload: true
//   }
// }));

// // CORS configuration
// const corsOptions = {
//   origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
//   credentials: true,
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
//   exposedHeaders: ['X-Token-Expires-At']
// };
// app.use(cors(corsOptions));

// // Compression and parsing
// app.use(compression());
// app.use(express.json({ limit: '10mb' }));
// app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// // Logging
// app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// // Rate limiting
// app.use(rateLimitMiddleware);

// // Health check endpoint
// app.get('/health', (req, res) => {
//   res.status(200).json({
//     status: 'healthy',
//     service: 'authentication-service',
//     timestamp: new Date().toISOString(),
//     uptime: process.uptime(),
//     memory: process.memoryUsage()
//   });
// });

// // API routes
// app.use('/api/auth', authRoutes);
// app.use('/api/otp', otpRoutes);
// app.use('/api/biometric', biometricRoutes);

// // 404 handler
// app.use('*', (req, res) => {
//   res.status(404).json({
//     success: false,
//     error: 'Endpoint not found',
//     path: req.originalUrl,
//     method: req.method
//   });
// });

// // Global error handler
// app.use(errorHandler);

// // Graceful shutdown
// process.on('SIGTERM', () => {
//   logger.info('SIGTERM received, shutting down gracefully');
//   process.exit(0);
// });

// process.on('SIGINT', () => {
//   logger.info('SIGINT received, shutting down gracefully');
//   process.exit(0);
// });

// // Start server
// const server = createServer(app);
// server.listen(PORT, () => {
//   logger.info(`🚀 Authentication Service running on port ${PORT}`);
//   logger.info(`📊 Health check: http://localhost:${PORT}/health`);
// });

// export default app;