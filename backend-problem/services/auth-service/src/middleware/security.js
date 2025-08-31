import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import hpp from 'hpp';
import mongoSanitize from 'express-mongo-sanitize';

// Parse allowed origins safely
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(url => url.trim())
  : [
      'http://localhost:3000',
      'http://localhost:5173',
      'https://vottery.com'
    ];

export const securityMiddleware = [
  // Enable CORS with specific origins
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps, curl)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('CORS policy: This origin is not allowed'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  }),

  // Security headers
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
  }),

  // Compress responses
  compression(),

  // Prevent HTTP Parameter Pollution
  hpp(),

  // Data sanitization against NoSQL query injection
  mongoSanitize(),
];







// // import helmet from 'helmet';
// // import cors from 'cors';
// // import compression from 'compression';
// // import hpp from 'hpp';
// // import mongoSanitize from 'express-mongo-sanitize';

// // export const securityMiddleware = [
// //   // Enable CORS with specific origins
// //   cors({
// //     origin: process.env.ALLOWED_ORIGINS?.split(',') || [
// //       'http://localhost:3000',
// //       'http://localhost:5173',
// //       'https://vottery.com'
// //     ],
// //     credentials: true,
// //     methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
// //     allowedHeaders: ['Content-Type', 'Authorization']
// //   }),

// //   // Security headers
// //   helmet({
// //     contentSecurityPolicy: {
// //       directives: {
// //         defaultSrc: ["'self'"],
// //         styleSrc: ["'self'", "'unsafe-inline'"],
// //         scriptSrc: ["'self'"],
// //         imgSrc: ["'self'", "data:", "https:"],
// //       },
// //     },
// //   }),

// //   // Compress responses
// //   compression(),

// //   // Prevent HTTP Parameter Pollution
// //   hpp(),

// //   // Data sanitization against NoSQL query injection
// //   mongoSanitize(),
// // ];