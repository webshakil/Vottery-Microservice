

// config/security.js
import helmet from 'helmet';

const securityConfig = {
  // JWT Configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'vottery-jwt-secret-key-change-in-production',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'vottery-jwt-refresh-secret-change-in-production',
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    issuer: process.env.JWT_ISSUER || 'Vottery',
    audience: process.env.JWT_AUDIENCE || 'vottery-users'
  },

  // Session Configuration
  session: {
    secret: process.env.SESSION_SECRET || 'vottery-session-secret-change-in-production',
    name: 'vottery.sid',
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      sameSite: 'strict'
    },
    resave: false,
    saveUninitialized: false
  },

  // CORS Configuration
  cors: {
    origin: process.env.ALLOWED_ORIGINS ? 
      process.env.ALLOWED_ORIGINS.split(',') : 
      ['http://localhost:3000', 'http://localhost:3001'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['X-Total-Count', 'X-Page-Count']
  },

  // Helmet Security Headers Configuration
  helmet: {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"]
      }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
  },

  // Rate Limiting Configuration
  rateLimiting: {
    // General API rate limiting
    general: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again later.',
      standardHeaders: true,
      legacyHeaders: false
    },

    // Authentication endpoints rate limiting
    auth: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // limit each IP to 5 requests per windowMs
      message: 'Too many authentication attempts, please try again later.',
      standardHeaders: true,
      legacyHeaders: false,
      skipSuccessfulRequests: true
    },

    // Password reset rate limiting
    passwordReset: {
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 3, // limit each IP to 3 password reset requests per hour
      message: 'Too many password reset attempts, please try again later.',
      standardHeaders: true,
      legacyHeaders: false
    }
  },

  // Password Policy
  passwordPolicy: {
    minLength: 8,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    preventReuse: 5, // prevent reuse of last 5 passwords
    maxAge: 90 * 24 * 60 * 60 * 1000, // 90 days in milliseconds
    lockoutThreshold: 5, // account lockout after 5 failed attempts
    lockoutDuration: 30 * 60 * 1000 // 30 minutes lockout
  },

  // Account Security
  account: {
    maxLoginAttempts: 5,
    lockoutDuration: 30 * 60 * 1000, // 30 minutes
    sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
    requireEmailVerification: true,
    require2FA: false, // can be enabled per user
    passwordResetTokenExpiry: 1 * 60 * 60 * 1000 // 1 hour
  },

  // Encryption Settings
  encryption: {
    algorithm: 'aes-256-gcm',
    keyDerivation: 'pbkdf2',
    iterations: 100000,
    keyLength: 32,
    ivLength: 16,
    tagLength: 16,
    saltLength: 32
  },

  // File Upload Security
  fileUpload: {
    maxFileSize: 10 * 1024 * 1024, // 10MB
    allowedMimeTypes: [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'application/pdf'
    ],
    uploadPath: process.env.UPLOAD_PATH || './uploads',
    maxFiles: 5
  },

  // Biometric Security
  biometric: {
    maxRetries: 3,
    sessionTimeout: 10 * 60 * 1000, // 10 minutes
    requireDeviceRegistration: true,
    allowFallback: true
  },

  // Audit Configuration
  audit: {
    retentionDays: 365,
    logLevel: process.env.AUDIT_LOG_LEVEL || 'info',
    enableRealTimeAlerts: true,
    alertThresholds: {
      failedLogins: 10,
      suspiciousActivity: 5,
      dataAccess: 100
    }
  }
};

export default securityConfig;