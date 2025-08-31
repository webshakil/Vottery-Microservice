// System-wide constants for Vottery User Service
export const HTTP_STATUS = {
    OK: 200,
    CREATED: 201,
    ACCEPTED: 202,
    NO_CONTENT: 204,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    CONFLICT: 409,
    UNPROCESSABLE_ENTITY: 422,
    TOO_MANY_REQUESTS: 429,
    INTERNAL_SERVER_ERROR: 500,
    SERVICE_UNAVAILABLE: 503
  };
  
  // User role categories and levels
  export const USER_ROLES = {
    // Admin roles (system management)
    ADMIN: {
      MANAGER: { name: 'manager', category: 'admin', level: 100 },
      ADMIN: { name: 'admin', category: 'admin', level: 90 },
      MODERATOR: { name: 'moderator', category: 'admin', level: 80 },
      AUDITOR: { name: 'auditor', category: 'admin', level: 70 },
      EDITOR: { name: 'editor', category: 'admin', level: 60 },
      ADVERTISER: { name: 'advertiser', category: 'admin', level: 50 },
      ANALYST: { name: 'analyst', category: 'admin', level: 40 }
    },
    // User types (platform usage)
    USER: {
      INDIVIDUAL_CREATOR: { name: 'individual_creator', category: 'user', level: 30 },
      ORGANIZATION_CREATOR: { name: 'organization_creator', category: 'user', level: 25 },
      VOTER: { name: 'voter', category: 'user', level: 10 }
    }
  };
  
  // Permission categories and definitions
  export const PERMISSIONS = {
    USERS: {
      VIEW: 'users:view',
      EDIT: 'users:edit',
      DELETE: 'users:delete',
      SUSPEND: 'users:suspend',
      MODERATE: 'users:moderate',
      ROLES_ASSIGN: 'users:roles:assign',
      ROLES_REMOVE: 'users:roles:remove',
      SECURITY_BULK: 'users:security:bulk'
    },
    ELECTIONS: {
      CREATE: 'elections:create',
      VIEW: 'elections:view',
      EDIT: 'elections:edit',
      DELETE: 'elections:delete',
      MODERATE: 'elections:moderate',
      APPROVE: 'elections:approve'
    },
    ORGANIZATIONS: {
      VIEW: 'organizations:view',
      EDIT: 'organizations:edit',
      DELETE: 'organizations:delete',
      VERIFY: 'organizations:verify',
      SUSPEND: 'organizations:suspend',
      COMPLIANCE: 'organizations:compliance'
    },
    SUBSCRIPTIONS: {
      VIEW: 'subscriptions:view',
      EDIT: 'subscriptions:edit',
      CANCEL: 'subscriptions:cancel',
      REFUND: 'subscriptions:refund',
      BULK: 'subscriptions:bulk',
      PLANS_CREATE: 'subscriptions:plans:create',
      PLANS_EDIT: 'subscriptions:plans:edit',
      PLANS_DELETE: 'subscriptions:plans:delete',
      PROMOS_VIEW: 'subscriptions:promos:view',
      PROMOS_CREATE: 'subscriptions:promos:create',
      PROMOS_EDIT: 'subscriptions:promos:edit',
      PROMOS_DELETE: 'subscriptions:promos:delete',
      PAYMENTS: 'subscriptions:payments'
    },
    ANALYTICS: {
      VIEW: 'analytics:view',
      EXPORT: 'analytics:export',
      ADVANCED: 'analytics:advanced',
      REPORTS: 'analytics:reports'
    },
    SYSTEM: {
      CONFIG: 'system:config',
      AUDIT: 'system:audit',
      SECURITY: 'system:security',
      ROLES: 'system:roles',
      ROLES_CREATE: 'system:roles:create',
      ROLES_EDIT: 'system:roles:edit',
      ROLES_DELETE: 'system:roles:delete',
      ROLES_VALIDATE: 'system:roles:validate',
      ROLES_IMPORT: 'system:roles:import',
      ROLES_RESET: 'system:roles:reset',
      SECURITY_KEYS: 'system:security:keys',
      SECURITY_MONITOR: 'system:security:monitor',
      SECURITY_EMERGENCY: 'system:security:emergency',
      SECURITY_VULNERABILITIES: 'system:security:vulnerabilities'
    }
  };
  
  // Subscription plans and limits
  export const SUBSCRIPTION_PLANS = {
    FREE: {
      name: 'free',
      price: 0,
      limits: {
        elections_created: 5,
        votes_per_month: 100,
        organizations: 0,
        custom_branding: false,
        analytics_export: false,
        api_access: false
      }
    },
    PAY_AS_YOU_GO: {
      name: 'pay_as_you_go',
      price_per_vote: 0.10,
      limits: {
        elections_created: -1, // unlimited
        votes_per_month: -1,
        organizations: 1,
        custom_branding: false,
        analytics_export: true,
        api_access: true
      }
    },
    MONTHLY: {
      name: 'monthly',
      price: 29.99,
      limits: {
        elections_created: -1,
        votes_per_month: -1,
        organizations: 3,
        custom_branding: true,
        analytics_export: true,
        api_access: true
      }
    },
    THREE_MONTH: {
      name: '3_month',
      price: 79.99,
      limits: {
        elections_created: -1,
        votes_per_month: -1,
        organizations: 5,
        custom_branding: true,
        analytics_export: true,
        api_access: true
      }
    },
    SIX_MONTH: {
      name: '6_month',
      price: 149.99,
      limits: {
        elections_created: -1,
        votes_per_month: -1,
        organizations: 10,
        custom_branding: true,
        analytics_export: true,
        api_access: true
      }
    },
    YEARLY: {
      name: 'yearly',
      price: 299.99,
      limits: {
        elections_created: -1,
        votes_per_month: -1,
        organizations: -1,
        custom_branding: true,
        analytics_export: true,
        api_access: true,
        priority_support: true
      }
    }
  };
  
  // Encryption algorithms and key sizes
  export const ENCRYPTION = {
    ALGORITHMS: {
      RSA: 'RSA',
      ELGAMAL: 'ElGamal',
      AES: 'AES',
      SHA256: 'SHA-256',
      BCRYPT: 'bcrypt'
    },
    KEY_SIZES: {
      RSA: 2048,
      ELGAMAL: 2048,
      AES: 256,
      THRESHOLD: 2048
    },
    HASH_ROUNDS: {
      BCRYPT: 12,
      PBKDF2: 100000
    }
  };
  
  // Database table names with vottery_ prefix
  export const DB_TABLES = {
    USERS: 'vottery_users',
    USER_PROFILES: 'user_profiles',
    ROLES: 'roles',
    USER_ROLES: 'user_roles',
    ORGANIZATIONS: 'organizations',
    ORGANIZATION_MEMBERS: 'organization_members',
    SUBSCRIPTIONS: 'subscriptions',
    USER_ACTIVITY_LOGS: 'user_activity_logs',
    ENCRYPTION_KEYS: 'encryption_keys',
    DIGITAL_SIGNATURES: 'digital_signatures',
    SECURITY_EVENTS: 'security_events'
  };
  
  // Validation constants
  export const VALIDATION = {
    PASSWORD: {
      MIN_LENGTH: 8,
      MAX_LENGTH: 128,
      REQUIRE_UPPERCASE: true,
      REQUIRE_LOWERCASE: true,
      REQUIRE_NUMBERS: true,
      REQUIRE_SPECIAL_CHARS: true
    },
    USERNAME: {
      MIN_LENGTH: 3,
      MAX_LENGTH: 30,
      PATTERN: /^[a-zA-Z0-9_.-]+$/
    },
    EMAIL: {
      MAX_LENGTH: 255,
      PATTERN: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    },
    FILE_UPLOAD: {
      MAX_SIZE: 5 * 1024 * 1024, // 5MB
      ALLOWED_TYPES: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
      AVATAR_MAX_SIZE: 2 * 1024 * 1024 // 2MB
    },
    PAGINATION: {
      DEFAULT_LIMIT: 20,
      MAX_LIMIT: 100,
      DEFAULT_OFFSET: 0
    }
  };
  
  // Rate limiting configurations
  export const RATE_LIMITS = {
    GLOBAL: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 1000, // 1000 requests per 15 minutes
      message: 'Too many requests from this IP'
    },
    STANDARD: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // 100 requests per 15 minutes
      message: 'Standard rate limit exceeded'
    },
    STRICT: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 20, // 20 requests per 15 minutes
      message: 'Strict rate limit exceeded'
    },
    UPLOAD: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 10, // 10 uploads per 15 minutes
      message: 'Upload rate limit exceeded'
    },
    AUTH: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // 5 auth attempts per 15 minutes
      message: 'Authentication rate limit exceeded'
    },
    EMERGENCY: {
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 3, // 3 emergency actions per hour
      message: 'Emergency action rate limit exceeded'
    },
    WEBHOOK: {
      windowMs: 1 * 60 * 1000, // 1 minute
      max: 100, // 100 webhook calls per minute
      message: 'Webhook rate limit exceeded'
    }
  };
  
  // Security event types
  export const SECURITY_EVENTS = {
    LOGIN_SUCCESS: 'login_success',
    LOGIN_FAILED: 'login_failed',
    LOGOUT: 'logout',
    PASSWORD_CHANGED: 'password_changed',
    EMAIL_CHANGED: 'email_changed',
    TWO_FA_ENABLED: '2fa_enabled',
    TWO_FA_DISABLED: '2fa_disabled',
    BIOMETRIC_REGISTERED: 'biometric_registered',
    BIOMETRIC_REMOVED: 'biometric_removed',
    KEY_GENERATED: 'key_generated',
    KEY_REVOKED: 'key_revoked',
    SIGNATURE_CREATED: 'signature_created',
    SUSPICIOUS_ACTIVITY: 'suspicious_activity',
    ACCOUNT_LOCKED: 'account_locked',
    ACCOUNT_UNLOCKED: 'account_unlocked',
    ROLE_ASSIGNED: 'role_assigned',
    ROLE_REMOVED: 'role_removed',
    PERMISSION_GRANTED: 'permission_granted',
    PERMISSION_REVOKED: 'permission_revoked'
  };
  
  // Organization verification statuses
  export const ORGANIZATION_STATUS = {
    PENDING: 'pending',
    VERIFIED: 'verified',
    REJECTED: 'rejected',
    SUSPENDED: 'suspended'
  };
  
  // Subscription statuses
  export const SUBSCRIPTION_STATUS = {
    ACTIVE: 'active',
    CANCELLED: 'cancelled',
    EXPIRED: 'expired',
    SUSPENDED: 'suspended',
    PENDING: 'pending'
  };
  
  // Organization member roles
  export const ORGANIZATION_ROLES = {
    OWNER: 'owner',
    ADMIN: 'admin',
    MEMBER: 'member'
  };
  
  // Supported languages (70+ languages as per specification)
  export const SUPPORTED_LANGUAGES = [
    'af', 'ar', 'az', 'be', 'bg', 'bn', 'bs', 'ca', 'cs', 'cy',
    'da', 'de', 'el', 'en', 'en-gb', 'en-us', 'eo', 'es', 'et', 'eu',
    'fa', 'fi', 'fr', 'ga', 'gl', 'gu', 'he', 'hi', 'hr', 'hu',
    'hy', 'id', 'is', 'it', 'ja', 'ka', 'kk', 'km', 'kn', 'ko',
    'lo', 'lt', 'lv', 'mk', 'ml', 'mn', 'mr', 'ms', 'mt', 'my',
    'nb', 'ne', 'nl', 'nn', 'pa', 'pl', 'pt', 'pt-br', 'ro', 'ru',
    'si', 'sk', 'sl', 'sq', 'sr', 'sv', 'sw', 'ta', 'te', 'th',
    'tl', 'tr', 'uk', 'ur', 'uz', 'vi', 'zh', 'zh-cn', 'zh-tw'
  ];
  
  // API response messages
  export const MESSAGES = {
    SUCCESS: {
      CREATED: 'Resource created successfully',
      UPDATED: 'Resource updated successfully',
      DELETED: 'Resource deleted successfully',
      RETRIEVED: 'Resource retrieved successfully',
      OPERATION_COMPLETED: 'Operation completed successfully'
    },
    ERROR: {
      VALIDATION_FAILED: 'Validation failed',
      UNAUTHORIZED: 'Authentication required',
      FORBIDDEN: 'Access denied',
      NOT_FOUND: 'Resource not found',
      CONFLICT: 'Resource already exists',
      INTERNAL_ERROR: 'Internal server error',
      SERVICE_UNAVAILABLE: 'Service temporarily unavailable',
      RATE_LIMIT_EXCEEDED: 'Rate limit exceeded',
      INVALID_CREDENTIALS: 'Invalid credentials',
      TOKEN_EXPIRED: 'Token has expired',
      PERMISSION_DENIED: 'Insufficient permissions'
    }
  };
  
  // Environment types
  export const ENVIRONMENTS = {
    DEVELOPMENT: 'development',
    TESTING: 'testing',
    STAGING: 'staging',
    PRODUCTION: 'production'
  };
  
  // Service configuration
  export const SERVICE_CONFIG = {
    NAME: 'user-service',
    VERSION: '1.0.0',
    PORT: process.env.PORT || 3001,
    API_PREFIX: '/api',
    CORS_ORIGINS: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
    JWT_EXPIRY: '24h',
    JWT_REFRESH_EXPIRY: '7d',
    SESSION_TIMEOUT: 30 * 60 * 1000, // 30 minutes
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_DURATION: 15 * 60 * 1000 // 15 minutes
  };
  
  // External service URLs
  export const EXTERNAL_SERVICES = {
    AUTH_SERVICE: process.env.AUTH_SERVICE_URL || 'http://localhost:3000',
    BIOMETRIC_SERVICE: process.env.BIOMETRIC_SERVICE_URL || 'http://localhost:3002',
    ELECTION_SERVICE: process.env.ELECTION_SERVICE_URL || 'http://localhost:3003',
    PAYMENT_SERVICE: process.env.PAYMENT_SERVICE_URL || 'http://localhost:3004'
  };
  
  // Audit action types
  export const AUDIT_ACTIONS = {
    CREATE: 'create',
    READ: 'read',
    UPDATE: 'update',
    DELETE: 'delete',
    LOGIN: 'login',
    LOGOUT: 'logout',
    ASSIGN: 'assign',
    REVOKE: 'revoke',
    SUSPEND: 'suspend',
    ACTIVATE: 'activate',
    VERIFY: 'verify',
    APPROVE: 'approve',
    REJECT: 'reject'
  };
  
  // Default export containing all constants
  export default {
    HTTP_STATUS,
    USER_ROLES,
    PERMISSIONS,
    SUBSCRIPTION_PLANS,
    ENCRYPTION,
    DB_TABLES,
    VALIDATION,
    RATE_LIMITS,
    SECURITY_EVENTS,
    ORGANIZATION_STATUS,
    SUBSCRIPTION_STATUS,
    ORGANIZATION_ROLES,
    SUPPORTED_LANGUAGES,
    MESSAGES,
    ENVIRONMENTS,
    SERVICE_CONFIG,
    EXTERNAL_SERVICES,
    AUDIT_ACTIONS
  };