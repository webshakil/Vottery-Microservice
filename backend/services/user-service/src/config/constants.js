export const HTTP_STATUS_CODES = {
    // Success
    OK: 200,
    CREATED: 201,
    ACCEPTED: 202,
    NO_CONTENT: 204,
    
    // Redirection
    MOVED_PERMANENTLY: 301,
    FOUND: 302,
    NOT_MODIFIED: 304,
    
    // Client Error
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    METHOD_NOT_ALLOWED: 405,
    CONFLICT: 409,
    UNPROCESSABLE_ENTITY: 422,
    TOO_MANY_REQUESTS: 429,
    
    // Server Error
    INTERNAL_SERVER_ERROR: 500,
    NOT_IMPLEMENTED: 501,
    BAD_GATEWAY: 502,
    SERVICE_UNAVAILABLE: 503,
    GATEWAY_TIMEOUT: 504
  };
  
  export const ERROR_CODES = {
    // Authentication Errors
    INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
    TOKEN_EXPIRED: 'TOKEN_EXPIRED',
    TOKEN_INVALID: 'TOKEN_INVALID',
    UNAUTHORIZED_ACCESS: 'UNAUTHORIZED_ACCESS',
    ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
    ACCOUNT_SUSPENDED: 'ACCOUNT_SUSPENDED',
    
    // Validation Errors
    VALIDATION_ERROR: 'VALIDATION_ERROR',
    MISSING_REQUIRED_FIELD: 'MISSING_REQUIRED_FIELD',
    INVALID_FORMAT: 'INVALID_FORMAT',
    DUPLICATE_ENTRY: 'DUPLICATE_ENTRY',
    
    // User Errors
    USER_NOT_FOUND: 'USER_NOT_FOUND',
    USER_ALREADY_EXISTS: 'USER_ALREADY_EXISTS',
    ROLE_NOT_FOUND: 'ROLE_NOT_FOUND',
    INSUFFICIENT_PERMISSIONS: 'INSUFFICIENT_PERMISSIONS',
    
    // Organization Errors
    ORGANIZATION_NOT_FOUND: 'ORGANIZATION_NOT_FOUND',
    ORGANIZATION_ACCESS_DENIED: 'ORGANIZATION_ACCESS_DENIED',
    
    // Subscription Errors
    SUBSCRIPTION_EXPIRED: 'SUBSCRIPTION_EXPIRED',
    SUBSCRIPTION_LIMIT_EXCEEDED: 'SUBSCRIPTION_LIMIT_EXCEEDED',
    PAYMENT_REQUIRED: 'PAYMENT_REQUIRED',
    
    // Security Errors
    ENCRYPTION_ERROR: 'ENCRYPTION_ERROR',
    DECRYPTION_ERROR: 'DECRYPTION_ERROR',
    SIGNATURE_INVALID: 'SIGNATURE_INVALID',
    RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
    
    // System Errors
    DATABASE_ERROR: 'DATABASE_ERROR',
    EXTERNAL_SERVICE_ERROR: 'EXTERNAL_SERVICE_ERROR',
    SERVER_ERROR: 'SERVER_ERROR'
  };
  
  export const USER_STATUS = {
    ACTIVE: 'active',
    INACTIVE: 'inactive',
    SUSPENDED: 'suspended',
    PENDING: 'pending',
    DELETED: 'deleted'
  };
  
  export const VERIFICATION_STATUS = {
    PENDING: 'pending',
    VERIFIED: 'verified',
    REJECTED: 'rejected',
    EXPIRED: 'expired'
  };
  
  export const ORGANIZATION_TYPES = {
    COMPANY: 'company',
    NONPROFIT: 'nonprofit',
    GOVERNMENT: 'government',
    EDUCATIONAL: 'educational',
    OTHER: 'other'
  };
  
  export const SUBSCRIPTION_PLANS = {
    FREE: 'free',
    PAY_AS_YOU_GO: 'pay_as_you_go',
    MONTHLY: 'monthly',
    THREE_MONTH: '3_month',
    SIX_MONTH: '6_month',
    YEARLY: 'yearly'
  };
  
  export const SUBSCRIPTION_STATUS = {
    ACTIVE: 'active',
    CANCELLED: 'cancelled',
    EXPIRED: 'expired',
    SUSPENDED: 'suspended',
    PENDING: 'pending'
  };
  
  export const ORGANIZATION_MEMBER_ROLES = {
    OWNER: 'owner',
    ADMIN: 'admin',
    MEMBER: 'member'
  };
  
  export const ENCRYPTION_TYPES = {
    RSA_PUBLIC: 'rsa_public',
    RSA_PRIVATE: 'rsa_private',
    ELGAMAL_PUBLIC: 'elgamal_public',
    ELGAMAL_PRIVATE: 'elgamal_private',
    THRESHOLD: 'threshold',
    AES: 'aes'
  };
  
  export const SIGNATURE_ALGORITHMS = {
    RSA_SHA256: 'RSA-SHA256',
    ECDSA_SHA256: 'ECDSA-SHA256',
    ED25519: 'ED25519'
  };
  
  export const ACTIVITY_ACTIONS = {
    // Authentication Actions
    LOGIN: 'login',
    LOGOUT: 'logout',
    LOGIN_FAILED: 'login_failed',
    PASSWORD_RESET: 'password_reset',
    ACCOUNT_LOCKED: 'account_locked',
    
    // User Actions
    USER_CREATED: 'user_created',
    USER_UPDATED: 'user_updated',
    USER_DELETED: 'user_deleted',
    USER_SUSPENDED: 'user_suspended',
    USER_ACTIVATED: 'user_activated',
    
    // Profile Actions
    PROFILE_UPDATED: 'profile_updated',
    PROFILE_VIEWED: 'profile_viewed',
    
    // Role Actions
    ROLE_ASSIGNED: 'role_assigned',
    ROLE_REMOVED: 'role_removed',
    ROLE_UPDATED: 'role_updated',
    
    // Organization Actions
    ORGANIZATION_CREATED: 'organization_created',
    ORGANIZATION_UPDATED: 'organization_updated',
    ORGANIZATION_DELETED: 'organization_deleted',
    ORGANIZATION_JOINED: 'organization_joined',
    ORGANIZATION_LEFT: 'organization_left',
    
    // Subscription Actions
    SUBSCRIPTION_CREATED: 'subscription_created',
    SUBSCRIPTION_UPDATED: 'subscription_updated',
    SUBSCRIPTION_CANCELLED: 'subscription_cancelled',
    SUBSCRIPTION_EXPIRED: 'subscription_expired',
    
    // Security Actions
    ENCRYPTION_KEY_CREATED: 'encryption_key_created',
    ENCRYPTION_KEY_ROTATED: 'encryption_key_rotated',
    SIGNATURE_CREATED: 'signature_created',
    SIGNATURE_VERIFIED: 'signature_verified',
    SECURITY_EVENT: 'security_event',
    
    // System Actions
    DATA_EXPORT: 'data_export',
    DATA_IMPORT: 'data_import',
    SYSTEM_CONFIG_CHANGED: 'system_config_changed'
  };
  
  export const RESOURCE_TYPES = {
    USER: 'user',
    PROFILE: 'profile',
    ROLE: 'role',
    ORGANIZATION: 'organization',
    SUBSCRIPTION: 'subscription',
    ENCRYPTION_KEY: 'encryption_key',
    DIGITAL_SIGNATURE: 'digital_signature',
    SECURITY_EVENT: 'security_event'
  };
  
  export const SECURITY_EVENT_TYPES = {
    BRUTE_FORCE_ATTEMPT: 'brute_force_attempt',
    SUSPICIOUS_LOGIN: 'suspicious_login',
    UNAUTHORIZED_ACCESS: 'unauthorized_access',
    DATA_BREACH_ATTEMPT: 'data_breach_attempt',
    ENCRYPTION_FAILURE: 'encryption_failure',
    RATE_LIMIT_EXCEEDED: 'rate_limit_exceeded',
    MALICIOUS_REQUEST: 'malicious_request'
  };
  
  export const PAGINATION = {
    DEFAULT_PAGE: 1,
    DEFAULT_LIMIT: 20,
    MAX_LIMIT: 100,
    MIN_LIMIT: 1
  };
  
  export const FILE_UPLOAD = {
    MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
    ALLOWED_MIME_TYPES: [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'application/pdf'
    ],
    ALLOWED_EXTENSIONS: ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf']
  };
  
  export const CACHE_KEYS = {
    USER_PROFILE: 'user_profile',
    USER_ROLES: 'user_roles',
    ORGANIZATION: 'organization',
    SUBSCRIPTION: 'subscription',
    ENCRYPTION_KEYS: 'encryption_keys',
    RATE_LIMIT: 'rate_limit'
  };
  
  export const CACHE_TTL = {
    SHORT: 5 * 60, // 5 minutes
    MEDIUM: 30 * 60, // 30 minutes
    LONG: 2 * 60 * 60, // 2 hours
    VERY_LONG: 24 * 60 * 60 // 24 hours
  };
  
  export const API_VERSIONS = {
    V1: 'v1',
    V2: 'v2'
  };
  
  export const SERVICE_NAMES = {
    USER_SERVICE: 'user-service',
    AUTH_SERVICE: 'auth-service',
    BIOMETRIC_SERVICE: 'biometric-service',
    ELECTION_SERVICE: 'election-service',
    VOTING_SERVICE: 'voting-service',
    PAYMENT_SERVICE: 'payment-service',
    LOTTERY_SERVICE: 'lottery-service'
  };
  
  export const ENVIRONMENT = {
    DEVELOPMENT: 'development',
    STAGING: 'staging',
    PRODUCTION: 'production',
    TEST: 'test'
  };
  
  export const LOG_LEVELS = {
    ERROR: 'error',
    WARN: 'warn',
    INFO: 'info',
    DEBUG: 'debug',
    TRACE: 'trace'
  };
  
  export const RESPONSE_MESSAGES = {
    // Success Messages
    SUCCESS: 'Operation completed successfully',
    CREATED: 'Resource created successfully',
    UPDATED: 'Resource updated successfully',
    DELETED: 'Resource deleted successfully',
    
    // Error Messages
    INTERNAL_ERROR: 'Internal server error occurred',
    VALIDATION_FAILED: 'Validation failed',
    NOT_FOUND: 'Resource not found',
    UNAUTHORIZED: 'Unauthorized access',
    FORBIDDEN: 'Access forbidden',
    CONFLICT: 'Resource already exists',
    
    // Authentication Messages
    LOGIN_SUCCESS: 'Login successful',
    LOGIN_FAILED: 'Invalid credentials',
    LOGOUT_SUCCESS: 'Logout successful',
    TOKEN_EXPIRED: 'Token has expired',
    TOKEN_INVALID: 'Invalid token',
    
    // User Messages
    USER_CREATED: 'User created successfully',
    USER_UPDATED: 'User updated successfully',
    USER_DELETED: 'User deleted successfully',
    USER_NOT_FOUND: 'User not found',
    
    // Organization Messages
    ORGANIZATION_CREATED: 'Organization created successfully',
    ORGANIZATION_UPDATED: 'Organization updated successfully',
    ORGANIZATION_NOT_FOUND: 'Organization not found',
    
    // Subscription Messages
    SUBSCRIPTION_CREATED: 'Subscription created successfully',
    SUBSCRIPTION_UPDATED: 'Subscription updated successfully',
    SUBSCRIPTION_EXPIRED: 'Subscription has expired',
    
    // Security Messages
    ENCRYPTION_SUCCESS: 'Data encrypted successfully',
    DECRYPTION_SUCCESS: 'Data decrypted successfully',
    SIGNATURE_VALID: 'Digital signature is valid',
    SIGNATURE_INVALID: 'Digital signature is invalid'
  };
  
  export const REGEX_PATTERNS = {
    EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    PHONE: /^\+?[1-9]\d{1,14}$/,
    PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
    USERNAME: /^[a-zA-Z0-9_-]{3,20}$/,
    UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    HEX: /^[a-fA-F0-9]+$/,
    BASE64: /^[A-Za-z0-9+/=]+$/
  };
  
  export const TIME_CONSTANTS = {
    MINUTE: 60 * 1000,
    HOUR: 60 * 60 * 1000,
    DAY: 24 * 60 * 60 * 1000,
    WEEK: 7 * 24 * 60 * 60 * 1000,
    MONTH: 30 * 24 * 60 * 60 * 1000,
    YEAR: 365 * 24 * 60 * 60 * 1000
  };
  
  export const DATABASE_CONSTRAINTS = {
    MAX_STRING_LENGTH: 255,
    MAX_TEXT_LENGTH: 65535,
    MAX_LONGTEXT_LENGTH: 4294967295,
    MIN_PASSWORD_LENGTH: 8,
    MAX_PASSWORD_LENGTH: 128,
    MAX_USERNAME_LENGTH: 50,
    MAX_EMAIL_LENGTH: 100
  };
  
  export const BIOMETRIC_TYPES = {
    FINGERPRINT: 'fingerprint',
    FACE_ID: 'face_id',
    IRIS: 'iris',
    VOICE: 'voice'
  };
  
  export const DEVICE_TYPES = {
    MOBILE: 'mobile',
    TABLET: 'tablet',
    DESKTOP: 'desktop',
    TV: 'tv',
    UNKNOWN: 'unknown'
  };
  
  export const BROWSER_TYPES = {
    CHROME: 'chrome',
    FIREFOX: 'firefox',
    SAFARI: 'safari',
    EDGE: 'edge',
    OPERA: 'opera',
    UNKNOWN: 'unknown'
  };
  
  export const OPERATING_SYSTEMS = {
    WINDOWS: 'windows',
    MACOS: 'macos',
    LINUX: 'linux',
    ANDROID: 'android',
    IOS: 'ios',
    UNKNOWN: 'unknown'
  };
  
  const constants = {
    HTTP_STATUS_CODES,
    ERROR_CODES,
    USER_STATUS,
    VERIFICATION_STATUS,
    ORGANIZATION_TYPES,
    SUBSCRIPTION_PLANS,
    SUBSCRIPTION_STATUS,
    ORGANIZATION_MEMBER_ROLES,
    ENCRYPTION_TYPES,
    SIGNATURE_ALGORITHMS,
    ACTIVITY_ACTIONS,
    RESOURCE_TYPES,
    SECURITY_EVENT_TYPES,
    PAGINATION,
    FILE_UPLOAD,
    CACHE_KEYS,
    CACHE_TTL,
    API_VERSIONS,
    SERVICE_NAMES,
    ENVIRONMENT,
    LOG_LEVELS,
    RESPONSE_MESSAGES,
    REGEX_PATTERNS,
    TIME_CONSTANTS,
    DATABASE_CONSTRAINTS,
    BIOMETRIC_TYPES,
    DEVICE_TYPES,
    BROWSER_TYPES,
    OPERATING_SYSTEMS
  };
  
  export default constants;