export const OTP_CONFIG = {
    EMAIL_LENGTH: 6,
    SMS_LENGTH: 6,
    EXPIRY_MINUTES: 5,
    MAX_ATTEMPTS: 3,
    RATE_LIMIT_MINUTES: 15,
    MAX_REQUESTS_PER_PERIOD: 3
  };
  
  export const JWT_CONFIG = {
    ACCESS_TOKEN_EXPIRY: '15m',
    REFRESH_TOKEN_EXPIRY: '7d',
    ALGORITHM: 'RS256'
  };
  
  export const DEVICE_CONFIG = {
    MAX_DEVICES_PER_USER: 5,
    FINGERPRINT_ALGORITHM: 'SHA256'
  };
  
  export const USER_STATUS = {
    PENDING: 'pending',
    EMAIL_VERIFIED: 'email_verified',
    PHONE_VERIFIED: 'phone_verified',
    BIOMETRIC_REGISTERED: 'biometric_registered',
    ACTIVE: 'active',
    SUSPENDED: 'suspended'
  };
  
  export const BIOMETRIC_TYPES = {
    WEBAUTHN: 'webauthn',
    FINGERPRINT: 'fingerprint',
    FACE_ID: 'face_id',
    MOCK: 'mock'
  };