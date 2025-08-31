import rateLimit from 'express-rate-limit';

export const biometricRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs for biometric operations
  message: {
    success: false,
    message: 'Too many biometric requests, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});