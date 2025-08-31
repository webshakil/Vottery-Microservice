import express from 'express';
import { AuthController } from '../controllers/authController.js';
import { authValidators } from '../utils/validators.js';
import { handleValidationErrors } from '../middleware/validation.js';
import { authenticateToken } from '../middleware/auth.js';
import { generalRateLimit, otpRateLimit, authRateLimit } from '../middleware/rateLimit.js';

const router = express.Router();

// Public routes with rate limiting
router.post('/check-user', 
  authRateLimit,
  authValidators.checkUser,
handleValidationErrors,
  AuthController.checkUser
);

router.post('/send-email-otp',
  otpRateLimit,
  authValidators.sendOTP,
handleValidationErrors,
  AuthController.sendEmailOTP
);

router.post('/send-sms-otp',
  otpRateLimit,
  authValidators.sendOTP,
handleValidationErrors,
  AuthController.sendSMSOTP
);

router.post('/verify-email-otp',
  authRateLimit,
  authValidators.verifyOTP,
handleValidationErrors,
  AuthController.verifyEmailOTP
);

router.post('/verify-sms-otp',
  authRateLimit,
  authValidators.verifyOTP,
handleValidationErrors,
  AuthController.verifySMSOTP
);

router.post('/complete',
  authRateLimit,
  authValidators.completeAuth,
handleValidationErrors,
  AuthController.completeAuth
);

router.post('/refresh',
  generalRateLimit,
  AuthController.refreshToken
);

// Protected routes
router.post('/logout',
  generalRateLimit,
  authenticateToken,
  AuthController.logout
);

router.get('/profile',
  generalRateLimit,
  authenticateToken,
  AuthController.getProfile
);

export default router;


