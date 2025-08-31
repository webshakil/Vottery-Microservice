import { body, param, query } from 'express-validator';

export const authValidators = {
  checkUser: [
    body('email')
      .isEmail()
      .normalizeEmail()
      .withMessage('Valid email is required'),
    body('phone')
      .isMobilePhone()
      .withMessage('Valid phone number is required')
  ],

  sendOTP: [
    body('email')
      .optional()
      .isEmail()
      .normalizeEmail(),
    body('phone')
      .optional()
      .isMobilePhone()
  ],

  // verifyOTP: [
  //   body('identifier')
  //     .notEmpty()
  //     .withMessage('Email or phone is required'),
  //   body('otp')
  //     .isLength({ min: 6, max: 6 })
  //     .isNumeric()
  //     .withMessage('OTP must be 6 digits')
  // ],

  verifyOTP: [
    body('otp')
      .isLength({ min: 6, max: 6 })
      .isNumeric()
      .withMessage('OTP must be 6 digits')
  ],
  completeAuth: [
    body('email')
      .isEmail()
      .normalizeEmail()
      .withMessage('Valid email is required'),
    body('phone')
      .isMobilePhone()
      .withMessage('Valid phone number is required'),
    body('deviceFingerprint')
      .notEmpty()
      .withMessage('Device fingerprint is required'),
    body('device')
      .isObject()
      .withMessage('Device information is required'),
    body('biometric')
      .isObject()
      .withMessage('Biometric data is required')
  ]
};