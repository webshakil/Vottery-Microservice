import express from 'express';
import { BiometricController } from '../controllers/biometricController.js';
import { validateDevice, validateBiometric } from '../middleware/validation.js';
import { biometricRateLimit } from '../middleware/rateLimit.js';

const router = express.Router();

// Device routes
router.post('/device/register', biometricRateLimit, validateDevice, BiometricController.registerDevice);
router.get('/device/:userId', BiometricController.getUserDevices);
router.put('/device/:deviceId/status', BiometricController.updateDeviceStatus);

// Biometric routes
router.post('/register', biometricRateLimit, validateBiometric, BiometricController.registerBiometric);
router.post('/verify', biometricRateLimit, validateBiometric, BiometricController.verifyBiometric);
router.get('/user/:userId', BiometricController.getUserBiometrics);
router.delete('/:biometricId', BiometricController.deleteBiometric);

// WebAuthn routes
router.post('/webauthn/register/begin', BiometricController.beginWebAuthnRegistration);
router.post('/webauthn/register/finish', BiometricController.finishWebAuthnRegistration);
router.post('/webauthn/authenticate/begin', BiometricController.beginWebAuthnAuthentication);
router.post('/webauthn/authenticate/finish', BiometricController.finishWebAuthnAuthentication);

export { router as biometricRoutes };