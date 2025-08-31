import express from 'express';
import { 
    updateProfile,
    getProfile,
    uploadAvatar,
    updateDemographics,
    getUserActivity,
    updateSubscription
} from '../controllers/profileController.js';
import { authenticateToken } from '../middleware/auth.js';
import { validateProfileUpdate } from '../utils/validator.js';

const router = express.Router();

// All profile routes require authentication
router.use(authenticateToken);

// Profile management
router.get('/:userId', getProfile);
router.patch('/:userId', validateProfileUpdate, updateProfile);
router.patch('/:userId/demographics',express.json({ limit: '10mb' }), updateDemographics);
router.patch('/:userId/subscription', updateSubscription);
router.post('/:userId/avatar', uploadAvatar);

// Activity tracking
router.get('/:userId/activity', getUserActivity);

export default router;