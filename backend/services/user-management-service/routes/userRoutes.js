import express from 'express';
import { 
    createUser, 
    getUserById, 
    updateUserStatus, 
    updateUserRole,
    deleteUser,
    getAllUsers
} from '../controllers/userController.js';
import { authenticateToken } from '../middleware/auth.js';
import { validateUserCreation, validateUserUpdate } from '../utils/validator.js';

const router = express.Router();

// Public routes (no auth required)
//router.post('/create', validateUserCreation, createUser);
router.post('/create', express.json({ limit: '10mb' }), createUser);

// Protected routes (auth required)
router.use(authenticateToken);

router.get('/profile/:userId', getUserById);
router.get('/all', getAllUsers);
router.patch('/status/:userId', express.json({ limit: '10mb' }),validateUserUpdate, updateUserStatus);
router.patch('/role/:userId', express.json({ limit: '10mb' }),validateUserUpdate, updateUserRole);
router.delete('/:userId', deleteUser);

export default router;