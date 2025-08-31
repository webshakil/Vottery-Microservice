import { encryptSensitiveData, decryptSensitiveData } from '../utils/encryption.js';
import { sanitizeInput } from '../utils/validator.js';
import UserManagement from '../models/UserManagement.js';
import { generateAccessToken, generateRefreshToken, createSession } from '../utils/sessionManager.js';

export const createUser = async (req, res) => {
    try {
        const { 
            user_id, 
            sngine_email, 
            sngine_phone, 
            user_age, 
            user_gender, 
            user_country, 
            device_id, 
            ip_address, 
            user_agent 
        } = req.body;

        if (!user_id) {
            return res.status(400).json({ 
                success: false, 
                message: 'user_id is required (from auth-service)' 
            });
        }

        // Encrypt sensitive fields
        const encryptedEmail = sngine_email ? encryptSensitiveData(sngine_email) : null;
        const encryptedPhone = sngine_phone ? encryptSensitiveData(sngine_phone) : null;

        // Create user profile
        await UserManagement.createUserProfile({
            user_id: parseInt(user_id, 10),
            sngine_email: encryptedEmail,
            sngine_phone: encryptedPhone,
            user_age: user_age || null,
            user_gender: user_gender || null,
            user_country: user_country || null,
            user_type: 'voter',
            admin_role: 'analyst',
            subscription_status: 'free'
        });

        // Generate tokens with proper payload
        const tokenPayload = {
            userId: parseInt(user_id, 10),
            userType: 'voter',
            adminRole: 'analyst'
        };

        const accessToken = generateAccessToken(tokenPayload);
        const refreshToken = generateRefreshToken();

        // Store session with all required info
        await createSession({ 
            userId: parseInt(user_id, 10), 
            accessToken, 
            refreshToken, 
            deviceId: device_id || null, 
            ipAddress: ip_address || req.ip, 
            userAgent: user_agent || req.headers['user-agent']
        });

        // Fetch complete user data
        const completeUser = await UserManagement.getCompleteUserById(user_id);
        
        // Decrypt sensitive data for response
        if (completeUser.sngine_email) {
            completeUser.sngine_email = decryptSensitiveData(completeUser.sngine_email);
        }
        if (completeUser.sngine_phone) {
            completeUser.sngine_phone = decryptSensitiveData(completeUser.sngine_phone);
        }

        res.status(201).json({
            success: true,
            message: 'User created successfully',
            data: completeUser,
            accessToken,
            refreshToken,
            tokenExpiry: {
                accessToken: process.env.ACCESS_TOKEN_EXPIRY || '1m',
                refreshToken: process.env.REFRESH_TOKEN_EXPIRY || '2m'
            }
        });
    } catch (error) {
        console.error('Create user profile error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to create user profile',
            error: error.message 
        });
    }
};

export const getUserById = async (req, res) => {
    try {
        const { userId } = req.params;
        const requestingUserId = req.user.userId;

        // Check if user is requesting their own profile or has admin privileges
        if (parseInt(userId) !== requestingUserId && !['manager', 'admin', 'moderator'].includes(req.user.adminRole)) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. You can only view your own profile.'
            });
        }

        const user = await UserManagement.getCompleteUserById(userId);
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Decrypt sensitive data
        if (user.sngine_email) {
            user.sngine_email = decryptSensitiveData(user.sngine_email);
        }
        if (user.sngine_phone) {
            user.sngine_phone = decryptSensitiveData(user.sngine_phone);
        }

        res.json({
            success: true,
            data: user
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve user',
            error: error.message
        });
    }
};

export const updateUserStatus = async (req, res) => {
    try {
        const { userId } = req.params;
        const { subscription_status, is_active } = req.body;

        // Only admins can update user status
        if (!['manager', 'admin', 'moderator'].includes(req.user.adminRole)) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }

        const updatedUser = await UserManagement.updateUserStatus(userId, {
            subscription_status,
            is_active
        });

        res.json({
            success: true,
            message: 'User status updated successfully',
            data: updatedUser
        });
    } catch (error) {
        console.error('Update user status error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user status',
            error: error.message
        });
    }
};

export const updateUserRole = async (req, res) => {
    try {
        const { userId } = req.params;
        const { admin_role, user_type } = req.body;

        // Only managers and admins can update user roles
        if (!['manager', 'admin'].includes(req.user.adminRole)) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Manager or Admin privileges required.'
            });
        }

        const updatedUser = await UserManagement.updateUserRole(userId, {
            admin_role,
            user_type
        });

        res.json({
            success: true,
            message: 'User role updated successfully',
            data: updatedUser
        });
    } catch (error) {
        console.error('Update user role error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user role',
            error: error.message
        });
    }
};

export const deleteUser = async (req, res) => {
    try {
        const { userId } = req.params;

        // Only managers can delete users
        if (req.user.adminRole !== 'manager') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Manager privileges required.'
            });
        }

        await UserManagement.deleteUser(userId);

        res.json({
            success: true,
            message: 'User deleted successfully'
        });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete user',
            error: error.message
        });
    }
};

export const getAllUsers = async (req, res) => {
    try {
        // Only admins can view all users
        if (!['manager', 'admin', 'moderator', 'analyst'].includes(req.user.adminRole)) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }

        const { page = 1, limit = 20, user_type, subscription_status } = req.query;

        const users = await UserManagement.getAllUsers({
            page: parseInt(page),
            limit: parseInt(limit),
            user_type,
            subscription_status
        });

        // Decrypt sensitive data for all users (only for admin viewing)
        const decryptedUsers = users.map(user => ({
            ...user,
            sngine_email: user.sngine_email ? decryptSensitiveData(user.sngine_email) : null,
            sngine_phone: user.sngine_phone ? decryptSensitiveData(user.sngine_phone) : null
        }));

        res.json({
            success: true,
            data: decryptedUsers,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit)
            }
        });
    } catch (error) {
        console.error('Get all users error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve users',
            error: error.message
        });
    }
};
// // controllers/userController.js
// //import { query } from '../config/database.js';
// import { encryptSensitiveData, decryptSensitiveData } from '../utils/encryption.js';
// import { sanitizeInput } from '../utils/validator.js';
// import UserManagement from '../models/UserManagement.js';
// import { generateAccessToken, generateRefreshToken, createSession } from '../utils/sessionManager.js';



// export const createUser = async (req, res) => {
//     try {
//         const { user_id, sngine_email, sngine_phone, user_age, user_gender, user_country, device_id, ip_address, user_agent } = req.body;

//         if (!user_id) {
//             return res.status(400).json({ success: false, message: 'user_id is required (from auth-service)' });
//         }

//         // Encrypt sensitive fields
//         const encryptedEmail = encryptSensitiveData(sngine_email);
//         const encryptedPhone = encryptSensitiveData(sngine_phone);

//         // Create user profile
//         await UserManagement.createUserProfile({
//             user_id: parseInt(user_id, 10),
//             sngine_email: encryptedEmail,
//             sngine_phone: encryptedPhone,
//             user_age: user_age || null,
//             user_gender: user_gender || null,
//             user_country: user_country || null,
//             user_type: 'voter',
//             admin_role: 'analyst',
//             subscription_status: 'free'
//         });

//         // Generate tokens
//         const tokenPayload = {
//             userId: parseInt(user_id, 10),
//             userType: 'voter',
//             adminRole: 'analyst'
//         };

//         const accessToken = generateAccessToken(tokenPayload);
//         const refreshToken = generateRefreshToken();

//         // Store session
//         await createSession({ userId: parseInt(user_id, 10), accessToken, refreshToken, deviceId: device_id, ipAddress: ip_address, userAgent: user_agent });

//         // Fetch and return
//         const completeUser = await UserManagement.getCompleteUserById(user_id);
//         completeUser.sngine_email = completeUser.sngine_email ? decryptSensitiveData(completeUser.sngine_email) : null;
//         completeUser.sngine_phone = completeUser.sngine_phone ? decryptSensitiveData(completeUser.sngine_phone) : null;

//         res.status(201).json({
//             success: true,
//             data: completeUser,
//             accessToken,
//             refreshToken
//         });
//     } catch (error) {
//         console.error('Complete user profile error:', error);
//         res.status(500).json({ success: false, error: error.message });
//     }
// };

// // export const createUser = async (req, res) => {
// //     try {
// //         const { user_id, sngine_email, sngine_phone, user_age, user_gender, user_country } = req.body;

// //         if (!user_id) {
// //             return res.status(400).json({ 
// //                 success: false, 
// //                 message: 'user_id is required (from auth-service)' 
// //             });
// //         }

// //         // Encrypt sensitive fields
// //         const encryptedEmail = encryptSensitiveData(sngine_email);
// //         const encryptedPhone = encryptSensitiveData(sngine_phone);

// //         // Create user profile
// //         await UserManagement.createUserProfile({
// //             user_id: parseInt(user_id, 10),  // ✅ ensure integer
// //             sngine_email: encryptedEmail,
// //             sngine_phone: encryptedPhone,
// //             user_age: user_age || null,
// //             user_gender: user_gender || null,
// //             user_country: user_country || null,
// //             user_type: 'voter',
// //             admin_role: 'analyst',
// //             subscription_status: 'free'
// //         });

// //         // Generate JWT
// //         const tokenPayload = {
// //             userId: parseInt(user_id, 10),
// //             userType: 'voter',
// //             adminRole: 'analyst'
// //         };

// //         const accessToken = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: JWT_EXPIRY });

// //         // Store session
// //         await query(
// //             `INSERT INTO vottery_sessions (user_id, session_token, is_active, created_at, expires_at) 
// //              VALUES ($1, $2, true, NOW(), NOW() + INTERVAL '7 days')`,
// //             [parseInt(user_id, 10), accessToken]   // ✅ integer not uuid
// //         );

// //         // Fetch and return
// //         const completeUser = await UserManagement.getCompleteUserById(user_id);
// //         completeUser.sngine_email = completeUser.sngine_email ? decryptSensitiveData(completeUser.sngine_email) : null;
// //         completeUser.sngine_phone = completeUser.sngine_phone ? decryptSensitiveData(completeUser.sngine_phone) : null;

// //         res.status(201).json({ 
// //             success: true, 
// //             data: completeUser,
// //             accessToken
// //         });
// //     } catch (error) {
// //         console.error('Complete user profile error:', error);
// //         res.status(500).json({ success: false, error: error.message });
// //     }
// // };




// // Get user by ID with biometric and device info
// export const getUserById = async (req, res) => {
//     try {
//         const { userId } = req.params;
        
//         // Get complete user data
//         const user = await UserManagement.getCompleteUserById(userId);

//         if (!user) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         // Get biometric and device info
//         const deviceInfo = await UserManagement.getUserDeviceInfo(userId);
        
//         // Decrypt sensitive data for response
//         user.sngine_email = decryptSensitiveData(user.sngine_email);
//         user.sngine_phone = decryptSensitiveData(user.sngine_phone);

//         // Add biometric and device info
//         user.has_biometrics = deviceInfo.has_biometrics;
//         user.registered_devices = deviceInfo.registered_devices;

//         res.json({
//             success: true,
//             data: user
//         });

//     } catch (error) {
//         console.error('Get user error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to fetch user' 
//         });
//     }
// };

// // Update user profile (age, gender, country)
// export const updateUserProfile = async (req, res) => {
//     try {
//         const { userId } = req.params;
//         const { user_age, user_gender, user_country } = req.body;

//         // Sanitize inputs
//         const sanitizedAge = user_age ? parseInt(user_age) : null;
//         const sanitizedGender = user_gender ? sanitizeInput(user_gender.toLowerCase()) : null;
//         const sanitizedCountry = user_country ? sanitizeInput(user_country.toUpperCase()) : null;

//         // Validate age range
//         if (sanitizedAge && (sanitizedAge < 13 || sanitizedAge > 120)) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Age must be between 13 and 120' 
//             });
//         }

//         // Validate gender
//         const validGenders = ['male', 'female', 'other', 'prefer_not_to_say'];
//         if (sanitizedGender && !validGenders.includes(sanitizedGender)) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Invalid gender value' 
//             });
//         }

//         // Validate country code (2 letters)
//         if (sanitizedCountry && sanitizedCountry.length !== 2) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Country code must be 2 letters (ISO format)' 
//             });
//         }

//         // Update user management profile
//         const result = await UserManagement.updateUserProfile(userId, {
//             user_age: sanitizedAge,
//             user_gender: sanitizedGender,
//             user_country: sanitizedCountry
//         });

//         if (!result) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User profile updated successfully',
//             data: result
//         });

//     } catch (error) {
//         console.error('Update profile error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to update user profile' 
//         });
//     }
// };

// // Update user status
// export const updateUserStatus = async (req, res) => {
//     try {
//         const { userId } = req.params;
//         const { status } = req.body;

//         const validStatuses = ['pending', 'verified', 'active', 'suspended'];
//         if (!validStatuses.includes(status)) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Invalid status value' 
//             });
//         }

//         const result = await UserManagement.updateUserStatus(userId, status);

//         if (!result) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User status updated successfully',
//             data: { status: result.status }
//         });

//     } catch (error) {
//         console.error('Update status error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to update user status' 
//         });
//     }
// };

// // Update user role (Admin only)
// export const updateUserRole = async (req, res) => {
//     try {
//         const { userId } = req.params;
//         const { user_type, admin_role, subscription_status } = req.body;

//         const validUserTypes = ['voter', 'individual_creator', 'organization_creator'];
//         const validAdminRoles = ['manager', 'admin', 'moderator', 'auditor', 'editor', 'advertiser', 'analyst'];
//         const validSubscriptions = ['free', 'subscribed'];

//         const updateData = {};

//         if (user_type && validUserTypes.includes(user_type)) {
//             updateData.user_type = user_type;
//         }

//         if (admin_role && validAdminRoles.includes(admin_role)) {
//             updateData.admin_role = admin_role;
//         }

//         if (subscription_status && validSubscriptions.includes(subscription_status)) {
//             updateData.subscription_status = subscription_status;
//         }

//         if (Object.keys(updateData).length === 0) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'No valid fields to update' 
//             });
//         }

//         const result = await UserManagement.updateUserRole(userId, updateData);

//         if (!result) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User role updated successfully',
//             data: result
//         });

//     } catch (error) {
//         console.error('Update role error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to update user role' 
//         });
//     }
// };

// // Get all users (Admin only)
// export const getAllUsers = async (req, res) => {
//     try {
//         const { page = 1, limit = 10, status, user_type } = req.query;

//         const users = await UserManagement.getAllUsers({
//             page: parseInt(page),
//             limit: parseInt(limit),
//             status,
//             user_type
//         });

//         // Decrypt sensitive data
//         const decryptedUsers = users.map(user => ({
//             ...user,
//             sngine_email: decryptSensitiveData(user.sngine_email),
//             sngine_phone: decryptSensitiveData(user.sngine_phone)
//         }));

//         res.json({
//             success: true,
//             data: {
//                 users: decryptedUsers,
//                 pagination: {
//                     page: parseInt(page),
//                     limit: parseInt(limit),
//                     total: decryptedUsers.length
//                 }
//             }
//         });

//     } catch (error) {
//         console.error('Get all users error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'No users found' 
//         });
//     }
// };

// // Delete user (Superpower admin only)
// export const deleteUser = async (req, res) => {
//     try {
//         const { userId } = req.params;

//         const result = await UserManagement.deleteUser(userId);

//         if (!result) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User deleted successfully'
//         });

//     } catch (error) {
//         console.error('Delete user error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to delete user' 
//         });
//     }
// };
// //same thing 3rd version
// import { query } from '../config/database.js';
// import { encryptSensitiveData, decryptSensitiveData } from '../utils/encryption.js';
// import { sanitizeInput } from '../utils/validator.js';

// // Complete user profile (user already exists from auth-service)
// export const createUser = async (req, res) => {
//     try {
//       const { sngine_email, sngine_phone, user_age, user_gender, user_country } = req.body;
  
//       // Encrypt sensitive fields
//       const encryptedEmail = encryptSensitiveData(sngine_email);
//       const encryptedPhone = encryptSensitiveData(sngine_phone);
  
//       // Insert user into database
//       const result = await query(
//         `INSERT INTO vottery_users 
//           (sngine_email, sngine_phone, user_age, user_gender, user_country, user_type)
//          VALUES ($1, $2, $3, $4, $5, $6)
//          RETURNING *`,
//         [encryptedEmail, encryptedPhone, user_age, user_gender, user_country, 'voter']
//       );
  
//       res.status(201).json({ success: true, data: result.rows[0] });
//     } catch (error) {
//       console.error('Complete user profile error:', error);
//       res.status(500).json({ success: false, error: error.message });
//     }
//   };
  
  
  

// // Get user by ID with biometric and device info
// export const getUserById = async (req, res) => {
//     try {
//         const { userId } = req.params;
        
//         // Get user data
//         const userResult = await query(
//             'SELECT * FROM vottery_users WHERE id = $1',
//             [userId]
//         );

//         if (userResult.rows.length === 0) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         const user = userResult.rows[0];
        
//         // Get biometric registration status
//         const biometricResult = await query(
//             'SELECT COUNT(*) as biometric_count FROM vottery_biometrics WHERE user_id = $1 AND is_active = true',
//             [userId]
//         );

//         // Get registered devices count
//         const deviceResult = await query(
//             'SELECT COUNT(*) as device_count FROM vottery_devices WHERE user_id = $1 AND is_active = true',
//             [userId]
//         );
        
//         // Decrypt sensitive data for response
//         user.sngine_email = decryptSensitiveData(user.sngine_email);
//         user.sngine_phone = decryptSensitiveData(user.sngine_phone);

//         // Add biometric and device info
//         user.has_biometrics = parseInt(biometricResult.rows[0].biometric_count) > 0;
//         user.registered_devices = parseInt(deviceResult.rows[0].device_count);

//         // Remove sensitive fields from response
//         delete user.password_hash;
//         delete user.salt;

//         res.json({
//             success: true,
//             data: user
//         });

//     } catch (error) {
//         console.error('Get user error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to fetch user' 
//         });
//     }
// };

// // Update user profile (age, gender, country)
// export const updateUserProfile = async (req, res) => {
//     try {
//         const { userId } = req.params;
//         const { user_age, user_gender, user_country } = req.body;

//         // Sanitize inputs
//         const sanitizedAge = user_age ? parseInt(user_age) : null;
//         const sanitizedGender = user_gender ? sanitizeInput(user_gender.toLowerCase()) : null;
//         const sanitizedCountry = user_country ? sanitizeInput(user_country.toUpperCase()) : null;

//         // Validate age range
//         if (sanitizedAge && (sanitizedAge < 13 || sanitizedAge > 120)) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Age must be between 13 and 120' 
//             });
//         }

//         // Validate gender
//         const validGenders = ['male', 'female', 'other', 'prefer_not_to_say'];
//         if (sanitizedGender && !validGenders.includes(sanitizedGender)) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Invalid gender value' 
//             });
//         }

//         // Validate country code (2 letters)
//         if (sanitizedCountry && sanitizedCountry.length !== 2) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Country code must be 2 letters (ISO format)' 
//             });
//         }

//         // Build dynamic update query
//         let updateFields = [];
//         let values = [];
//         let paramCount = 1;

//         if (sanitizedAge !== null) {
//             updateFields.push(`user_age = $${paramCount}`);
//             values.push(sanitizedAge);
//             paramCount++;
//         }

//         if (sanitizedGender) {
//             updateFields.push(`user_gender = $${paramCount}`);
//             values.push(sanitizedGender);
//             paramCount++;
//         }

//         if (sanitizedCountry) {
//             updateFields.push(`user_country = $${paramCount}`);
//             values.push(sanitizedCountry);
//             paramCount++;
//         }

//         if (updateFields.length === 0) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'No valid fields to update' 
//             });
//         }

//         updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
//         values.push(userId);

//         const result = await query(
//             `UPDATE vottery_users SET ${updateFields.join(', ')} WHERE id = $${paramCount} 
//              RETURNING user_age, user_gender, user_country, updated_at`,
//             values
//         );

//         if (result.rows.length === 0) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User profile updated successfully',
//             data: result.rows[0]
//         });

//     } catch (error) {
//         console.error('Update profile error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to update user profile' 
//         });
//     }
// };

// // Update user status
// export const updateUserStatus = async (req, res) => {
//     try {
//         const { userId } = req.params;
//         const { status } = req.body;

//         const validStatuses = ['pending', 'verified', 'active', 'suspended'];
//         if (!validStatuses.includes(status)) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Invalid status value' 
//             });
//         }

//         const result = await query(
//             'UPDATE vottery_users SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING status',
//             [status, userId]
//         );

//         if (result.rows.length === 0) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User status updated successfully',
//             data: { status: result.rows[0].status }
//         });

//     } catch (error) {
//         console.error('Update status error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to update user status' 
//         });
//     }
// };

// // Update user role (Admin only)
// export const updateUserRole = async (req, res) => {
//     try {
//         const { userId } = req.params;
//         const { user_type, admin_role, subscription_status } = req.body;

//         const validUserTypes = ['voter', 'individual_creator', 'organization_creator'];
//         const validAdminRoles = ['manager', 'admin', 'moderator', 'auditor', 'editor', 'advertiser', 'analyst'];
//         const validSubscriptions = ['free', 'subscribed'];

//         let updateFields = [];
//         let values = [];
//         let paramCount = 1;

//         if (user_type && validUserTypes.includes(user_type)) {
//             updateFields.push(`user_type = $${paramCount}`);
//             values.push(user_type);
//             paramCount++;
//         }

//         if (admin_role && validAdminRoles.includes(admin_role)) {
//             updateFields.push(`admin_role = $${paramCount}`);
//             values.push(admin_role);
//             paramCount++;
//         }

//         if (subscription_status && validSubscriptions.includes(subscription_status)) {
//             updateFields.push(`subscription_status = $${paramCount}`);
//             values.push(subscription_status);
//             paramCount++;
//         }

//         if (updateFields.length === 0) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'No valid fields to update' 
//             });
//         }

//         updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
//         values.push(userId);

//         const result = await query(
//             `UPDATE vottery_users SET ${updateFields.join(', ')} WHERE id = $${paramCount} 
//              RETURNING user_type, admin_role, subscription_status`,
//             values
//         );

//         if (result.rows.length === 0) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User role updated successfully',
//             data: result.rows[0]
//         });

//     } catch (error) {
//         console.error('Update role error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to update user role' 
//         });
//     }
// };

// // Get all users (Admin only)
// export const getAllUsers = async (req, res) => {
//     try {
//         const { page = 1, limit = 10, status, user_type } = req.query;
//         const offset = (page - 1) * limit;

//         let whereClause = '';
//         let values = [limit, offset];
//         let paramCount = 3;

//         if (status) {
//             whereClause += ` WHERE status = $${paramCount}`;
//             values.push(status);
//             paramCount++;
//         }

//         if (user_type) {
//             whereClause += status ? ` AND user_type = $${paramCount}` : ` WHERE user_type = $${paramCount}`;
//             values.push(user_type);
//         }

//         const result = await query(
//             `SELECT id, sngine_email, sngine_phone, user_type, admin_role, subscription_status, 
//                     status, user_age, user_gender, user_country, email_verified_at, phone_verified_at, 
//                     biometric_registered_at, last_login, created_at, updated_at 
//              FROM vottery_users ${whereClause} 
//              ORDER BY created_at DESC 
//              LIMIT $1 OFFSET $2`,
//             values
//         );

//         // Decrypt sensitive data
//         const users = result.rows.map(user => ({
//             ...user,
//             sngine_email: decryptSensitiveData(user.sngine_email),
//             sngine_phone: decryptSensitiveData(user.sngine_phone)
//         }));

//         res.json({
//             success: true,
//             data: {
//                 users,
//                 pagination: {
//                     page: parseInt(page),
//                     limit: parseInt(limit),
//                     total: result.rows.length
//                 }
//             }
//         });

//     } catch (error) {
//         console.error('Get all users error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to fetch users' 
//         });
//     }
// };

// // Delete user (Superpower admin only)
// export const deleteUser = async (req, res) => {
//     try {
//         const { userId } = req.params;

//         const result = await query(
//             'DELETE FROM vottery_users WHERE id = $1 RETURNING id',
//             [userId]
//         );

//         if (result.rows.length === 0) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User deleted successfully'
//         });

//     } catch (error) {
//         console.error('Delete user error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to delete user' 
//         });
//     }
// };
//2nd version
// import { query } from '../config/database.js';
// import { encryptSensitiveData, decryptSensitiveData } from '../utils/encryption.js';
// import { sanitizeInput } from '../utils/validator.js';

// // Create new user
// export const createUser = async (req, res) => {
//     try {
//         const { sngine_email, sngine_phone, user_type = 'voter', subscription_status = 'free' } = req.body;
        
//         // Check if user already exists
//         const existingUser = await query(
//             'SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2',
//             [sngine_email, sngine_phone]
//         );
        
//         if (existingUser.rows.length > 0) {
//             return res.status(409).json({ 
//                 success: false, 
//                 message: 'User already exists with this email or phone' 
//             });
//         }

//         // Encrypt sensitive data
//         const encryptedEmail = encryptSensitiveData(sngine_email);
//         const encryptedPhone = encryptSensitiveData(sngine_phone);

//         const result = await query(
//             `INSERT INTO vottery_users (sngine_email, sngine_phone, user_type, subscription_status, status) 
//              VALUES ($1, $2, $3, $4, 'pending') RETURNING id, created_at`,
//             [encryptedEmail, encryptedPhone, user_type, subscription_status]
//         );

//         res.status(201).json({
//             success: true,
//             message: 'User created successfully',
//             data: {
//                 userId: result.rows[0].id,
//                 status: 'pending',
//                 createdAt: result.rows[0].created_at
//             }
//         });

//     } catch (error) {
//         console.error('Create user error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to create user' 
//         });
//     }
// };

// // Get user by ID with biometric and device info
// export const getUserById = async (req, res) => {
//     try {
//         const { userId } = req.params;
        
//         // Get user data
//         const userResult = await query(
//             'SELECT * FROM vottery_users WHERE id = $1',
//             [userId]
//         );

//         if (userResult.rows.length === 0) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         const user = userResult.rows[0];
        
//         // Get biometric registration status
//         const biometricResult = await query(
//             'SELECT COUNT(*) as biometric_count FROM vottery_biometrics WHERE user_id = $1 AND is_active = true',
//             [userId]
//         );

//         // Get registered devices count
//         const deviceResult = await query(
//             'SELECT COUNT(*) as device_count FROM vottery_devices WHERE user_id = $1 AND is_active = true',
//             [userId]
//         );
        
//         // Decrypt sensitive data for response
//         user.sngine_email = decryptSensitiveData(user.sngine_email);
//         user.sngine_phone = decryptSensitiveData(user.sngine_phone);

//         // Add biometric and device info
//         user.has_biometrics = parseInt(biometricResult.rows[0].biometric_count) > 0;
//         user.registered_devices = parseInt(deviceResult.rows[0].device_count);

//         // Remove sensitive fields from response
//         delete user.password_hash;
//         delete user.salt;

//         res.json({
//             success: true,
//             data: user
//         });

//     } catch (error) {
//         console.error('Get user error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to fetch user' 
//         });
//     }
// };

// // Update user profile (age, gender, country)
// export const updateUserProfile = async (req, res) => {
//     try {
//         const { userId } = req.params;
//         const { user_age, user_gender, user_country } = req.body;

//         // Sanitize inputs
//         const sanitizedAge = user_age ? parseInt(user_age) : null;
//         const sanitizedGender = user_gender ? sanitizeInput(user_gender.toLowerCase()) : null;
//         const sanitizedCountry = user_country ? sanitizeInput(user_country.toUpperCase()) : null;

//         // Validate age range
//         if (sanitizedAge && (sanitizedAge < 13 || sanitizedAge > 120)) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Age must be between 13 and 120' 
//             });
//         }

//         // Validate gender
//         const validGenders = ['male', 'female', 'other', 'prefer_not_to_say'];
//         if (sanitizedGender && !validGenders.includes(sanitizedGender)) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Invalid gender value' 
//             });
//         }

//         // Validate country code (2 letters)
//         if (sanitizedCountry && sanitizedCountry.length !== 2) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Country code must be 2 letters (ISO format)' 
//             });
//         }

//         // Build dynamic update query
//         let updateFields = [];
//         let values = [];
//         let paramCount = 1;

//         if (sanitizedAge !== null) {
//             updateFields.push(`user_age = $${paramCount}`);
//             values.push(sanitizedAge);
//             paramCount++;
//         }

//         if (sanitizedGender) {
//             updateFields.push(`user_gender = $${paramCount}`);
//             values.push(sanitizedGender);
//             paramCount++;
//         }

//         if (sanitizedCountry) {
//             updateFields.push(`user_country = $${paramCount}`);
//             values.push(sanitizedCountry);
//             paramCount++;
//         }

//         if (updateFields.length === 0) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'No valid fields to update' 
//             });
//         }

//         updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
//         values.push(userId);

//         const result = await query(
//             `UPDATE vottery_users SET ${updateFields.join(', ')} WHERE id = $${paramCount} 
//              RETURNING user_age, user_gender, user_country, updated_at`,
//             values
//         );

//         if (result.rows.length === 0) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User profile updated successfully',
//             data: result.rows[0]
//         });

//     } catch (error) {
//         console.error('Update profile error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to update user profile' 
//         });
//     }
// };

// // Update user status
// export const updateUserStatus = async (req, res) => {
//     try {
//         const { userId } = req.params;
//         const { status } = req.body;

//         const validStatuses = ['pending', 'verified', 'active', 'suspended'];
//         if (!validStatuses.includes(status)) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Invalid status value' 
//             });
//         }

//         const result = await query(
//             'UPDATE vottery_users SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING status',
//             [status, userId]
//         );

//         if (result.rows.length === 0) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User status updated successfully',
//             data: { status: result.rows[0].status }
//         });

//     } catch (error) {
//         console.error('Update status error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to update user status' 
//         });
//     }
// };

// // Update user role (Admin only)
// export const updateUserRole = async (req, res) => {
//     try {
//         const { userId } = req.params;
//         const { user_type, admin_role, subscription_status } = req.body;

//         const validUserTypes = ['voter', 'individual_creator', 'organization_creator'];
//         const validAdminRoles = ['manager', 'admin', 'moderator', 'auditor', 'editor', 'advertiser', 'analyst'];
//         const validSubscriptions = ['free', 'subscribed'];

//         let updateFields = [];
//         let values = [];
//         let paramCount = 1;

//         if (user_type && validUserTypes.includes(user_type)) {
//             updateFields.push(`user_type = $${paramCount}`);
//             values.push(user_type);
//             paramCount++;
//         }

//         if (admin_role && validAdminRoles.includes(admin_role)) {
//             updateFields.push(`admin_role = $${paramCount}`);
//             values.push(admin_role);
//             paramCount++;
//         }

//         if (subscription_status && validSubscriptions.includes(subscription_status)) {
//             updateFields.push(`subscription_status = $${paramCount}`);
//             values.push(subscription_status);
//             paramCount++;
//         }

//         if (updateFields.length === 0) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'No valid fields to update' 
//             });
//         }

//         updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
//         values.push(userId);

//         const result = await query(
//             `UPDATE vottery_users SET ${updateFields.join(', ')} WHERE id = $${paramCount} 
//              RETURNING user_type, admin_role, subscription_status`,
//             values
//         );

//         if (result.rows.length === 0) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User role updated successfully',
//             data: result.rows[0]
//         });

//     } catch (error) {
//         console.error('Update role error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to update user role' 
//         });
//     }
// };

// // Get all users (Admin only)
// export const getAllUsers = async (req, res) => {
//     try {
//         const { page = 1, limit = 10, status, user_type } = req.query;
//         const offset = (page - 1) * limit;

//         let whereClause = '';
//         let values = [limit, offset];
//         let paramCount = 3;

//         if (status) {
//             whereClause += ` WHERE status = $${paramCount}`;
//             values.push(status);
//             paramCount++;
//         }

//         if (user_type) {
//             whereClause += status ? ` AND user_type = $${paramCount}` : ` WHERE user_type = $${paramCount}`;
//             values.push(user_type);
//         }

//         const result = await query(
//             `SELECT id, sngine_email, sngine_phone, user_type, admin_role, subscription_status, 
//                     status, user_age, user_gender, user_country, email_verified_at, phone_verified_at, 
//                     biometric_registered_at, last_login, created_at, updated_at 
//              FROM vottery_users ${whereClause} 
//              ORDER BY created_at DESC 
//              LIMIT $1 OFFSET $2`,
//             values
//         );

//         // Decrypt sensitive data
//         const users = result.rows.map(user => ({
//             ...user,
//             sngine_email: decryptSensitiveData(user.sngine_email),
//             sngine_phone: decryptSensitiveData(user.sngine_phone)
//         }));

//         res.json({
//             success: true,
//             data: {
//                 users,
//                 pagination: {
//                     page: parseInt(page),
//                     limit: parseInt(limit),
//                     total: result.rows.length
//                 }
//             }
//         });

//     } catch (error) {
//         console.error('Get all users error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to fetch users' 
//         });
//     }
// };

// // Delete user (Superpower admin only)
// export const deleteUser = async (req, res) => {
//     try {
//         const { userId } = req.params;

//         const result = await query(
//             'DELETE FROM vottery_users WHERE id = $1 RETURNING id',
//             [userId]
//         );

//         if (result.rows.length === 0) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User deleted successfully'
//         });

//     } catch (error) {
//         console.error('Delete user error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to delete user' 
//         });
//     }
// };

//same thing ist version
// import { query } from '../config/database.js';
// import { encryptSensitiveData, decryptSensitiveData } from '../utils/encryption.js';
// import bcrypt from 'bcryptjs';

// // Create new user
// export const createUser = async (req, res) => {
//     try {
//         const { sngine_email, sngine_phone, user_type = 'voter', subscription_status = 'free' } = req.body;
        
//         // Check if user already exists
//         const existingUser = await query(
//             'SELECT id FROM vottery_users WHERE sngine_email = $1 OR sngine_phone = $2',
//             [sngine_email, sngine_phone]
//         );
        
//         if (existingUser.rows.length > 0) {
//             return res.status(409).json({ 
//                 success: false, 
//                 message: 'User already exists with this email or phone' 
//             });
//         }

//         // Encrypt sensitive data
//         const encryptedEmail = encryptSensitiveData(sngine_email);
//         const encryptedPhone = encryptSensitiveData(sngine_phone);

//         const result = await query(
//             `INSERT INTO vottery_users (sngine_email, sngine_phone, user_type, subscription_status, status) 
//              VALUES ($1, $2, $3, $4, 'pending') RETURNING id, created_at`,
//             [encryptedEmail, encryptedPhone, user_type, subscription_status]
//         );

//         res.status(201).json({
//             success: true,
//             message: 'User created successfully',
//             data: {
//                 userId: result.rows[0].id,
//                 status: 'pending',
//                 createdAt: result.rows[0].created_at
//             }
//         });

//     } catch (error) {
//         console.error('Create user error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to create user' 
//         });
//     }
// };

// // Get user by ID
// export const getUserById = async (req, res) => {
//     try {
//         const { userId } = req.params;
        
//         const result = await query(
//             'SELECT * FROM vottery_users WHERE id = $1',
//             [userId]
//         );

//         if (result.rows.length === 0) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         const user = result.rows[0];
        
//         // Decrypt sensitive data for response
//         user.sngine_email = decryptSensitiveData(user.sngine_email);
//         user.sngine_phone = decryptSensitiveData(user.sngine_phone);

//         // Remove sensitive fields from response
//         delete user.password_hash;
//         delete user.salt;

//         res.json({
//             success: true,
//             data: user
//         });

//     } catch (error) {
//         console.error('Get user error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to fetch user' 
//         });
//     }
// };

// // Update user status
// export const updateUserStatus = async (req, res) => {
//     try {
//         const { userId } = req.params;
//         const { status } = req.body;

//         const validStatuses = ['pending', 'verified', 'active', 'suspended'];
//         if (!validStatuses.includes(status)) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Invalid status value' 
//             });
//         }

//         const result = await query(
//             'UPDATE vottery_users SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING status',
//             [status, userId]
//         );

//         if (result.rows.length === 0) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User status updated successfully',
//             data: { status: result.rows[0].status }
//         });

//     } catch (error) {
//         console.error('Update status error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to update user status' 
//         });
//     }
// };

// // Update user role
// export const updateUserRole = async (req, res) => {
//     try {
//         const { userId } = req.params;
//         const { user_type, admin_role, subscription_status } = req.body;

//         const validUserTypes = ['voter', 'individual_creator', 'organization_creator'];
//         const validAdminRoles = ['manager', 'admin', 'moderator', 'auditor', 'editor', 'advertiser', 'analyst'];
//         const validSubscriptions = ['free', 'subscribed'];

//         let updateFields = [];
//         let values = [];
//         let paramCount = 1;

//         if (user_type && validUserTypes.includes(user_type)) {
//             updateFields.push(`user_type = $${paramCount}`);
//             values.push(user_type);
//             paramCount++;
//         }

//         if (admin_role && validAdminRoles.includes(admin_role)) {
//             updateFields.push(`admin_role = $${paramCount}`);
//             values.push(admin_role);
//             paramCount++;
//         }

//         if (subscription_status && validSubscriptions.includes(subscription_status)) {
//             updateFields.push(`subscription_status = $${paramCount}`);
//             values.push(subscription_status);
//             paramCount++;
//         }

//         if (updateFields.length === 0) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'No valid fields to update' 
//             });
//         }

//         updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
//         values.push(userId);

//         const result = await query(
//             `UPDATE vottery_users SET ${updateFields.join(', ')} WHERE id = $${paramCount} 
//              RETURNING user_type, admin_role, subscription_status`,
//             values
//         );

//         if (result.rows.length === 0) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User role updated successfully',
//             data: result.rows[0]
//         });

//     } catch (error) {
//         console.error('Update role error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to update user role' 
//         });
//     }
// };

// // Get all users (admin only)
// export const getAllUsers = async (req, res) => {
//     try {
//         const { page = 1, limit = 10, status, user_type } = req.query;
//         const offset = (page - 1) * limit;

//         let whereClause = '';
//         let values = [limit, offset];
//         let paramCount = 3;

//         if (status) {
//             whereClause += ` WHERE status = $${paramCount}`;
//             values.push(status);
//             paramCount++;
//         }

//         if (user_type) {
//             whereClause += status ? ` AND user_type = $${paramCount}` : ` WHERE user_type = $${paramCount}`;
//             values.push(user_type);
//         }

//         const result = await query(
//             `SELECT id, sngine_email, sngine_phone, user_type, admin_role, subscription_status, 
//                     status, email_verified_at, phone_verified_at, biometric_registered_at, 
//                     last_login, created_at, updated_at 
//              FROM vottery_users ${whereClause} 
//              ORDER BY created_at DESC 
//              LIMIT $1 OFFSET $2`,
//             values
//         );

//         // Decrypt sensitive data
//         const users = result.rows.map(user => ({
//             ...user,
//             sngine_email: decryptSensitiveData(user.sngine_email),
//             sngine_phone: decryptSensitiveData(user.sngine_phone)
//         }));

//         res.json({
//             success: true,
//             data: {
//                 users,
//                 pagination: {
//                     page: parseInt(page),
//                     limit: parseInt(limit),
//                     total: result.rows.length
//                 }
//             }
//         });

//     } catch (error) {
//         console.error('Get all users error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to fetch users' 
//         });
//     }
// };

// // Delete user
// export const deleteUser = async (req, res) => {
//     try {
//         const { userId } = req.params;

//         const result = await query(
//             'DELETE FROM vottery_users WHERE id = $1 RETURNING id',
//             [userId]
//         );

//         if (result.rows.length === 0) {
//             return res.status(404).json({ 
//                 success: false, 
//                 message: 'User not found' 
//             });
//         }

//         res.json({
//             success: true,
//             message: 'User deleted successfully'
//         });

//     } catch (error) {
//         console.error('Delete user error:', error);
//         res.status(500).json({ 
//             success: false, 
//             message: 'Failed to delete user' 
//         });
//     }
// };