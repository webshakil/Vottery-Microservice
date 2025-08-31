// models/UserManagement.js
import { query } from '../config/database.js';
class UserManagement {
    static async createUserProfile(userData) {
        const {
            user_id,
            sngine_email,
            sngine_phone,
            user_type = 'voter',
            admin_role = 'analyst',
            subscription_status = 'free',
            user_age = null,
            user_gender = null,
            user_country = null
        } = userData;

        try {
            // Check if user_id already exists
            const existingUser = await query(
                `SELECT * FROM vottery_user_management WHERE user_id = $1`,
                [user_id]
            );

            if (existingUser.rows.length > 0) {
                // User already exists, return existing row
                return existingUser.rows[0];
            }

            // Insert new user
            const result = await query(
                `INSERT INTO vottery_user_management (
                    user_id, sngine_email, sngine_phone, user_type, admin_role, subscription_status,
                    user_age, user_gender, user_country
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING *`,
                [
                    user_id, sngine_email, sngine_phone, user_type, admin_role, subscription_status,
                    user_age, user_gender, user_country
                ]
            );

            return result.rows[0];
        } catch (error) {
            throw error;
        }
    }





    


    // Get complete user data (joins vottery_users + vottery_user_management)
    static async getCompleteUserById(userId) {
        try {
            const result = await query(
                `SELECT 
                    vu.id,
                    vu.sngine_email,
                    vu.sngine_phone,
                    vu.email_verified_at,
                    vu.phone_verified_at,
                    vu.biometric_registered_at,
                    vu.status,
                    vu.last_login,
                    vu.created_at,
                    vu.updated_at,
                    COALESCE(vum.user_type, 'voter') as user_type,
                    vum.admin_role,
                    COALESCE(vum.subscription_status, 'free') as subscription_status,
                    vum.subscription_plan,
                    vum.subscription_expires_at,
                    vum.first_name,
                    vum.last_name,
                    vum.date_of_birth,
                    vum.gender,
                    vum.country,
                    vum.city,
                    COALESCE(vum.timezone, 'UTC') as timezone,
                    vum.user_age,
                    vum.user_gender,
                    vum.user_country
                FROM vottery_users vu
                LEFT JOIN vottery_user_management vum ON vu.id = vum.user_id
                WHERE vu.id = $1`,
                [userId]
            );
            return result.rows[0] || null;
        } catch (error) {
            throw error;
        }
    }

    // Update user profile (age, gender, country in user_management table)
    static async updateUserProfile(userId, profileData) {
        const allowedFields = ['user_age', 'user_gender', 'user_country', 'first_name', 'last_name', 'city', 'timezone'];
        
        let updateFields = [];
        let values = [];
        let paramCount = 1;

        Object.keys(profileData).forEach(key => {
            if (allowedFields.includes(key) && profileData[key] !== undefined) {
                updateFields.push(`${key} = $${paramCount}`);
                values.push(profileData[key]);
                paramCount++;
            }
        });

        if (updateFields.length === 0) {
            throw new Error('No valid fields to update');
        }

        updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
        values.push(userId);

        try {
            // Check if user_management record exists, if not create it
            const existsResult = await query(
                'SELECT user_id FROM vottery_user_management WHERE user_id = $1',
                [userId]
            );

            if (existsResult.rows.length === 0) {
                // Create user_management record first
                await this.createUserProfile({ user_id: userId, ...profileData });
            }

            const result = await query(
                `UPDATE vottery_user_management 
                 SET ${updateFields.join(', ')} 
                 WHERE user_id = $${paramCount}
                 RETURNING user_age, user_gender, user_country, first_name, last_name, city, timezone, updated_at`,
                values
            );

            return result.rows[0] || null;
        } catch (error) {
            throw error;
        }
    }

    // Update user role/subscription (admin operations)
    static async updateUserRole(userId, roleData) {
        const allowedFields = ['user_type', 'admin_role', 'subscription_status', 'subscription_plan'];
        
        let updateFields = [];
        let values = [];
        let paramCount = 1;

        Object.keys(roleData).forEach(key => {
            if (allowedFields.includes(key) && roleData[key] !== undefined) {
                updateFields.push(`${key} = $${paramCount}`);
                values.push(roleData[key]);
                paramCount++;
            }
        });

        if (updateFields.length === 0) {
            throw new Error('No valid fields to update');
        }

        updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
        values.push(userId);

        try {
            // Ensure user_management record exists
            const existsResult = await query(
                'SELECT user_id FROM vottery_user_management WHERE user_id = $1',
                [userId]
            );

            if (existsResult.rows.length === 0) {
                await this.createUserProfile({ user_id: userId, ...roleData });
            }

            const result = await query(
                `UPDATE vottery_user_management 
                 SET ${updateFields.join(', ')} 
                 WHERE user_id = $${paramCount}
                 RETURNING user_type, admin_role, subscription_status, subscription_plan`,
                values
            );

            return result.rows[0] || null;
        } catch (error) {
            throw error;
        }
    }

    // Update user status (in vottery_users table)
    static async updateUserStatus(userId, status) {
        try {
            const result = await query(
                'UPDATE vottery_users SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING status',
                [status, userId]
            );
            return result.rows[0] || null;
        } catch (error) {
            throw error;
        }
    }

    // Get all users with pagination and filters
    // Get all users with pagination (simplified query)
static async getAllUsers(filters = {}) {
    const { page = 1, limit = 10 } = filters;
    const offset = (page - 1) * limit;

    try {
        const result = await query(
            `SELECT *
             FROM vottery_user_management
             ORDER BY created_at DESC
             LIMIT $1 OFFSET $2`,
            [limit, offset]
        );

        return result.rows;
    } catch (error) {
        throw error;
    }
}

  

    // Get biometric and device counts
    static async getUserDeviceInfo(userId) {
        try {
            const biometricResult = await query(
                'SELECT COUNT(*) as biometric_count FROM vottery_biometrics WHERE user_id = $1 AND is_active = true',
                [userId]
            );

            const deviceResult = await query(
                'SELECT COUNT(*) as device_count FROM vottery_devices WHERE user_id = $1 AND is_active = true',
                [userId]
            );

            return {
                has_biometrics: parseInt(biometricResult.rows[0].biometric_count) > 0,
                registered_devices: parseInt(deviceResult.rows[0].device_count)
            };
        } catch (error) {
            throw error;
        }
    }

    // Delete user (cascades to user_management)
    static async deleteUser(userId) {
        try {
            const result = await query(
                'DELETE FROM vottery_users WHERE id = $1 RETURNING id',
                [userId]
            );
            return result.rows[0] || null;
        } catch (error) {
            throw error;
        }
    }
}

export default UserManagement;
// // models/UserManagement.js
// import { query } from '../config/database.js';

// class UserManagement {
//     // Complete user profile (user already exists from auth-service)
//     static async createUserProfile(userData) {
//         const {
//             user_id,
//             user_type = 'voter',
//             admin_role = 'analyst',
//             subscription_status = 'free',
//             subscription_plan = null,
//             subscription_expires_at = null,
//             first_name = null,
//             last_name = null,
//             date_of_birth = null,
//             gender = null,
//             country = null,
//             city = null,
//             timezone = 'UTC',
//             user_age = null,
//             user_gender = null,
//             user_country = null
//         } = userData;

//         try {
//             const result = await query(
//                 `INSERT INTO vottery_user_management (
//                     user_id, user_type, admin_role, subscription_status, subscription_plan,
//                     subscription_expires_at, first_name, last_name, date_of_birth, gender,
//                     country, city, timezone, user_age, user_gender, user_country
//                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
//                 RETURNING *`,
//                 [
//                     user_id, user_type, admin_role, subscription_status, subscription_plan,
//                     subscription_expires_at, first_name, last_name, date_of_birth, gender,
//                     country, city, timezone, user_age, user_gender, user_country
//                 ]
//             );
//             return result.rows[0];
//         } catch (error) {
//             throw error;
//         }
//     }

//     // Get complete user data (joins vottery_users + vottery_user_management)
//     static async getCompleteUserById(userId) {
//         try {
//             const result = await query(
//                 `SELECT 
//                     vu.id,
//                     vu.sngine_email,
//                     vu.sngine_phone,
//                     vu.email_verified_at,
//                     vu.phone_verified_at,
//                     vu.biometric_registered_at,
//                     vu.status,
//                     vu.last_login,
//                     vu.created_at,
//                     vu.updated_at,
//                     COALESCE(vum.user_type, 'voter') as user_type,
//                     vum.admin_role,
//                     COALESCE(vum.subscription_status, 'free') as subscription_status,
//                     vum.subscription_plan,
//                     vum.subscription_expires_at,
//                     vum.first_name,
//                     vum.last_name,
//                     vum.date_of_birth,
//                     vum.gender,
//                     vum.country,
//                     vum.city,
//                     COALESCE(vum.timezone, 'UTC') as timezone,
//                     vum.user_age,
//                     vum.user_gender,
//                     vum.user_country
//                 FROM vottery_users vu
//                 LEFT JOIN vottery_user_management vum ON vu.id = vum.user_id
//                 WHERE vu.id = $1`,
//                 [userId]
//             );
//             return result.rows[0] || null;
//         } catch (error) {
//             throw error;
//         }
//     }

//     // Update user profile (age, gender, country in user_management table)
//     static async updateUserProfile(userId, profileData) {
//         const allowedFields = ['user_age', 'user_gender', 'user_country', 'first_name', 'last_name', 'city', 'timezone'];
        
//         let updateFields = [];
//         let values = [];
//         let paramCount = 1;

//         Object.keys(profileData).forEach(key => {
//             if (allowedFields.includes(key) && profileData[key] !== undefined) {
//                 updateFields.push(`${key} = $${paramCount}`);
//                 values.push(profileData[key]);
//                 paramCount++;
//             }
//         });

//         if (updateFields.length === 0) {
//             throw new Error('No valid fields to update');
//         }

//         updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
//         values.push(userId);

//         try {
//             // Check if user_management record exists, if not create it
//             const existsResult = await query(
//                 'SELECT user_id FROM vottery_user_management WHERE user_id = $1',
//                 [userId]
//             );

//             if (existsResult.rows.length === 0) {
//                 // Create user_management record first
//                 await this.createUserProfile({ user_id: userId, ...profileData });
//             }

//             const result = await query(
//                 `UPDATE vottery_user_management 
//                  SET ${updateFields.join(', ')} 
//                  WHERE user_id = $${paramCount}
//                  RETURNING user_age, user_gender, user_country, first_name, last_name, city, timezone, updated_at`,
//                 values
//             );

//             return result.rows[0] || null;
//         } catch (error) {
//             throw error;
//         }
//     }

//     // Update user role/subscription (admin operations)
//     static async updateUserRole(userId, roleData) {
//         const allowedFields = ['user_type', 'admin_role', 'subscription_status', 'subscription_plan'];
        
//         let updateFields = [];
//         let values = [];
//         let paramCount = 1;

//         Object.keys(roleData).forEach(key => {
//             if (allowedFields.includes(key) && roleData[key] !== undefined) {
//                 updateFields.push(`${key} = $${paramCount}`);
//                 values.push(roleData[key]);
//                 paramCount++;
//             }
//         });

//         if (updateFields.length === 0) {
//             throw new Error('No valid fields to update');
//         }

//         updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
//         values.push(userId);

//         try {
//             // Ensure user_management record exists
//             const existsResult = await query(
//                 'SELECT user_id FROM vottery_user_management WHERE user_id = $1',
//                 [userId]
//             );

//             if (existsResult.rows.length === 0) {
//                 await this.createUserProfile({ user_id: userId, ...roleData });
//             }

//             const result = await query(
//                 `UPDATE vottery_user_management 
//                  SET ${updateFields.join(', ')} 
//                  WHERE user_id = $${paramCount}
//                  RETURNING user_type, admin_role, subscription_status, subscription_plan`,
//                 values
//             );

//             return result.rows[0] || null;
//         } catch (error) {
//             throw error;
//         }
//     }

//     // Update user status (in vottery_users table)
//     static async updateUserStatus(userId, status) {
//         try {
//             const result = await query(
//                 'UPDATE vottery_users SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING status',
//                 [status, userId]
//             );
//             return result.rows[0] || null;
//         } catch (error) {
//             throw error;
//         }
//     }

//     // Get all users with pagination and filters
//     static async getAllUsers(filters = {}) {
//         const { page = 1, limit = 10, status, user_type } = filters;
//         const offset = (page - 1) * limit;

//         let whereClause = '';
//         let values = [limit, offset];
//         let paramCount = 3;

//         if (status) {
//             whereClause += ` WHERE vu.status = $${paramCount}`;
//             values.push(status);
//             paramCount++;
//         }

//         if (user_type) {
//             const andOr = status ? ' AND' : ' WHERE';
//             whereClause += `${andOr} COALESCE(vum.user_type, 'voter') = $${paramCount}`;
//             values.push(user_type);
//         }

//         try {
//             const result = await query(
//                 `SELECT 
//                     vu.id, vu.sngine_email, vu.sngine_phone, vu.status, vu.email_verified_at, 
//                     vu.phone_verified_at, vu.biometric_registered_at, vu.last_login, 
//                     vu.created_at, vu.updated_at,
//                     COALESCE(vum.user_type, 'voter') as user_type,
//                     vum.admin_role,
//                     COALESCE(vum.subscription_status, 'free') as subscription_status,
//                     vum.user_age, vum.user_gender, vum.user_country
//                 FROM vottery_users vu
//                 LEFT JOIN vottery_user_management vum ON vu.id = vum.user_id
//                 ${whereClause}
//                 ORDER BY vu.created_at DESC 
//                 LIMIT $1 OFFSET $2`,
//                 values
//             );

//             return result.rows;
//         } catch (error) {
//             throw error;
//         }
//     }

//     // Get biometric and device counts
//     static async getUserDeviceInfo(userId) {
//         try {
//             const biometricResult = await query(
//                 'SELECT COUNT(*) as biometric_count FROM vottery_biometrics WHERE user_id = $1 AND is_active = true',
//                 [userId]
//             );

//             const deviceResult = await query(
//                 'SELECT COUNT(*) as device_count FROM vottery_devices WHERE user_id = $1 AND is_active = true',
//                 [userId]
//             );

//             return {
//                 has_biometrics: parseInt(biometricResult.rows[0].biometric_count) > 0,
//                 registered_devices: parseInt(deviceResult.rows[0].device_count)
//             };
//         } catch (error) {
//             throw error;
//         }
//     }

//     // Delete user (cascades to user_management)
//     static async deleteUser(userId) {
//         try {
//             const result = await query(
//                 'DELETE FROM vottery_users WHERE id = $1 RETURNING id',
//                 [userId]
//             );
//             return result.rows[0] || null;
//         } catch (error) {
//             throw error;
//         }
//     }
// }

// export default UserManagement;