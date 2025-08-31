import { query } from '../config/database.js';
import { encryptSensitiveData, decryptSensitiveData } from '../utils/encryption.js';

// Get user profile
export const getProfile = async (req, res) => {
    try {
        const { userId } = req.params;
        
        const result = await query(`
            SELECT 
                id, sngine_email, sngine_phone, user_type, admin_role, subscription_status,
                status, email_verified_at, phone_verified_at, biometric_registered_at,
                first_name, last_name, date_of_birth, gender, country, city, 
                bio, avatar_url, timezone, language, notifications_enabled,
                last_login, created_at, updated_at
            FROM vottery_users 
            WHERE id = $1
        `, [userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        const user = result.rows[0];
        
        // Decrypt sensitive data
        user.sngine_email = decryptSensitiveData(user.sngine_email);
        user.sngine_phone = decryptSensitiveData(user.sngine_phone);

        res.json({
            success: true,
            data: user
        });

    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch profile' 
        });
    }
};

// Update user profile
export const updateProfile = async (req, res) => {
    try {
        const { userId } = req.params;
        const { 
            first_name, 
            last_name, 
            bio, 
            timezone, 
            language, 
            notifications_enabled 
        } = req.body;

        let updateFields = [];
        let values = [];
        let paramCount = 1;

        if (first_name !== undefined) {
            updateFields.push(`first_name = $${paramCount}`);
            values.push(first_name);
            paramCount++;
        }

        if (last_name !== undefined) {
            updateFields.push(`last_name = $${paramCount}`);
            values.push(last_name);
            paramCount++;
        }

        if (bio !== undefined) {
            updateFields.push(`bio = $${paramCount}`);
            values.push(bio);
            paramCount++;
        }

        if (timezone !== undefined) {
            updateFields.push(`timezone = $${paramCount}`);
            values.push(timezone);
            paramCount++;
        }

        if (language !== undefined) {
            updateFields.push(`language = $${paramCount}`);
            values.push(language);
            paramCount++;
        }

        if (notifications_enabled !== undefined) {
            updateFields.push(`notifications_enabled = $${paramCount}`);
            values.push(notifications_enabled);
            paramCount++;
        }

        if (updateFields.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'No fields to update' 
            });
        }

        updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
        values.push(userId);

        const result = await query(`
            UPDATE vottery_users 
            SET ${updateFields.join(', ')} 
            WHERE id = $${paramCount} 
            RETURNING first_name, last_name, bio, timezone, language, notifications_enabled
        `, values);

        if (result.rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        // Log activity
        await logActivity(userId, 'profile_update', { fields: Object.keys(req.body) });

        res.json({
            success: true,
            message: 'Profile updated successfully',
            data: result.rows[0]
        });

    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to update profile' 
        });
    }
};

// Update demographics
export const updateDemographics = async (req, res) => {
    try {
        const { userId } = req.params;
        const { date_of_birth, gender, country, city } = req.body;

        let updateFields = [];
        let values = [];
        let paramCount = 1;

        if (date_of_birth !== undefined) {
            updateFields.push(`date_of_birth = $${paramCount}`);
            values.push(date_of_birth);
            paramCount++;
        }

        if (gender !== undefined) {
            updateFields.push(`gender = $${paramCount}`);
            values.push(gender);
            paramCount++;
        }

        if (country !== undefined) {
            updateFields.push(`country = $${paramCount}`);
            values.push(country);
            paramCount++;
        }

        if (city !== undefined) {
            updateFields.push(`city = $${paramCount}`);
            values.push(city);
            paramCount++;
        }

        if (updateFields.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'No demographic fields to update' 
            });
        }

        updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
        values.push(userId);

        const result = await query(`
            UPDATE vottery_user_management 
            SET ${updateFields.join(', ')} 
            WHERE id = $${paramCount} 
            RETURNING date_of_birth, gender, country, city
        `, values);

        if (result.rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        // Log activity
        await logActivity(userId, 'demographics_update', { fields: Object.keys(req.body) });

        res.json({
            success: true,
            message: 'Demographics updated successfully',
            data: result.rows[0]
        });

    } catch (error) {
        console.error('Update demographics error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to update demographics' 
        });
    }
};

// Update subscription
export const updateSubscription = async (req, res) => {
    try {
        const { userId } = req.params;
        const { subscription_status, subscription_plan, subscription_expires_at } = req.body;

        let updateFields = [];
        let values = [];
        let paramCount = 1;

        if (subscription_status !== undefined) {
            const validStatuses = ['free', 'subscribed'];
            if (!validStatuses.includes(subscription_status)) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Invalid subscription status' 
                });
            }
            updateFields.push(`subscription_status = $${paramCount}`);
            values.push(subscription_status);
            paramCount++;
        }

        if (subscription_plan !== undefined) {
            const validPlans = ['pay_as_you_go', 'monthly', '3_month', '6_month', 'yearly'];
            if (!validPlans.includes(subscription_plan)) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Invalid subscription plan' 
                });
            }
            updateFields.push(`subscription_plan = $${paramCount}`);
            values.push(subscription_plan);
            paramCount++;
        }

        if (subscription_expires_at !== undefined) {
            updateFields.push(`subscription_expires_at = $${paramCount}`);
            values.push(subscription_expires_at);
            paramCount++;
        }

        if (updateFields.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'No subscription fields to update' 
            });
        }

        updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
        values.push(userId);

        const result = await query(`
            UPDATE vottery_users 
            SET ${updateFields.join(', ')} 
            WHERE id = $${paramCount} 
            RETURNING subscription_status, subscription_plan, subscription_expires_at
        `, values);

        if (result.rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        // Log activity
        await logActivity(userId, 'subscription_update', { 
            status: subscription_status, 
            plan: subscription_plan 
        });

        res.json({
            success: true,
            message: 'Subscription updated successfully',
            data: result.rows[0]
        });

    } catch (error) {
        console.error('Update subscription error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to update subscription' 
        });
    }
};

// Upload avatar (placeholder - in production use cloud storage)
export const uploadAvatar = async (req, res) => {
    try {
        const { userId } = req.params;
        const { avatar_url } = req.body;

        if (!avatar_url) {
            return res.status(400).json({ 
                success: false, 
                message: 'Avatar URL required' 
            });
        }

        const result = await query(`
            UPDATE vottery_users 
            SET avatar_url = $1, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $2 
            RETURNING avatar_url
        `, [avatar_url, userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        // Log activity
        await logActivity(userId, 'avatar_update', { avatar_url });

        res.json({
            success: true,
            message: 'Avatar updated successfully',
            data: { avatar_url: result.rows[0].avatar_url }
        });

    } catch (error) {
        console.error('Upload avatar error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to upload avatar' 
        });
    }
};

// Get user activity logs
export const getUserActivity = async (req, res) => {
    try {
        const { userId } = req.params;
        const { page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;

        const result = await query(`
            SELECT 
                id, action, details, ip_address, user_agent, success, created_at
            FROM vottery_audit_logs 
            WHERE user_id = $1 
            ORDER BY created_at DESC 
            LIMIT $2 OFFSET $3
        `, [userId, limit, offset]);

        res.json({
            success: true,
            data: {
                activities: result.rows,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: result.rows.length
                }
            }
        });

    } catch (error) {
        console.error('Get activity error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch activity' 
        });
    }
};

// Helper function to log user activities
const logActivity = async (userId, action, details = {}, req = null) => {
    try {
        await query(`
            INSERT INTO vottery_audit_logs (user_id, action, details, ip_address, user_agent, success) 
            VALUES ($1, $2, $3, $4, $5, $6)
        `, [
            userId,
            action,
            JSON.stringify(details),
            req?.ip || null,
            req?.get('User-Agent') || null,
            true
        ]);
    } catch (error) {
        console.error('Log activity error:', error);
    }
};