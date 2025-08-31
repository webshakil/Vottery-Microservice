import pool from '../config/database.js';
import { logger } from '../utils/logger.js';
import { EncryptionUtils } from '../utils/encryption.js';
import { USER_STATUS } from '../utils/constants.js';

export class User {
  // Check if user exists in SngEngine database
  static async checkSngineUser(email, phone) {
    const client = await pool.connect();
    try {
      const query = `
        SELECT user_id, user_email, user_phone, user_email_verified, user_phone_verified
        FROM users 
        WHERE user_email = $1 AND user_phone = $2
        LIMIT 1
      `;
      
      const result = await client.query(query, [email, phone]);
      
      if (result.rows.length === 0) {
        return { exists: false, message: 'User not found in SngEngine database' };
      }

      const user = result.rows[0];
      
      // Check if email and phone are verified in SngEngine
      if (user.user_email_verified !== 1) {
        return { exists: false, message: 'Email not verified in SngEngine' };
      }

      return {
        exists: true,
        sngineUserId: user.user_id,
        email: user.user_email,
        phone: user.user_phone,
        emailVerified: user.user_email_verified === 1,
        phoneVerified: user.user_phone_verified === 1
      };
      
    } catch (error) {
      logger.error('Error checking SngEngine user:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Create or get Vottery user
  static async createOrGetVotteryUser(email, phone) {
    const client = await pool.connect();
    try {
      // Check if Vottery user already exists
      let query = `
        SELECT * FROM vottery_users 
        WHERE sngine_email = $1 AND sngine_phone = $2
        LIMIT 1
      `;
      
      let result = await client.query(query, [email, phone]);
      
      if (result.rows.length > 0) {
        return result.rows[0];
      }

      // Create new Vottery user
      query = `
        INSERT INTO vottery_users (sngine_email, sngine_phone, status, created_at, updated_at)
        VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING *
      `;
      
      result = await client.query(query, [email, phone, USER_STATUS.PENDING]);
      logger.info(`New Vottery user created for email: ${email}`);
      
      return result.rows[0];
      
    } catch (error) {
      logger.error('Error creating/getting Vottery user:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Update user status
  static async updateStatus(userId, status, field = null) {
    const client = await pool.connect();
    try {
      let query, params;
      
      if (field) {
        query = `
          UPDATE vottery_users 
          SET status = $1, ${field} = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
          WHERE id = $2
          RETURNING *
        `;
        params = [status, userId];
      } else {
        query = `
          UPDATE vottery_users 
          SET status = $1, updated_at = CURRENT_TIMESTAMP
          WHERE id = $2
          RETURNING *
        `;
        params = [status, userId];
      }
      
      const result = await client.query(query, params);
      return result.rows[0];
      
    } catch (error) {
      logger.error('Error updating user status:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Get user by ID
  static async getById(userId) {
    const client = await pool.connect();
    try {
      const query = `
        SELECT * FROM vottery_users 
        WHERE id = $1
        LIMIT 1
      `;
      
      const result = await client.query(query, [userId]);
      return result.rows[0] || null;
      
    } catch (error) {
      logger.error('Error getting user by ID:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Update last login
  static async updateLastLogin(userId) {
    const client = await pool.connect();
    try {
      const query = `
        UPDATE vottery_users 
        SET last_login = CURRENT_TIMESTAMP
        WHERE id = $1
      `;
      
      await client.query(query, [userId]);
      
    } catch (error) {
      logger.error('Error updating last login:', error);
      throw error;
    } finally {
      client.release();
    }
  }
}