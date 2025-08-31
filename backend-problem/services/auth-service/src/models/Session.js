import pool from '../config/database.js';
import { logger } from '../utils/logger.js';
import { EncryptionUtils } from '../utils/encryption.js';
import { JWT_CONFIG } from '../utils/constants.js';

export class Session {
  // Create session
  static async create(userId, deviceId, sessionToken, refreshToken, ipAddress, userAgent) {
    const client = await pool.connect();
    try {
      const expiresAt = new Date(Date.now() + (15 * 60 * 1000)); // 15 minutes
      const refreshExpiresAt = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)); // 7 days

      const query = `
        INSERT INTO vottery_sessions (
          user_id, device_id, session_token, refresh_token, 
          expires_at, refresh_expires_at, ip_address, user_agent, 
          created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
        RETURNING *
      `;
      
      const result = await client.query(query, [
        userId, deviceId, sessionToken, refreshToken,
        expiresAt, refreshExpiresAt, ipAddress, userAgent
      ]);
      
      logger.info(`Session created for user ${userId}, device ${deviceId}`);
      return result.rows[0];
      
    } catch (error) {
      logger.error('Error creating session:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Get session by token
  static async getByToken(sessionToken) {
    const client = await pool.connect();
    try {
      const query = `
        SELECT s.*, u.sngine_email, u.status 
        FROM vottery_sessions s
        JOIN vottery_users u ON s.user_id = u.id
        WHERE s.session_token = $1 AND s.is_active = true
        LIMIT 1
      `;
      
      const result = await client.query(query, [sessionToken]);
      return result.rows[0] || null;
      
    } catch (error) {
      logger.error('Error getting session by token:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Refresh session
  static async refresh(refreshToken) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Get current session
      const getQuery = `
        SELECT * FROM vottery_sessions 
        WHERE refresh_token = $1 AND is_active = true
        LIMIT 1
      `;
      
      const result = await client.query(getQuery, [refreshToken]);
      
      if (result.rows.length === 0) {
        await client.query('ROLLBACK');
        return null;
      }

      const session = result.rows[0];

      // Check if refresh token is expired
      if (new Date() > new Date(session.refresh_expires_at)) {
        await client.query('ROLLBACK');
        return null;
      }

      // Generate new tokens
      const newSessionToken = EncryptionUtils.generateToken();
      const newRefreshToken = EncryptionUtils.generateToken();
      const newExpiresAt = new Date(Date.now() + (15 * 60 * 1000)); // 15 minutes
      const newRefreshExpiresAt = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)); // 7 days

      // Update session
      const updateQuery = `
        UPDATE vottery_sessions 
        SET session_token = $1, refresh_token = $2, 
            expires_at = $3, refresh_expires_at = $4
        WHERE id = $5
        RETURNING *
      `;
      
      const updateResult = await client.query(updateQuery, [
        newSessionToken, newRefreshToken, newExpiresAt, newRefreshExpiresAt, session.id
      ]);

      await client.query('COMMIT');
      
      logger.info(`Session refreshed for user ${session.user_id}`);
      return updateResult.rows[0];
      
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error('Error refreshing session:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Revoke session
  static async revoke(sessionToken) {
    const client = await pool.connect();
    try {
      const query = `
        UPDATE vottery_sessions 
        SET is_active = false 
        WHERE session_token = $1
        RETURNING *
      `;
      
      const result = await client.query(query, [sessionToken]);
      
      if (result.rows.length > 0) {
        logger.info(`Session revoked: ${sessionToken}`);
      }
      
      return result.rows[0] || null;
      
    } catch (error) {
      logger.error('Error revoking session:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Clean expired sessions
  static async cleanExpired() {
    const client = await pool.connect();
    try {
      const query = `
        UPDATE vottery_sessions 
        SET is_active = false 
        WHERE refresh_expires_at < CURRENT_TIMESTAMP AND is_active = true
      `;
      
      const result = await client.query(query);
      
      logger.info(`Cleaned ${result.rowCount} expired sessions`);
      return result.rowCount;
      
    } catch (error) {
      logger.error('Error cleaning expired sessions:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Get user sessions
  static async getUserSessions(userId, limit = 10) {
    const client = await pool.connect();
    try {
      const query = `
        SELECT s.*, d.device_type, d.browser_name, d.os_name
        FROM vottery_sessions s
        LEFT JOIN vottery_devices d ON s.device_id = d.id
        WHERE s.user_id = $1 AND s.is_active = true
        ORDER BY s.created_at DESC
        LIMIT $2
      `;
      
      const result = await client.query(query, [userId, limit]);
      return result.rows;
      
    } catch (error) {
      logger.error('Error getting user sessions:', error);
      throw error;
    } finally {
      client.release();
    }
  }
}