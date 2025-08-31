import { db } from '../config/database.js';
import { DeviceUtils } from '../utils/deviceUtils.js';
import { logger } from '../utils/logger.js';

export class DeviceService {
  static async registerDevice(deviceData) {
    const {
      userId, // This should be an integer from SERIAL PRIMARY KEY
      deviceInfo,
      ipAddress,
      userAgent,
      location,
      capabilities
    } = deviceData;

    try {
      console.log('DeviceService.registerDevice called with:', {
        userId,
        deviceInfo,
        userIdType: typeof userId
      });

      // Debug: Check actual table schema
      const schemaCheck = await db.query(`
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'vottery_devices' AND column_name = 'user_id'
      `);
      console.log('Actual vottery_devices.user_id schema:', schemaCheck.rows);

      // Validate that userId exists and is a number
      if (!userId || typeof userId !== 'number') {
        throw new Error('Valid user ID (integer) is required');
      }

      // Generate device fingerprint using the actual deviceInfo structure
      const deviceFingerprint = DeviceUtils.generateFingerprint({
        userAgent,
        ipAddress,
        deviceInfo // Pass deviceInfo as a property, not spread
      });

      console.log('Generated device fingerprint:', deviceFingerprint);

      // Check if device already exists - make sure userId is treated as integer
      const existingDevice = await db.query(
        `SELECT id FROM vottery_devices WHERE device_fingerprint = $1 AND user_id = $2`,
        [deviceFingerprint, userId]
      );

      if (existingDevice.rows.length > 0) {
        console.log('Device already exists, updating...');
        // Update existing device
        const result = await db.query(
          `UPDATE vottery_devices 
           SET last_used = CURRENT_TIMESTAMP, is_active = true, 
               ip_address = $1, location = $2,
               updated_at = CURRENT_TIMESTAMP
           WHERE id = $3
           RETURNING *`,
          [
            ipAddress, 
            location ? JSON.stringify(location) : null, 
            existingDevice.rows[0].id
          ]
        );
        return result.rows[0];
      }

      console.log('Creating new device...');
      
      // Extract device information properly
      const extractedDeviceInfo = DeviceUtils.extractDeviceInfo(deviceInfo);
      
      // Create new device - ensure all values are properly formatted
      const result = await db.query(
        `INSERT INTO vottery_devices (
          user_id, device_fingerprint, device_type, browser_name, browser_version,
          os_name, os_version, screen_info, ip_address, location
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING *`,
        [
          userId, // Integer user ID
          deviceFingerprint,
          extractedDeviceInfo.device_type,
          extractedDeviceInfo.browser_name,
          extractedDeviceInfo.browser_version,
          extractedDeviceInfo.os_name,
          extractedDeviceInfo.os_version,
          JSON.stringify(extractedDeviceInfo.screen_info),
          ipAddress,
          location ? JSON.stringify(location) : null
        ]
      );

      logger.info(`Device registered for user ${userId}: ${result.rows[0].id}`);
      return result.rows[0];

    } catch (error) {
      logger.error('Device registration error in service:', error);
      console.error('Full DeviceService error:', error);
      throw error;
    }
  }

  static async getUserDevices(userId) {
    try {
      // Ensure userId is integer
      const parsedUserId = parseInt(userId);
      
      const result = await db.query(
        `SELECT * FROM vottery_devices WHERE user_id = $1 ORDER BY created_at DESC`,
        [parsedUserId]
      );

      return result.rows;

    } catch (error) {
      logger.error('Get user devices error:', error);
      throw error;
    }
  }

  static async updateDeviceStatus(deviceId, isActive) {
    try {
      // Ensure deviceId is integer
      const parsedDeviceId = parseInt(deviceId);
      
      await db.query(
        `UPDATE vottery_devices SET is_active = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`,
        [isActive, parsedDeviceId]
      );

    } catch (error) {
      logger.error('Update device status error:', error);
      throw error;
    }
  }
}