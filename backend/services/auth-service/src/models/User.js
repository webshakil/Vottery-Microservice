// import pool from '../config/database.js';
// import { logger } from '../utils/logger.js';
// import { USER_STATUS } from '../utils/constants.js';

// export class User {
//   // Check if user exists in SngEngine database
//   static async checkSngineUser(email, phone) {
//     const client = await pool.connect();
//     try {
//     //   const query = `
//     //   SELECT user_email, user_phone
//     //     FROM users 
//     //     WHERE TRIM(LOWER(user_email)) = LOWER($1)
//     //       AND TRIM(user_phone) = $2
//     //     LIMIT 1
//     // `;
//     const query = `
//       SELECT user_email, user_phone
//       FROM users 
//       WHERE TRIM(LOWER(user_email)) = LOWER($1)
//          OR TRIM(user_phone) = $2
//       LIMIT 1
//     `;
//       const result = await client.query(query, [email, phone]);
      
//       if (result.rows.length === 0) {
//         return { exists: false, message: 'User not found in SngEngine database' };
//       }

//       const user = result.rows[0];
   
//       return {
//         exists: true,
//         email: user.user_email,
//         phone: user.user_phone
//       };
      
//     } catch (error) {
//       logger.error('Error checking SngEngine user:', error);
//       throw error;
//     } finally {
//       client.release();
//     }
//   }

//   static async createOrGetVotteryUser(email, phone) {
//     const client = await pool.connect();
//     try {
//       // Check if Vottery user already exists
//       let query = `
//         SELECT * FROM vottery_users 
//         WHERE sngine_email = $1 AND sngine_phone = $2
//         LIMIT 1
//       `;
      
//       let result = await client.query(query, [email, phone]);
      
//       if (result.rows.length > 0) {
//         return result.rows[0];
//       }

//       // Create new Vottery user
//       query = `
//         INSERT INTO vottery_users (sngine_email, sngine_phone, status, created_at, updated_at)
//         VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
//         RETURNING *
//       `;
      
//       result = await client.query(query, [email, phone, USER_STATUS.PENDING]);
//       logger.info(`New Vottery user created for email: ${email}`);
      
//       return result.rows[0];
      
//     } catch (error) {
//       logger.error('Error creating/getting Vottery user:', error);
//       throw error;
//     } finally {
//       client.release();
//     }
//   }


  
//   // Update user status
//   static async updateStatus(userId, status, field = null) {
//     const client = await pool.connect();
//     try {
//       let query, params;
      
//       if (field) {
//         query = `
//           UPDATE vottery_users 
//           SET status = $1, ${field} = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
//           WHERE id = $2
//           RETURNING *
//         `;
//         params = [status, userId];
//       } else {
//         query = `
//           UPDATE vottery_users 
//           SET status = $1, updated_at = CURRENT_TIMESTAMP
//           WHERE id = $2
//           RETURNING *
//         `;
//         params = [status, userId];
//       }
      
//       const result = await client.query(query, params);
//       return result.rows[0];
      
//     } catch (error) {
//       logger.error('Error updating user status:', error);
//       throw error;
//     } finally {
//       client.release();
//     }
//   }

//   // Get user by ID
//   static async getById(userId) {
//     const client = await pool.connect();
//     try {
//       const query = `
//         SELECT * FROM vottery_users 
//         WHERE id = $1
//         LIMIT 1
//       `;
      
//       const result = await client.query(query, [userId]);
//       return result.rows[0] || null;
      
//     } catch (error) {
//       logger.error('Error getting user by ID:', error);
//       throw error;
//     } finally {
//       client.release();
//     }
//   }

//   // Update last login
//   static async updateLastLogin(userId) {
//     const client = await pool.connect();
//     try {
//       const query = `
//         UPDATE vottery_users 
//         SET last_login = CURRENT_TIMESTAMP
//         WHERE id = $1
//       `;
      
//       await client.query(query, [userId]);
      
//     } catch (error) {
//       logger.error('Error updating last login:', error);
//       throw error;
//     } finally {
//       client.release();
//     }
//   }
// }



//only email or phone 

import pool from '../config/database.js';
import { logger } from '../utils/logger.js';
import { USER_STATUS } from '../utils/constants.js';

export class User {
  // Check if user exists in SngEngine database
  static async checkSngineUser(email = '', phone = '') {
    const client = await pool.connect();
    try {
      let query, params;

      // Determine query based on provided fields
      if (email && phone) {
        query = `
          SELECT user_email, user_phone
          FROM users 
          WHERE TRIM(LOWER(user_email)) = LOWER($1)
             OR TRIM(user_phone) = $2
          LIMIT 1
        `;
        params = [email, phone];
      } else if (phone) {
        query = `
          SELECT user_email, user_phone
          FROM users 
          WHERE TRIM(user_phone) = $1
          LIMIT 1
        `;
        params = [phone];
      } else if (email) {
        query = `
          SELECT user_email, user_phone
          FROM users 
          WHERE TRIM(LOWER(user_email)) = LOWER($1)
          LIMIT 1
        `;
        params = [email];
      } else {
        return { exists: false, message: 'No email or phone provided' };
      }

      const result = await client.query(query, params);

      if (result.rows.length === 0) {
        return { exists: false, message: 'User not found in SngEngine database' };
      }

      const user = result.rows[0];

      return {
        exists: true,
        email: user.user_email,
        phone: user.user_phone
      };

    } catch (error) {
      logger.error('Error checking SngEngine user:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  static async createOrGetVotteryUser(email = '', phone = '') {
    const client = await pool.connect();
    try {
      // Check if Vottery user already exists (match any)
      let query = `
        SELECT * FROM vottery_users 
        WHERE sngine_email = $1 OR sngine_phone = $2
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
      logger.info(`New Vottery user created for email: ${email || 'N/A'} / phone: ${phone || 'N/A'}`);

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
