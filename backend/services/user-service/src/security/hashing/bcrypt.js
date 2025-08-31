// src/security/hashing/bcrypt.js
import bcrypt from 'bcryptjs';

/**
 * Bcrypt Hashing Utility for Vottery User Service
 * Provides secure password hashing and verification with adaptive cost
 */
class BcryptHasher {
  // Default salt rounds - can be adjusted based on security requirements
  static DEFAULT_SALT_ROUNDS = 12;
  static MIN_SALT_ROUNDS = 10;
  static MAX_SALT_ROUNDS = 16;

  /**
   * Hash password using bcrypt with configurable salt rounds
   * @param {string} password - Plain text password
   * @param {number} saltRounds - Number of salt rounds (default: 12)
   * @returns {Promise<string>} Bcrypt hash
   */
  static async hashPassword(password, saltRounds = this.DEFAULT_SALT_ROUNDS) {
    try {
      // Validate input
      if (!password || typeof password !== 'string') {
        throw new Error('Password must be a non-empty string');
      }

      // Validate salt rounds
      if (saltRounds < this.MIN_SALT_ROUNDS || saltRounds > this.MAX_SALT_ROUNDS) {
        throw new Error(`Salt rounds must be between ${this.MIN_SALT_ROUNDS} and ${this.MAX_SALT_ROUNDS}`);
      }

      return await bcrypt.hash(password, saltRounds);
    } catch (error) {
      throw new Error(`Password hashing failed: ${error.message}`);
    }
  }

  /**
   * Verify password against bcrypt hash
   * @param {string} password - Plain text password
   * @param {string} hash - Bcrypt hash to verify against
   * @returns {Promise<boolean>} Verification result
   */
  static async verifyPassword(password, hash) {
    try {
      // Validate input
      if (!password || typeof password !== 'string') {
        return false;
      }
      
      if (!hash || typeof hash !== 'string') {
        return false;
      }

      return await bcrypt.compare(password, hash);
    } catch (error) {
      // Log error but don't throw to prevent timing attacks
      console.error('Password verification error:', error.message);
      return false;
    }
  }

  /**
   * Generate salt for manual hashing operations
   * @param {number} rounds - Salt rounds
   * @returns {Promise<string>} Generated salt
   */
  static async generateSalt(rounds = this.DEFAULT_SALT_ROUNDS) {
    try {
      if (rounds < this.MIN_SALT_ROUNDS || rounds > this.MAX_SALT_ROUNDS) {
        throw new Error(`Salt rounds must be between ${this.MIN_SALT_ROUNDS} and ${this.MAX_SALT_ROUNDS}`);
      }

      return await bcrypt.genSalt(rounds);
    } catch (error) {
      throw new Error(`Salt generation failed: ${error.message}`);
    }
  }

  /**
   * Hash data with existing salt
   * @param {string} data - Data to hash
   * @param {string} salt - Existing salt
   * @returns {Promise<string>} Hash result
   */
  static async hashWithSalt(data, salt) {
    try {
      if (!data || typeof data !== 'string') {
        throw new Error('Data must be a non-empty string');
      }

      if (!salt || typeof salt !== 'string') {
        throw new Error('Salt must be a non-empty string');
      }

      return await bcrypt.hash(data, salt);
    } catch (error) {
      throw new Error(`Hashing with salt failed: ${error.message}`);
    }
  }

  /**
   * Get hash info (salt rounds, salt, hash) from bcrypt hash
   * @param {string} hash - Bcrypt hash
   * @returns {Object} Hash information
   */
  static getHashInfo(hash) {
    try {
      if (!hash || typeof hash !== 'string') {
        throw new Error('Hash must be a non-empty string');
      }

      const parts = hash.split('$');
      if (parts.length !== 4 || parts[0] !== '' || parts[1] !== '2b') {
        throw new Error('Invalid bcrypt hash format');
      }

      return {
        algorithm: '2b',
        cost: parseInt(parts[2]),
        salt: parts[3].substring(0, 22),
        hash: parts[3].substring(22)
      };
    } catch (error) {
      throw new Error(`Hash info extraction failed: ${error.message}`);
    }
  }

  /**
   * Check if password needs rehashing (cost too low)
   * @param {string} hash - Current password hash
   * @param {number} targetCost - Target cost factor
   * @returns {boolean} Whether rehashing is needed
   */
  static needsRehash(hash, targetCost = this.DEFAULT_SALT_ROUNDS) {
    try {
      const info = this.getHashInfo(hash);
      return info.cost < targetCost;
    } catch (error) {
      // If we can't parse the hash, assume it needs rehashing
      return true;
    }
  }

  /**
   * Hash user security questions for account recovery
   * @param {string} question - Security question
   * @param {string} answer - User's answer
   * @returns {Promise<string>} Hashed Q&A combination
   */
  static async hashSecurityQA(question, answer) {
    try {
      if (!question || !answer) {
        throw new Error('Question and answer are required');
      }

      // Normalize the answer (lowercase, trim whitespace)
      const normalizedAnswer = answer.toLowerCase().trim();
      const combined = `${question}:${normalizedAnswer}`;
      
      return await this.hashPassword(combined);
    } catch (error) {
      throw new Error(`Security Q&A hashing failed: ${error.message}`);
    }
  }

  /**
   * Verify security question answer
   * @param {string} question - Security question
   * @param {string} answer - User's answer
   * @param {string} hash - Stored hash
   * @returns {Promise<boolean>} Verification result
   */
  static async verifySecurityQA(question, answer, hash) {
    try {
      if (!question || !answer || !hash) {
        return false;
      }

      const normalizedAnswer = answer.toLowerCase().trim();
      const combined = `${question}:${normalizedAnswer}`;
      
      return await this.verifyPassword(combined, hash);
    } catch (error) {
      return false;
    }
  }

  /**
   * Hash API key for secure storage
   * @param {string} apiKey - API key to hash
   * @returns {Promise<string>} Hashed API key
   */
  static async hashApiKey(apiKey) {
    try {
      if (!apiKey || typeof apiKey !== 'string') {
        throw new Error('API key must be a non-empty string');
      }

      // Use higher cost for API keys since they're hashed less frequently
      return await this.hashPassword(apiKey, 14);
    } catch (error) {
      throw new Error(`API key hashing failed: ${error.message}`);
    }
  }

  /**
   * Verify API key against hash
   * @param {string} apiKey - API key to verify
   * @param {string} hash - Stored hash
   * @returns {Promise<boolean>} Verification result
   */
  static async verifyApiKey(apiKey, hash) {
    try {
      return await this.verifyPassword(apiKey, hash);
    } catch (error) {
      return false;
    }
  }

  /**
   * Hash organization verification code
   * @param {string} code - Verification code
   * @param {string} orgId - Organization ID as salt
   * @returns {Promise<string>} Hashed verification code
   */
  static async hashVerificationCode(code, orgId) {
    try {
      if (!code || !orgId) {
        throw new Error('Code and organization ID are required');
      }

      const combined = `${orgId}:${code}`;
      return await this.hashPassword(combined, 10); // Lower cost for temporary codes
    } catch (error) {
      throw new Error(`Verification code hashing failed: ${error.message}`);
    }
  }

  /**
   * Batch hash multiple passwords (for admin operations)
   * @param {string[]} passwords - Array of passwords to hash
   * @param {number} saltRounds - Salt rounds to use
   * @returns {Promise<string[]>} Array of hashed passwords
   */
  static async batchHashPasswords(passwords, saltRounds = this.DEFAULT_SALT_ROUNDS) {
    try {
      if (!Array.isArray(passwords)) {
        throw new Error('Passwords must be an array');
      }

      const hashPromises = passwords.map(password => 
        this.hashPassword(password, saltRounds)
      );

      return await Promise.all(hashPromises);
    } catch (error) {
      throw new Error(`Batch password hashing failed: ${error.message}`);
    }
  }

  /**
   * Calculate recommended salt rounds based on server performance
   * @param {number} targetTime - Target time in milliseconds (default: 100ms)
   * @returns {Promise<number>} Recommended salt rounds
   */
  static async calculateOptimalSaltRounds(targetTime = 100) {
    try {
      const testPassword = 'test-password-for-benchmark';
      let rounds = 10;
      
      while (rounds <= 16) {
        const startTime = Date.now();
        await this.hashPassword(testPassword, rounds);
        const duration = Date.now() - startTime;
        
        if (duration >= targetTime) {
          return Math.max(rounds - 1, this.MIN_SALT_ROUNDS);
        }
        
        rounds++;
      }
      
      return this.MAX_SALT_ROUNDS;
    } catch (error) {
      // Return default if benchmark fails
      return this.DEFAULT_SALT_ROUNDS;
    }
  }
}

export default BcryptHasher;