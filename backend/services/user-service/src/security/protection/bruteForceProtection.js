// src/security/protection/bruteForceProtection.js
import { createClient } from 'redis';
import { createHash } from 'crypto';

/**
 * Brute Force Protection Service for Vottery User Service
 * Advanced protection against brute force attacks on authentication
 */
class BruteForceProtection {
  constructor() {
    this.redisClient = null;
    this.isRedisAvailable = false;
    this.attemptCache = new Map();
    this.blockedAccounts = new Map();
    this.suspiciousIPs = new Map();
    this.initializeRedis();
    this.startCleanupInterval();
  }

  // Protection thresholds and configurations
  static CONFIG = {
    // Account-based protection
    MAX_ATTEMPTS_PER_ACCOUNT: 5,
    ACCOUNT_LOCKOUT_DURATION: 30 * 60 * 1000, // 30 minutes
    ACCOUNT_PROGRESSIVE_DELAY: [1000, 2000, 5000, 10000, 30000], // Progressive delays
    
    // IP-based protection
    MAX_ATTEMPTS_PER_IP: 10,
    IP_BLOCK_DURATION: 60 * 60 * 1000, // 1 hour
    
    // Global protection
    MAX_ATTEMPTS_PER_IP_ACCOUNT: 3,
    DISTRIBUTED_ATTACK_THRESHOLD: 50, // Failed attempts across all accounts
    
    // Time windows
    ATTEMPT_WINDOW: 15 * 60 * 1000, // 15 minutes
    CLEANUP_INTERVAL: 5 * 60 * 1000, // 5 minutes
    
    // Advanced protection
    CAPTCHA_THRESHOLD: 3,
    SUSPICIOUS_PATTERN_THRESHOLD: 5
  };

  /**
   * Initialize Redis connection
   */
  async initializeRedis() {
    try {
      if (process.env.REDIS_URL) {
        this.redisClient = createClient({
          url: process.env.REDIS_URL,
          retry_strategy: (options) => {
            if (options.error && options.error.code === 'ECONNREFUSED') {
              console.warn('Redis connection refused for brute force protection');
              return undefined;
            }
            return Math.min(options.attempt * 100, 3000);
          }
        });

        await this.redisClient.connect();
        this.isRedisAvailable = true;
        console.log('Redis connected for brute force protection');
      }
    } catch (error) {
      console.warn('Redis not available for brute force protection:', error.message);
      this.isRedisAvailable = false;
    }
  }

  /**
   * Main brute force protection middleware
   * @param {Object} options - Configuration options
   * @returns {Function} Express middleware
   */
  createProtectionMiddleware(options = {}) {
    const config = { ...BruteForceProtection.CONFIG, ...options };

    return async (req, res, next) => {
      // Only protect authentication endpoints
      if (!this.isAuthEndpoint(req.path)) {
        return next();
      }

      const clientIP = this.getClientIP(req);
      const identifier = req.body?.email || req.body?.username;

      try {
        // Check if this IP is blocked
        const ipStatus = await this.checkIPStatus(clientIP, config);
        if (ipStatus.blocked) {
          return this.sendBlockedResponse(res, 'IP', ipStatus);
        }

        // Check if account is locked (if identifier provided)
        if (identifier) {
          const accountStatus = await this.checkAccountStatus(identifier, config);
          if (accountStatus.blocked) {
            return this.sendBlockedResponse(res, 'account', accountStatus);
          }

          // Check IP-Account combination
          const combinedStatus = await this.checkCombinedStatus(clientIP, identifier, config);
          if (combinedStatus.requiresCaptcha) {
            req.bruteForce = { requiresCaptcha: true, attempts: combinedStatus.attempts };
          }

          if (combinedStatus.applyDelay) {
            await this.applyProgressiveDelay(combinedStatus.attempts);
          }
        }

        // Add attempt tracking to request
        req.bruteForce = req.bruteForce || {};
        req.bruteForce.clientIP = clientIP;
        req.bruteForce.identifier = identifier;
        req.bruteForce.config = config;

        next();
      } catch (error) {
        console.error('Brute force protection error:', error);
        next(); // Continue on error to avoid blocking legitimate users
      }
    };
  }

  /**
   * Record failed authentication attempt
   * @param {Object} req - Request object
   * @param {Object} details - Additional details about the attempt
   */
  async recordFailedAttempt(req, details = {}) {
    const { clientIP, identifier, config } = req.bruteForce || {};
    
    if (!clientIP) return;

    const timestamp = Date.now();
    const attemptData = {
      ip: clientIP,
      identifier: identifier || null,
      timestamp,
      userAgent: req.get('User-Agent'),
      details
    };

    try {
      // Record IP-based attempt
      await this.recordIPAttempt(clientIP, attemptData, config);

      // Record account-based attempt (if identifier provided)
      if (identifier) {
        await this.recordAccountAttempt(identifier, attemptData, config);
        
        // Record combined IP-Account attempt
        await this.recordCombinedAttempt(clientIP, identifier, attemptData, config);
      }

      // Check for distributed attacks
      await this.checkDistributedAttack(attemptData, config);

      // Analyze patterns for additional security
      await this.analyzeAttackPatterns(attemptData, config);

    } catch (error) {
      console.error('Error recording failed attempt:', error);
    }
  }

  /**
   * Record successful authentication (reset counters)
   * @param {Object} req - Request object
   */
  async recordSuccessfulAttempt(req) {
    const { clientIP, identifier } = req.bruteForce || {};
    
    if (!clientIP) return;

    try {
      // Reset IP-based counter
      await this.resetIPAttempts(clientIP);

      // Reset account-based counter (if identifier provided)
      if (identifier) {
        await this.resetAccountAttempts(identifier);
        await this.resetCombinedAttempts(clientIP, identifier);
      }

      // Remove from suspicious list
      await this.removeSuspiciousIP(clientIP);

    } catch (error) {
      console.error('Error recording successful attempt:', error);
    }
  }

  /**
   * Check IP status
   * @param {string} clientIP - Client IP address
   * @param {Object} config - Configuration
   * @returns {Promise<Object>} IP status
   */
  async checkIPStatus(clientIP, config) {
    const key = `bf_ip_${clientIP}`;
    
    try {
      const data = await this.getAttemptData(key);
      
      if (!data || !data.attempts) {
        return { blocked: false, attempts: 0 };
      }

      // Check if currently blocked
      if (data.blockedUntil && data.blockedUntil > Date.now()) {
        return {
          blocked: true,
          reason: 'IP temporarily blocked due to multiple failed attempts',
          blockedUntil: data.blockedUntil,
          attempts: data.attempts.length
        };
      }

      // Check if should be blocked
      const recentAttempts = this.getRecentAttempts(data.attempts, config.ATTEMPT_WINDOW);
      if (recentAttempts.length >= config.MAX_ATTEMPTS_PER_IP) {
        const blockUntil = Date.now() + config.IP_BLOCK_DURATION;
        await this.blockIP(clientIP, blockUntil, config);
        
        return {
          blocked: true,
          reason: 'IP blocked due to excessive failed attempts',
          blockedUntil: blockUntil,
          attempts: recentAttempts.length
        };
      }

      return { blocked: false, attempts: recentAttempts.length };
    } catch (error) {
      console.error('Error checking IP status:', error);
      return { blocked: false, attempts: 0 };
    }
  }

  /**
   * Check account status
   * @param {string} identifier - Account identifier (email/username)
   * @param {Object} config - Configuration
   * @returns {Promise<Object>} Account status
   */
  async checkAccountStatus(identifier, config) {
    const key = `bf_account_${this.hashIdentifier(identifier)}`;
    
    try {
      const data = await this.getAttemptData(key);
      
      if (!data || !data.attempts) {
        return { blocked: false, attempts: 0 };
      }

      // Check if currently locked
      if (data.lockedUntil && data.lockedUntil > Date.now()) {
        return {
          blocked: true,
          reason: 'Account temporarily locked due to multiple failed attempts',
          lockedUntil: data.lockedUntil,
          attempts: data.attempts.length
        };
      }

      // Check if should be locked
      const recentAttempts = this.getRecentAttempts(data.attempts, config.ATTEMPT_WINDOW);
      if (recentAttempts.length >= config.MAX_ATTEMPTS_PER_ACCOUNT) {
        const lockUntil = Date.now() + config.ACCOUNT_LOCKOUT_DURATION;
        await this.lockAccount(identifier, lockUntil, config);
        
        return {
          blocked: true,
          reason: 'Account locked due to excessive failed attempts',
          lockedUntil: lockUntil,
          attempts: recentAttempts.length
        };
      }

      return { blocked: false, attempts: recentAttempts.length };
    } catch (error) {
      console.error('Error checking account status:', error);
      return { blocked: false, attempts: 0 };
    }
  }

  /**
   * Check combined IP-Account status
   * @param {string} clientIP - Client IP
   * @param {string} identifier - Account identifier
   * @param {Object} config - Configuration
   * @returns {Promise<Object>} Combined status
   */
  async checkCombinedStatus(clientIP, identifier, config) {
    const key = `bf_combined_${clientIP}_${this.hashIdentifier(identifier)}`;
    
    try {
      const data = await this.getAttemptData(key);
      const attempts = data?.attempts ? this.getRecentAttempts(data.attempts, config.ATTEMPT_WINDOW).length : 0;

      return {
        attempts,
        requiresCaptcha: attempts >= config.CAPTCHA_THRESHOLD,
        applyDelay: attempts >= 2 && attempts < config.MAX_ATTEMPTS_PER_IP_ACCOUNT
      };
    } catch (error) {
      console.error('Error checking combined status:', error);
      return { attempts: 0, requiresCaptcha: false, applyDelay: false };
    }
  }

  /**
   * Record IP-based attempt
   * @param {string} clientIP - Client IP
   * @param {Object} attemptData - Attempt data
   * @param {Object} config - Configuration
   */
  async recordIPAttempt(clientIP, attemptData, config) {
    const key = `bf_ip_${clientIP}`;
    const data = await this.getAttemptData(key) || { attempts: [] };
    
    data.attempts.push({
      timestamp: attemptData.timestamp,
      userAgent: attemptData.userAgent,
      identifier: attemptData.identifier
    });

    // Keep only recent attempts
    data.attempts = this.getRecentAttempts(data.attempts, config.ATTEMPT_WINDOW);

    await this.setAttemptData(key, data, config.ATTEMPT_WINDOW);
  }

  /**
   * Record account-based attempt
   * @param {string} identifier - Account identifier
   * @param {Object} attemptData - Attempt data
   * @param {Object} config - Configuration
   */
  async recordAccountAttempt(identifier, attemptData, config) {
    const key = `bf_account_${this.hashIdentifier(identifier)}`;
    const data = await this.getAttemptData(key) || { attempts: [] };
    
    data.attempts.push({
      timestamp: attemptData.timestamp,
      ip: attemptData.ip,
      userAgent: attemptData.userAgent
    });

    data.attempts = this.getRecentAttempts(data.attempts, config.ATTEMPT_WINDOW);
    await this.setAttemptData(key, data, config.ATTEMPT_WINDOW);
  }

  /**
   * Record combined IP-Account attempt
   * @param {string} clientIP - Client IP
   * @param {string} identifier - Account identifier
   * @param {Object} attemptData - Attempt data
   * @param {Object} config - Configuration
   */
  async recordCombinedAttempt(clientIP, identifier, attemptData, config) {
    const key = `bf_combined_${clientIP}_${this.hashIdentifier(identifier)}`;
    const data = await this.getAttemptData(key) || { attempts: [] };
    
    data.attempts.push({
      timestamp: attemptData.timestamp,
      userAgent: attemptData.userAgent
    });

    data.attempts = this.getRecentAttempts(data.attempts, config.ATTEMPT_WINDOW);
    await this.setAttemptData(key, data, config.ATTEMPT_WINDOW);
  }

  /**
   * Block IP address
   * @param {string} clientIP - IP to block
   * @param {number} blockUntil - Block expiry timestamp
   * @param {Object} config - Configuration
   */
  async blockIP(clientIP, blockUntil, config) {
    const key = `bf_ip_${clientIP}`;
    const data = await this.getAttemptData(key) || { attempts: [] };
    
    data.blockedUntil = blockUntil;
    data.blockedAt = Date.now();
    
    await this.setAttemptData(key, data, config.IP_BLOCK_DURATION);
    console.warn(`Brute Force Protection: Blocked IP ${clientIP} until ${new Date(blockUntil)}`);
  }

  /**
   * Lock account
   * @param {string} identifier - Account identifier
   * @param {number} lockUntil - Lock expiry timestamp
   * @param {Object} config - Configuration
   */
  async lockAccount(identifier, lockUntil, config) {
    const key = `bf_account_${this.hashIdentifier(identifier)}`;
    const data = await this.getAttemptData(key) || { attempts: [] };
    
    data.lockedUntil = lockUntil;
    data.lockedAt = Date.now();
    
    await this.setAttemptData(key, data, config.ACCOUNT_LOCKOUT_DURATION);
    console.warn(`Brute Force Protection: Locked account ${identifier} until ${new Date(lockUntil)}`);
  }

  /**
   * Apply progressive delay based on attempt count
   * @param {number} attemptCount - Number of attempts
   */
  async applyProgressiveDelay(attemptCount) {
    const delays = BruteForceProtection.CONFIG.ACCOUNT_PROGRESSIVE_DELAY;
    const delayIndex = Math.min(attemptCount - 1, delays.length - 1);
    const delay = delays[delayIndex] || delays[delays.length - 1];
    
    return new Promise(resolve => setTimeout(resolve, delay));
  }

  /**
   * Check for distributed attacks
   * @param {Object} attemptData - Attempt data
   * @param {Object} config - Configuration
   */
  async checkDistributedAttack(attemptData, config) {
    const key = 'bf_global_attempts';
    
    try {
      let globalAttempts = [];
      
      if (this.isRedisAvailable) {
        const data = await this.redisClient.get(key);
        globalAttempts = data ? JSON.parse(data) : [];
      } else {
        globalAttempts = this.attemptCache.get('global') || [];
      }

      globalAttempts.push(attemptData.timestamp);
      globalAttempts = globalAttempts.filter(
        timestamp => Date.now() - timestamp < config.ATTEMPT_WINDOW
      );

      if (globalAttempts.length >= config.DISTRIBUTED_ATTACK_THRESHOLD) {
        console.error(`Distributed brute force attack detected: ${globalAttempts.length} attempts in ${config.ATTEMPT_WINDOW}ms`);
        // Could trigger additional security measures here
      }

      if (this.isRedisAvailable) {
        await this.redisClient.setex(
          key, 
          Math.ceil(config.ATTEMPT_WINDOW / 1000), 
          JSON.stringify(globalAttempts)
        );
      } else {
        this.attemptCache.set('global', globalAttempts);
      }
    } catch (error) {
      console.error('Error checking distributed attack:', error);
    }
  }

  /**
   * Analyze attack patterns for advanced detection
   * @param {Object} attemptData - Attempt data
   * @param {Object} config - Configuration
   */
  async analyzeAttackPatterns(attemptData, config) {
    // Pattern 1: Same User-Agent from different IPs (botnet)
    await this.detectBotnetPattern(attemptData, config);
    
    // Pattern 2: Sequential account testing from same IP
    await this.detectAccountEnumeration(attemptData, config);
    
    // Pattern 3: Rapid attempts with different User-Agents (evasion)
    await this.detectUserAgentRotation(attemptData, config);
  }

  /**
   * Detect botnet patterns
   * @param {Object} attemptData - Attempt data
   * @param {Object} config - Configuration
   */
  async detectBotnetPattern(attemptData, config) {
    if (!attemptData.userAgent) return;

    const key = `bf_ua_${this.hashIdentifier(attemptData.userAgent)}`;
    
    try {
      let uaData = await this.getAttemptData(key) || { ips: new Set(), attempts: [] };
      
      // Convert Set to Array for JSON serialization
      if (Array.isArray(uaData.ips)) {
        uaData.ips = new Set(uaData.ips);
      } else if (!uaData.ips) {
        uaData.ips = new Set();
      }

      uaData.ips.add(attemptData.ip);
      uaData.attempts.push({
        ip: attemptData.ip,
        timestamp: attemptData.timestamp,
        identifier: attemptData.identifier
      });

      // Keep recent attempts
      uaData.attempts = this.getRecentAttempts(uaData.attempts, config.ATTEMPT_WINDOW);

      if (uaData.ips.size >= config.SUSPICIOUS_PATTERN_THRESHOLD) {
        console.warn(`Potential botnet detected: User-Agent "${attemptData.userAgent}" from ${uaData.ips.size} different IPs`);
        await this.markSuspiciousUserAgent(attemptData.userAgent, Array.from(uaData.ips));
      }

      // Convert Set back to Array for storage
      uaData.ips = Array.from(uaData.ips);
      await this.setAttemptData(key, uaData, config.ATTEMPT_WINDOW);
    } catch (error) {
      console.error('Error detecting botnet pattern:', error);
    }
  }

  /**
   * Detect account enumeration
   * @param {Object} attemptData - Attempt data
   * @param {Object} config - Configuration
   */
  async detectAccountEnumeration(attemptData, config) {
    const key = `bf_enum_${attemptData.ip}`;
    
    try {
      let enumData = await this.getAttemptData(key) || { identifiers: new Set(), attempts: [] };
      
      if (Array.isArray(enumData.identifiers)) {
        enumData.identifiers = new Set(enumData.identifiers);
      } else if (!enumData.identifiers) {
        enumData.identifiers = new Set();
      }

      if (attemptData.identifier) {
        enumData.identifiers.add(attemptData.identifier);
      }

      enumData.attempts.push({
        identifier: attemptData.identifier,
        timestamp: attemptData.timestamp
      });

      enumData.attempts = this.getRecentAttempts(enumData.attempts, config.ATTEMPT_WINDOW);

      if (enumData.identifiers.size >= config.SUSPICIOUS_PATTERN_THRESHOLD) {
        console.warn(`Account enumeration detected from IP ${attemptData.ip}: ${enumData.identifiers.size} different accounts attempted`);
        await this.markSuspiciousIP(attemptData.ip, 'account_enumeration');
      }

      enumData.identifiers = Array.from(enumData.identifiers);
      await this.setAttemptData(key, enumData, config.ATTEMPT_WINDOW);
    } catch (error) {
      console.error('Error detecting account enumeration:', error);
    }
  }

  /**
   * Detect user agent rotation (evasion technique)
   * @param {Object} attemptData - Attempt data
   * @param {Object} config - Configuration
   */
  async detectUserAgentRotation(attemptData, config) {
    const key = `bf_ua_rotation_${attemptData.ip}`;
    
    try {
      let rotationData = await this.getAttemptData(key) || { userAgents: new Set(), attempts: [] };
      
      if (Array.isArray(rotationData.userAgents)) {
        rotationData.userAgents = new Set(rotationData.userAgents);
      } else if (!rotationData.userAgents) {
        rotationData.userAgents = new Set();
      }

      if (attemptData.userAgent) {
        rotationData.userAgents.add(attemptData.userAgent);
      }

      rotationData.attempts.push({
        userAgent: attemptData.userAgent,
        timestamp: attemptData.timestamp
      });

      rotationData.attempts = this.getRecentAttempts(rotationData.attempts, config.ATTEMPT_WINDOW);

      if (rotationData.userAgents.size >= config.SUSPICIOUS_PATTERN_THRESHOLD) {
        console.warn(`User-Agent rotation detected from IP ${attemptData.ip}: ${rotationData.userAgents.size} different User-Agents`);
        await this.markSuspiciousIP(attemptData.ip, 'user_agent_rotation');
      }

      rotationData.userAgents = Array.from(rotationData.userAgents);
      await this.setAttemptData(key, rotationData, config.ATTEMPT_WINDOW);
    } catch (error) {
      console.error('Error detecting user agent rotation:', error);
    }
  }

  /**
   * Reset IP attempts
   * @param {string} clientIP - Client IP
   */
  async resetIPAttempts(clientIP) {
    const key = `bf_ip_${clientIP}`;
    await this.deleteAttemptData(key);
  }

  /**
   * Reset account attempts
   * @param {string} identifier - Account identifier
   */
  async resetAccountAttempts(identifier) {
    const key = `bf_account_${this.hashIdentifier(identifier)}`;
    await this.deleteAttemptData(key);
  }

  /**
   * Reset combined attempts
   * @param {string} clientIP - Client IP
   * @param {string} identifier - Account identifier
   */
  async resetCombinedAttempts(clientIP, identifier) {
    const key = `bf_combined_${clientIP}_${this.hashIdentifier(identifier)}`;
    await this.deleteAttemptData(key);
  }

  /**
   * Mark IP as suspicious
   * @param {string} clientIP - Client IP
   * @param {string} reason - Reason for suspicion
   */
  async markSuspiciousIP(clientIP, reason) {
    const key = `bf_suspicious_ip_${clientIP}`;
    const data = {
      reason,
      markedAt: Date.now(),
      count: 1
    };

    const existing = await this.getAttemptData(key);
    if (existing) {
      data.count = (existing.count || 0) + 1;
    }

    await this.setAttemptData(key, data, 24 * 60 * 60 * 1000); // 24 hours
  }

  /**
   * Mark User-Agent as suspicious
   * @param {string} userAgent - User agent string
   * @param {Array} ips - Associated IP addresses
   */
  async markSuspiciousUserAgent(userAgent, ips) {
    const key = `bf_suspicious_ua_${this.hashIdentifier(userAgent)}`;
    const data = {
      userAgent,
      ips,
      markedAt: Date.now()
    };

    await this.setAttemptData(key, data, 24 * 60 * 60 * 1000); // 24 hours
  }

  /**
   * Remove IP from suspicious list
   * @param {string} clientIP - Client IP
   */
  async removeSuspiciousIP(clientIP) {
    const key = `bf_suspicious_ip_${clientIP}`;
    await this.deleteAttemptData(key);
  }

  /**
   * Send blocked response
   * @param {Object} res - Response object
   * @param {string} type - Block type ('IP' or 'account')
   * @param {Object} status - Status information
   */
  sendBlockedResponse(res, type, status) {
    const remainingTime = status.blockedUntil || status.lockedUntil;
    const minutes = Math.ceil((remainingTime - Date.now()) / 60000);

    res.status(429).json({
      error: 'Access Temporarily Restricted',
      message: status.reason,
      type: `${type}_locked`,
      attemptsCount: status.attempts,
      remainingMinutes: minutes,
      retryAfter: new Date(remainingTime).toISOString(),
      support: 'Contact support if you believe this is an error'
    });
  }

  /**
   * Get recent attempts within time window
   * @param {Array} attempts - All attempts
   * @param {number} windowMs - Time window in milliseconds
   * @returns {Array} Recent attempts
   */
  getRecentAttempts(attempts, windowMs) {
    const cutoff = Date.now() - windowMs;
    return attempts.filter(attempt => attempt.timestamp > cutoff);
  }

  /**
   * Hash identifier for storage
   * @param {string} identifier - Identifier to hash
   * @returns {string} Hashed identifier
   */
  hashIdentifier(identifier) {
    return createHash('sha256').update(identifier.toLowerCase()).digest('hex').substring(0, 16);
  }

  /**
   * Check if endpoint is an authentication endpoint
   * @param {string} path - Request path
   * @returns {boolean} True if auth endpoint
   */
  isAuthEndpoint(path) {
    const authPaths = ['/login', '/signin', '/auth', '/authenticate', '/api/auth/login'];
    return authPaths.some(authPath => path.includes(authPath));
  }

  /**
   * Get client IP address
   * @param {Object} req - Request object
   * @returns {string} Client IP
   */
  getClientIP(req) {
    return req.ip || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress || 
           '127.0.0.1';
  }

  /**
   * Get attempt data from storage
   * @param {string} key - Storage key
   * @returns {Promise<Object>} Attempt data
   */
  async getAttemptData(key) {
    try {
      if (this.isRedisAvailable) {
        const data = await this.redisClient.get(key);
        return data ? JSON.parse(data) : null;
      } else {
        return this.attemptCache.get(key) || null;
      }
    } catch (error) {
      console.error('Error getting attempt data:', error);
      return null;
    }
  }

  /**
   * Set attempt data in storage
   * @param {string} key - Storage key
   * @param {Object} data - Data to store
   * @param {number} ttlMs - TTL in milliseconds
   */
  async setAttemptData(key, data, ttlMs) {
    try {
      if (this.isRedisAvailable) {
        await this.redisClient.setex(key, Math.ceil(ttlMs / 1000), JSON.stringify(data));
      } else {
        this.attemptCache.set(key, data);
        // Set cleanup timer for memory cache
        setTimeout(() => {
          this.attemptCache.delete(key);
        }, ttlMs);
      }
    } catch (error) {
      console.error('Error setting attempt data:', error);
    }
  }

  /**
   * Delete attempt data from storage
   * @param {string} key - Storage key
   */
  async deleteAttemptData(key) {
    try {
      if (this.isRedisAvailable) {
        await this.redisClient.del(key);
      } else {
        this.attemptCache.delete(key);
      }
    } catch (error) {
      console.error('Error deleting attempt data:', error);
    }
  }

  /**
   * Start cleanup interval for memory management
   */
  startCleanupInterval() {
    setInterval(() => {
      this.cleanup();
    }, BruteForceProtection.CONFIG.CLEANUP_INTERVAL);
  }

  /**
   * Cleanup expired entries
   */
  cleanup() {
    if (!this.isRedisAvailable) {
      // Only cleanup memory cache, Redis handles expiration automatically
      const now = Date.now();
      
      for (const [key, data] of this.attemptCache.entries()) {
        if (data.attempts) {
          const recentAttempts = this.getRecentAttempts(
            data.attempts, 
            BruteForceProtection.CONFIG.ATTEMPT_WINDOW
          );
          
          if (recentAttempts.length === 0 && 
              (!data.blockedUntil || data.blockedUntil < now) &&
              (!data.lockedUntil || data.lockedUntil < now)) {
            this.attemptCache.delete(key);
          }
        }
      }
    }
  }

  /**
   * Get protection statistics
   * @returns {Object} Protection statistics
   */
  getStatistics() {
    return {
      cacheSize: this.attemptCache.size,
      blockedAccounts: Array.from(this.attemptCache.entries())
        .filter(([key, data]) => key.startsWith('bf_account_') && data.lockedUntil > Date.now()).length,
      blockedIPs: Array.from(this.attemptCache.entries())
        .filter(([key, data]) => key.startsWith('bf_ip_') && data.blockedUntil > Date.now()).length,
      suspiciousIPs: Array.from(this.attemptCache.entries())
        .filter(([key]) => key.startsWith('bf_suspicious_ip_')).length,
      redisAvailable: this.isRedisAvailable
    };
  }

  /**
   * Admin function to unblock IP or account
   * @param {string} type - 'ip' or 'account'
   * @param {string} identifier - IP address or account identifier
   * @returns {Promise<boolean>} Success status
   */
  async adminUnblock(type, identifier) {
    try {
      let key;
      if (type === 'ip') {
        key = `bf_ip_${identifier}`;
      } else if (type === 'account') {
        key = `bf_account_${this.hashIdentifier(identifier)}`;
      } else {
        return false;
      }

      await this.deleteAttemptData(key);
      console.log(`Admin unblocked ${type}: ${identifier}`);
      return true;
    } catch (error) {
      console.error('Error in admin unblock:', error);
      return false;
    }
  }
}

export default BruteForceProtection;