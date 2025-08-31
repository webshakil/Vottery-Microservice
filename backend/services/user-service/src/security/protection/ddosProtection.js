// src/security/protection/ddosProtection.js
import { createClient } from 'redis';
import { promisify } from 'util';

/**
 * DDoS Protection Service for Vottery User Service
 * Advanced distributed denial of service attack prevention
 */
class DdosProtection {
  constructor() {
    this.redisClient = null;
    this.isRedisAvailable = false;
    this.suspiciousIPs = new Map();
    this.blockedIPs = new Map();
    this.connectionCounts = new Map();
    this.requestPatterns = new Map();
    this.initializeRedis();
    this.startCleanupInterval();
  }

  // DDoS detection thresholds
  static THRESHOLDS = {
    REQUESTS_PER_SECOND: 50,
    REQUESTS_PER_MINUTE: 1000,
    CONCURRENT_CONNECTIONS: 100,
    SUSPICIOUS_PATTERN_THRESHOLD: 10,
    AUTO_BLOCK_THRESHOLD: 20,
    BLOCK_DURATION: 24 * 60 * 60 * 1000, // 24 hours
    CLEANUP_INTERVAL: 5 * 60 * 1000 // 5 minutes
  };

  /**
   * Initialize Redis connection for distributed tracking
   */
  async initializeRedis() {
    try {
      if (process.env.REDIS_URL) {
        this.redisClient = createClient({
          url: process.env.REDIS_URL,
          retry_strategy: (options) => {
            if (options.error && options.error.code === 'ECONNREFUSED') {
              console.warn('Redis connection refused for DDoS protection');
              return undefined;
            }
            return Math.min(options.attempt * 100, 3000);
          }
        });

        await this.redisClient.connect();
        this.isRedisAvailable = true;
        console.log('Redis connected for DDoS protection');
      }
    } catch (error) {
      console.warn('Redis not available for DDoS protection:', error.message);
      this.isRedisAvailable = false;
    }
  }

  /**
   * Main DDoS protection middleware
   * @param {Object} options - Configuration options
   * @returns {Function} Express middleware
   */
  createProtectionMiddleware(options = {}) {
    const config = { ...DdosProtection.THRESHOLDS, ...options };

    return async (req, res, next) => {
      const clientIP = this.getClientIP(req);
      const userAgent = req.get('User-Agent') || 'unknown';
      const timestamp = Date.now();

      try {
        // Check if IP is blocked
        if (await this.isIPBlocked(clientIP)) {
          return this.handleBlockedRequest(req, res, 'IP blocked due to suspicious activity');
        }

        // Track request patterns
        await this.trackRequestPattern(clientIP, req.url, timestamp);

        // Check for DDoS patterns
        const threat = await this.analyzeRequest(clientIP, userAgent, req, config);

        if (threat.level === 'block') {
          await this.blockIP(clientIP, threat.reason, config.BLOCK_DURATION);
          return this.handleBlockedRequest(req, res, threat.reason);
        }

        if (threat.level === 'suspicious') {
          await this.markSuspicious(clientIP, threat.reason);
          // Add delay for suspicious requests
          await this.delay(1000);
        }

        // Track connection
        this.trackConnection(clientIP, true);
        
        // Cleanup on response end
        res.on('finish', () => {
          this.trackConnection(clientIP, false);
        });

        next();
      } catch (error) {
        console.error('DDoS protection error:', error);
        next(); // Continue on error to avoid blocking legitimate traffic
      }
    };
  }

  /**
   * Analyze incoming request for DDoS patterns
   * @param {string} clientIP - Client IP address
   * @param {string} userAgent - User agent string
   * @param {Object} req - Express request object
   * @param {Object} config - Configuration thresholds
   * @returns {Promise<Object>} Threat analysis result
   */
  async analyzeRequest(clientIP, userAgent, req, config) {
    const threats = [];

    // Check request rate
    const requestRate = await this.getRequestRate(clientIP);
    if (requestRate.perSecond > config.REQUESTS_PER_SECOND) {
      threats.push({
        type: 'high_request_rate',
        severity: 'high',
        details: `${requestRate.perSecond} requests/second`
      });
    }

    if (requestRate.perMinute > config.REQUESTS_PER_MINUTE) {
      threats.push({
        type: 'very_high_request_rate',
        severity: 'critical',
        details: `${requestRate.perMinute} requests/minute`
      });
    }

    // Check concurrent connections
    const connections = this.getConnectionCount(clientIP);
    if (connections > config.CONCURRENT_CONNECTIONS) {
      threats.push({
        type: 'too_many_connections',
        severity: 'high',
        details: `${connections} concurrent connections`
      });
    }

    // Check for suspicious patterns
    const patterns = await this.detectSuspiciousPatterns(clientIP, req);
    if (patterns.length > 0) {
      threats.push(...patterns);
    }

    // Check user agent patterns
    const uaThreats = this.analyzeUserAgent(userAgent);
    if (uaThreats.length > 0) {
      threats.push(...uaThreats);
    }

    // Determine threat level
    const criticalThreats = threats.filter(t => t.severity === 'critical');
    const highThreats = threats.filter(t => t.severity === 'high');

    if (criticalThreats.length > 0 || highThreats.length >= 2) {
      return {
        level: 'block',
        reason: 'Multiple DDoS indicators detected',
        threats
      };
    }

    if (highThreats.length > 0 || threats.length >= 3) {
      return {
        level: 'suspicious',
        reason: 'Suspicious activity patterns detected',
        threats
      };
    }

    return { level: 'safe', threats: [] };
  }

  /**
   * Track request patterns for analysis
   * @param {string} clientIP - Client IP
   * @param {string} url - Request URL
   * @param {number} timestamp - Request timestamp
   */
  async trackRequestPattern(clientIP, url, timestamp) {
    const key = `ddos_pattern_${clientIP}`;
    const pattern = {
      url,
      timestamp,
      count: 1
    };

    if (this.isRedisAvailable) {
      // Store in Redis for distributed tracking
      const existing = await this.redisClient.get(key);
      const patterns = existing ? JSON.parse(existing) : [];
      
      // Find existing pattern for this URL
      const existingPattern = patterns.find(p => p.url === url);
      if (existingPattern) {
        existingPattern.count++;
        existingPattern.lastSeen = timestamp;
      } else {
        patterns.push({ ...pattern, lastSeen: timestamp });
      }

      // Keep only recent patterns (last 5 minutes)
      const recentPatterns = patterns.filter(
        p => timestamp - p.lastSeen < 5 * 60 * 1000
      );

      await this.redisClient.setex(key, 300, JSON.stringify(recentPatterns));
    } else {
      // Store in memory
      if (!this.requestPatterns.has(clientIP)) {
        this.requestPatterns.set(clientIP, []);
      }
      
      const patterns = this.requestPatterns.get(clientIP);
      const existingPattern = patterns.find(p => p.url === url);
      
      if (existingPattern) {
        existingPattern.count++;
        existingPattern.lastSeen = timestamp;
      } else {
        patterns.push({ ...pattern, lastSeen: timestamp });
      }

      // Clean old patterns
      this.requestPatterns.set(
        clientIP,
        patterns.filter(p => timestamp - p.lastSeen < 5 * 60 * 1000)
      );
    }
  }

  /**
   * Detect suspicious request patterns
   * @param {string} clientIP - Client IP
   * @param {Object} req - Request object
   * @returns {Promise<Array>} Array of detected threats
   */
  async detectSuspiciousPatterns(clientIP, req) {
    const threats = [];
    const patterns = await this.getRequestPatterns(clientIP);

    // Pattern 1: Rapid identical requests
    const identicalRequests = patterns.filter(p => p.url === req.url);
    if (identicalRequests.length > 0 && identicalRequests[0].count > 20) {
      threats.push({
        type: 'identical_request_spam',
        severity: 'high',
        details: `${identicalRequests[0].count} identical requests`
      });
    }

    // Pattern 2: Sequential resource scanning
    const uniqueUrls = [...new Set(patterns.map(p => p.url))];
    if (uniqueUrls.length > 50) {
      threats.push({
        type: 'resource_scanning',
        severity: 'high',
        details: `Accessing ${uniqueUrls.length} different endpoints`
      });
    }

    // Pattern 3: Suspicious query patterns
    if (req.query) {
      const queryString = JSON.stringify(req.query);
      if (this.containsSuspiciousQueries(queryString)) {
        threats.push({
          type: 'malicious_queries',
          severity: 'critical',
          details: 'Potential injection or exploit attempts in queries'
        });
      }
    }

    // Pattern 4: Large request bodies (potential DoS)
    if (req.get('content-length')) {
      const contentLength = parseInt(req.get('content-length'));
      if (contentLength > 10 * 1024 * 1024) { // 10MB
        threats.push({
          type: 'large_request_body',
          severity: 'high',
          details: `Request body size: ${contentLength} bytes`
        });
      }
    }

    return threats;
  }

  /**
   * Analyze user agent for bot patterns
   * @param {string} userAgent - User agent string
   * @returns {Array} Array of threats
   */
  analyzeUserAgent(userAgent) {
    const threats = [];

    // Check for missing or suspicious user agents
    if (!userAgent || userAgent === 'unknown') {
      threats.push({
        type: 'missing_user_agent',
        severity: 'medium',
        details: 'No user agent provided'
      });
      return threats;
    }

    // Known bot patterns
    const botPatterns = [
      /bot|crawler|spider|scraper/i,
      /curl|wget|python|java|go-http/i,
      /attack|exploit|scan|hack/i
    ];

    if (botPatterns.some(pattern => pattern.test(userAgent))) {
      threats.push({
        type: 'suspicious_user_agent',
        severity: 'high',
        details: 'User agent indicates automated tool or bot'
      });
    }

    // Check for very short or very long user agents
    if (userAgent.length < 10 || userAgent.length > 500) {
      threats.push({
        type: 'abnormal_user_agent_length',
        severity: 'medium',
        details: `User agent length: ${userAgent.length} characters`
      });
    }

    return threats;
  }

  /**
   * Get request rate for IP
   * @param {string} clientIP - Client IP
   * @returns {Promise<Object>} Request rate statistics
   */
  async getRequestRate(clientIP) {
    const now = Date.now();
    const key = `ddos_rate_${clientIP}`;

    if (this.isRedisAvailable) {
      const requests = await this.redisClient.lrange(key, 0, -1);
      const timestamps = requests.map(r => parseInt(r));
      
      const perSecond = timestamps.filter(t => now - t < 1000).length;
      const perMinute = timestamps.filter(t => now - t < 60000).length;

      // Add current request
      await this.redisClient.lpush(key, now);
      await this.redisClient.ltrim(key, 0, 999); // Keep last 1000 requests
      await this.redisClient.expire(key, 300); // Expire after 5 minutes

      return { perSecond, perMinute };
    } else {
      // Memory-based tracking
      if (!this.requestPatterns.has(clientIP)) {
        this.requestPatterns.set(clientIP, []);
      }

      const timestamps = this.requestPatterns.get(clientIP) || [];
      const perSecond = timestamps.filter(t => now - t < 1000).length;
      const perMinute = timestamps.filter(t => now - t < 60000).length;

      // Add current timestamp
      timestamps.push(now);
      
      // Keep only recent timestamps
      this.requestPatterns.set(
        clientIP,
        timestamps.filter(t => now - t < 300000) // 5 minutes
      );

      return { perSecond, perMinute };
    }
  }

  /**
   * Get request patterns for IP
   * @param {string} clientIP - Client IP
   * @returns {Promise<Array>} Request patterns
   */
  async getRequestPatterns(clientIP) {
    const key = `ddos_pattern_${clientIP}`;
    
    if (this.isRedisAvailable) {
      const data = await this.redisClient.get(key);
      return data ? JSON.parse(data) : [];
    } else {
      return this.requestPatterns.get(clientIP) || [];
    }
  }

  /**
   * Track concurrent connections
   * @param {string} clientIP - Client IP
   * @param {boolean} isConnecting - True if connecting, false if disconnecting
   */
  trackConnection(clientIP, isConnecting) {
    const current = this.connectionCounts.get(clientIP) || 0;
    
    if (isConnecting) {
      this.connectionCounts.set(clientIP, current + 1);
    } else {
      this.connectionCounts.set(clientIP, Math.max(0, current - 1));
    }
  }

  /**
   * Get connection count for IP
   * @param {string} clientIP - Client IP
   * @returns {number} Connection count
   */
  getConnectionCount(clientIP) {
    return this.connectionCounts.get(clientIP) || 0;
  }

  /**
   * Check if IP is blocked
   * @param {string} clientIP - Client IP
   * @returns {Promise<boolean>} True if blocked
   */
  async isIPBlocked(clientIP) {
    const key = `ddos_blocked_${clientIP}`;
    
    if (this.isRedisAvailable) {
      const blocked = await this.redisClient.get(key);
      return blocked !== null;
    } else {
      const blockInfo = this.blockedIPs.get(clientIP);
      return blockInfo && blockInfo.expiresAt > Date.now();
    }
  }

  /**
   * Block IP address
   * @param {string} clientIP - IP to block
   * @param {string} reason - Block reason
   * @param {number} duration - Block duration in milliseconds
   */
  async blockIP(clientIP, reason, duration) {
    const key = `ddos_blocked_${clientIP}`;
    const blockInfo = {
      reason,
      blockedAt: Date.now(),
      expiresAt: Date.now() + duration
    };

    if (this.isRedisAvailable) {
      await this.redisClient.setex(key, Math.floor(duration / 1000), JSON.stringify(blockInfo));
    } else {
      this.blockedIPs.set(clientIP, blockInfo);
    }

    console.warn(`DDoS Protection: Blocked IP ${clientIP} for ${reason}`);
  }

  /**
   * Mark IP as suspicious
   * @param {string} clientIP - Client IP
   * @param {string} reason - Suspicion reason
   */
  async markSuspicious(clientIP, reason) {
    const key = `ddos_suspicious_${clientIP}`;
    const suspicionInfo = {
      reason,
      markedAt: Date.now(),
      count: 1
    };

    if (this.isRedisAvailable) {
      const existing = await this.redisClient.get(key);
      if (existing) {
        const info = JSON.parse(existing);
        info.count++;
        suspicionInfo.count = info.count;
      }
      await this.redisClient.setex(key, 3600, JSON.stringify(suspicionInfo)); // 1 hour
    } else {
      const existing = this.suspiciousIPs.get(clientIP);
      if (existing) {
        existing.count++;
        suspicionInfo.count = existing.count;
      }
      this.suspiciousIPs.set(clientIP, suspicionInfo);
    }
  }

  /**
   * Handle blocked request
   * @param {Object} req - Request object
   * @param {Object} res - Response object
   * @param {string} reason - Block reason
   */
  handleBlockedRequest(req, res, reason) {
    res.status(429).json({
      error: 'Access Denied',
      message: 'Your request has been blocked due to suspicious activity',
      reason: reason,
      timestamp: new Date().toISOString(),
      support: 'Contact support if you believe this is an error'
    });
  }

  /**
   * Check for suspicious query patterns
   * @param {string} queryString - Query string
   * @returns {boolean} True if suspicious
   */
  containsSuspiciousQueries(queryString) {
    const suspiciousPatterns = [
      /union\s+select/i,
      /drop\s+table/i,
      /insert\s+into/i,
      /<script/i,
      /javascript:/i,
      /eval\(/i,
      /\.\.\//g,
      /%2e%2e%2f/gi
    ];

    return suspiciousPatterns.some(pattern => pattern.test(queryString));
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
           (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
           '127.0.0.1';
  }

  /**
   * Add delay for suspicious requests
   * @param {number} ms - Delay in milliseconds
   * @returns {Promise} Delay promise
   */
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Start cleanup interval for memory management
   */
  startCleanupInterval() {
    setInterval(() => {
      this.cleanup();
    }, DdosProtection.THRESHOLDS.CLEANUP_INTERVAL);
  }

  /**
   * Clean up expired entries
   */
  cleanup() {
    const now = Date.now();

    // Cleanup blocked IPs
    for (const [ip, blockInfo] of this.blockedIPs.entries()) {
      if (blockInfo.expiresAt <= now) {
        this.blockedIPs.delete(ip);
      }
    }

    // Cleanup suspicious IPs (after 1 hour)
    for (const [ip, suspicionInfo] of this.suspiciousIPs.entries()) {
      if (now - suspicionInfo.markedAt > 3600000) {
        this.suspiciousIPs.delete(ip);
      }
    }

    // Cleanup request patterns
    for (const [ip, patterns] of this.requestPatterns.entries()) {
      const recentPatterns = patterns.filter(p => now - p.lastSeen < 300000);
      if (recentPatterns.length === 0) {
        this.requestPatterns.delete(ip);
      } else {
        this.requestPatterns.set(ip, recentPatterns);
      }
    }

    // Cleanup connection counts (reset to 0 if no activity)
    for (const [ip, count] of this.connectionCounts.entries()) {
      if (count === 0) {
        this.connectionCounts.delete(ip);
      }
    }
  }

  /**
   * Get DDoS protection statistics
   * @returns {Object} Protection statistics
   */
  getStatistics() {
    return {
      blockedIPs: this.blockedIPs.size,
      suspiciousIPs: this.suspiciousIPs.size,
      trackedIPs: this.requestPatterns.size,
      activeConnections: Array.from(this.connectionCounts.values()).reduce((a, b) => a + b, 0),
      redisAvailable: this.isRedisAvailable
    };
  }
}

export default DdosProtection;