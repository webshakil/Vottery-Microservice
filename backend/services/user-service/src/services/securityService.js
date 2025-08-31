// services/securityService.js
import SecurityEvent from '../models/SecurityEvent.js';
import EncryptionKey from '../models/EncryptionKey.js';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import encryptionService from './encryptionService.js';
import keyManagementService from './keyManagementService.js';
import auditService from './auditService.js';
import { AppError } from '../utils/response.js';
import { SECURITY_LEVELS, THREAT_TYPES } from '../utils/constants.js';

class SecurityService {
  constructor() {
    this.securityConfig = {
      maxLoginAttempts: 5,
      lockoutDuration: 15 * 60 * 1000, // 15 minutes
      passwordMinLength: 8,
      sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
      tokenExpiration: 60 * 60 * 1000 // 1 hour
    };
    
    this.blockedIPs = new Set();
    this.suspiciousActivities = new Map();
  }

  /**
   * Validate password strength
   * @param {string} password 
   * @returns {object}
   */
  validatePasswordStrength(password) {
    const validation = {
      isValid: false,
      score: 0,
      issues: [],
      strength: 'weak'
    };

    if (!password || typeof password !== 'string') {
      validation.issues.push('Password is required');
      return validation;
    }

    // Length check
    if (password.length < this.securityConfig.passwordMinLength) {
      validation.issues.push(`Password must be at least ${this.securityConfig.passwordMinLength} characters long`);
    } else {
      validation.score += 1;
    }

    // Complexity checks
    const hasLowercase = /[a-z]/.test(password);
    const hasUppercase = /[A-Z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChars = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (hasLowercase) validation.score += 1;
    if (hasUppercase) validation.score += 1;
    if (hasNumbers) validation.score += 1;
    if (hasSpecialChars) validation.score += 1;

    if (!hasLowercase || !hasUppercase) {
      validation.issues.push('Password must contain both uppercase and lowercase letters');
    }

    if (!hasNumbers) {
      validation.issues.push('Password must contain at least one number');
    }

    if (!hasSpecialChars) {
      validation.issues.push('Password must contain at least one special character');
    }

    // Common password check
    if (this.isCommonPassword(password)) {
      validation.issues.push('Password is too common');
      validation.score -= 2;
    }

    // Sequential characters check
    if (this.hasSequentialCharacters(password)) {
      validation.issues.push('Password contains sequential characters');
      validation.score -= 1;
    }

    // Determine strength
    if (validation.score >= 5) {
      validation.strength = 'strong';
      validation.isValid = true;
    } else if (validation.score >= 3) {
      validation.strength = 'medium';
      validation.isValid = validation.issues.length === 0;
    } else {
      validation.strength = 'weak';
    }

    return validation;
  }

  /**
   * Generate secure random token
   * @param {number} length 
   * @returns {string}
   */
  generateSecureToken(length = 32) {
    return randomBytes(length).toString('hex');
  }

  /**
   * Hash data securely
   * @param {string} data 
   * @param {string} algorithm 
   * @returns {string}
   */
  secureHash(data, algorithm = 'sha256') {
    return createHash(algorithm).update(data).digest('hex');
  }

  /**
   * Safe string comparison to prevent timing attacks
   * @param {string} a 
   * @param {string} b 
   * @returns {boolean}
   */
  safeCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') {
      return false;
    }

    if (a.length !== b.length) {
      return false;
    }

    return timingSafeEqual(Buffer.from(a), Buffer.from(b));
  }

  /**
   * Check if IP is blocked
   * @param {string} ipAddress 
   * @returns {boolean}
   */
  isIPBlocked(ipAddress) {
    return this.blockedIPs.has(ipAddress);
  }

  /**
   * Block IP address
   * @param {string} ipAddress 
   * @param {string} reason 
   * @param {number} duration 
   * @returns {Promise<void>}
   */
  async blockIP(ipAddress, reason = 'Security violation', duration = null) {
    try {
      this.blockedIPs.add(ipAddress);

      // Log security event
      await auditService.logSecurityEvent(
        null,
        'IP_BLOCKED',
        'high',
        `IP address ${ipAddress} blocked: ${reason}`,
        { ip_address: ipAddress, reason, duration },
        ipAddress
      );

      // Auto-unblock after duration if specified
      if (duration) {
        setTimeout(() => {
          this.unblockIP(ipAddress);
        }, duration);
      }

      console.warn(`IP ${ipAddress} blocked: ${reason}`);
    } catch (error) {
      console.error('IP blocking failed:', error);
    }
  }

  /**
   * Unblock IP address
   * @param {string} ipAddress 
   * @returns {Promise<void>}
   */
  async unblockIP(ipAddress) {
    try {
      this.blockedIPs.delete(ipAddress);

      await auditService.logSecurityEvent(
        null,
        'IP_UNBLOCKED',
        'medium',
        `IP address ${ipAddress} unblocked`,
        { ip_address: ipAddress },
        ipAddress
      );

      console.info(`IP ${ipAddress} unblocked`);
    } catch (error) {
      console.error('IP unblocking failed:', error);
    }
  }

  /**
   * Analyze request for security threats
   * @param {object} request 
   * @returns {object}
   */
  analyzeRequest(request) {
    const analysis = {
      threatLevel: 'low',
      threats: [],
      blocked: false,
      recommendations: []
    };

    const { ip, userAgent, headers, body, path } = request;

    // Check blocked IPs
    if (this.isIPBlocked(ip)) {
      analysis.blocked = true;
      analysis.threatLevel = 'critical';
      analysis.threats.push('IP_BLOCKED');
      return analysis;
    }

    // SQL Injection detection
    if (this.detectSQLInjection(body, path)) {
      analysis.threats.push('SQL_INJECTION');
      analysis.threatLevel = 'high';
    }

    // XSS detection
    if (this.detectXSS(body)) {
      analysis.threats.push('XSS_ATTEMPT');
      analysis.threatLevel = 'high';
    }

    // Suspicious user agent
    if (this.isSuspiciousUserAgent(userAgent)) {
      analysis.threats.push('SUSPICIOUS_USER_AGENT');
      analysis.threatLevel = analysis.threatLevel === 'low' ? 'medium' : analysis.threatLevel;
    }

    // Rate limiting check
    if (this.checkRateLimit(ip)) {
      analysis.threats.push('RATE_LIMIT_EXCEEDED');
      analysis.threatLevel = 'medium';
    }

    // Generate recommendations
    this.generateSecurityRecommendations(analysis);

    return analysis;
  }

  /**
   * Detect SQL injection attempts
   * @param {object} data 
   * @param {string} path 
   * @returns {boolean}
   */
  detectSQLInjection(data, path) {
    const sqlPatterns = [
      /union\s+select/i,
      /select\s+\*\s+from/i,
      /drop\s+table/i,
      /insert\s+into/i,
      /delete\s+from/i,
      /update\s+set/i,
      /exec\s*\(/i,
      /script\s*\(/i,
      /'.*or.*'/i,
      /".*or.*"/i,
      /1\s*=\s*1/i,
      /1\s*or\s*1/i
    ];

    const dataString = JSON.stringify(data) + path;
    return sqlPatterns.some(pattern => pattern.test(dataString));
  }

  /**
   * Detect XSS attempts
   * @param {object} data 
   * @returns {boolean}
   */
  detectXSS(data) {
    const xssPatterns = [
      /<script[^>]*>.*?<\/script>/i,
      /javascript\s*:/i,
      /on\w+\s*=\s*['"]/i,
      /<iframe[^>]*>/i,
      /<object[^>]*>/i,
      /<embed[^>]*>/i,
      /<link[^>]*>/i,
      /<meta[^>]*>/i,
      /eval\s*\(/i,
      /setTimeout\s*\(/i,
      /setInterval\s*\(/i
    ];

    const dataString = JSON.stringify(data);
    return xssPatterns.some(pattern => pattern.test(dataString));
  }

  /**
   * Check if user agent is suspicious
   * @param {string} userAgent 
   * @returns {boolean}
   */
  isSuspiciousUserAgent(userAgent) {
    if (!userAgent) return true;

    const suspiciousPatterns = [
      /bot/i,
      /crawler/i,
      /spider/i,
      /scraper/i,
      /curl/i,
      /wget/i,
      /python/i,
      /perl/i,
      /php/i,
      /scanner/i,
      /vulnerability/i
    ];

    // Very short or very long user agents are suspicious
    if (userAgent.length < 10 || userAgent.length > 500) {
      return true;
    }

    return suspiciousPatterns.some(pattern => pattern.test(userAgent));
  }

  /**
   * Check rate limiting
   * @param {string} ip 
   * @returns {boolean}
   */
  checkRateLimit(ip) {
    const now = Date.now();
    const windowSize = 60 * 1000; // 1 minute
    const maxRequests = 100;

    if (!this.suspiciousActivities.has(ip)) {
      this.suspiciousActivities.set(ip, []);
    }

    const requests = this.suspiciousActivities.get(ip);
    
    // Remove old requests outside the window
    const validRequests = requests.filter(timestamp => now - timestamp < windowSize);
    
    // Add current request
    validRequests.push(now);
    
    // Update the map
    this.suspiciousActivities.set(ip, validRequests);

    return validRequests.length > maxRequests;
  }

  /**
   * Generate security recommendations
   * @param {object} analysis 
   */
  generateSecurityRecommendations(analysis) {
    if (analysis.threats.includes('SQL_INJECTION')) {
      analysis.recommendations.push('Block request and investigate SQL injection attempt');
    }

    if (analysis.threats.includes('XSS_ATTEMPT')) {
      analysis.recommendations.push('Sanitize input and block XSS attempt');
    }

    if (analysis.threats.includes('RATE_LIMIT_EXCEEDED')) {
      analysis.recommendations.push('Implement rate limiting and consider temporary IP block');
    }

    if (analysis.threats.includes('SUSPICIOUS_USER_AGENT')) {
      analysis.recommendations.push('Monitor user agent and consider additional verification');
    }
  }

  /**
   * Encrypt sensitive user data
   * @param {object} data 
   * @param {number} userId 
   * @returns {Promise<object>}
   */
  async encryptUserData(data, userId = null) {
    try {
      const encryptedData = {};

      for (const [key, value] of Object.entries(data)) {
        if (value !== null && value !== undefined) {
          encryptedData[key] = await encryptionService.encrypt(String(value));
        }
      }

      // Log encryption activity
      if (userId) {
        await auditService.logActivity(
          userId,
          'DATA_ENCRYPT',
          'user_data',
          null,
          { fields_encrypted: Object.keys(data) }
        );
      }

      return encryptedData;
    } catch (error) {
      throw new AppError(`Data encryption failed: ${error.message}`, 500);
    }
  }

  /**
   * Decrypt sensitive user data
   * @param {object} encryptedData 
   * @param {number} userId 
   * @returns {Promise<object>}
   */
  async decryptUserData(encryptedData, userId = null) {
    try {
      const decryptedData = {};

      for (const [key, value] of Object.entries(encryptedData)) {
        if (value !== null && value !== undefined) {
          decryptedData[key] = await encryptionService.decrypt(value);
        }
      }

      // Log decryption activity
      if (userId) {
        await auditService.logActivity(
          userId,
          'DATA_DECRYPT',
          'user_data',
          null,
          { fields_decrypted: Object.keys(encryptedData) }
        );
      }

      return decryptedData;
    } catch (error) {
      throw new AppError(`Data decryption failed: ${error.message}`, 500);
    }
  }

  /**
   * Perform security scan on user account
   * @param {number} userId 
   * @returns {Promise<object>}
   */
  async performSecurityScan(userId) {
    try {
      const scan = {
        userId,
        scannedAt: new Date(),
        overallRisk: 'low',
        findings: [],
        recommendations: []
      };

      // Check for weak encryption keys
      const userKeys = await EncryptionKey.findAll({
        where: { user_id: userId, revoked_at: null }
      });

      for (const key of userKeys) {
        const validation = keyManagementService.validateKey(key.key_data_encrypted, key.key_type);
        if (!validation.isValid || validation.strength === 'weak') {
          scan.findings.push({
            type: 'WEAK_ENCRYPTION_KEY',
            severity: 'medium',
            description: `Weak or invalid ${key.key_type} key detected`,
            keyId: key.id
          });
          scan.recommendations.push('Rotate weak encryption keys');
        }
      }

      // Check for expired keys
      const expiredKeys = userKeys.filter(key => key.expires_at && key.expires_at < new Date());
      if (expiredKeys.length > 0) {
        scan.findings.push({
          type: 'EXPIRED_KEYS',
          severity: 'medium',
          description: `${expiredKeys.length} expired encryption keys found`,
          count: expiredKeys.length
        });
        scan.recommendations.push('Remove or renew expired keys');
      }

      // Check recent security events
      const recentEvents = await SecurityEvent.findAll({
        where: {
          user_id: userId,
          created_at: { [Op.gte]: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
        }
      });

      const highSeverityEvents = recentEvents.filter(event => 
        ['high', 'critical'].includes(event.severity)
      );

      if (highSeverityEvents.length > 0) {
        scan.findings.push({
          type: 'HIGH_RISK_EVENTS',
          severity: 'high',
          description: `${highSeverityEvents.length} high-risk security events in past 7 days`,
          count: highSeverityEvents.length
        });
        scan.overallRisk = 'high';
        scan.recommendations.push('Review and address high-risk security events');
      }

      // Check for unused keys (no recent activity)
      const unusedKeys = userKeys.filter(key => {
        const age = Date.now() - key.created_at.getTime();
        return age > 90 * 24 * 60 * 60 * 1000; // 90 days
      });

      if (unusedKeys.length > 0) {
        scan.findings.push({
          type: 'UNUSED_KEYS',
          severity: 'low',
          description: `${unusedKeys.length} keys haven't been used in 90+ days`,
          count: unusedKeys.length
        });
        scan.recommendations.push('Review and revoke unused keys');
      }

      // Determine overall risk
      const mediumRiskCount = scan.findings.filter(f => f.severity === 'medium').length;
      const highRiskCount = scan.findings.filter(f => f.severity === 'high').length;

      if (highRiskCount > 0) {
        scan.overallRisk = 'high';
      } else if (mediumRiskCount > 2) {
        scan.overallRisk = 'medium';
      }

      // Log security scan
      await auditService.logActivity(
        userId,
        'SECURITY_SCAN',
        'user',
        userId,
        {
          findings_count: scan.findings.length,
          overall_risk: scan.overallRisk,
          scan_duration: Date.now() - scan.scannedAt.getTime()
        }
      );

      return scan;
    } catch (error) {
      throw new AppError(`Security scan failed: ${error.message}`, 500);
    }
  }

  /**
   * Check if password is commonly used
   * @param {string} password 
   * @returns {boolean}
   */
  isCommonPassword(password) {
    const commonPasswords = [
      'password', '123456', '123456789', '12345678', '12345',
      'qwerty', 'abc123', 'password123', 'admin', 'welcome',
      'letmein', 'monkey', '1234567890', 'dragon', 'master',
      'login', 'pass', 'hello', 'guest', 'default'
    ];

    return commonPasswords.includes(password.toLowerCase());
  }

  /**
   * Check for sequential characters
   * @param {string} password 
   * @returns {boolean}
   */
  hasSequentialCharacters(password) {
    const sequences = [
      'abcdefghijklmnopqrstuvwxyz',
      'qwertyuiopasdfghjklzxcvbnm',
      '1234567890'
    ];

    for (const seq of sequences) {
      for (let i = 0; i <= seq.length - 3; i++) {
        const subseq = seq.substring(i, i + 3);
        if (password.toLowerCase().includes(subseq)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Get security metrics
   * @returns {Promise<object>}
   */
  async getSecurityMetrics() {
    try {
      const [
        totalSecurityEvents,
        highRiskEvents,
        blockedIPs,
        encryptionKeys,
        recentThreats
      ] = await Promise.all([
        SecurityEvent.count(),
        SecurityEvent.count({ where: { severity: { [Op.in]: ['high', 'critical'] } } }),
        Promise.resolve(this.blockedIPs.size),
        EncryptionKey.count({ where: { revoked_at: null } }),
        SecurityEvent.findAll({
          where: {
            created_at: { [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000) },
            severity: { [Op.in]: ['high', 'critical'] }
          },
          limit: 10,
          order: [['created_at', 'DESC']]
        })
      ]);

      return {
        totalSecurityEvents,
        highRiskEvents,
        blockedIPs,
        activeEncryptionKeys: encryptionKeys,
        threatLevel: this.calculateThreatLevel(highRiskEvents, blockedIPs),
        recentThreats: recentThreats.map(event => ({
          type: event.event_type,
          severity: event.severity,
          description: event.description,
          createdAt: event.created_at
        }))
      };
    } catch (error) {
      throw new AppError(error.message, 500);
    }
  }

  /**
   * Calculate overall threat level
   * @param {number} highRiskEvents 
   * @param {number} blockedIPs 
   * @returns {string}
   */
  calculateThreatLevel(highRiskEvents, blockedIPs) {
    if (highRiskEvents > 10 || blockedIPs > 5) {
      return 'high';
    } else if (highRiskEvents > 3 || blockedIPs > 1) {
      return 'medium';
    } else {
      return 'low';
    }
  }
}

export default new SecurityService();