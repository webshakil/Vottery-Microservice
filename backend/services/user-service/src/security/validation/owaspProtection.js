// src/security/validation/owaspProtection.js
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { randomBytes, createHash } from 'crypto';

/**
 * OWASP Security Protection Service for Vottery User Service
 * Implements OWASP Top 10 security controls and best practices
 */
class OwaspProtection {
  // Content Security Policy configuration
  static CSP_CONFIG = {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      connectSrc: ["'self'", "https://api.vottery.com"]
    }
  };

  // Rate limiting configurations
  static RATE_LIMITS = {
    general: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP'
    },
    auth: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // limit each IP to 5 auth attempts per windowMs
      message: 'Too many authentication attempts'
    },
    api: {
      windowMs: 60 * 1000, // 1 minute
      max: 30, // limit each IP to 30 API calls per minute
      message: 'API rate limit exceeded'
    }
  };

  /**
   * Configure Helmet security middleware
   * @param {Object} customConfig - Custom helmet configuration
   * @returns {Function} Helmet middleware
   */
  static configureHelmet(customConfig = {}) {
    return helmet({
      // Content Security Policy
      contentSecurityPolicy: customConfig.csp || this.CSP_CONFIG,
      
      // DNS Prefetch Control
      dnsPrefetchControl: { allow: false },
      
      // Frame Guard (prevent clickjacking)
      frameguard: { action: 'deny' },
      
      // Hide X-Powered-By header
      hidePoweredBy: true,
      
      // HTTP Strict Transport Security
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      },
      
      // IE No Open
      ieNoOpen: true,
      
      // Don't Sniff Mimetype
      noSniff: true,
      
      // Referrer Policy
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      
      // X-XSS-Protection
      xssFilter: true,
      
      ...customConfig
    });
  }

  /**
   * Create rate limiting middleware
   * @param {string} type - Rate limit type (general, auth, api)
   * @param {Object} customConfig - Custom rate limit configuration
   * @returns {Function} Rate limiting middleware
   */
  static createRateLimit(type = 'general', customConfig = {}) {
    const config = { ...this.RATE_LIMITS[type], ...customConfig };
    
    return rateLimit({
      ...config,
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        res.status(429).json({
          error: 'Rate limit exceeded',
          message: config.message,
          retryAfter: Math.round(config.windowMs / 1000)
        });
      }
    });
  }

  /**
   * A1: Injection Prevention
   * Prevent SQL, NoSQL, OS, and LDAP injection attacks
   */
  static preventInjection = {
    /**
     * SQL Injection prevention
     * @param {string} input - User input
     * @returns {boolean} True if input is safe
     */
    checkSqlInjection(input) {
      if (!input || typeof input !== 'string') return true;
      
      const sqlPatterns = [
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/gi,
        /(--|\/\*|\*\/|;|'|"|\|)/g,
        /(\b(OR|AND)\b\s*[\d\w]+\s*=\s*[\d\w]+)/gi,
        /(EXEC|EXECUTE)/gi,
        /(SP_|XP_)/gi
      ];
      
      return !sqlPatterns.some(pattern => pattern.test(input));
    },

    /**
     * NoSQL Injection prevention
     * @param {Object} query - Database query object
     * @returns {boolean} True if query is safe
     */
    checkNoSqlInjection(query) {
      if (!query || typeof query !== 'object') return true;
      
      const dangerousKeys = ['$where', '$regex', '$ne', '$gt', '$lt', '$or', '$and'];
      const queryString = JSON.stringify(query);
      
      return !dangerousKeys.some(key => queryString.includes(key));
    },

    /**
     * Command Injection prevention
     * @param {string} input - User input
     * @returns {boolean} True if input is safe
     */
    checkCommandInjection(input) {
      if (!input || typeof input !== 'string') return true;
      
      const cmdPatterns = [
        /[;&|`$(){}[\]]/g,
        /(ls|cat|pwd|whoami|id|ps|netstat|ifconfig)/gi,
        /(rm|mv|cp|chmod|chown)/gi,
        /(wget|curl|nc|telnet|ssh)/gi
      ];
      
      return !cmdPatterns.some(pattern => pattern.test(input));
    }
  };

  /**
   * A2: Broken Authentication Prevention
   */
  static authenticationSecurity = {
    /**
     * Validate password strength
     * @param {string} password - Password to validate
     * @returns {Object} Validation result
     */
    validatePasswordStrength(password) {
      const requirements = {
        minLength: password && password.length >= 8,
        hasUppercase: /[A-Z]/.test(password),
        hasLowercase: /[a-z]/.test(password),
        hasNumbers: /\d/.test(password),
        hasSpecialChars: /[!@#$%^&*(),.?":{}|<>]/.test(password),
        noCommonPatterns: !this.checkCommonPatterns(password)
      };
      
      const score = Object.values(requirements).filter(Boolean).length;
      
      return {
        isValid: score >= 5,
        score: score,
        requirements: requirements,
        strength: this.getPasswordStrength(score)
      };
    },

    /**
     * Check for common password patterns
     * @param {string} password - Password to check
     * @returns {boolean} True if common patterns found
     */
    checkCommonPatterns(password) {
      const commonPatterns = [
        /123456/,
        /password/i,
        /qwerty/i,
        /admin/i,
        /letmein/i,
        /welcome/i,
        /monkey/i,
        /dragon/i
      ];
      
      return commonPatterns.some(pattern => pattern.test(password));
    },

    /**
     * Get password strength level
     * @param {number} score - Password score
     * @returns {string} Strength level
     */
    getPasswordStrength(score) {
      if (score >= 6) return 'very_strong';
      if (score >= 5) return 'strong';
      if (score >= 4) return 'medium';
      if (score >= 3) return 'weak';
      return 'very_weak';
    }
  };

  /**
   * A3: Sensitive Data Exposure Prevention
   */
  static dataProtection = {
    /**
     * Generate secure random token
     * @param {number} length - Token length in bytes
     * @returns {string} Secure random token
     */
    generateSecureToken(length = 32) {
      return randomBytes(length).toString('hex');
    },

    /**
     * Create data hash for integrity checking
     * @param {string} data - Data to hash
     * @param {string} salt - Salt for hashing
     * @returns {string} Data hash
     */
    createDataHash(data, salt = '') {
      return createHash('sha256').update(salt + data).digest('hex');
    },

    /**
     * Mask sensitive data for logging
     * @param {string} data - Sensitive data
     * @param {number} visibleChars - Number of visible characters
     * @returns {string} Masked data
     */
    maskSensitiveData(data, visibleChars = 4) {
      if (!data || data.length <= visibleChars) return '***';
      return data.substring(0, visibleChars) + '*'.repeat(data.length - visibleChars);
    }
  };

  /**
   * A4: XML External Entities (XXE) Prevention
   */
  static xxePrevention = {
    /**
     * Safe XML parsing configuration
     * @returns {Object} Safe XML parser options
     */
    getSafeXmlConfig() {
      return {
        explicitRoot: false,
        explicitArray: false,
        ignoreAttrs: true,
        parseNumbers: false,
        parseBooleans: false,
        trim: true,
        normalize: true,
        normalizeTags: true,
        async: false
      };
    },

    /**
     * Validate XML content before parsing
     * @param {string} xmlContent - XML content
     * @returns {boolean} True if XML is safe
     */
    validateXmlContent(xmlContent) {
      if (!xmlContent) return false;
      
      const dangerousPatterns = [
        /<!DOCTYPE/gi,
        /<!ENTITY/gi,
        /SYSTEM/gi,
        /PUBLIC/gi,
        /file:\/\//gi,
        /http:\/\//gi,
        /https:\/\//gi
      ];
      
      return !dangerousPatterns.some(pattern => pattern.test(xmlContent));
    }
  };

  /**
   * A5: Broken Access Control Prevention
   */
  static accessControl = {
    /**
     * Validate user permissions for resource access
     * @param {Object} user - User object
     * @param {string} resource - Resource identifier
     * @param {string} action - Action to perform
     * @returns {boolean} True if access is allowed
     */
    validateAccess(user, resource, action) {
      if (!user || !user.permissions) return false;
      
      const requiredPermission = `${resource}:${action}`;
      return user.permissions.includes(requiredPermission) || 
             user.permissions.includes(`${resource}:*`) ||
             user.permissions.includes('*:*');
    },

    /**
     * Check for privilege escalation attempts
     * @param {Object} currentUser - Current user
     * @param {Object} targetUser - Target user for modification
     * @returns {boolean} True if escalation attempt detected
     */
    checkPrivilegeEscalation(currentUser, targetUser) {
      if (!currentUser || !targetUser) return true;
      
      // Can't modify users with higher or equal privilege levels
      return targetUser.privilegeLevel >= currentUser.privilegeLevel;
    }
  };

  /**
   * A6: Security Misconfiguration Prevention
   */
  static securityConfig = {
    /**
     * Validate security headers
     * @param {Object} headers - HTTP headers
     * @returns {Object} Security validation result
     */
    validateSecurityHeaders(headers) {
      const requiredHeaders = {
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'x-xss-protection': '1; mode=block',
        'strict-transport-security': /max-age=\d+/,
        'content-security-policy': /.+/
      };
      
      const missing = [];
      const invalid = [];
      
      for (const [header, expectedValue] of Object.entries(requiredHeaders)) {
        const actualValue = headers[header];
        
        if (!actualValue) {
          missing.push(header);
        } else if (expectedValue instanceof RegExp) {
          if (!expectedValue.test(actualValue)) {
            invalid.push(header);
          }
        } else if (actualValue !== expectedValue) {
          invalid.push(header);
        }
      }
      
      return {
        isSecure: missing.length === 0 && invalid.length === 0,
        missing,
        invalid
      };
    }
  };

  /**
   * A7: Cross-Site Scripting (XSS) Prevention
   */
  static xssPrevention = {
    /**
     * Detect XSS patterns
     * @param {string} input - User input
     * @returns {boolean} True if XSS detected
     */
    detectXss(input) {
      if (!input || typeof input !== 'string') return false;
      
      const xssPatterns = [
        /<script[^>]*>[\s\S]*?<\/script>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi,
        /<iframe[^>]*>/gi,
        /<object[^>]*>/gi,
        /<embed[^>]*>/gi,
        /eval\s*\(/gi,
        /expression\s*\(/gi,
        /<svg[^>]*onload/gi,
        /<img[^>]*onerror/gi
      ];
      
      return xssPatterns.some(pattern => pattern.test(input));
    }
  };

  /**
   * A8: Insecure Deserialization Prevention
   */
  static deserializationSecurity = {
    /**
     * Safe JSON parsing with size and depth limits
     * @param {string} jsonString - JSON string to parse
     * @param {Object} options - Parsing options
     * @returns {Object} Parsed object or null if unsafe
     */
    safeJsonParse(jsonString, options = {}) {
      const maxSize = options.maxSize || 1048576; // 1MB default
      const maxDepth = options.maxDepth || 10;
      
      if (!jsonString || jsonString.length > maxSize) {
        return null;
      }
      
      try {
        const parsed = JSON.parse(jsonString);
        
        if (this.getObjectDepth(parsed) > maxDepth) {
          return null;
        }
        
        return parsed;
      } catch (error) {
        return null;
      }
    },

    /**
     * Calculate object depth
     * @param {Object} obj - Object to analyze
     * @returns {number} Object depth
     */
    getObjectDepth(obj) {
      if (obj === null || typeof obj !== 'object') return 0;
      
      let depth = 1;
      for (const value of Object.values(obj)) {
        if (typeof value === 'object' && value !== null) {
          depth = Math.max(depth, 1 + this.getObjectDepth(value));
        }
      }
      
      return depth;
    }
  };

  /**
   * A10: Insufficient Logging & Monitoring Prevention
   */
  static loggingMonitoring = {
    /**
     * Create security event log entry
     * @param {string} eventType - Type of security event
     * @param {Object} details - Event details
     * @param {Object} request - HTTP request object
     * @returns {Object} Log entry
     */
    createSecurityLog(eventType, details, request) {
      return {
        timestamp: new Date().toISOString(),
        eventType,
        severity: this.getEventSeverity(eventType),
        userId: request.user?.id || 'anonymous',
        sessionId: request.sessionID,
        ip: request.ip || request.connection.remoteAddress,
        userAgent: request.get('User-Agent'),
        url: request.url,
        method: request.method,
        details
      };
    },

    /**
     * Get event severity level
     * @param {string} eventType - Event type
     * @returns {string} Severity level
     */
    getEventSeverity(eventType) {
      const severityMap = {
        'login_attempt': 'info',
        'login_failure': 'warning',
        'multiple_login_failures': 'high',
        'privilege_escalation': 'critical',
        'data_access_violation': 'high',
        'injection_attempt': 'critical',
        'xss_attempt': 'high',
        'rate_limit_exceeded': 'warning'
      };
      
      return severityMap[eventType] || 'info';
    }
  };

  /**
   * Create comprehensive OWASP middleware stack
   * @param {Object} options - Configuration options
   * @returns {Array} Array of middleware functions
   */
  static createMiddlewareStack(options = {}) {
    return [
      // Security headers
      this.configureHelmet(options.helmet),
      
      // Rate limiting
      this.createRateLimit('general', options.rateLimit),
      
      // Custom security middleware
      (req, res, next) => {
        // Add security context to request
        req.security = {
          validateAccess: (resource, action) => 
            this.accessControl.validateAccess(req.user, resource, action),
          checkInjection: (input) => 
            this.preventInjection.checkSqlInjection(input),
          logSecurityEvent: (eventType, details) => 
            this.loggingMonitoring.createSecurityLog(eventType, details, req)
        };
        
        next();
      }
    ];
  }
}

export default OwaspProtection;