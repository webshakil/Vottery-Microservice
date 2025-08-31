// src/security/validation/sanitizer.js
import DOMPurify from 'isomorphic-dompurify';
import validator from 'validator';

/**
 * Data Sanitization Service for Vottery User Service
 * Advanced sanitization to prevent XSS, SQL injection, and other attacks
 */
class Sanitizer {
  // HTML sanitization configuration
  static HTML_CONFIG = {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'u', 'p', 'br', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['class', 'id'],
    FORBID_TAGS: ['script', 'object', 'embed', 'iframe', 'form', 'input'],
    FORBID_ATTR: ['onclick', 'onload', 'onerror', 'onmouseover', 'style']
  };

  // SQL injection patterns
  static SQL_INJECTION_PATTERNS = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/gi,
    /(--|\*\/|\*|;|'|"|\|)/g,
    /(\b(OR|AND)\b\s*(\d+\s*=\s*\d+|\w+\s*=\s*\w+))/gi,
    /(\/\*[\s\S]*?\*\/)/g
  ];

  // XSS patterns
  static XSS_PATTERNS = [
    /<script[^>]*>[\s\S]*?<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<iframe[^>]*>[\s\S]*?<\/iframe>/gi,
    /<object[^>]*>[\s\S]*?<\/object>/gi,
    /<embed[^>]*>/gi,
    /eval\s*\(/gi,
    /expression\s*\(/gi
  ];

  // Path traversal patterns
  static PATH_TRAVERSAL_PATTERNS = [
    /\.\.\//g,
    /\.\.\\g/g,
    /%2e%2e%2f/gi,
    /%2e%2e\\/gi,
    /\.\.%2f/gi,
    /\.\.%5c/gi
  ];

  /**
   * Comprehensive input sanitization
   * @param {string} input - Input to sanitize
   * @param {Object} options - Sanitization options
   * @returns {string} Sanitized input
   */
  static sanitizeInput(input, options = {}) {
    if (!input || typeof input !== 'string') {
      return '';
    }

    let sanitized = input;

    // Basic sanitization
    if (options.trim !== false) {
      sanitized = sanitized.trim();
    }

    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '');

    // HTML sanitization
    if (options.allowHtml) {
      sanitized = this.sanitizeHtml(sanitized, options.htmlConfig);
    } else {
      sanitized = validator.escape(sanitized);
    }

    // SQL injection prevention
    if (options.preventSql !== false) {
      sanitized = this.preventSqlInjection(sanitized);
    }

    // XSS prevention
    if (options.preventXss !== false) {
      sanitized = this.preventXss(sanitized);
    }

    // Path traversal prevention
    if (options.preventPathTraversal !== false) {
      sanitized = this.preventPathTraversal(sanitized);
    }

    // Length limiting
    if (options.maxLength) {
      sanitized = sanitized.substring(0, options.maxLength);
    }

    return sanitized;
  }

  /**
   * Sanitize HTML content
   * @param {string} html - HTML content
   * @param {Object} config - DOMPurify configuration
   * @returns {string} Sanitized HTML
   */
  static sanitizeHtml(html, config = {}) {
    const mergedConfig = {
      ...this.HTML_CONFIG,
      ...config
    };

    return DOMPurify.sanitize(html, mergedConfig);
  }

  /**
   * Prevent SQL injection attacks
   * @param {string} input - Input to check
   * @returns {string} Sanitized input
   */
  static preventSqlInjection(input) {
    let sanitized = input;

    this.SQL_INJECTION_PATTERNS.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '');
    });

    // Additional SQL-specific sanitization
    sanitized = sanitized
      .replace(/'/g, "''") // Escape single quotes
      .replace(/;/g, '') // Remove semicolons
      .replace(/--/g, '') // Remove comment markers
      .replace(/\/\*/g, '') // Remove comment start
      .replace(/\*\//g, ''); // Remove comment end

    return sanitized;
  }

  /**
   * Prevent XSS attacks
   * @param {string} input - Input to check
   * @returns {string} Sanitized input
   */
  static preventXss(input) {
    let sanitized = input;

    this.XSS_PATTERNS.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '');
    });

    // Additional XSS prevention
    sanitized = sanitized
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');

    return sanitized;
  }

  /**
   * Prevent path traversal attacks
   * @param {string} input - Input to check
   * @returns {string} Sanitized input
   */
  static preventPathTraversal(input) {
    let sanitized = input;

    this.PATH_TRAVERSAL_PATTERNS.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '');
    });

    // Remove other dangerous path characters
    sanitized = sanitized.replace(/[<>:"|?*]/g, '');

    return sanitized;
  }

  /**
   * Sanitize user profile data
   * @param {Object} profileData - User profile data
   * @returns {Object} Sanitized profile data
   */
  static sanitizeUserProfile(profileData) {
    return {
      firstName: this.sanitizeInput(profileData.firstName, { maxLength: 50 }),
      lastName: this.sanitizeInput(profileData.lastName, { maxLength: 50 }),
      bio: this.sanitizeInput(profileData.bio, { 
        maxLength: 1000,
        allowHtml: true,
        htmlConfig: {
          ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
          ALLOWED_ATTR: []
        }
      }),
      website: profileData.website ? validator.normalizeURL(profileData.website) : null,
      location: this.sanitizeInput(profileData.location, { maxLength: 100 }),
      company: this.sanitizeInput(profileData.company, { maxLength: 100 })
    };
  }

  /**
   * Sanitize election data
   * @param {Object} electionData - Election data
   * @returns {Object} Sanitized election data
   */
  static sanitizeElectionData(electionData) {
    return {
      title: this.sanitizeInput(electionData.title, { maxLength: 200 }),
      description: this.sanitizeInput(electionData.description, {
        maxLength: 5000,
        allowHtml: true,
        htmlConfig: {
          ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'u', 'p', 'br', 'ul', 'ol', 'li'],
          ALLOWED_ATTR: []
        }
      }),
      candidates: electionData.candidates?.map(candidate => ({
        name: this.sanitizeInput(candidate.name, { maxLength: 100 }),
        description: this.sanitizeInput(candidate.description, {
          maxLength: 1000,
          allowHtml: true,
          htmlConfig: {
            ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
            ALLOWED_ATTR: []
          }
        }),
        imageUrl: candidate.imageUrl ? this.sanitizeUrl(candidate.imageUrl) : null
      })),
      tags: electionData.tags?.map(tag => 
        this.sanitizeInput(tag, { maxLength: 30 })
      ).filter(tag => tag.length > 0)
    };
  }

  /**
   * Sanitize organization data
   * @param {Object} orgData - Organization data
   * @returns {Object} Sanitized organization data
   */
  static sanitizeOrganizationData(orgData) {
    return {
      name: this.sanitizeInput(orgData.name, { maxLength: 100 }),
      description: this.sanitizeInput(orgData.description, {
        maxLength: 2000,
        allowHtml: true,
        htmlConfig: {
          ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li'],
          ALLOWED_ATTR: []
        }
      }),
      website: orgData.website ? this.sanitizeUrl(orgData.website) : null,
      registrationNumber: this.sanitizeInput(orgData.registrationNumber, { 
        maxLength: 50,
        preventSql: true,
        preventXss: true
      }),
      address: this.sanitizeInput(orgData.address, { maxLength: 200 }),
      contactEmail: orgData.contactEmail ? validator.normalizeEmail(orgData.contactEmail) : null
    };
  }

  /**
   * Sanitize URL
   * @param {string} url - URL to sanitize
   * @returns {string} Sanitized URL
   */
  static sanitizeUrl(url) {
    if (!url || typeof url !== 'string') {
      return null;
    }

    // Remove dangerous protocols
    const dangerousProtocols = ['javascript:', 'data:', 'vbscript:', 'file:'];
    const lowerUrl = url.toLowerCase();
    
    if (dangerousProtocols.some(protocol => lowerUrl.startsWith(protocol))) {
      return null;
    }

    // Validate and normalize URL
    if (validator.isURL(url, { protocols: ['http', 'https'] })) {
      return validator.normalizeURL(url);
    }

    return null;
  }

  /**
   * Sanitize filename for safe storage
   * @param {string} filename - Original filename
   * @returns {string} Sanitized filename
   */
  static sanitizeFilename(filename) {
    if (!filename || typeof filename !== 'string') {
      return 'unknown';
    }

    // Remove path traversal attempts
    let sanitized = filename.replace(/[\/\\:*?"<>|]/g, '');
    
    // Remove leading/trailing dots and spaces
    sanitized = sanitized.replace(/^[\.\s]+|[\.\s]+$/g, '');
    
    // Limit length
    if (sanitized.length > 255) {
      const ext = sanitized.substring(sanitized.lastIndexOf('.'));
      const name = sanitized.substring(0, 255 - ext.length);
      sanitized = name + ext;
    }

    // Ensure filename is not empty
    if (sanitized.length === 0) {
      sanitized = 'file';
    }

    return sanitized;
  }

  /**
   * Sanitize search query
   * @param {string} query - Search query
   * @returns {string} Sanitized query
   */
  static sanitizeSearchQuery(query) {
    if (!query || typeof query !== 'string') {
      return '';
    }

    let sanitized = query.trim();

    // Remove SQL injection attempts
    sanitized = this.preventSqlInjection(sanitized);

    // Remove XSS attempts
    sanitized = this.preventXss(sanitized);

    // Remove special regex characters that could cause ReDoS
    sanitized = sanitized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    // Limit length
    sanitized = sanitized.substring(0, 200);

    return sanitized;
  }

  /**
   * Sanitize JSON data recursively
   * @param {Object} data - JSON data
   * @param {Object} options - Sanitization options
   * @returns {Object} Sanitized data
   */
  static sanitizeJson(data, options = {}) {
    if (data === null || data === undefined) {
      return data;
    }

    if (typeof data === 'string') {
      return this.sanitizeInput(data, options);
    }

    if (typeof data === 'number' || typeof data === 'boolean') {
      return data;
    }

    if (Array.isArray(data)) {
      return data.map(item => this.sanitizeJson(item, options));
    }

    if (typeof data === 'object') {
      const sanitized = {};
      for (const [key, value] of Object.entries(data)) {
        const sanitizedKey = this.sanitizeInput(key, { preventSql: true, preventXss: true });
        sanitized[sanitizedKey] = this.sanitizeJson(value, options);
      }
      return sanitized;
    }

    return data;
  }

  /**
   * Create sanitization middleware for Express
   * @param {Object} options - Middleware options
   * @returns {Function} Express middleware
   */
  static createMiddleware(options = {}) {
    return (req, res, next) => {
      // Sanitize request body
      if (req.body && typeof req.body === 'object') {
        req.body = this.sanitizeJson(req.body, options);
      }

      // Sanitize query parameters
      if (req.query && typeof req.query === 'object') {
        req.query = this.sanitizeJson(req.query, options);
      }

      // Sanitize URL parameters
      if (req.params && typeof req.params === 'object') {
        req.params = this.sanitizeJson(req.params, options);
      }

      next();
    };
  }
}

export default Sanitizer;