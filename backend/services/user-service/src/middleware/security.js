import helmet from 'helmet';
import xss from 'xss';
import validator from 'validator';

// Input sanitization middleware
const sanitizeInput = (req, res, next) => {
  try {
    // Sanitize request body
    if (req.body && typeof req.body === 'object') {
      req.body = sanitizeObject(req.body);
    }

    // Sanitize query parameters
    if (req.query && typeof req.query === 'object') {
      req.query = sanitizeObject(req.query);
    }

    // Sanitize route parameters
    if (req.params && typeof req.params === 'object') {
      req.params = sanitizeObject(req.params);
    }

    next();
  } catch (error) {
    return res.status(400).json({
      success: false,
      message: 'Invalid input data',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// XSS prevention middleware
const preventXSS = (req, res, next) => {
  try {
    // Clean request body
    if (req.body && typeof req.body === 'object') {
      req.body = cleanXSS(req.body);
    }

    // Clean query parameters
    if (req.query && typeof req.query === 'object') {
      req.query = cleanXSS(req.query);
    }

    // Clean route parameters
    if (req.params && typeof req.params === 'object') {
      req.params = cleanXSS(req.params);
    }

    next();
  } catch (error) {
    return res.status(400).json({
      success: false,
      message: 'Invalid input detected',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// SQL injection prevention middleware
const preventSQLInjection = (req, res, next) => {
  try {
    const sqlInjectionPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/i,
      /('|(\\')|(;)|(\\)|(\/\*)|(\*\/)|(--)|(\|))/i,
      /(0x[0-9A-Fa-f]+)/i
    ];

    const checkForSQLInjection = (value) => {
      if (typeof value === 'string') {
        return sqlInjectionPatterns.some(pattern => pattern.test(value));
      }
      return false;
    };

    const hasInjection = 
      checkObjectForSQLInjection(req.body) ||
      checkObjectForSQLInjection(req.query) ||
      checkObjectForSQLInjection(req.params);

    if (hasInjection) {
      return res.status(400).json({
        success: false,
        message: 'Potential SQL injection detected'
      });
    }

    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Security validation error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Rate limiting for security-sensitive endpoints
const securityRateLimit = (maxRequests = 10, windowMs = 15 * 60 * 1000) => {
  const requests = new Map();

  return (req, res, next) => {
    const clientId = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowStart = now - windowMs;

    if (!requests.has(clientId)) {
      requests.set(clientId, []);
    }

    const clientRequests = requests.get(clientId);
    const validRequests = clientRequests.filter(time => time > windowStart);
    
    if (validRequests.length >= maxRequests) {
      return res.status(429).json({
        success: false,
        message: 'Too many security requests. Please try again later.',
        retryAfter: Math.ceil(windowMs / 1000)
      });
    }

    validRequests.push(now);
    requests.set(clientId, validRequests);

    next();
  };
};

// CSRF protection middleware
const csrfProtection = (req, res, next) => {
  // Skip CSRF for GET requests and API endpoints with proper authentication
  if (req.method === 'GET' || req.path.startsWith('/api/auth/')) {
    return next();
  }

  const token = req.headers['x-csrf-token'] || req.body._csrf;
  const sessionToken = req.session?.csrfToken;

  if (!token || !sessionToken || token !== sessionToken) {
    return res.status(403).json({
      success: false,
      message: 'CSRF token validation failed'
    });
  }

  next();
};

// Content Security Policy middleware
const contentSecurityPolicy = helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", 'https://trusted-cdn.com'],
    styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    imgSrc: ["'self'", 'data:', 'https:'],
    connectSrc: ["'self'"],
    fontSrc: ["'self'", 'https://fonts.gstatic.com'],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"]
  }
});

// Helper functions
function sanitizeObject(obj) {
  if (obj === null || obj === undefined) return obj;
  
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item));
  }
  
  if (typeof obj === 'object') {
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      const cleanKey = validator.escape(key.toString());
      sanitized[cleanKey] = sanitizeObject(value);
    }
    return sanitized;
  }
  
  if (typeof obj === 'string') {
    return validator.escape(obj.trim());
  }
  
  return obj;
}

function cleanXSS(obj) {
  if (obj === null || obj === undefined) return obj;
  
  if (Array.isArray(obj)) {
    return obj.map(item => cleanXSS(item));
  }
  
  if (typeof obj === 'object') {
    const cleaned = {};
    for (const [key, value] of Object.entries(obj)) {
      cleaned[key] = cleanXSS(value);
    }
    return cleaned;
  }
  
  if (typeof obj === 'string') {
    return xss(obj, {
      whiteList: {}, // No HTML tags allowed
      stripIgnoreTag: true,
      stripIgnoreTagBody: ['script']
    });
  }
  
  return obj;
}

function checkObjectForSQLInjection(obj) {
  if (!obj || typeof obj !== 'object') return false;
  
  if (Array.isArray(obj)) {
    return obj.some(item => checkObjectForSQLInjection(item));
  }
  
  for (const value of Object.values(obj)) {
    if (typeof value === 'string') {
      const sqlInjectionPatterns = [
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/i,
        /('|(\\')|(;)|(\\)|(\/\*)|(\*\/)|(--)|(\|))/i,
        /(0x[0-9A-Fa-f]+)/i
      ];
      
      if (sqlInjectionPatterns.some(pattern => pattern.test(value))) {
        return true;
      }
    } else if (typeof value === 'object') {
      if (checkObjectForSQLInjection(value)) {
        return true;
      }
    }
  }
  
  return false;
}

// Export all security middleware
export const security = {
  sanitizeInput,
  preventXSS,
  preventSQLInjection,
  securityRateLimit,
  csrfProtection,
  contentSecurityPolicy,
  
  // Helmet middleware for additional security headers
  helmet: helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false // We handle this separately above
  })
};

// Default export for convenience
export default security;