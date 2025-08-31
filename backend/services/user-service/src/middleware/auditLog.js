
//import { auditService } from '../services/auditService.js';
import  auditService  from '../services/auditService.js';
import  redisClient  from '../config/redis.js';

/**
 * Audit Log Middleware
 * Comprehensive logging for security, compliance, and monitoring
 */

/**
 * General request/response audit logging
 */
export const auditLogger = (options = {}) => {
  const {
    logRequests = true,
    logResponses = true,
    excludePaths = ['/health', '/ping', '/favicon.ico'],
    excludeMethods = ['OPTIONS'],
    logBody = true,
    logHeaders = false,
    sensitiveFields = ['password', 'token', 'key', 'secret'],
    maxBodySize = 10000 // 10KB max body logging
  } = options;

  return async (req, res, next) => {
    try {
      const startTime = Date.now();
      const requestId = req.id || generateRequestId();
      
      // Skip excluded paths and methods
      if (excludePaths.includes(req.path) || excludeMethods.includes(req.method)) {
        return next();
      }

      // Store request context
      req.auditContext = {
        requestId,
        startTime,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        method: req.method,
        path: req.originalUrl,
        userId: req.user?.id || null
      };

      // Log request if enabled
      if (logRequests) {
        await logRequest(req, { logBody, logHeaders, sensitiveFields, maxBodySize });
      }

      // Store original res.end to intercept response
      const originalEnd = res.end;
      let responseBody = '';

      // Capture response body if logging responses
      if (logResponses) {
        const originalSend = res.send;
        res.send = function(data) {
          responseBody = data;
          return originalSend.call(this, data);
        };
      }

      // Override res.end to log when response completes
      res.end = async function(chunk) {
        const endTime = Date.now();
        const duration = endTime - startTime;

        try {
          // Log response if enabled
          if (logResponses) {
            await logResponse(req, res, responseBody, duration);
          }

          // Log performance metrics
          await logPerformanceMetrics(req, duration);

          // Log security events
          await logSecurityEvents(req, res);

        } catch (logError) {
          console.error('Audit logging error:', logError);
        }

        return originalEnd.call(this, chunk);
      };

      next();

    } catch (error) {
      console.error('Audit middleware error:', error);
      next();
    }
  };
};

/**
 * Authentication event logging
 */
export const auditAuthentication = async (req, res, next) => {
  try {
    const originalSend = res.send;

    res.send = async function(data) {
      try {
        let parsedData = data;
        if (typeof data === 'string') {
          try {
            parsedData = JSON.parse(data);
          } catch (e) {
            parsedData = { message: data };
          }
        }

        // Determine authentication event type
        let eventType = 'AUTH_UNKNOWN';
        let success = false;

        if (req.path.includes('/login')) {
          eventType = res.statusCode < 400 ? 'LOGIN_SUCCESS' : 'LOGIN_FAILED';
          success = res.statusCode < 400;
        } else if (req.path.includes('/logout')) {
          eventType = 'LOGOUT';
          success = true;
        } else if (req.path.includes('/register')) {
          eventType = res.statusCode < 400 ? 'REGISTRATION_SUCCESS' : 'REGISTRATION_FAILED';
          success = res.statusCode < 400;
        } else if (req.path.includes('/reset-password')) {
          eventType = res.statusCode < 400 ? 'PASSWORD_RESET_SUCCESS' : 'PASSWORD_RESET_FAILED';
          success = res.statusCode < 400;
        }

        // Log authentication event
        await auditService.log(req.user?.id || null, eventType, 'auth', null, {
          success,
          email: req.body?.email,
          method: req.body?.method || 'email_password',
          ip: req.ip,
          userAgent: req.headers['user-agent'],
          statusCode: res.statusCode,
          sessionId: req.sessionID,
          biometricUsed: !!req.body?.biometric_data,
          mfaUsed: !!req.headers['x-mfa-token']
        }, req);

      } catch (error) {
        console.error('Authentication audit error:', error);
      }

      return originalSend.call(this, data);
    };

    next();

  } catch (error) {
    console.error('Authentication audit middleware error:', error);
    next();
  }
};

/**
 * Data access audit logging
 */
export const auditDataAccess = (resourceType, action = 'READ') => {
  return async (req, res, next) => {
    try {
      const resourceId = req.params.id || req.params.userId || req.params.organizationId;
      
      const originalSend = res.send;

      res.send = async function(data) {
        try {
          const success = res.statusCode < 400;
          
          await auditService.log(req.user?.id || null, `DATA_${action}`, resourceType, resourceId, {
            success,
            statusCode: res.statusCode,
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            method: req.method,
            path: req.originalUrl,
            query: req.query,
            dataSize: typeof data === 'string' ? data.length : JSON.stringify(data).length
          }, req);

        } catch (error) {
          console.error('Data access audit error:', error);
        }

        return originalSend.call(this, data);
      };

      next();

    } catch (error) {
      console.error('Data access audit middleware error:', error);
      next();
    }
  };
};

/**
 * Admin action audit logging
 */
export const auditAdminActions = async (req, res, next) => {
  try {
    if (!req.user || !req.isAdmin) {
      return next();
    }

    const originalSend = res.send;

    res.send = async function(data) {
      try {
        const action = determineAdminAction(req);
        const targetUserId = req.params.userId || req.body.userId || req.body.user_id;
        const targetResourceId = req.params.id;

        await auditService.log(req.user.id, action, 'admin', targetResourceId, {
          targetUserId,
          adminRole: req.userRoles?.find(r => r.category === 'admin')?.name,
          method: req.method,
          path: req.originalUrl,
          body: sanitizeForAudit(req.body),
          query: req.query,
          statusCode: res.statusCode,
          success: res.statusCode < 400,
          ip: req.ip,
          severity: determineActionSeverity(action)
        }, req);

      } catch (error) {
        console.error('Admin action audit error:', error);
      }

      return originalSend.call(this, data);
    };

    next();

  } catch (error) {
    console.error('Admin audit middleware error:', error);
    next();
  }
};

/**
 * Financial transaction audit logging
 */
export const auditFinancialTransactions = async (req, res, next) => {
  try {
    const isFinancialEndpoint = req.path.includes('/subscription') || 
                               req.path.includes('/payment') || 
                               req.path.includes('/billing');

    if (!isFinancialEndpoint) {
      return next();
    }

    const originalSend = res.send;

    res.send = async function(data) {
      try {
        let parsedData = data;
        if (typeof data === 'string') {
          try {
            parsedData = JSON.parse(data);
          } catch (e) {
            parsedData = {};
          }
        }

        const transactionType = determineTransactionType(req, parsedData);
        const amount = req.body?.amount || parsedData?.amount;
        
        await auditService.log(req.user?.id || null, transactionType, 'financial', null, {
          amount: amount ? parseFloat(amount) : null,
          currency: req.body?.currency || 'USD',
          paymentMethod: req.body?.payment_method,
          subscriptionPlan: req.body?.plan_type,
          statusCode: res.statusCode,
          success: res.statusCode < 400,
          transactionId: parsedData?.transaction_id || parsedData?.payment_id,
          provider: req.body?.provider || 'stripe',
          ip: req.ip,
          compliance: {
            pciScope: true,
            dataClassification: 'financial',
            retentionPeriod: '7years'
          }
        }, req);

      } catch (error) {
        console.error('Financial audit error:', error);
      }

      return originalSend.call(this, data);
    };

    next();

  } catch (error) {
    console.error('Financial audit middleware error:', error);
    next();
  }
};

/**
 * Security event audit logging
 */
export const auditSecurityEvents = async (req, res, next) => {
  try {
    // Check for various security indicators
    const securityIndicators = detectSecurityIndicators(req);
    
    if (securityIndicators.length > 0) {
      for (const indicator of securityIndicators) {
        await auditService.log(req.user?.id || null, indicator.type, 'security', null, {
          ...indicator.details,
          ip: req.ip,
          userAgent: req.headers['user-agent'],
          path: req.originalUrl,
          method: req.method,
          severity: indicator.severity,
          timestamp: new Date().toISOString()
        }, req);
      }
    }

    next();

  } catch (error) {
    console.error('Security audit middleware error:', error);
    next();
  }
};

/**
 * GDPR compliance audit logging
 */
export const auditGDPRCompliance = async (req, res, next) => {
  try {
    const isGDPRRelevant = checkGDPRRelevance(req);
    
    if (!isGDPRRelevant) {
      return next();
    }

    const originalSend = res.send;

    res.send = async function(data) {
      try {
        const gdprAction = determineGDPRAction(req);
        const dataSubject = req.user?.id || req.body?.email;

        await auditService.log(req.user?.id || null, gdprAction, 'gdpr', null, {
          dataSubject,
          legalBasis: determineLegalBasis(req),
          dataProcessed: getDataCategories(req.body),
          retentionPeriod: getRetentionPeriod(req.path),
          dataMinimization: true,
          consentGiven: !!req.body?.consent || !!req.body?.terms_accepted,
          rightExercised: detectRightExercised(req),
          statusCode: res.statusCode,
          ip: req.ip,
          jurisdiction: detectJurisdiction(req),
          compliance: {
            gdprArticle: getRelevantGDPRArticle(gdprAction),
            dataController: 'Vottery Platform',
            processingPurpose: getProcessingPurpose(req.path)
          }
        }, req);

      } catch (error) {
        console.error('GDPR audit error:', error);
      }

      return originalSend.call(this, data);
    };

    next();

  } catch (error) {
    console.error('GDPR audit middleware error:', error);
    next();
  }
};

/**
 * Performance and availability audit logging
 */
export const auditPerformance = async (req, res, next) => {
  try {
    const startTime = process.hrtime.bigint();
    const startMemory = process.memoryUsage();

    const originalSend = res.send;

    res.send = async function(data) {
      try {
        const endTime = process.hrtime.bigint();
        const endMemory = process.memoryUsage();
        const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds

        // Log performance metrics
        await auditService.log(req.user?.id || null, 'PERFORMANCE_METRIC', 'system', null, {
          endpoint: req.originalUrl,
          method: req.method,
          duration,
          statusCode: res.statusCode,
          memoryUsage: {
            heapUsed: endMemory.heapUsed - startMemory.heapUsed,
            heapTotal: endMemory.heapTotal - startMemory.heapTotal,
            external: endMemory.external - startMemory.external
          },
          responseSize: typeof data === 'string' ? data.length : JSON.stringify(data).length,
          userAgent: req.headers['user-agent'],
          ip: req.ip,
          slowQuery: duration > 1000, // Flag slow responses (>1s)
          userId: req.user?.id
        }, req);

        // Store performance data in Redis for monitoring
        await storePerformanceMetrics(req.originalUrl, duration, res.statusCode);

      } catch (error) {
        console.error('Performance audit error:', error);
      }

      return originalSend.call(this, data);
    };

    next();

  } catch (error) {
    console.error('Performance audit middleware error:', error);
    next();
  }
};

// Helper Functions

/**
 * Log incoming request details
 */
async function logRequest(req, options) {
  try {
    const { logBody, logHeaders, sensitiveFields, maxBodySize } = options;
    
    const logData = {
      requestId: req.auditContext.requestId,
      method: req.method,
      path: req.originalUrl,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      userId: req.user?.id || null,
      query: req.query
    };

    if (logHeaders) {
      logData.headers = sanitizeHeaders(req.headers, sensitiveFields);
    }

    if (logBody && req.body && Object.keys(req.body).length > 0) {
      const bodySize = JSON.stringify(req.body).length;
      if (bodySize <= maxBodySize) {
        logData.body = sanitizeForAudit(req.body, sensitiveFields);
      } else {
        logData.bodyTruncated = true;
        logData.bodySize = bodySize;
      }
    }

    await auditService.log(req.user?.id || null, 'REQUEST_RECEIVED', 'http', null, logData, req);

  } catch (error) {
    console.error('Request logging error:', error);
  }
}

/**
 * Log response details
 */
async function logResponse(req, res, responseBody, duration) {
  try {
    const logData = {
      requestId: req.auditContext.requestId,
      statusCode: res.statusCode,
      duration,
      responseSize: typeof responseBody === 'string' ? responseBody.length : JSON.stringify(responseBody).length,
      headers: sanitizeHeaders(res.getHeaders(), ['set-cookie', 'authorization'])
    };

    // Include response body for errors or specific status codes
    if (res.statusCode >= 400 || res.statusCode === 201) {
      try {
        const parsedBody = typeof responseBody === 'string' ? JSON.parse(responseBody) : responseBody;
        logData.responseBody = sanitizeForAudit(parsedBody);
      } catch (e) {
        logData.responseBody = responseBody;
      }
    }

    await auditService.log(req.user?.id || null, 'RESPONSE_SENT', 'http', null, logData, req);

  } catch (error) {
    console.error('Response logging error:', error);
  }
}

/**
 * Generate unique request ID
 */
function generateRequestId() {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Sanitize sensitive data for audit logging
 */
function sanitizeForAudit(data, sensitiveFields = ['password', 'token', 'key', 'secret']) {
  if (!data || typeof data !== 'object') {
    return data;
  }

  const sanitized = Array.isArray(data) ? [...data] : { ...data };

  for (const [key, value] of Object.entries(sanitized)) {
    const lowerKey = key.toLowerCase();
    
    // Check if field is sensitive
    if (sensitiveFields.some(field => lowerKey.includes(field))) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeForAudit(value, sensitiveFields);
    }
  }

  return sanitized;
}

/**
 * Sanitize headers for logging
 */
function sanitizeHeaders(headers, sensitiveFields = ['authorization', 'cookie', 'x-api-key']) {
  const sanitized = { ...headers };
  
  for (const field of sensitiveFields) {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  }

  return sanitized;
}

/**
 * Determine admin action type
 */
function determineAdminAction(req) {
  const { method, path } = req;
  
  if (path.includes('/users') && method === 'DELETE') return 'USER_DELETED';
  if (path.includes('/users') && method === 'PUT') return 'USER_UPDATED';
  if (path.includes('/roles') && method === 'POST') return 'ROLE_CREATED';
  if (path.includes('/roles') && method === 'DELETE') return 'ROLE_DELETED';
  if (path.includes('/suspend')) return 'USER_SUSPENDED';
  if (path.includes('/activate')) return 'USER_ACTIVATED';
  if (path.includes('/ban')) return 'USER_BANNED';
  if (path.includes('/settings') && method === 'PUT') return 'SYSTEM_SETTINGS_CHANGED';
  
  return `ADMIN_${method}_${path.split('/').pop()?.toUpperCase() || 'UNKNOWN'}`;
}

/**
 * Determine action severity for admin actions
 */
function determineActionSeverity(action) {
  const highSeverity = ['USER_DELETED', 'USER_BANNED', 'SYSTEM_SETTINGS_CHANGED', 'ROLE_DELETED'];
  const mediumSeverity = ['USER_SUSPENDED', 'ROLE_CREATED', 'USER_UPDATED'];
  
  if (highSeverity.includes(action)) return 'HIGH';
  if (mediumSeverity.includes(action)) return 'MEDIUM';
  return 'LOW';
}

/**
 * Determine transaction type for financial operations
 */
function determineTransactionType(req, responseData) {
  const { path, method } = req;
  
  if (path.includes('/subscription')) {
    if (method === 'POST') return 'SUBSCRIPTION_CREATED';
    if (method === 'PUT') return 'SUBSCRIPTION_UPDATED';
    if (method === 'DELETE') return 'SUBSCRIPTION_CANCELLED';
  }
  
  if (path.includes('/payment')) {
    if (method === 'POST') return 'PAYMENT_PROCESSED';
    if (responseData?.refund) return 'REFUND_ISSUED';
  }
  
  if (path.includes('/webhook')) {
    return 'PAYMENT_WEBHOOK_RECEIVED';
  }
  
  return 'FINANCIAL_TRANSACTION';
}

/**
 * Detect security indicators in request
 */
function detectSecurityIndicators(req) {
  const indicators = [];
  
  // SQL injection patterns
  const sqlPatterns = [/union\s+select/i, /or\s+1\s*=\s*1/i, /drop\s+table/i, /insert\s+into/i];
  const requestData = JSON.stringify({ ...req.query, ...req.body, path: req.originalUrl });
  
  if (sqlPatterns.some(pattern => pattern.test(requestData))) {
    indicators.push({
      type: 'SQL_INJECTION_ATTEMPT',
      severity: 'HIGH',
      details: { pattern: 'SQL injection patterns detected', source: 'request_data' }
    });
  }
  
  // XSS patterns
  const xssPatterns = [/<script/i, /javascript:/i, /on\w+=/i, /<iframe/i];
  if (xssPatterns.some(pattern => pattern.test(requestData))) {
    indicators.push({
      type: 'XSS_ATTEMPT',
      severity: 'HIGH',
      details: { pattern: 'XSS patterns detected', source: 'request_data' }
    });
  }
  
  // Directory traversal
  if (/\.\.\//.test(req.originalUrl)) {
    indicators.push({
      type: 'DIRECTORY_TRAVERSAL_ATTEMPT',
      severity: 'HIGH',
      details: { pattern: 'Directory traversal detected', path: req.originalUrl }
    });
  }
  
  // Suspicious user agents
  const suspiciousUA = [/sqlmap/i, /nmap/i, /nikto/i, /burp/i, /scanner/i];
  const userAgent = req.headers['user-agent'] || '';
  if (suspiciousUA.some(pattern => pattern.test(userAgent))) {
    indicators.push({
      type: 'SUSPICIOUS_USER_AGENT',
      severity: 'MEDIUM',
      details: { userAgent, pattern: 'Known security tool detected' }
    });
  }
  
  // Multiple rapid requests (basic detection)
  if (req.headers['x-forwarded-for'] || req.connection.remoteAddress) {
    // This would typically be enhanced with Redis-based tracking
    // For now, just flag if certain headers suggest automated requests
    if (!req.headers['user-agent'] || req.headers['user-agent'].length < 10) {
      indicators.push({
        type: 'AUTOMATED_REQUEST',
        severity: 'MEDIUM',
        details: { reason: 'Missing or minimal user agent' }
      });
    }
  }
  
  return indicators;
}

/**
 * Check if request is GDPR relevant
 */
function checkGDPRRelevance(req) {
  const gdprPaths = [
    '/register', '/login', '/profile', '/users', '/data-export',
    '/data-deletion', '/consent', '/privacy', '/subscription'
  ];
  
  return gdprPaths.some(path => req.originalUrl.includes(path)) || 
         !!req.body?.email || 
         !!req.body?.personal_data;
}

/**
 * Determine GDPR action type
 */
function determineGDPRAction(req) {
  if (req.path.includes('/register')) return 'DATA_COLLECTION';
  if (req.path.includes('/profile') && req.method === 'GET') return 'DATA_ACCESS';
  if (req.path.includes('/profile') && req.method === 'PUT') return 'DATA_RECTIFICATION';
  if (req.path.includes('/data-export')) return 'DATA_PORTABILITY';
  if (req.path.includes('/data-deletion') || req.path.includes('/delete-account')) return 'DATA_ERASURE';
  if (req.path.includes('/consent')) return 'CONSENT_MANAGEMENT';
  
  return 'DATA_PROCESSING';
}

/**
 * Determine legal basis for data processing
 */
function determineLegalBasis(req) {
  if (req.path.includes('/register') || req.path.includes('/subscription')) {
    return 'contract'; // Article 6(1)(b) - contract performance
  }
  if (req.path.includes('/security') || req.path.includes('/fraud')) {
    return 'legitimate_interest'; // Article 6(1)(f)
  }
  if (req.body?.consent || req.body?.terms_accepted) {
    return 'consent'; // Article 6(1)(a)
  }
  if (req.path.includes('/compliance') || req.path.includes('/audit')) {
    return 'legal_obligation'; // Article 6(1)(c)
  }
  
  return 'legitimate_interest';
}

/**
 * Get data categories being processed
 */
function getDataCategories(body) {
  const categories = [];
  
  if (body?.email) categories.push('contact_data');
  if (body?.first_name || body?.last_name) categories.push('identity_data');
  if (body?.age || body?.gender) categories.push('demographic_data');
  if (body?.payment_method || body?.billing_address) categories.push('financial_data');
  if (body?.biometric_data) categories.push('biometric_data');
  if (body?.preferences) categories.push('preference_data');
  
  return categories.length > 0 ? categories : ['general_data'];
}

/**
 * Get retention period based on data type
 */
function getRetentionPeriod(path) {
  if (path.includes('/financial') || path.includes('/payment')) return '7years';
  if (path.includes('/audit') || path.includes('/security')) return '3years';
  if (path.includes('/marketing') || path.includes('/analytics')) return '2years';
  
  return '1year'; // Default retention period
}

/**
 * Detect if a GDPR right is being exercised
 */
function detectRightExercised(req) {
  if (req.path.includes('/data-export')) return 'right_to_portability';
  if (req.path.includes('/data-deletion')) return 'right_to_erasure';
  if (req.path.includes('/data-access')) return 'right_to_access';
  if (req.path.includes('/data-rectification')) return 'right_to_rectification';
  if (req.path.includes('/object-processing')) return 'right_to_object';
  if (req.path.includes('/restrict-processing')) return 'right_to_restriction';
  
  return null;
}

/**
 * Detect jurisdiction based on request
 */
function detectJurisdiction(req) {
  // Simple IP-based detection (in production, use proper geolocation service)
  const acceptLanguage = req.headers['accept-language'] || '';
  
  if (acceptLanguage.includes('de')) return 'DE';
  if (acceptLanguage.includes('fr')) return 'FR';
  if (acceptLanguage.includes('it')) return 'IT';
  if (acceptLanguage.includes('es')) return 'ES';
  
  // Default to EU for GDPR compliance
  return 'EU';
}

/**
 * Get relevant GDPR article for action
 */
function getRelevantGDPRArticle(action) {
  const articles = {
    'DATA_COLLECTION': 'Article 13',
    'DATA_ACCESS': 'Article 15',
    'DATA_RECTIFICATION': 'Article 16',
    'DATA_ERASURE': 'Article 17',
    'DATA_PORTABILITY': 'Article 20',
    'CONSENT_MANAGEMENT': 'Article 7'
  };
  
  return articles[action] || 'Article 6';
}

/**
 * Get processing purpose
 */
function getProcessingPurpose(path) {
  if (path.includes('/register')) return 'account_creation';
  if (path.includes('/voting')) return 'election_participation';
  if (path.includes('/analytics')) return 'service_improvement';
  if (path.includes('/marketing')) return 'marketing_communications';
  if (path.includes('/security')) return 'fraud_prevention';
  
  return 'service_provision';
}

/**
 * Log performance metrics
 */
async function logPerformanceMetrics(req, duration) {
  try {
    // Store metrics in Redis for real-time monitoring
    const metricsKey = `metrics:${req.method}:${req.route?.path || req.originalUrl}`;
    const timestamp = Date.now();
    
    // Store individual metric
    await redisClient.zadd(`${metricsKey}:response_times`, timestamp, duration);
    await redisClient.expire(`${metricsKey}:response_times`, 86400); // 24 hours
    
    // Increment request counter
    await redisClient.incr(`${metricsKey}:count`);
    await redisClient.expire(`${metricsKey}:count`, 86400);
    
    // Track status codes
    await redisClient.incr(`${metricsKey}:status:${req.res?.statusCode || 200}`);
    await redisClient.expire(`${metricsKey}:status:${req.res?.statusCode || 200}`, 86400);

  } catch (error) {
    console.error('Performance metrics logging error:', error);
  }
}

/**
 * Log security events
 */
async function logSecurityEvents(req, res) {
  try {
    // Check for failed authentication
    if (req.path.includes('/login') && res.statusCode === 401) {
      await auditService.log(null, 'AUTHENTICATION_FAILED', 'security', null, {
        email: req.body?.email,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        reason: 'invalid_credentials'
      }, req);
    }
    
    // Check for authorization failures
    if (res.statusCode === 403) {
      await auditService.log(req.user?.id || null, 'AUTHORIZATION_FAILED', 'security', null, {
        path: req.originalUrl,
        method: req.method,
        ip: req.ip,
        requiredPermission: req.headers['x-required-permission']
      }, req);
    }
    
    // Check for rate limit violations
    if (res.statusCode === 429) {
      await auditService.log(req.user?.id || null, 'RATE_LIMIT_VIOLATION', 'security', null, {
        path: req.originalUrl,
        ip: req.ip,
        userAgent: req.headers['user-agent']
      }, req);
    }

  } catch (error) {
    console.error('Security event logging error:', error);
  }
}

/**
 * Store performance metrics for monitoring dashboard
 */
async function storePerformanceMetrics(endpoint, duration, statusCode) {
  try {
    const hour = Math.floor(Date.now() / (60 * 60 * 1000));
    const key = `perf:${hour}`;
    
    // Store aggregated performance data
    await redisClient.hincrby(key, `${endpoint}:count`, 1);
    await redisClient.hincrby(key, `${endpoint}:total_time`, Math.round(duration));
    await redisClient.hincrby(key, `${endpoint}:status_${statusCode}`, 1);
    await redisClient.expire(key, 86400); // Keep for 24 hours

  } catch (error) {
    console.error('Performance metrics storage error:', error);
  }
}

// Add this to the end of your auditLog.js file

/**
 * Combined audit logging object for easy import
 */
// export const auditLog = {
//   logger: auditLogger,
//   authentication: auditAuthentication,
//   dataAccess: auditDataAccess,
//   adminActions: auditAdminActions,
//   financialTransactions: auditFinancialTransactions,
//   securityEvents: auditSecurityEvents,
//   gdprCompliance: auditGDPRCompliance,
//   performance: auditPerformance,
//   logActivity: auditLogger() // Default general activity logging
// };
export const auditLog = {
  logger: auditLogger,
  authentication: auditAuthentication,
  dataAccess: auditDataAccess,
  adminActions: auditAdminActions,
  financialTransactions: auditFinancialTransactions,
  securityEvents: auditSecurityEvents,
  gdprCompliance: auditGDPRCompliance,
  performance: auditPerformance,
  logActivity: auditLogger() // Default general activity logging
};
