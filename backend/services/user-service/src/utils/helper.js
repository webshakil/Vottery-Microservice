import { randomBytes } from 'node:crypto';
import { VALIDATION, SUPPORTED_LANGUAGES, PERMISSIONS } from './constants.js';

/**
 * Generate a random string of specified length
 * @param {number} length - Length of the random string
 * @param {string} charset - Character set to use
 * @returns {string} Random string
 */
export const generateRandomString = (length = 32, charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') => {
  const bytes = randomBytes(length);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[bytes[i] % charset.length];
  }
  return result;
};

/**
 * Generate a secure random token
 * @param {number} length - Token length in bytes (default 32)
 * @returns {string} Hex-encoded random token
 */
export const generateSecureToken = (length = 32) => {
  return randomBytes(length).toString('hex');
};

/**
 * Generate a numeric OTP code
 * @param {number} digits - Number of digits (default 6)
 * @returns {string} OTP code
 */
export const generateOTP = (digits = 6) => {
  const min = Math.pow(10, digits - 1);
  const max = Math.pow(10, digits) - 1;
  return Math.floor(Math.random() * (max - min + 1) + min).toString();
};

/**
 * Sleep for specified milliseconds
 * @param {number} ms - Milliseconds to sleep
 * @returns {Promise} Promise that resolves after delay
 */
export const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Deep clone an object
 * @param {*} obj - Object to clone
 * @returns {*} Cloned object
 */
export const deepClone = (obj) => {
  if (obj === null || typeof obj !== 'object') return obj;
  if (obj instanceof Date) return new Date(obj.getTime());
  if (obj instanceof Array) return obj.map(item => deepClone(item));
  if (typeof obj === 'object') {
    const cloned = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        cloned[key] = deepClone(obj[key]);
      }
    }
    return cloned;
  }
};

/**
 * Merge objects deeply
 * @param {object} target - Target object
 * @param {...object} sources - Source objects
 * @returns {object} Merged object
 */
export const deepMerge = (target, ...sources) => {
  if (!sources.length) return target;
  const source = sources.shift();

  if (isObject(target) && isObject(source)) {
    for (const key in source) {
      if (isObject(source[key])) {
        if (!target[key]) Object.assign(target, { [key]: {} });
        deepMerge(target[key], source[key]);
      } else {
        Object.assign(target, { [key]: source[key] });
      }
    }
  }

  return deepMerge(target, ...sources);
};

/**
 * Check if value is an object
 * @param {*} item - Item to check
 * @returns {boolean} True if object
 */
export const isObject = (item) => {
  return item && typeof item === 'object' && !Array.isArray(item);
};

/**
 * Capitalize first letter of a string
 * @param {string} str - String to capitalize
 * @returns {string} Capitalized string
 */
export const capitalize = (str) => {
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
};

/**
 * Convert string to camelCase
 * @param {string} str - String to convert
 * @returns {string} CamelCase string
 */
export const toCamelCase = (str) => {
  return str.replace(/_([a-z])/g, (g) => g[1].toUpperCase());
};

/**
 * Convert string to snake_case
 * @param {string} str - String to convert
 * @returns {string} snake_case string
 */
export const toSnakeCase = (str) => {
  return str.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
};

/**
 * Format file size in human-readable format
 * @param {number} bytes - Size in bytes
 * @param {number} decimals - Number of decimal places
 * @returns {string} Formatted file size
 */
export const formatFileSize = (bytes, decimals = 2) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
};

/**
 * Format date to ISO string
 * @param {Date|string} date - Date to format
 * @returns {string} ISO date string
 */
export const formatDate = (date) => {
  if (!date) return null;
  return new Date(date).toISOString();
};

/**
 * Format date for display
 * @param {Date|string} date - Date to format
 * @param {string} locale - Locale for formatting
 * @param {object} options - Formatting options
 * @returns {string} Formatted date string
 */
export const formatDateForDisplay = (date, locale = 'en-US', options = {}) => {
  if (!date) return '';
  const defaultOptions = {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  };
  return new Date(date).toLocaleDateString(locale, { ...defaultOptions, ...options });
};

/**
 * Calculate age from birth date
 * @param {Date|string} birthDate - Birth date
 * @returns {number} Age in years
 */
export const calculateAge = (birthDate) => {
  if (!birthDate) return null;
  const today = new Date();
  const birth = new Date(birthDate);
  let age = today.getFullYear() - birth.getFullYear();
  const monthDiff = today.getMonth() - birth.getMonth();
  
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
    age--;
  }
  
  return age;
};

/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean} True if valid email
 */
export const isValidEmail = (email) => {
  if (!email || email.length > VALIDATION.EMAIL.MAX_LENGTH) return false;
  return VALIDATION.EMAIL.PATTERN.test(email);
};

/**
 * Validate username format
 * @param {string} username - Username to validate
 * @returns {boolean} True if valid username
 */
export const isValidUsername = (username) => {
  if (!username || 
      username.length < VALIDATION.USERNAME.MIN_LENGTH || 
      username.length > VALIDATION.USERNAME.MAX_LENGTH) return false;
  return VALIDATION.USERNAME.PATTERN.test(username);
};

/**
 * Check password strength
 * @param {string} password - Password to check
 * @returns {object} Strength analysis
 */
export const checkPasswordStrength = (password) => {
  const checks = {
    length: password.length >= VALIDATION.PASSWORD.MIN_LENGTH,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    numbers: /\d/.test(password),
    special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
  };

  const score = Object.values(checks).filter(Boolean).length;
  
  let strength = 'very-weak';
  if (score === 5) strength = 'very-strong';
  else if (score === 4) strength = 'strong';
  else if (score === 3) strength = 'medium';
  else if (score === 2) strength = 'weak';

  return {
    score,
    strength,
    checks,
    isValid: score >= 4
  };
};

/**
 * Sanitize filename for storage
 * @param {string} filename - Original filename
 * @returns {string} Sanitized filename
 */
export const sanitizeFilename = (filename) => {
  return filename
    .replace(/[^a-zA-Z0-9.-]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '')
    .substring(0, 255);
};

/**
 * Generate unique filename
 * @param {string} originalName - Original filename
 * @param {string} prefix - Optional prefix
 * @returns {string} Unique filename
 */
export const generateUniqueFilename = (originalName, prefix = '') => {
  const timestamp = Date.now();
  const random = generateRandomString(8);
  const extension = originalName.split('.').pop();
  const sanitized = sanitizeFilename(originalName.replace(`.${extension}`, ''));
  
  return `${prefix}${prefix ? '_' : ''}${sanitized}_${timestamp}_${random}.${extension}`;
};

/**
 * Parse pagination parameters
 * @param {object} query - Query parameters
 * @returns {object} Parsed pagination
 */
export const parsePagination = (query) => {
  const limit = Math.min(
    parseInt(query.limit) || VALIDATION.PAGINATION.DEFAULT_LIMIT,
    VALIDATION.PAGINATION.MAX_LIMIT
  );
  const offset = parseInt(query.offset) || VALIDATION.PAGINATION.DEFAULT_OFFSET;
  const page = Math.floor(offset / limit) + 1;

  return { limit, offset, page };
};

/**
 * Parse date range parameters
 * @param {object} query - Query parameters
 * @returns {object} Parsed date range
 */
export const parseDateRange = (query) => {
  const { start_date, end_date } = query;
  
  let startDate = null;
  let endDate = null;

  if (start_date) {
    startDate = new Date(start_date);
    if (isNaN(startDate.getTime())) startDate = null;
  }

  if (end_date) {
    endDate = new Date(end_date);
    if (isNaN(endDate.getTime())) endDate = null;
  }

  // Default to last 30 days if no dates provided
  if (!startDate && !endDate) {
    endDate = new Date();
    startDate = new Date(endDate.getTime() - 30 * 24 * 60 * 60 * 1000);
  }

  return { startDate, endDate };
};

/**
 * Remove sensitive data from user object
 * @param {object} user - User object
 * @returns {object} Sanitized user object
 */
export const sanitizeUser = (user) => {
  if (!user) return null;
  
  const sanitized = { ...user };
  delete sanitized.password;
  delete sanitized.password_hash;
  delete sanitized.two_factor_secret;
  delete sanitized.recovery_codes;
  delete sanitized.salt;
  
  return sanitized;
};

/**
 * Remove sensitive data from multiple user objects
 * @param {Array} users - Array of user objects
 * @returns {Array} Array of sanitized user objects
 */
export const sanitizeUsers = (users) => {
  if (!Array.isArray(users)) return [];
  return users.map(sanitizeUser);
};

/**
 * Check if user has permission
 * @param {object} user - User object with roles
 * @param {string} permission - Permission to check
 * @returns {boolean} True if user has permission
 */
export const userHasPermission = (user, permission) => {
  if (!user || !user.roles) return false;
  
  return user.roles.some(role => {
    return role.permissions && role.permissions.includes(permission);
  });
};

/**
 * Get user's highest role level
 * @param {object} user - User object with roles
 * @returns {number} Highest role level
 */
export const getUserHighestRoleLevel = (user) => {
  if (!user || !user.roles || !user.roles.length) return 0;
  
  return Math.max(...user.roles.map(role => role.level || 0));
};

/**
 * Filter object keys based on allowed list
 * @param {object} obj - Object to filter
 * @param {Array} allowedKeys - Array of allowed keys
 * @returns {object} Filtered object
 */
export const filterObjectKeys = (obj, allowedKeys) => {
  if (!obj || !allowedKeys) return {};
  
  return Object.keys(obj)
    .filter(key => allowedKeys.includes(key))
    .reduce((filtered, key) => {
      filtered[key] = obj[key];
      return filtered;
    }, {});
};

/**
 * Omit specific keys from object
 * @param {object} obj - Object to filter
 * @param {Array} keysToOmit - Array of keys to omit
 * @returns {object} Filtered object
 */
export const omitObjectKeys = (obj, keysToOmit) => {
  if (!obj || !keysToOmit) return obj;
  
  return Object.keys(obj)
    .filter(key => !keysToOmit.includes(key))
    .reduce((filtered, key) => {
      filtered[key] = obj[key];
      return filtered;
    }, {});
};

/**
 * Convert array to lookup object
 * @param {Array} array - Array to convert
 * @param {string} keyField - Field to use as key
 * @param {string} valueField - Field to use as value (optional)
 * @returns {object} Lookup object
 */
export const arrayToLookup = (array, keyField, valueField = null) => {
  if (!Array.isArray(array)) return {};
  
  return array.reduce((lookup, item) => {
    const key = item[keyField];
    if (key !== undefined) {
      lookup[key] = valueField ? item[valueField] : item;
    }
    return lookup;
  }, {});
};

/**
 * Group array by field
 * @param {Array} array - Array to group
 * @param {string} field - Field to group by
 * @returns {object} Grouped object
 */
export const groupBy = (array, field) => {
  if (!Array.isArray(array)) return {};
  
  return array.reduce((groups, item) => {
    const key = item[field];
    if (!groups[key]) {
      groups[key] = [];
    }
    groups[key].push(item);
    return groups;
  }, {});
};

/**
 * Sort array of objects by multiple fields
 * @param {Array} array - Array to sort
 * @param {Array} sortBy - Array of {field, direction} objects
 * @returns {Array} Sorted array
 */
export const multiSort = (array, sortBy) => {
  if (!Array.isArray(array) || !Array.isArray(sortBy)) return array;
  
  return [...array].sort((a, b) => {
    for (const { field, direction = 'asc' } of sortBy) {
      const aVal = a[field];
      const bVal = b[field];
      
      if (aVal < bVal) return direction === 'asc' ? -1 : 1;
      if (aVal > bVal) return direction === 'asc' ? 1 : -1;
    }
    return 0;
  });
};

/**
 * Get nested object property safely
 * @param {object} obj - Object to traverse
 * @param {string} path - Dot-separated path
 * @param {*} defaultValue - Default value if path not found
 * @returns {*} Property value or default
 */
export const getNestedProperty = (obj, path, defaultValue = null) => {
  if (!obj || !path) return defaultValue;
  
  const keys = path.split('.');
  let current = obj;
  
  for (const key of keys) {
    if (current === null || current === undefined || !current.hasOwnProperty(key)) {
      return defaultValue;
    }
    current = current[key];
  }
  
  return current;
};

/**
 * Set nested object property
 * @param {object} obj - Object to modify
 * @param {string} path - Dot-separated path
 * @param {*} value - Value to set
 * @returns {object} Modified object
 */
export const setNestedProperty = (obj, path, value) => {
  if (!obj || !path) return obj;
  
  const keys = path.split('.');
  let current = obj;
  
  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (!current[key] || typeof current[key] !== 'object') {
      current[key] = {};
    }
    current = current[key];
  }
  
  current[keys[keys.length - 1]] = value;
  return obj;
};

/**
 * Flatten nested object
 * @param {object} obj - Object to flatten
 * @param {string} prefix - Prefix for keys
 * @returns {object} Flattened object
 */
export const flattenObject = (obj, prefix = '') => {
  if (!obj || typeof obj !== 'object') return { [prefix]: obj };
  
  const flattened = {};
  
  for (const [key, value] of Object.entries(obj)) {
    const newKey = prefix ? `${prefix}.${key}` : key;
    
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      Object.assign(flattened, flattenObject(value, newKey));
    } else {
      flattened[newKey] = value;
    }
  }
  
  return flattened;
};

/**
 * Check if string contains only ASCII characters
 * @param {string} str - String to check
 * @returns {boolean} True if ASCII only
 */
export const isASCII = (str) => {
  return /^[\x00-\x7F]*$/.test(str);
};

/**
 * Truncate string with ellipsis
 * @param {string} str - String to truncate
 * @param {number} length - Maximum length
 * @param {string} suffix - Suffix to add
 * @returns {string} Truncated string
 */
export const truncate = (str, length = 100, suffix = '...') => {
  if (!str || str.length <= length) return str;
  return str.substring(0, length - suffix.length) + suffix;
};

/**
 * Generate initials from name
 * @param {string} name - Full name
 * @param {number} maxInitials - Maximum number of initials
 * @returns {string} Initials
 */
export const generateInitials = (name, maxInitials = 2) => {
  if (!name) return '';
  
  return name
    .split(' ')
    .filter(word => word.length > 0)
    .slice(0, maxInitials)
    .map(word => word.charAt(0).toUpperCase())
    .join('');
};

/**
 * Mask sensitive data
 * @param {string} value - Value to mask
 * @param {number} visibleStart - Characters to show at start
 * @param {number} visibleEnd - Characters to show at end
 * @param {string} maskChar - Character to use for masking
 * @returns {string} Masked value
 */
export const maskSensitiveData = (value, visibleStart = 2, visibleEnd = 2, maskChar = '*') => {
  if (!value || value.length <= visibleStart + visibleEnd) return value;
  
  const start = value.substring(0, visibleStart);
  const end = value.substring(value.length - visibleEnd);
  const maskLength = value.length - visibleStart - visibleEnd;
  const mask = maskChar.repeat(Math.max(maskLength, 4));
  
  return start + mask + end;
};

/**
 * Convert bytes to base64
 * @param {Buffer} buffer - Buffer to convert
 * @returns {string} Base64 string
 */
export const bufferToBase64 = (buffer) => {
  return buffer.toString('base64');
};

/**
 * Convert base64 to bytes
 * @param {string} base64 - Base64 string
 * @returns {Buffer} Buffer
 */
export const base64ToBuffer = (base64) => {
  return Buffer.from(base64, 'base64');
};

/**
 * Generate fingerprint from data
 * @param {string} data - Data to fingerprint
 * @returns {string} Fingerprint hash
 */
export const generateFingerprint = async (data) => {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(data).digest('hex');
};

/**
 * Validate language code
 * @param {string} langCode - Language code to validate
 * @returns {boolean} True if valid language code
 */
export const isValidLanguage = (langCode) => {
  return SUPPORTED_LANGUAGES.includes(langCode);
};

/**
 * Get default language based on accept-language header
 * @param {string} acceptLanguage - Accept-Language header value
 * @returns {string} Best matching language code
 */
export const getBestLanguage = (acceptLanguage) => {
  if (!acceptLanguage) return 'en';
  
  const preferred = acceptLanguage
    .split(',')
    .map(lang => {
      const parts = lang.trim().split(';q=');
      return {
        code: parts[0].toLowerCase(),
        quality: parts[1] ? parseFloat(parts[1]) : 1.0
      };
    })
    .sort((a, b) => b.quality - a.quality);

  for (const lang of preferred) {
    if (SUPPORTED_LANGUAGES.includes(lang.code)) {
      return lang.code;
    }
    
    // Try base language (e.g., 'en' for 'en-US')
    const baseLang = lang.code.split('-')[0];
    if (SUPPORTED_LANGUAGES.includes(baseLang)) {
      return baseLang;
    }
  }
  
  return 'en';
};

/**
 * Debounce function execution
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @param {boolean} immediate - Execute immediately
 * @returns {Function} Debounced function
 */
export const debounce = (func, wait, immediate = false) => {
  let timeout;
  
  return function executedFunction(...args) {
    const later = () => {
      timeout = null;
      if (!immediate) func(...args);
    };
    
    const callNow = immediate && !timeout;
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
    
    if (callNow) func(...args);
  };
};

/**
 * Throttle function execution
 * @param {Function} func - Function to throttle
 * @param {number} limit - Time limit in milliseconds
 * @returns {Function} Throttled function
 */
export const throttle = (func, limit) => {
  let inThrottle;
  
  return function executedFunction(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
};

/**
 * Retry async function with exponential backoff
 * @param {Function} fn - Async function to retry
 * @param {number} maxRetries - Maximum number of retries
 * @param {number} baseDelay - Base delay in milliseconds
 * @returns {Promise} Promise that resolves with function result
 */
export const retryWithBackoff = async (fn, maxRetries = 3, baseDelay = 1000) => {
  let lastError;
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      
      if (attempt === maxRetries) {
        throw lastError;
      }
      
      const delay = baseDelay * Math.pow(2, attempt);
      await sleep(delay);
    }
  }
};

/**
 * Create a promise that resolves after timeout
 * @param {Promise} promise - Promise to race against timeout
 * @param {number} timeoutMs - Timeout in milliseconds
 * @param {string} timeoutMessage - Error message for timeout
 * @returns {Promise} Promise that rejects on timeout
 */
export const withTimeout = (promise, timeoutMs, timeoutMessage = 'Operation timed out') => {
  const timeout = new Promise((_, reject) => {
    setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
  });
  
  return Promise.race([promise, timeout]);
};

/**
 * Default export containing all helper functions
 */
export default {
  generateRandomString,
  generateOTP,
  sleep,
  deepClone,
  deepMerge,
  isObject,
  capitalize,
  toCamelCase,
  toSnakeCase,
  formatFileSize,
  formatDate,
  formatDateForDisplay,
  calculateAge,
  isValidEmail,
  isValidUsername,
  checkPasswordStrength,
  sanitizeFilename,
  generateUniqueFilename,
  parsePagination,
  parseDateRange,
  sanitizeUser,
  sanitizeUsers,
  userHasPermission,
  getUserHighestRoleLevel,
  filterObjectKeys,
  omitObjectKeys,
  arrayToLookup,
  groupBy,
  multiSort,
  getNestedProperty,
  setNestedProperty,
  flattenObject,
  isASCII,
  truncate,
  generateInitials,
  maskSensitiveData,
  bufferToBase64,
  base64ToBuffer,
  generateFingerprint,
  isValidLanguage,
  getBestLanguage,
  debounce,
  throttle,
  retryWithBackoff,
  withTimeout
};