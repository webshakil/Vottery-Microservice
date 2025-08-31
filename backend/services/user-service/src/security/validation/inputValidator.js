// src/security/validation/inputValidator.js
import validator from 'validator';

/**
 * Input Validation Service for Vottery User Service
 * Comprehensive validation for all user inputs and API requests
 */
class InputValidator {
  // Validation patterns
  static PATTERNS = {
    USERNAME: /^[a-zA-Z0-9_]{3,30}$/,
    PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,128}$/,
    PHONE: /^\+?[1-9]\d{1,14}$/,
    ORGANIZATION_NAME: /^[a-zA-Z0-9\s\-_.]{2,100}$/,
    ELECTION_TITLE: /^[a-zA-Z0-9\s\-_.!?]{3,200}$/,
    API_KEY: /^[a-zA-Z0-9]{32,64}$/
  };

  // Allowed file types
  static ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
  static ALLOWED_VIDEO_TYPES = ['video/mp4', 'video/webm', 'video/ogg'];
  static MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

  /**
   * Validate user registration data
   * @param {Object} userData - User registration data
   * @returns {Object} Validation result
   */
  static validateUserRegistration(userData) {
    const errors = [];
    const { email, password, username, firstName, lastName, phone, country } = userData;

    // Email validation
    if (!email || !validator.isEmail(email)) {
      errors.push('Invalid email format');
    }

    // Password validation
    if (!password || !this.PATTERNS.PASSWORD.test(password)) {
      errors.push('Password must contain at least 8 characters with uppercase, lowercase, number, and special character');
    }

    // Username validation
    if (username && !this.PATTERNS.USERNAME.test(username)) {
      errors.push('Username must be 3-30 characters with only letters, numbers, and underscores');
    }

    // Name validation
    if (!firstName || !validator.isLength(firstName.trim(), { min: 1, max: 50 })) {
      errors.push('First name is required and must be 1-50 characters');
    }

    if (!lastName || !validator.isLength(lastName.trim(), { min: 1, max: 50 })) {
      errors.push('Last name is required and must be 1-50 characters');
    }

    // Phone validation (optional)
    if (phone && !this.PATTERNS.PHONE.test(phone)) {
      errors.push('Invalid phone number format');
    }

    // Country validation
    if (!country || !validator.isISO31661Alpha2(country)) {
      errors.push('Invalid country code');
    }

    return {
      isValid: errors.length === 0,
      errors,
      sanitizedData: this.sanitizeUserData(userData)
    };
  }

  /**
   * Validate election creation data
   * @param {Object} electionData - Election data
   * @returns {Object} Validation result
   */
  static validateElectionCreation(electionData) {
    const errors = [];
    const {
      title, description, votingType, startDate, endDate,
      participationFee, biometricRequired, permissions,
      candidates, questionType, images, videos
    } = electionData;

    // Title validation
    if (!title || !this.PATTERNS.ELECTION_TITLE.test(title)) {
      errors.push('Election title is required and must be 3-200 characters');
    }

    // Description validation
    if (description && !validator.isLength(description, { max: 5000 })) {
      errors.push('Description must not exceed 5000 characters');
    }

    // Voting type validation
    const allowedVotingTypes = ['plurality', 'ranked_choice', 'approval'];
    if (!votingType || !allowedVotingTypes.includes(votingType)) {
      errors.push('Invalid voting type');
    }

    // Date validation
    if (!startDate || !validator.isISO8601(startDate)) {
      errors.push('Invalid start date format');
    }

    if (!endDate || !validator.isISO8601(endDate)) {
      errors.push('Invalid end date format');
    }

    if (startDate && endDate && new Date(startDate) >= new Date(endDate)) {
      errors.push('End date must be after start date');
    }

    // Participation fee validation
    if (participationFee !== undefined) {
      if (!validator.isFloat(participationFee.toString(), { min: 0, max: 1000 })) {
        errors.push('Participation fee must be between 0 and 1000');
      }
    }

    // Candidates validation
    if (!candidates || !Array.isArray(candidates) || candidates.length < 2) {
      errors.push('At least 2 candidates are required');
    }

    // File validation
    if (images) {
      const imageValidation = this.validateFiles(images, this.ALLOWED_IMAGE_TYPES);
      if (!imageValidation.isValid) {
        errors.push(...imageValidation.errors);
      }
    }

    if (videos) {
      const videoValidation = this.validateFiles(videos, this.ALLOWED_VIDEO_TYPES);
      if (!videoValidation.isValid) {
        errors.push(...videoValidation.errors);
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      sanitizedData: this.sanitizeElectionData(electionData)
    };
  }

  /**
   * Validate organization data
   * @param {Object} orgData - Organization data
   * @returns {Object} Validation result
   */
  static validateOrganization(orgData) {
    const errors = [];
    const { name, type, registrationNumber, website } = orgData;

    // Name validation
    if (!name || !this.PATTERNS.ORGANIZATION_NAME.test(name)) {
      errors.push('Organization name is required and must be 2-100 characters');
    }

    // Type validation
    const allowedTypes = ['company', 'nonprofit', 'government', 'educational', 'other'];
    if (!type || !allowedTypes.includes(type)) {
      errors.push('Invalid organization type');
    }

    // Registration number (optional but validated if provided)
    if (registrationNumber && !validator.isLength(registrationNumber, { min: 3, max: 50 })) {
      errors.push('Registration number must be 3-50 characters');
    }

    // Website validation (optional)
    if (website && !validator.isURL(website, { protocols: ['http', 'https'] })) {
      errors.push('Invalid website URL');
    }

    return {
      isValid: errors.length === 0,
      errors,
      sanitizedData: this.sanitizeOrganizationData(orgData)
    };
  }

  /**
   * Validate API request parameters
   * @param {Object} params - Request parameters
   * @param {Object} schema - Validation schema
   * @returns {Object} Validation result
   */
  static validateApiRequest(params, schema) {
    const errors = [];
    const sanitizedParams = {};

    for (const [key, rules] of Object.entries(schema)) {
      const value = params[key];

      // Required field check
      if (rules.required && (value === undefined || value === null || value === '')) {
        errors.push(`${key} is required`);
        continue;
      }

      // Skip validation if field is not required and not provided
      if (!rules.required && (value === undefined || value === null || value === '')) {
        continue;
      }

      // Type validation
      if (rules.type && typeof value !== rules.type) {
        errors.push(`${key} must be of type ${rules.type}`);
        continue;
      }

      // String length validation
      if (rules.minLength && value.length < rules.minLength) {
        errors.push(`${key} must be at least ${rules.minLength} characters`);
      }

      if (rules.maxLength && value.length > rules.maxLength) {
        errors.push(`${key} must not exceed ${rules.maxLength} characters`);
      }

      // Numeric range validation
      if (rules.min !== undefined && value < rules.min) {
        errors.push(`${key} must be at least ${rules.min}`);
      }

      if (rules.max !== undefined && value > rules.max) {
        errors.push(`${key} must not exceed ${rules.max}`);
      }

      // Pattern validation
      if (rules.pattern && !rules.pattern.test(value)) {
        errors.push(`${key} format is invalid`);
      }

      // Enum validation
      if (rules.enum && !rules.enum.includes(value)) {
        errors.push(`${key} must be one of: ${rules.enum.join(', ')}`);
      }

      // Custom validation
      if (rules.custom && !rules.custom(value)) {
        errors.push(`${key} failed custom validation`);
      }

      // Sanitize the value
      sanitizedParams[key] = this.sanitizeValue(value, rules.sanitize);
    }

    return {
      isValid: errors.length === 0,
      errors,
      sanitizedData: sanitizedParams
    };
  }

  /**
   * Validate file uploads
   * @param {Array} files - Array of files
   * @param {Array} allowedTypes - Allowed MIME types
   * @returns {Object} Validation result
   */
  static validateFiles(files, allowedTypes) {
    const errors = [];

    if (!Array.isArray(files)) {
      return { isValid: false, errors: ['Files must be an array'] };
    }

    for (const file of files) {
      // File type validation
      if (!allowedTypes.includes(file.mimetype)) {
        errors.push(`Invalid file type: ${file.mimetype}`);
      }

      // File size validation
      if (file.size > this.MAX_FILE_SIZE) {
        errors.push(`File size exceeds limit: ${file.originalname}`);
      }

      // File name validation
      if (!validator.isLength(file.originalname, { min: 1, max: 255 })) {
        errors.push(`Invalid file name: ${file.originalname}`);
      }
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Sanitize user data
   * @param {Object} userData - Raw user data
   * @returns {Object} Sanitized data
   */
  static sanitizeUserData(userData) {
    return {
      email: userData.email ? validator.normalizeEmail(userData.email) : null,
      username: userData.username ? validator.escape(userData.username.trim()) : null,
      firstName: userData.firstName ? validator.escape(userData.firstName.trim()) : null,
      lastName: userData.lastName ? validator.escape(userData.lastName.trim()) : null,
      phone: userData.phone ? userData.phone.replace(/\s/g, '') : null,
      country: userData.country ? userData.country.toUpperCase() : null,
      bio: userData.bio ? validator.escape(userData.bio.trim()) : null
    };
  }

  /**
   * Sanitize election data
   * @param {Object} electionData - Raw election data
   * @returns {Object} Sanitized data
   */
  static sanitizeElectionData(electionData) {
    return {
      ...electionData,
      title: validator.escape(electionData.title?.trim() || ''),
      description: validator.escape(electionData.description?.trim() || ''),
      candidates: electionData.candidates?.map(candidate => ({
        ...candidate,
        name: validator.escape(candidate.name?.trim() || ''),
        description: validator.escape(candidate.description?.trim() || '')
      }))
    };
  }

  /**
   * Sanitize organization data
   * @param {Object} orgData - Raw organization data
   * @returns {Object} Sanitized data
   */
  static sanitizeOrganizationData(orgData) {
    return {
      name: validator.escape(orgData.name?.trim() || ''),
      type: orgData.type,
      registrationNumber: orgData.registrationNumber ? validator.escape(orgData.registrationNumber.trim()) : null,
      website: orgData.website ? validator.normalizeURL(orgData.website) : null
    };
  }

  /**
   * Sanitize individual value based on rules
   * @param {any} value - Value to sanitize
   * @param {string} sanitizeType - Sanitization type
   * @returns {any} Sanitized value
   */
  static sanitizeValue(value, sanitizeType) {
    if (!sanitizeType || value === null || value === undefined) {
      return value;
    }

    switch (sanitizeType) {
      case 'escape':
        return validator.escape(value.toString());
      case 'trim':
        return value.toString().trim();
      case 'lowercase':
        return value.toString().toLowerCase();
      case 'uppercase':
        return value.toString().toUpperCase();
      case 'email':
        return validator.normalizeEmail(value);
      case 'url':
        return validator.normalizeURL(value);
      default:
        return value;
    }
  }
}

export default InputValidator;