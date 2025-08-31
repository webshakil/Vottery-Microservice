import Joi from 'joi';

// User creation validation schema
const userCreationSchema = Joi.object({
    sngine_email: Joi.string().email().required(),
    sngine_phone: Joi.string().pattern(/^\+?[1-9]\d{1,14}$/).required(),
    user_type: Joi.string().valid('voter', 'individual_creator', 'organization_creator').optional(),
    subscription_status: Joi.string().valid('free', 'subscribed').optional()
}).unknown(true);

// User update validation schema
const userUpdateSchema = Joi.object({
    status: Joi.string().valid('pending', 'verified', 'active', 'suspended').optional(),
    user_type: Joi.string().valid('voter', 'individual_creator', 'organization_creator').optional(),
    admin_role: Joi.string().valid('manager', 'admin', 'moderator', 'auditor', 'editor', 'advertiser', 'analyst').optional(),
    subscription_status: Joi.string().valid('free', 'subscribed').optional()
});

// Profile update validation schema
const profileUpdateSchema = Joi.object({
    first_name: Joi.string().min(2).max(50).optional(),
    last_name: Joi.string().min(2).max(50).optional(),
    date_of_birth: Joi.date().max('now').optional(),
    gender: Joi.string().valid('male', 'female', 'other', 'prefer_not_to_say').optional(),
    country: Joi.string().length(2).optional(), // ISO country code
    city: Joi.string().max(100).optional(),
    bio: Joi.string().max(500).optional(),
    avatar_url: Joi.string().uri().optional()
});

export const validateUserCreation = (req, res, next) => {
    const { error } = userCreationSchema.validate(req.body);
    if (error) {
        return res.status(400).json({
            success: false,
            message: 'Validation error',
            errors: error.details.map(detail => detail.message)
        });
    }
    next();
};

export const validateUserUpdate = (req, res, next) => {
    const { error } = userUpdateSchema.validate(req.body);
    if (error) {
        return res.status(400).json({
            success: false,
            message: 'Validation error',
            errors: error.details.map(detail => detail.message)
        });
    }
    next();
};

export const validateProfileUpdate = (req, res, next) => {
    const { error } = profileUpdateSchema.validate(req.body);
    if (error) {
        return res.status(400).json({
            success: false,
            message: 'Validation error',
            errors: error.details.map(detail => detail.message)
        });
    }
    next();
};

// Sanitize input to prevent XSS
export const sanitizeInput = (input) => {
    if (typeof input !== 'string') return input;
    return input
        .replace(/[<>]/g, '')
        .trim()
        .substring(0, 1000);
};