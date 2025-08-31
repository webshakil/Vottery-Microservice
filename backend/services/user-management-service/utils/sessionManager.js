import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { query } from '../config/database.js';

const JWT_SECRET = process.env.JWT_SECRET || 'vottery_secret_key_change_in_production';
const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '1m';       // Short-lived access token
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '2m';      // Refresh token expiry

/**
 * Helper: parse expiry strings like "1m", "15m", "1h", "7d" into seconds
 */
const parseExpiryToSeconds = (expiry) => {
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) throw new Error(`Invalid expiry format: ${expiry}`);

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
        case 's': return value;
        case 'm': return value * 60;
        case 'h': return value * 3600;
        case 'd': return value * 86400;
        default: throw new Error(`Unsupported expiry unit: ${unit}`);
    }
};

/**
 * Generate a new access token
 */
export const generateAccessToken = (payload) => {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
};

/**
 * Generate a new refresh token
 */
export const generateRefreshToken = () => {
    return crypto.randomBytes(64).toString('hex');
};

/**
 * Verify access token
 */
export const verifyAccessToken = (token) => {
    return jwt.verify(token, JWT_SECRET);
};

/**
 * Create a session in vottery_sessions
 */
export const createSession = async ({ userId, accessToken, refreshToken, deviceId, ipAddress, userAgent }) => {
    const jwtTokenId = crypto.randomUUID(); // This generates proper UUID format

    // compute expiry times
    const accessTokenSeconds = parseExpiryToSeconds(ACCESS_TOKEN_EXPIRY);
    const refreshTokenSeconds = parseExpiryToSeconds(REFRESH_TOKEN_EXPIRY);

    // First, get user info for token generation
    const userResult = await query(
        'SELECT user_type, admin_role FROM vottery_user_management WHERE user_id = $1',
        [userId]
    );

    if (userResult.rows.length === 0) {
        throw new Error('User not found');
    }

    const { user_type, admin_role } = userResult.rows[0];

    await query(
        `INSERT INTO vottery_sessions 
          (user_id, session_token, refresh_token, jwt_token_id, device_id, ip_address, user_agent, user_type, admin_role, is_active, created_at, expires_at, refresh_expires_at, last_activity)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,TRUE,NOW(),NOW() + $10 * INTERVAL '1 second', NOW() + $11 * INTERVAL '1 second', NOW())`,
        [userId, accessToken, refreshToken, jwtTokenId, deviceId || null, ipAddress || null, userAgent || null, user_type, admin_role, accessTokenSeconds, refreshTokenSeconds]
    );
    
    return { accessToken, refreshToken };
};

/**
 * Refresh token rotation
 */
export const rotateRefreshToken = async ({ refreshToken, deviceId }) => {
    // Get active session
    const sessionResult = await query(
        `SELECT * FROM vottery_sessions 
          WHERE refresh_token = $1 AND device_id = $2 AND is_active = TRUE AND refresh_expires_at > NOW()`,
        [refreshToken, deviceId]
    );

    if (sessionResult.rows.length === 0) {
        throw new Error('Invalid or expired refresh token');
    }

    const session = sessionResult.rows[0];

    // Generate new tokens with fresh user data
    const newAccessToken = generateAccessToken({
        userId: session.user_id,
        userType: session.user_type || 'voter',
        adminRole: session.admin_role || 'analyst'
    });
    const newRefreshToken = generateRefreshToken();

    // compute expiry times
    const accessTokenSeconds = parseExpiryToSeconds(ACCESS_TOKEN_EXPIRY);
    const refreshTokenSeconds = parseExpiryToSeconds(REFRESH_TOKEN_EXPIRY);

    // Update session in DB (rotate tokens)
    await query(
        `UPDATE vottery_sessions 
         SET session_token=$1, refresh_token=$2, jwt_token_id=$3, expires_at=NOW() + $4 * INTERVAL '1 second', refresh_expires_at=NOW() + $5 * INTERVAL '1 second', last_activity=NOW()
         WHERE id=$6`,
        [newAccessToken, newRefreshToken, crypto.randomUUID(), accessTokenSeconds, refreshTokenSeconds, session.id] // This also generates proper UUID
    );

    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
};

/**
 * Invalidate session (logout)
 */
export const invalidateSession = async (sessionToken) => {
    await query(
        'UPDATE vottery_sessions SET is_active = FALSE WHERE session_token = $1',
        [sessionToken]
    );
};

/**
 * Clean up expired sessions
 */
export const cleanupExpiredSessions = async () => {
    await query(
        'UPDATE vottery_sessions SET is_active = FALSE WHERE refresh_expires_at <= NOW() AND is_active = TRUE'
    );
};
// import jwt from 'jsonwebtoken';
// import crypto from 'crypto';
// import { query } from '../config/database.js';

// const JWT_SECRET = process.env.JWT_SECRET || 'vottery_secret_key_change_in_production';
// const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '1m';       // Short-lived access token
// const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '2m';      // Refresh token expiry

// /**
//  * Helper: parse expiry strings like "1m", "15m", "1h", "7d" into seconds
//  */
// const parseExpiryToSeconds = (expiry) => {
//     const match = expiry.match(/^(\d+)([smhd])$/);
//     if (!match) throw new Error(`Invalid expiry format: ${expiry}`);

//     const value = parseInt(match[1], 10);
//     const unit = match[2];

//     switch (unit) {
//         case 's': return value;
//         case 'm': return value * 60;
//         case 'h': return value * 3600;
//         case 'd': return value * 86400;
//         default: throw new Error(`Unsupported expiry unit: ${unit}`);
//     }
// };

// /**
//  * Generate a new access token
//  */
// export const generateAccessToken = (payload) => {
//     return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
// };

// /**
//  * Generate a new refresh token
//  */
// export const generateRefreshToken = () => {
//     return crypto.randomBytes(64).toString('hex');
// };

// /**
//  * Verify access token
//  */
// export const verifyAccessToken = (token) => {
//     return jwt.verify(token, JWT_SECRET);
// };

// /**
//  * Create a session in vottery_sessions
//  */
// export const createSession = async ({ userId, accessToken, refreshToken, deviceId, ipAddress, userAgent }) => {
//     const jwtTokenId = crypto.randomUUID();

//     // compute expiry times
//     const accessTokenSeconds = parseExpiryToSeconds(ACCESS_TOKEN_EXPIRY);
//     const refreshTokenSeconds = parseExpiryToSeconds(REFRESH_TOKEN_EXPIRY);

//     // First, get user info for token generation
//     const userResult = await query(
//         'SELECT user_type, admin_role FROM vottery_user_management WHERE user_id = $1',
//         [userId]
//     );

//     if (userResult.rows.length === 0) {
//         throw new Error('User not found');
//     }

//     const { user_type, admin_role } = userResult.rows[0];

//     await query(
//         `INSERT INTO vottery_sessions 
//           (user_id, session_token, refresh_token, jwt_token_id, device_id, ip_address, user_agent, user_type, admin_role, is_active, created_at, expires_at, refresh_expires_at, last_activity)
//          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,TRUE,NOW(),NOW() + $10 * INTERVAL '1 second', NOW() + $11 * INTERVAL '1 second', NOW())`,
//         [userId, accessToken, refreshToken, jwtTokenId, deviceId || null, ipAddress || null, userAgent || null, user_type, admin_role, accessTokenSeconds, refreshTokenSeconds]
//     );
    
//     return { accessToken, refreshToken };
// };

// /**
//  * Refresh token rotation
//  */
// export const rotateRefreshToken = async ({ refreshToken, deviceId }) => {
//     // Get active session
//     const sessionResult = await query(
//         `SELECT * FROM vottery_sessions 
//           WHERE refresh_token = $1 AND device_id = $2 AND is_active = TRUE AND refresh_expires_at > NOW()`,
//         [refreshToken, deviceId]
//     );

//     if (sessionResult.rows.length === 0) {
//         throw new Error('Invalid or expired refresh token');
//     }

//     const session = sessionResult.rows[0];

//     // Generate new tokens with fresh user data
//     const newAccessToken = generateAccessToken({
//         userId: session.user_id,
//         userType: session.user_type || 'voter',
//         adminRole: session.admin_role || 'analyst'
//     });
//     const newRefreshToken = generateRefreshToken();

//     // compute expiry times
//     const accessTokenSeconds = parseExpiryToSeconds(ACCESS_TOKEN_EXPIRY);
//     const refreshTokenSeconds = parseExpiryToSeconds(REFRESH_TOKEN_EXPIRY);

//     // Update session in DB (rotate tokens)
//     await query(
//         `UPDATE vottery_sessions 
//          SET session_token=$1, refresh_token=$2, jwt_token_id=$3, expires_at=NOW() + $4 * INTERVAL '1 second', refresh_expires_at=NOW() + $5 * INTERVAL '1 second', last_activity=NOW()
//          WHERE id=$6`,
//         [newAccessToken, newRefreshToken, crypto.randomUUID(), accessTokenSeconds, refreshTokenSeconds, session.id]
//     );

//     return { accessToken: newAccessToken, refreshToken: newRefreshToken };
// };

// /**
//  * Invalidate session (logout)
//  */
// export const invalidateSession = async (sessionToken) => {
//     await query(
//         'UPDATE vottery_sessions SET is_active = FALSE WHERE session_token = $1',
//         [sessionToken]
//     );
// };

// /**
//  * Clean up expired sessions
//  */
// export const cleanupExpiredSessions = async () => {
//     await query(
//         'UPDATE vottery_sessions SET is_active = FALSE WHERE refresh_expires_at <= NOW() AND is_active = TRUE'
//     );
// };
// import jwt from 'jsonwebtoken';
// import crypto from 'crypto';
// import { query } from '../config/database.js';

// const JWT_SECRET = process.env.JWT_SECRET || 'vottery_secret_key_change_in_production';
// const ACCESS_TOKEN_EXPIRY = '1m';       // Short-lived access token
// const REFRESH_TOKEN_EXPIRY = '7d';      // Refresh token expiry

// /**
//  * Helper: parse expiry strings like "1m", "15m", "1h", "7d" into seconds
//  */
// const parseExpiryToSeconds = (expiry) => {
//     const match = expiry.match(/^(\d+)([smhd])$/);
//     if (!match) throw new Error(`Invalid expiry format: ${expiry}`);

//     const value = parseInt(match[1], 10);
//     const unit = match[2];

//     switch (unit) {
//         case 's': return value;
//         case 'm': return value * 60;
//         case 'h': return value * 3600;
//         case 'd': return value * 86400;
//         default: throw new Error(`Unsupported expiry unit: ${unit}`);
//     }
// };

// /**
//  * Generate a new access token
//  */
// export const generateAccessToken = (payload) => {
//     return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
// };

// /**
//  * Generate a new refresh token
//  */
// export const generateRefreshToken = () => {
//     return crypto.randomBytes(64).toString('hex');
// };

// /**
//  * Verify access token
//  */
// export const verifyAccessToken = (token) => {
//     return jwt.verify(token, JWT_SECRET);
// };

// /**
//  * Create a session in vottery_sessions
//  */
// export const createSession = async ({ userId, accessToken, refreshToken, deviceId, ipAddress, userAgent }) => {
//     const jwtTokenId = crypto.randomUUID();

//     // compute expiry times
//     const accessTokenSeconds = parseExpiryToSeconds(ACCESS_TOKEN_EXPIRY);
//     const refreshTokenSeconds = parseExpiryToSeconds(REFRESH_TOKEN_EXPIRY);

//     await query(
//         `INSERT INTO vottery_sessions 
//          (user_id, session_token, refresh_token, jwt_token_id, device_id, ip_address, user_agent, is_active, created_at, expires_at, refresh_expires_at, last_activity)
//          VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE,NOW(),NOW() + $8 * INTERVAL '1 second', NOW() + $9 * INTERVAL '1 second', NOW())`,
//         [userId, accessToken, refreshToken, jwtTokenId, deviceId || null, ipAddress || null, userAgent || null, accessTokenSeconds, refreshTokenSeconds]
//     );
//     return { accessToken, refreshToken };
// };

// /**
//  * Refresh token rotation
//  */
// export const rotateRefreshToken = async ({ refreshToken, deviceId }) => {
//     // Get active session
//     const sessionResult = await query(
//         `SELECT * FROM vottery_sessions 
//          WHERE refresh_token = $1 AND device_id = $2 AND is_active = TRUE AND refresh_expires_at > NOW()`,
//         [refreshToken, deviceId]
//     );

//     if (sessionResult.rows.length === 0) {
//         throw new Error('Invalid or expired refresh token');
//     }

//     const session = sessionResult.rows[0];

//     // Generate new tokens
//     const newAccessToken = generateAccessToken({
//         userId: session.user_id,
//         userType: session.user_type || 'voter',
//         adminRole: session.admin_role || 'analyst'
//     });
//     const newRefreshToken = generateRefreshToken();

//     // compute expiry times
//     const accessTokenSeconds = parseExpiryToSeconds(ACCESS_TOKEN_EXPIRY);
//     const refreshTokenSeconds = parseExpiryToSeconds(REFRESH_TOKEN_EXPIRY);

//     // Update session in DB (rotate tokens)
//     await query(
//         `UPDATE vottery_sessions
//          SET session_token=$1, refresh_token=$2, jwt_token_id=$3, expires_at=NOW() + $4 * INTERVAL '1 second', refresh_expires_at=NOW() + $5 * INTERVAL '1 second', last_activity=NOW()
//          WHERE id=$6`,
//         [newAccessToken, newRefreshToken, crypto.randomUUID(), accessTokenSeconds, refreshTokenSeconds, session.id]
//     );

//     return { accessToken: newAccessToken, refreshToken: newRefreshToken };
// };

// // utils/sessionManager.js
// import jwt from 'jsonwebtoken';
// import crypto from 'crypto';
// import { query } from '../config/database.js';

// const JWT_SECRET = process.env.JWT_SECRET || 'vottery_secret_key_change_in_production';
// const ACCESS_TOKEN_EXPIRY = '1m';       // Short-lived access token


// /**
//  * Generate a new access token
//  */
// export const generateAccessToken = (payload) => {
//     return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
// };

// /**
//  * Generate a new refresh token
//  */
// export const generateRefreshToken = () => {
//     return crypto.randomBytes(64).toString('hex');
// };

// /**
//  * Verify access token
//  */
// export const verifyAccessToken = (token) => {
//     return jwt.verify(token, JWT_SECRET);
// };

// /**
//  * Create a session in vottery_sessions
//  */
// export const createSession = async ({ userId, accessToken, refreshToken, deviceId, ipAddress, userAgent }) => {
//     const jwtTokenId = crypto.randomUUID();
//     await query(
//         `INSERT INTO vottery_sessions 
//          (user_id, session_token, refresh_token, jwt_token_id, device_id, ip_address, user_agent, is_active, created_at, expires_at, refresh_expires_at, last_activity)
//          VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE,NOW(),NOW() + INTERVAL '15 minutes', NOW() + INTERVAL '7 days', NOW())`,
//         [userId, accessToken, refreshToken, jwtTokenId, deviceId || null, ipAddress || null, userAgent || null]
//     );
//     return { accessToken, refreshToken };
// };

// /**
//  * Refresh token rotation
//  */
// export const rotateRefreshToken = async ({ refreshToken, deviceId }) => {
//     // Get active session
//     const sessionResult = await query(
//         `SELECT * FROM vottery_sessions 
//          WHERE refresh_token = $1 AND device_id = $2 AND is_active = TRUE AND refresh_expires_at > NOW()`,
//         [refreshToken, deviceId]
//     );

//     if (sessionResult.rows.length === 0) {
//         throw new Error('Invalid or expired refresh token');
//     }

//     const session = sessionResult.rows[0];

//     // Generate new tokens
//     const newAccessToken = generateAccessToken({ userId: session.user_id, userType: session.user_type || 'voter', adminRole: session.admin_role || 'analyst' });
//     const newRefreshToken = generateRefreshToken();

//     // Update session in DB (rotate tokens)
//     await query(
//         `UPDATE vottery_sessions
//          SET session_token=$1, refresh_token=$2, jwt_token_id=$3, expires_at=NOW() + INTERVAL '15 minutes', refresh_expires_at=NOW() + INTERVAL '7 days', last_activity=NOW()
//          WHERE id=$4`,
//         [newAccessToken, newRefreshToken, crypto.randomUUID(), session.id]
//     );

//     return { accessToken: newAccessToken, refreshToken: newRefreshToken };
// };

/**
 * Authenticate access token middleware
 */
// export const authenticateToken = async (req, res, next) => {
//     try {
//         const authHeader = req.headers['authorization'];
//         const token = authHeader?.split(' ')[1]?.trim();

//         if (!token) return res.status(401).json({ success: false, message: 'Access token required' });

//         let decoded;
//         try {
//             decoded = verifyAccessToken(token);
//         } catch (err) {
//             return res.status(403).json({ 
//                 success: false, 
//                 message: err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token'
//             });
//         }

//         const sessionResult = await query(
//             `SELECT * FROM vottery_sessions WHERE session_token = $1 AND is_active = TRUE AND expires_at > NOW()`,
//             [token]
//         );

//         if (sessionResult.rows.length === 0) {
//             return res.status(401).json({ success: false, message: 'Invalid or expired session' });
//         }

//         req.user = {
//             userId: decoded.userId,
//             userType: decoded.userType,
//             adminRole: decoded.adminRole
//         };

//         next();
//     } catch (err) {
//         console.error('Auth middleware error:', err);
//         return res.status(500).json({ success: false, message: 'Server error' });
//     }


// // utils/sessionManager.js
// import jwt from 'jsonwebtoken';
// import crypto from 'crypto';
// import { query } from '../config/database.js';

// const JWT_SECRET = process.env.JWT_SECRET || 'vottery_secret_key_change_in_production';
// const ACCESS_TOKEN_EXPIRY = '15m';       // Short-lived access token
// const REFRESH_TOKEN_EXPIRY = '7d';       // Refresh token validity

// /**
//  * Generate a new access token
//  */
// export const generateAccessToken = (payload) => {
//     return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
// };

// /**
//  * Generate a new refresh token
//  */
// export const generateRefreshToken = () => {
//     return crypto.randomBytes(64).toString('hex');
// };

// /**
//  * Verify access token
//  */
// export const verifyAccessToken = (token) => {
//     return jwt.verify(token, JWT_SECRET);
// };

// /**
//  * Create a session in vottery_sessions
//  */
// export const createSession = async ({ userId, accessToken, refreshToken, deviceId, ipAddress, userAgent }) => {
//     const jwtTokenId = crypto.randomUUID();
//     await query(
//         `INSERT INTO vottery_sessions 
//          (user_id, session_token, refresh_token, jwt_token_id, device_id, ip_address, user_agent, is_active, created_at, expires_at, refresh_expires_at, last_activity)
//          VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE,NOW(),NOW() + INTERVAL '15 minutes', NOW() + INTERVAL '7 days', NOW())`,
//         [userId, accessToken, refreshToken, jwtTokenId, deviceId || null, ipAddress || null, userAgent || null]
//     );
//     return { accessToken, refreshToken };
// };

// /**
//  * Refresh token rotation
//  */
// export const rotateRefreshToken = async ({ refreshToken, deviceId }) => {
//     // Get active session
//     const sessionResult = await query(
//         `SELECT * FROM vottery_sessions 
//          WHERE refresh_token = $1 AND device_id = $2 AND is_active = TRUE AND refresh_expires_at > NOW()`,
//         [refreshToken, deviceId]
//     );

//     if (sessionResult.rows.length === 0) {
//         throw new Error('Invalid or expired refresh token');
//     }

//     const session = sessionResult.rows[0];

//     // Generate new tokens
//     const newAccessToken = generateAccessToken({ userId: session.user_id, userType: session.user_type || 'voter', adminRole: session.admin_role || 'analyst' });
//     const newRefreshToken = generateRefreshToken();

//     // Update session in DB (rotate tokens)
//     await query(
//         `UPDATE vottery_sessions
//          SET session_token=$1, refresh_token=$2, jwt_token_id=$3, expires_at=NOW() + INTERVAL '15 minutes', refresh_expires_at=NOW() + INTERVAL '7 days', last_activity=NOW()
//          WHERE id=$4`,
//         [newAccessToken, newRefreshToken, crypto.randomUUID(), session.id]
//     );

//     return { accessToken: newAccessToken, refreshToken: newRefreshToken };
// };

// /**
//  * Authenticate access token middleware
//  */
// export const authenticateToken = async (req, res, next) => {
//     try {
//         const authHeader = req.headers['authorization'];
//         const token = authHeader?.split(' ')[1]?.trim();

//         if (!token) return res.status(401).json({ success: false, message: 'Access token required' });

//         let decoded;
//         try {
//             decoded = verifyAccessToken(token);
//         } catch (err) {
//             return res.status(403).json({ 
//                 success: false, 
//                 message: err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token'
//             });
//         }

//         const sessionResult = await query(
//             `SELECT * FROM vottery_sessions WHERE session_token = $1 AND is_active = TRUE AND expires_at > NOW()`,
//             [token]
//         );

//         if (sessionResult.rows.length === 0) {
//             return res.status(401).json({ success: false, message: 'Invalid or expired session' });
//         }

//         req.user = {
//             userId: decoded.userId,
//             userType: decoded.userType,
//             adminRole: decoded.adminRole
//         };

//         next();
//     } catch (err) {
//         console.error('Auth middleware error:', err);
//         return res.status(500).json({ success: false, message: 'Server error' });
//     }
// };
