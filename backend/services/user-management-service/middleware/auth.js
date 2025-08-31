import { query } from '../config/database.js';
import { verifyAccessToken, rotateRefreshToken } from '../utils/sessionManager.js';

export const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const accessToken = authHeader?.split(' ')[1]?.trim();
        const refreshToken = req.headers['x-refresh-token'] || req.body?.refreshToken;
        const deviceId = req.headers['x-device-id'] || req.body?.device_id;

        if (!accessToken) {
            return res.status(401).json({ 
                success: false, 
                message: 'Access token required',
                code: 'NO_ACCESS_TOKEN'
            });
        }

        let decoded;
        let activeAccessToken = accessToken;
        let tokenRotated = false;

        console.log("Attempting to verify access token...");
        
        try {
            // Try to verify access token
            decoded = verifyAccessToken(accessToken);
            console.log("Access token is valid:", decoded);
        } catch (err) {
            console.log("Access token verification failed:", err.name, err.message);
            
            if (err.name === 'TokenExpiredError') {
                console.log("Access token expired, attempting refresh...");
                
                // Token expired → try refresh flow
                if (!refreshToken || !deviceId) {
                    return res.status(401).json({ 
                        success: false, 
                        message: 'Access token expired, refresh token and device ID required',
                        code: 'TOKEN_EXPIRED_NO_REFRESH'
                    });
                }

                try {
                    // Rotate refresh token and get new tokens
                    console.log("Rotating refresh token...");
                    const tokens = await rotateRefreshToken({ refreshToken, deviceId });

                    // Attach new tokens to response headers
                    res.setHeader('x-access-token', tokens.accessToken);
                    res.setHeader('x-refresh-token', tokens.refreshToken);

                    // Decode new access token
                    decoded = verifyAccessToken(tokens.accessToken);
                    console.log("New access token generated and verified:", decoded);

                    // Use the new token for DB check
                    activeAccessToken = tokens.accessToken;
                    tokenRotated = true;
                } catch (rotationErr) {
                    console.error("Token rotation failed:", rotationErr.message);
                    return res.status(401).json({ 
                        success: false, 
                        message: rotationErr.message,
                        code: 'REFRESH_TOKEN_INVALID'
                    });
                }
            } else {
                console.error("Invalid access token:", err.message);
                return res.status(403).json({ 
                    success: false, 
                    message: 'Invalid access token',
                    code: 'ACCESS_TOKEN_INVALID'
                });
            }
        }

        // Validate session with the correct token (old valid one or new refreshed one)
        console.log("Validating session in database...");
        const sessionResult = await query(
            'SELECT * FROM vottery_sessions WHERE session_token = $1 AND is_active = TRUE AND expires_at > NOW()',
            [activeAccessToken]
        );

        if (sessionResult.rows.length === 0) {
            console.log("No valid session found in database");
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid or expired session',
                code: 'SESSION_INVALID'
            });
        }

        console.log("Valid session found in database");

        // Update last activity
        await query(
            'UPDATE vottery_sessions SET last_activity = NOW() WHERE session_token = $1',
            [activeAccessToken]
        );

        // Attach user info to request
        req.user = {
            userId: decoded.userId,
            userType: decoded.userType,
            adminRole: decoded.adminRole,
        };

        // Add token rotation info for debugging
        if (tokenRotated) {
            req.tokenRotated = true;
            console.log("Token successfully rotated for user:", decoded.userId);
        }

        next();
    } catch (err) {
        console.error('Auth middleware error:', err);
        return res.status(500).json({ 
            success: false, 
            message: 'Server error',
            code: 'SERVER_ERROR'
        });
    }
};

// export const authenticateToken = async (req, res, next) => {
//     try {
//         const authHeader = req.headers['authorization'];
//         const token = authHeader?.split(' ')[1]?.trim();

//         if (!token) {
//             return res.status(401).json({ success: false, message: 'Access token required' });
//         }

//         let decoded;
//         try {
//             decoded = jwt.verify(token, JWT_SECRET);
//         } catch (err) {
//             return res.status(403).json({
//                 success: false,
//                 message: err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token'
//             });
//         }

//         const sessionResult = await query(
//             'SELECT user_id, is_active FROM vottery_sessions WHERE session_token = $1 AND expires_at > NOW()',
//             [token]
//         );

//         if (sessionResult.rows.length === 0 || !sessionResult.rows[0].is_active) {
//             return res.status(401).json({ success: false, message: 'Invalid or expired token' });
//         }

//         req.user = {
//             userId: decoded.userId,
//             userType: decoded.userType,
//             adminRole: decoded.adminRole
//         };

//         next();
//     } catch (error) {
//         console.error('Auth middleware error:', error);
//         return res.status(500).json({ success: false, message: 'Internal server error' });
//     }
// };

export const requireAdmin = (req, res, next) => {
    if (!req.user.adminRole) {
        return res.status(403).json({ success: false, message: 'Admin access required' });
    }
    next();
};

export const requireRole = (allowedRoles) => {
    return (req, res, next) => {
        if (!req.user.adminRole || !allowedRoles.includes(req.user.adminRole)) {
            return res.status(403).json({ success: false, message: 'Insufficient permissions' });
        }
        next();
    };
};

// import jwt from 'jsonwebtoken';
// import { query } from '../config/database.js';

// const JWT_SECRET = process.env.JWT_SECRET || 'vottery_secret_key_change_in_production';

// export const authenticateToken = async (req, res, next) => {
//     try {
//         const authHeader = req.headers['authorization'];
//         const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

//         if (!token) {
//             return res.status(401).json({ 
//                 success: false, 
//                 message: 'Access token required' 
//             });
//         }

//         const decoded = jwt.verify(token, JWT_SECRET);
        
//         // Verify token exists in database and is active
//         const sessionResult = await query(
//             'SELECT user_id, is_active FROM vottery_sessions WHERE session_token = $1 AND expires_at > NOW()',
//             [token]
//         );

//         if (sessionResult.rows.length === 0 || !sessionResult.rows[0].is_active) {
//             return res.status(401).json({ 
//                 success: false, 
//                 message: 'Invalid or expired token' 
//             });
//         }

//         // Add user info to request
//         req.user = {
//             userId: decoded.userId,
//             userType: decoded.userType,
//             adminRole: decoded.adminRole
//         };

//         next();
//     } catch (error) {
//         console.error('Auth middleware error:', error);
//         return res.status(403).json({ 
//             success: false, 
//             message: 'Invalid token' 
//         });
//     }
// };

// export const requireAdmin = (req, res, next) => {
//     if (!req.user.adminRole) {
//         return res.status(403).json({ 
//             success: false, 
//             message: 'Admin access required' 
//         });
//     }
//     next();
// };

// export const requireRole = (allowedRoles) => {
//     return (req, res, next) => {
//         if (!req.user.adminRole || !allowedRoles.includes(req.user.adminRole)) {
//             return res.status(403).json({ 
//                 success: false, 
//                 message: 'Insufficient permissions' 
//             });
//         }
//         next();
//     };
// };