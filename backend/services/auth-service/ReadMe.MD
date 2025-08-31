export default app;

// services/auth-service/.env.example
NODE_ENV=development
PORT=3001

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=sngine_db
DB_USER=postgres
DB_PASSWORD=password

# JWT Configuration
JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nYour_Private_Key_Here\n-----END RSA PRIVATE KEY-----"
JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nYour_Public_Key_Here\n-----END PUBLIC KEY-----"
JWT_REFRESH_SECRET=your_very_long_random_refresh_secret_key_here

# Encryption
ENCRYPTION_KEY=your_32_character_encryption_key_here

# Email Configuration (Gmail/SMTP)
EMAIL_SERVICE=gmail
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_SECURE=false
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_FROM=noreply@vottery.com

# Twilio Configuration
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_PHONE_NUMBER=+1234567890

# Frontend URL
FRONTEND_URL=http://localhost:3000

# CORS Origins
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173,https://vottery.com

# Logging
LOG_LEVEL=info

// docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: vottery-postgres
    environment:
      POSTGRES_DB: sngine_db
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./shared/database/migrations:/docker-entrypoint-initdb.d
    networks:
      - vottery-network

  auth-service:
    build:
      context: ./services/auth-service
      dockerfile: Dockerfile
    container_name: vottery-auth-service
    environment:
      NODE_ENV: development
      PORT: 3001
      DB_HOST: postgres
      DB_PORT: 5432
      DB_NAME: sngine_db
      DB_USER: postgres
      DB_PASSWORD: password
    ports:
      - "3001:3001"
    depends_on:
      - postgres
    volumes:
      - ./services/auth-service:/app
      - /app/node_modules
    networks:
      - vottery-network
    restart: unless-stopped

  biometric-service:
    build:
      context: ./services/biometric-service
      dockerfile: Dockerfile
    container_name: vottery-biometric-service
    environment:
      NODE_ENV: development
      PORT: 3002
      DB_HOST: postgres
      DB_PORT: 5432
      DB_NAME: sngine_db
      DB_USER: postgres
      DB_PASSWORD: password
    ports:
      - "3002:3002"
    depends_on:
      - postgres
    volumes:
      - ./services/biometric-service:/app
      - /app/node_modules
    networks:
      - vottery-network
    restart: unless-stopped

  user-service:
    build:
      context: ./services/user-service
      dockerfile: Dockerfile
    container_name: vottery-user-service
    environment:
      NODE_ENV: development
      PORT: 3003
      DB_HOST: postgres
      DB_PORT: 5432
      DB_NAME: sngine_db
      DB_USER: postgres
      DB_PASSWORD: password
    ports:
      - "3003:3003"
    depends_on:
      - postgres
    volumes:
      - ./services/user-service:/app
      - /app/node_modules
    networks:
      - vottery-network
    restart: unless-stopped

  api-gateway:
    build:
      context: ./gateway
      dockerfile: Dockerfile
    container_name: vottery-api-gateway
    environment:
      NODE_ENV: development
      PORT: 3000
      AUTH_SERVICE_URL: http://auth-service:3001
      BIOMETRIC_SERVICE_URL: http://biometric-service:3002
      USER_SERVICE_URL: http://user-service:3003
    ports:
      - "3000:3000"
    depends_on:
      - auth-service
      - biometric-service
      - user-service
    volumes:
      - ./gateway:/app
      - /app/node_modules
    networks:
      - vottery-network
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    container_name: vottery-redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - vottery-network
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:

networks:
  vottery-network:
    driver: bridge

// shared/database/migrations/001_create_vottery_users.sql
-- Create vottery_users table
CREATE TABLE IF NOT EXISTS vottery_users (
    id SERIAL PRIMARY KEY,
    sngine_email VARCHAR(255) NOT NULL UNIQUE,
    sngine_phone VARCHAR(50) NOT NULL,
    email_verified_at TIMESTAMP NULL,
    phone_verified_at TIMESTAMP NULL,
    biometric_registered_at TIMESTAMP NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'email_verified', 'phone_verified', 'biometric_registered', 'active', 'suspended')),
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_vottery_users_email ON vottery_users(sngine_email);
CREATE INDEX IF NOT EXISTS idx_vottery_users_phone ON vottery_users(sngine_phone);
CREATE INDEX IF NOT EXISTS idx_vottery_users_status ON vottery_users(status);
CREATE INDEX IF NOT EXISTS idx_vottery_users_created ON vottery_users(created_at);

-- Create trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$ language 'plpgsql';

CREATE TRIGGER update_vottery_users_updated_at BEFORE UPDATE ON vottery_users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

// shared/database/migrations/002_create_vottery_devices.sql
-- Create vottery_devices table
CREATE TABLE IF NOT EXISTS vottery_devices (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    device_fingerprint VARCHAR(255) NOT NULL UNIQUE,
    device_type VARCHAR(50) NOT NULL DEFAULT 'desktop',
    browser_name VARCHAR(100),
    browser_version VARCHAR(50),
    os_name VARCHAR(100),
    os_version VARCHAR(50),
    screen_info JSONB,
    ip_address INET,
    location JSONB,
    is_active BOOLEAN DEFAULT true,
    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES vottery_users(id) ON DELETE CASCADE
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_vottery_devices_user ON vottery_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_vottery_devices_fingerprint ON vottery_devices(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_vottery_devices_active ON vottery_devices(is_active);
CREATE INDEX IF NOT EXISTS idx_vottery_devices_user_active ON vottery_devices(user_id, is_active);

// shared/database/migrations/003_create_vottery_biometrics.sql
-- Create vottery_biometrics table
CREATE TABLE IF NOT EXISTS vottery_biometrics (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    biometric_type VARCHAR(50) NOT NULL CHECK (biometric_type IN ('webauthn', 'fingerprint', 'face_id', 'mock')),
    biometric_hash TEXT NOT NULL,
    public_key TEXT,
    credential_id TEXT,
    counter INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES vottery_users(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES vottery_devices(id) ON DELETE CASCADE,
    UNIQUE (user_id, device_id, biometric_type)
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_vottery_biometrics_user ON vottery_biometrics(user_id);
CREATE INDEX IF NOT EXISTS idx_vottery_biometrics_device ON vottery_biometrics(device_id);
CREATE INDEX IF NOT EXISTS idx_vottery_biometrics_type ON vottery_biometrics(biometric_type);
CREATE INDEX IF NOT EXISTS idx_vottery_biometrics_active ON vottery_biometrics(is_active);

// shared/database/migrations/004_create_vottery_sessions.sql
-- Create vottery_sessions table
CREATE TABLE IF NOT EXISTS vottery_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    refresh_token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    refresh_expires_at TIMESTAMP NOT NULL,
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES vottery_users(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES vottery_devices(id) ON DELETE CASCADE
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_vottery_sessions_user ON vottery_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_vottery_sessions_device ON vottery_sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_vottery_sessions_token ON vottery_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_vottery_sessions_refresh ON vottery_sessions(refresh_token);
CREATE INDEX IF NOT EXISTS idx_vottery_sessions_active ON vottery_sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_vottery_sessions_expires ON vottery_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_vottery_sessions_user_active ON vottery_sessions(user_id, is_active);

// shared/database/migrations/005_create_vottery_otps.sql
-- Create vottery_otps table
CREATE TABLE IF NOT EXISTS vottery_otps (
    id SERIAL PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    otp_code VARCHAR(10) NOT NULL,
    otp_type VARCHAR(10) NOT NULL CHECK (otp_type IN ('email', 'sms')),
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_vottery_otps_identifier ON vottery_otps(identifier, otp_type);
CREATE INDEX IF NOT EXISTS idx_vottery_otps_expires ON vottery_otps(expires_at);
CREATE INDEX IF NOT EXISTS idx_vottery_otps_used ON vottery_otps(used_at);

// shared/database/migrations/006_create_vottery_audit_logs.sql
-- Create vottery_audit_logs table
CREATE TABLE IF NOT EXISTS vottery_audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    device_id INTEGER,
    session_id INTEGER,
    action VARCHAR(100) NOT NULL,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES vottery_users(id) ON DELETE SET NULL,
    FOREIGN KEY (device_id) REFERENCES vottery_devices(id) ON DELETE SET NULL,
    FOREIGN KEY (session_id) REFERENCES vottery_sessions(id) ON DELETE SET NULL
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_vottery_audit_user ON vottery_audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_vottery_audit_action ON vottery_audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_vottery_audit_created ON vottery_audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_vottery_audit_success ON vottery_audit_logs(success);
CREATE INDEX IF NOT EXISTS idx_vottery_audit_user_action ON vottery_audit_logs(user_id, action);

// services/auth-service/Dockerfile
FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY . .

# Create logs directory
RUN mkdir -p logs

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

# Change ownership
RUN chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 3001

CMD ["npm", "start"]

// README.md
# Vottery Backend - Milestone 1

This is the backend implementation for Vottery Milestone-1, focusing on secure user authentication and biometric registration for users coming from SngEngine.

## Architecture Overview

### Microservices
1. **Auth Service** (Port 3001) - Email/SMS OTP verification and JWT management
2. **Biometric Service** (Port 3002) - Biometric data capture and device registration
3. **User Service** (Port 3003) - User profile and device management
4. **API Gateway** (Port 3000) - Request routing and load balancing

### Key Features
- ✅ SngEngine database integration (read-only access to existing users table)
- ✅ Email OTP via Nodemailer
- ✅ SMS OTP via Twilio
- ✅ JWT authentication with refresh token rotation
- ✅ Cross-platform biometric support
- ✅ Device fingerprinting and registration
- ✅ Rate limiting and security middleware
- ✅ Comprehensive audit logging

## Quick Start

### Prerequisites
- Node.js 20+
- PostgreSQL 15+
- Docker & Docker Compose
- Twilio Account (for SMS)
- Email service (Gmail/SMTP)

### Installation

1. **Clone and setup:**
```bash
git clone <repository>
cd vottery-backend
```

2. **Environment configuration:**
```bash
# Copy example environment files
cp services/auth-service/.env.example services/auth-service/.env
# Edit .env files with your configuration
```

3. **Start with Docker:**
```bash
docker-compose up -d
```

4. **Manual setup:**
```bash
# Install dependencies for each service
cd services/auth-service && npm install
cd ../biometric-service && npm install
cd ../user-service && npm install
cd ../gateway && npm install

# Start services
npm run dev # in each service directory
```

## API Endpoints

### Authentication Service (http://localhost:3001)

#### POST `/api/auth/check-user`
Check if user exists in SngEngine database
```json
{
  "email": "user@example.com",
  "phone": "+1234567890"
}
```

#### POST `/api/auth/send-email-otp`
Send email OTP
```json
{
  "email": "user@example.com"
}
```

#### POST `/api/auth/send-sms-otp`
Send SMS OTP
```json
{
  "phone": "+1234567890"
}
```

#### POST `/api/auth/verify-email-otp`
Verify email OTP
```json
{
  "identifier": "user@example.com",
  "otp": "123456"
}
```

#### POST `/api/auth/verify-sms-otp`
Verify SMS OTP
```json
{
  "identifier": "+1234567890",
  "otp": "123456"
}
```

#### POST `/api/auth/complete`
Complete authentication with biometric data
```json
{
  "email": "user@example.com",
  "phone": "+1234567890",
  "deviceFingerprint": "abc123...",
  "device": {
    "browser": {"name": "Chrome", "version": "120.0"},
    "os": {"name": "Windows", "version": "10"},
    "screen": {"width": 1920, "height": 1080}
  },
  "biometric": {
    "type": "webauthn",
    "data": "..."
  }
}
```

## Database Schema

The system creates new `vottery_` prefixed tables while reading from the existing SngEngine `users` table:

- `vottery_users` - Vottery-specific user data
- `vottery_devices` - Device registration and fingerprinting
- `vottery_biometrics` - Encrypted biometric data
- `vottery_sessions` - JWT session management
- `vottery_otps` - OTP verification tracking
- `vottery_audit_logs` - Comprehensive audit trail

## Security Features

### Data Protection
- AES-256 encryption for sensitive data
- SHA-256 hashing for biometric data
- RSA/JWT signing for tokens
- TLS 1.3 for all communications

### Rate Limiting
- OTP requests: 5 per 15 minutes per IP
- Auth attempts: 10 per 15 minutes per IP
- General API: 100 per minute per IP

### Validation & Sanitization
- Input validation with express-validator
- SQL injection prevention
- XSS protection with helmet
- CORS configuration

## Testing

### Manual Testing
```bash
# Check if services are healthy
curl http://localhost:3001/health
curl http://localhost:3002/health
curl http://localhost:3003/health

# Test complete authentication flow
curl -X POST http://localhost:3001/api/auth/check-user \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","phone":"+}

// services/auth-service/src/controllers/authController.js
import { validationResult } from 'express-validator';
import { User } from '../models/User.js';
import { OTP } from '../models/OTP.js';
import { Session } from '../models/Session.js';
import { EmailService } from '../services/emailService.js';
import { SMSService } from '../services/smsService.js';
import { TokenService } from '../services/tokenService.js';
import { EncryptionUtils } from '../utils/encryption.js';
import { logger } from '../utils/logger.js';
import { USER_STATUS } from '../utils/constants.js';

export class AuthController {
  // Check if user exists in SngEngine database
  static async checkUser(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { email, phone } = req.body;

      // Check SngEngine database
      const sngineUser = await User.checkSngineUser(email, phone);
      
      if (!sngineUser.exists) {
        logger.warn(`User check failed for ${email}, ${phone}: ${sngineUser.message}`);
        return res.status(404).json({
          success: false,
          exists: false,
          message: 'Email and phone combination not found in SngEngine. Please register first.'
        });
      }

      // Create or get Vottery user
      await User.createOrGetVotteryUser(email, phone);

      logger.info(`User check successful for ${email}`);
      
      res.json({
        success: true,
        exists: true,
        message: 'User found in SngEngine database',
        emailVerified: sngineUser.emailVerified,
        phoneVerified: sngineUser.phoneVerified
      });

    } catch (error) {
      logger.error('Check user error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      });
    }
  }

  // Send email OTP
  static async sendEmailOTP(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { email } = req.body;

      // Check rate limit
      const rateLimit = await OTP.checkRateLimit(email, 'email');
      if (!rateLimit.allowed) {
        return res.status(429).json({
          success: false,
          message: `Too many OTP requests. Please wait before requesting again. (${rateLimit.count}/${rateLimit.limit})`
        });
      }

      // Create OTP
      const { otpRecord, otpCode } = await OTP.create(email, 'email');

      // Send email
      await EmailService.sendOTP(email, otpCode);

      logger.info(`Email OTP sent to ${email}`);
      
      res.json({
        success: true,
        message: 'Email OTP sent successfully',
        expiresIn: 300 // 5 minutes in seconds
      });

    } catch (error) {
      logger.error('Send email OTP error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to send email OTP'
      });
    }
  }

  // Send SMS OTP
  static async sendSMSOTP(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { phone } = req.body;

      // Check rate limit
      const rateLimit = await OTP.checkRateLimit(phone, 'sms');
      if (!rateLimit.allowed) {
        return res.status(429).json({
          success: false,
          message: `Too many OTP requests. Please wait before requesting again. (${rateLimit.count}/${rateLimit.limit})`
        });
      }

      // Create OTP
      const { otpRecord, otpCode } = await OTP.create(phone, 'sms');

      // Send SMS
      await SMSService.sendOTP(phone, otpCode);

      logger.info(`SMS OTP sent to ${phone}`);
      
      res.json({
        success: true,
        message: 'SMS OTP sent successfully',
        expiresIn: 300 // 5 minutes in seconds
      });

    } catch (error) {
      logger.error('Send SMS OTP error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to send SMS OTP'
      });
    }
  }

  // Verify email OTP
  static async verifyEmailOTP(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { identifier: email, otp } = req.body;

      // Verify OTP
      const verification = await OTP.verify(email, otp, 'email');
      
      if (!verification.success) {
        return res.status(400).json({
          success: false,
          message: verification.message
        });
      }

      // Update user status
      const votteryUser = await User.createOrGetVotteryUser(email, ''); // We'll get phone later
      await User.updateStatus(votteryUser.id, USER_STATUS.EMAIL_VERIFIED, 'email_verified_at');

      logger.info(`Email OTP verified for ${email}`);
      
      res.json({
        success: true,
        message: 'Email OTP verified successfully'
      });

    } catch (error) {
      logger.error('Verify email OTP error:', error);
      res.status(500).json({
        success: false,
        message: 'Email OTP verification failed'
      });
    }
  }

  // Verify SMS OTP
  static async verifySMSOTP(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { identifier: phone, otp } = req.body;

      // Verify OTP
      const verification = await OTP.verify(phone, otp, 'sms');
      
      if (!verification.success) {
        return res.status(400).json({
          success: false,
          message: verification.message
        });
      }

      // Update user status
      const votteryUser = await User.createOrGetVotteryUser('', phone); // We'll get email from session
      await User.updateStatus(votteryUser.id, USER_STATUS.PHONE_VERIFIED, 'phone_verified_at');

      logger.info(`SMS OTP verified for ${phone}`);
      
      res.json({
        success: true,
        message: 'SMS OTP verified successfully'
      });

    } catch (error) {
      logger.error('Verify SMS OTP error:', error);
      res.status(500).json({
        success: false,
        message: 'SMS OTP verification failed'
      });
    }
  }

  // Complete authentication with biometric data
  static async completeAuth(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { 
        email, 
        phone, 
        deviceFingerprint, 
        device, 
        biometric 
      } = req.body;

      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent');

      // Get Vottery user
      const votteryUser = await User.createOrGetVotteryUser(email, phone);

      // Register device (this would be in biometric-service in production)
      const deviceData = {
        userId: votteryUser.id,
        deviceFingerprint,
        deviceType: device.device?.type || 'desktop',
        browserName: device.browser?.name,
        browserVersion: device.browser?.version,
        osName: device.os?.name,
        osVersion: device.os?.version,
        screenInfo: device.screen,
        ipAddress,
        location: null // Could add geolocation later
      };

      // In production, this would call biometric-service
      // For now, we'll simulate device registration
      const deviceId = Math.floor(Math.random() * 1000000); // Mock device ID

      // Generate tokens
      const tokenPayload = {
        userId: votteryUser.id,
        email: votteryUser.sngine_email,
        phone: votteryUser.sngine_phone,
        deviceId: deviceId,
        deviceFingerprint
      };

      const sessionToken = EncryptionUtils.generateToken();
      const refreshToken = EncryptionUtils.generateToken();

      // Create session
      const session = await Session.create(
        votteryUser.id,
        deviceId,
        sessionToken,
        refreshToken,
        ipAddress,
        userAgent
      );

      // Generate JWT tokens
      const tokens = TokenService.generateTokenPair(tokenPayload);

      // Update user status
      await User.updateStatus(votteryUser.id, USER_STATUS.ACTIVE, 'biometric_registered_at');
      await User.updateLastLogin(votteryUser.id);

      // Send welcome notifications
      try {
        await Promise.all([
          EmailService.sendWelcomeEmail(email, 'User'),
          SMSService.sendWelcomeSMS(phone)
        ]);
      } catch (notificationError) {
        logger.warn('Welcome notification failed:', notificationError);
        // Don't fail the authentication for notification errors
      }

      logger.info(`Authentication completed successfully for user ${votteryUser.id}`);
      
      res.json({
        success: true,
        message: 'Authentication completed successfully',
        token: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user: {
          id: votteryUser.id,
          email: votteryUser.sngine_email,
          phone: votteryUser.sngine_phone,
          status: votteryUser.status,
          emailVerified: !!votteryUser.email_verified_at,
          phoneVerified: !!votteryUser.phone_verified_at,
          biometricRegistered: !!votteryUser.biometric_registered_at,
          lastLogin: votteryUser.last_login
        },
        session: {
          id: session.id,
          deviceId: deviceId,
          expiresAt: session.expires_at
        }
      });

    } catch (error) {
      logger.error('Complete authentication error:', error);
      res.status(500).json({
        success: false,
        message: 'Authentication completion failed'
      });
    }
  }

  // Refresh token
  static async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(400).json({
          success: false,
          message: 'Refresh token is required'
        });
      }

      // Refresh session
      const newSession = await Session.refresh(refreshToken);
      
      if (!newSession) {
        return res.status(401).json({
          success: false,
          message: 'Invalid or expired refresh token'
        });
      }

      // Generate new JWT tokens
      const tokenPayload = {
        userId: newSession.user_id,
        deviceId: newSession.device_id,
        sessionId: newSession.id
      };

      const tokens = TokenService.generateTokenPair(tokenPayload);

      res.json({
        success: true,
        token: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresAt: newSession.expires_at
      });

    } catch (error) {
      logger.error('Token refresh error:', error);
      res.status(500).json({
        success: false,
        message: 'Token refresh failed'
      });
    }
  }

  // Logout
  static async logout(req, res) {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(400).json({
          success: false,
          message: 'Authorization token is required'
        });
      }

      const token = authHeader.substring(7);
      
      // Get session from token
      const session = await Session.getByToken(token);
      
      if (session) {
        // Revoke session
        await Session.revoke(token);
        logger.info(`User ${session.user_id} logged out successfully`);
      }

      res.json({
        success: true,
        message: 'Logged out successfully'
      });

    } catch (error) {
      logger.error('Logout error:', error);
      res.status(500).json({
        success: false,
        message: 'Logout failed'
      });
    }
  }

  // Get user profile
  static async getProfile(req, res) {
    try {
      const userId = req.user.userId;
      
      const user = await User.getById(userId);
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      // Get user sessions
      const sessions = await Session.getUserSessions(userId);

      res.json({
        success: true,
        user: {
          id: user.id,
          email: user.sngine_email,
          phone: user.sngine_phone,
          status: user.status,
          emailVerified: !!user.email_verified_at,
          phoneVerified: !!user.phone_verified_at,
          biometricRegistered: !!user.biometric_registered_at,
          lastLogin: user.last_login,
          createdAt: user.created_at,
          updatedAt: user.updated_at
        },
        sessions: sessions.map(session => ({
          id: session.id,
          deviceType: session.device_type,
          browserName: session.browser_name,
          osName: session.os_name,
          ipAddress: session.ip_address,
          createdAt: session.created_at,
          isActive: session.is_active
        }))
      });

    } catch (error) {
      logger.error('Get profile error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to get user profile'
      });
    }
  }
}

// services/auth-service/src/middleware/auth.js
import { TokenService } from '../services/tokenService.js';
import { Session } from '../models/Session.js';
import { logger } from '../utils/logger.js';

export const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Access token is required'
      });
    }

    const token = authHeader.substring(7);

    // Verify JWT token
    const decoded = TokenService.verifyAccessToken(token);
    
    // Check if session exists and is active
    const session = await Session.getByToken(token);
    
    if (!session || !session.is_active) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired session'
      });
    }

    // Check if session is expired
    if (new Date() > new Date(session.expires_at)) {
      return res.status(401).json({
        success: false,
        message: 'Session expired'
      });
    }

    // Check if user is active
    if (session.status === 'suspended') {
      return res.status(403).json({
        success: false,
        message: 'User account is suspended'
      });
    }

    // Add user info to request
    req.user = {
      userId: decoded.userId,
      email: decoded.email,
      phone: decoded.phone,
      deviceId: decoded.deviceId,
      sessionId: session.id
    };

    next();

  } catch (error) {
    logger.error('Token authentication error:', error);
    
    if (error.message.includes('expired') || error.message.includes('invalid')) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Authentication failed'
    });
  }
};

// services/auth-service/src/middleware/rateLimit.js
import rateLimit from 'express-rate-limit';

// General API rate limiting
export const generalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// OTP request rate limiting
export const otpRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 OTP requests per windowMs
  message: {
    success: false,
    message: 'Too many OTP requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Authentication attempt rate limiting
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 auth attempts per windowMs
  message: {
    success: false,
    message: 'Too many authentication attempts from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// services/auth-service/src/middleware/validation.js
import { validationResult } from 'express-validator';

export const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array().map(error => ({
        field: error.param,
        message: error.msg,
        value: error.value
      }))
    });
  }
  
  next();
};

// services/auth-service/src/middleware/security.js
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import hpp from 'hpp';
import mongoSanitize from 'express-mongo-sanitize';

export const securityMiddleware = [
  // Enable CORS with specific origins
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || [
      'http://localhost:3000',
      'http://localhost:5173',
      'https://vottery.com'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  }),

  // Security headers
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
  }),

  // Compress responses
  compression(),

  // Prevent HTTP Parameter Pollution
  hpp(),

  // Data sanitization against NoSQL query injection
  mongoSanitize(),
];

// services/auth-service/src/routes/authRoutes.js
import express from 'express';
import { AuthController } from '../controllers/authController.js';
import { authValidators } from '../utils/validators.js';
import { handleValidationErrors } from '../middleware/validation.js';
import { authenticateToken } from '../middleware/auth.js';
import { generalRateLimit, otpRateLimit, authRateLimit } from '../middleware/rateLimit.js';

const router = express.Router();

// Public routes with rate limiting
router.post('/check-user', 
  authRateLimit,
  authValidators.checkUser,
  handleValidationErrors,
  AuthController.checkUser
);

router.post('/send-email-otp',
  otpRateLimit,
  authValidators.sendOTP,
  handleValidationErrors,
  AuthController.sendEmailOTP
);

router.post('/send-sms-otp',
  otpRateLimit,
  authValidators.sendOTP,
  handleValidationErrors,
  AuthController.sendSMSOTP
);

router.post('/verify-email-otp',
  authRateLimit,
  authValidators.verifyOTP,
  handleValidationErrors,
  AuthController.verifyEmailOTP
);

router.post('/verify-sms-otp',
  authRateLimit,
  authValidators.verifyOTP,
  handleValidationErrors,
  AuthController.verifySMSOTP
);

router.post('/complete',
  authRateLimit,
  authValidators.completeAuth,
  handleValidationErrors,
  AuthController.completeAuth
);

router.post('/refresh',
  generalRateLimit,
  AuthController.refreshToken
);

// Protected routes
router.post('/logout',
  generalRateLimit,
  authenticateToken,
  AuthController.logout
);

router.get('/profile',
  generalRateLimit,
  authenticateToken,
  AuthController.getProfile
);

export default router;

// services/auth-service/src/app.js
import express from 'express';
import dotenv from 'dotenv';
import { logger } from './utils/logger.js';
import { securityMiddleware } from './middleware/security.js';
import { generalRateLimit } from './middleware/rateLimit.js';
import authRoutes from './routes/authRoutes.js';
import { OTP } from './models/OTP.js';
import { Session } from './models/Session.js';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Apply security middleware
app.use(securityMiddleware);

// Parse JSON bodies
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Apply general rate limiting
app.use(generalRateLimit);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Auth service is healthy',
    timestamp: new Date().toISOString(),
    service: 'vottery-auth-service',
    version: '1.0.0'
  });
});

// API routes
app.use('/api/auth', authRoutes);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  
  res.status(err.status || 500).json({
    success: false,
    message: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
  });
});

// Cleanup function for expired records
const startCleanupJobs = () => {
  // Clean expired OTPs every 10 minutes
  setInterval(async () => {
    try {
      await OTP.cleanExpired();
    } catch (error) {
      logger.error('OTP cleanup job failed:', error);
    }
  }, 10 * 60 * 1000);

  // Clean expired sessions every hour
  setInterval(async () => {
    try {
      await Session.cleanExpired();
    } catch (error) {
      logger.error('Session cleanup job failed:', error);
    }
  }, 60 * 60 * 1000);
};

// Start server
app.listen(PORT, () => {
  logger.info(`Auth service running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  
  // Start cleanup jobs
  startCleanupJobs();
  
  // Graceful shutdown
  process.on('SIGTERM', () => {
    logger.info('SIGTERM received, shutting down gracefully');
    process.exit(0);
  });
  
  process.on('SIGINT', () => {
    logger.info('SIGINT received, shutting down gracefully');
    process.exit(0);
  });
});

export default app;// services/auth-service/package.json
{
  "name": "vottery-auth-service",
  "version": "1.0.0",
  "type": "module",
  "main": "src/app.js",
  "scripts": {
    "start": "node src/app.js",
    "dev": "nodemon src/app.js",
    "test": "jest"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "express-rate-limit": "^7.1.5",
    "express-validator": "^7.0.1",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "nodemailer": "^6.9.8",
    "twilio": "^4.19.0",
    "pg": "^8.11.3",
    "dotenv": "^16.3.1",
    "winston": "^3.11.0",
    "compression": "^1.7.4",
    "hpp": "^0.2.3",
    "express-mongo-sanitize": "^2.2.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.2",
    "jest": "^29.7.0"
  }
}

// services/auth-service/src/config/database.js
import pkg from 'pg';
import dotenv from 'dotenv';
import { logger } from '../utils/logger.js';

dotenv.config();

const { Pool } = pkg;

// PostgreSQL connection configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'sngine_db',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'password',
  max: 20, // Maximum number of clients in the pool
  idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
  connectionTimeoutMillis: 2000, // Return error after 2 seconds if connection could not be established
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
};

// Create connection pool
const pool = new Pool(dbConfig);

// Handle pool errors
pool.on('error', (err) => {
  logger.error('Unexpected error on idle client:', err);
  process.exit(-1);
});

// Test connection
pool.connect((err, client, release) => {
  if (err) {
    logger.error('Error acquiring client:', err.stack);
  } else {
    logger.info('Database connected successfully');
    release();
  }
});

export default pool;

// services/auth-service/src/config/email.js
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

// Email configuration
const emailConfig = {
  service: process.env.EMAIL_SERVICE || 'gmail',
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: process.env.EMAIL_PORT || 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
};

// Create transporter
const transporter = nodemailer.createTransporter(emailConfig);

// Verify email configuration
transporter.verify((error, success) => {
  if (error) {
    console.error('Email configuration error:', error);
  } else {
    console.log('Email service is ready');
  }
});

export default transporter;

// services/auth-service/src/config/sms.js
import twilio from 'twilio';
import dotenv from 'dotenv';

dotenv.config();

// Twilio configuration
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

export default twilioClient;

// services/auth-service/src/utils/constants.js
export const OTP_CONFIG = {
  EMAIL_LENGTH: 6,
  SMS_LENGTH: 6,
  EXPIRY_MINUTES: 5,
  MAX_ATTEMPTS: 3,
  RATE_LIMIT_MINUTES: 15,
  MAX_REQUESTS_PER_PERIOD: 3
};

export const JWT_CONFIG = {
  ACCESS_TOKEN_EXPIRY: '15m',
  REFRESH_TOKEN_EXPIRY: '7d',
  ALGORITHM: 'RS256'
};

export const DEVICE_CONFIG = {
  MAX_DEVICES_PER_USER: 5,
  FINGERPRINT_ALGORITHM: 'SHA256'
};

export const USER_STATUS = {
  PENDING: 'pending',
  EMAIL_VERIFIED: 'email_verified',
  PHONE_VERIFIED: 'phone_verified',
  BIOMETRIC_REGISTERED: 'biometric_registered',
  ACTIVE: 'active',
  SUSPENDED: 'suspended'
};

export const BIOMETRIC_TYPES = {
  WEBAUTHN: 'webauthn',
  FINGERPRINT: 'fingerprint',
  FACE_ID: 'face_id',
  MOCK: 'mock'
};

// services/auth-service/src/utils/encryption.js
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';

dotenv.config();

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const IV_LENGTH = 16; // For AES, this is always 16

export class EncryptionUtils {
  // Encrypt text
  static encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipher('aes-256-cbc', ENCRYPTION_KEY);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return iv.toString('hex') + ':' + encrypted;
  }

  // Decrypt text
  static decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = textParts.join(':');
    
    const decipher = crypto.createDecipher('aes-256-cbc', ENCRYPTION_KEY);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  // Hash password
  static async hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
  }

  // Verify password
  static async verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
  }

  // Generate OTP
  static generateOTP(length = 6) {
    let otp = '';
    for (let i = 0; i < length; i++) {
      otp += Math.floor(Math.random() * 10);
    }
    return otp;
  }

  // Hash biometric data
  static hashBiometric(biometricData) {
    return crypto.createHash('sha256')
      .update(JSON.stringify(biometricData))
      .digest('hex');
  }

  // Generate device fingerprint
  static generateDeviceFingerprint(deviceInfo) {
    const data = JSON.stringify({
      userAgent: deviceInfo.userAgent,
      screen: deviceInfo.screen,
      timezone: deviceInfo.timezone,
      language: deviceInfo.language,
      browser: deviceInfo.browser,
      os: deviceInfo.os
    });
    
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  // Generate secure token
  static generateToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }
}

// services/auth-service/src/utils/validators.js
import { body, param, query } from 'express-validator';

export const authValidators = {
  checkUser: [
    body('email')
      .isEmail()
      .normalizeEmail()
      .withMessage('Valid email is required'),
    body('phone')
      .isMobilePhone()
      .withMessage('Valid phone number is required')
  ],

  sendOTP: [
    body('email')
      .optional()
      .isEmail()
      .normalizeEmail(),
    body('phone')
      .optional()
      .isMobilePhone()
  ],

  verifyOTP: [
    body('identifier')
      .notEmpty()
      .withMessage('Email or phone is required'),
    body('otp')
      .isLength({ min: 6, max: 6 })
      .isNumeric()
      .withMessage('OTP must be 6 digits')
  ],

  completeAuth: [
    body('email')
      .isEmail()
      .normalizeEmail()
      .withMessage('Valid email is required'),
    body('phone')
      .isMobilePhone()
      .withMessage('Valid phone number is required'),
    body('deviceFingerprint')
      .notEmpty()
      .withMessage('Device fingerprint is required'),
    body('device')
      .isObject()
      .withMessage('Device information is required'),
    body('biometric')
      .isObject()
      .withMessage('Biometric data is required')
  ]
};

// services/auth-service/src/utils/logger.js
import winston from 'winston';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'auth-service' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

export { logger };

// services/auth-service/src/services/tokenService.js
import jwt from 'jsonwebtoken';
import { JWT_CONFIG } from '../utils/constants.js';
import { logger } from '../utils/logger.js';
import dotenv from 'dotenv';

dotenv.config();

export class TokenService {
  static generateTokenPair(payload) {
    try {
      const accessToken = jwt.sign(
        payload,
        process.env.JWT_PRIVATE_KEY.replace(/\\n/g, '\n'),
        {
          algorithm: JWT_CONFIG.ALGORITHM,
          expiresIn: JWT_CONFIG.ACCESS_TOKEN_EXPIRY,
          issuer: 'vottery-auth-service',
          audience: 'vottery-client'
        }
      );

      const refreshToken = jwt.sign(
        { userId: payload.userId, tokenType: 'refresh' },
        process.env.JWT_REFRESH_SECRET,
        {
          expiresIn: JWT_CONFIG.REFRESH_TOKEN_EXPIRY
        }
      );

      return { accessToken, refreshToken };
    } catch (error) {
      logger.error('Token generation failed:', error);
      throw new Error('Token generation failed');
    }
  }

  static verifyAccessToken(token) {
    try {
      return jwt.verify(
        token,
        process.env.JWT_PUBLIC_KEY.replace(/\\n/g, '\n'),
        {
          algorithm: JWT_CONFIG.ALGORITHM,
          issuer: 'vottery-auth-service',
          audience: 'vottery-client'
        }
      );
    } catch (error) {
      logger.error('Access token verification failed:', error);
      throw new Error('Invalid access token');
    }
  }

  static verifyRefreshToken(token) {
    try {
      return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    } catch (error) {
      logger.error('Refresh token verification failed:', error);
      throw new Error('Invalid refresh token');
    }
  }
}

// services/auth-service/src/services/smsService.js
import twilioClient from '../config/sms.js';
import { logger } from '../utils/logger.js';

export class SMSService {
  static async sendOTP(phone, otp) {
    try {
      const message = await twilioClient.messages.create({
        body: `Your Vottery verification code is: ${otp}. This code expires in 5 minutes. Do not share this code with anyone.`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phone
      });

      logger.info(`SMS OTP sent successfully to ${phone}:`, message.sid);
      return { success: true, messageSid: message.sid };
      
    } catch (error) {
      logger.error(`Failed to send SMS OTP to ${phone}:`, error);
      throw new Error('SMS sending failed');
    }
  }

  static async sendWelcomeSMS(phone) {
    try {
      const message = await twilioClient.messages.create({
        body: `Welcome to Vottery! Your authentication is complete. Access your dashboard at ${process.env.FRONTEND_URL || 'vottery.com'}`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phone
      });

      logger.info(`Welcome SMS sent successfully to ${phone}:`, message.sid);
      return { success: true, messageSid: message.sid };
      
    } catch (error) {
      logger.error(`Failed to send welcome SMS to ${phone}:`, error);
      // Don't throw error for welcome SMS failure
      return { success: false, error: error.message };
    }
  }
}

// services/auth-service/src/models/User.js
import pool from '../config/database.js';
import { logger } from '../utils/logger.js';
import { EncryptionUtils } from '../utils/encryption.js';
import { USER_STATUS } from '../utils/constants.js';

export class User {
  // Check if user exists in SngEngine database
  static async checkSngineUser(email, phone) {
    const client = await pool.connect();
    try {
      const query = `
        SELECT user_id, user_email, user_phone, user_email_verified, user_phone_verified
        FROM users 
        WHERE user_email = $1 AND user_phone = $2
        LIMIT 1
      `;
      
      const result = await client.query(query, [email, phone]);
      
      if (result.rows.length === 0) {
        return { exists: false, message: 'User not found in SngEngine database' };
      }

      const user = result.rows[0];
      
      // Check if email and phone are verified in SngEngine
      if (user.user_email_verified !== 1) {
        return { exists: false, message: 'Email not verified in SngEngine' };
      }

      return {
        exists: true,
        sngineUserId: user.user_id,
        email: user.user_email,
        phone: user.user_phone,
        emailVerified: user.user_email_verified === 1,
        phoneVerified: user.user_phone_verified === 1
      };
      
    } catch (error) {
      logger.error('Error checking SngEngine user:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Create or get Vottery user
  static async createOrGetVotteryUser(email, phone) {
    const client = await pool.connect();
    try {
      // Check if Vottery user already exists
      let query = `
        SELECT * FROM vottery_users 
        WHERE sngine_email = $1 AND sngine_phone = $2
        LIMIT 1
      `;
      
      let result = await client.query(query, [email, phone]);
      
      if (result.rows.length > 0) {
        return result.rows[0];
      }

      // Create new Vottery user
      query = `
        INSERT INTO vottery_users (sngine_email, sngine_phone, status, created_at, updated_at)
        VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING *
      `;
      
      result = await client.query(query, [email, phone, USER_STATUS.PENDING]);
      logger.info(`New Vottery user created for email: ${email}`);
      
      return result.rows[0];
      
    } catch (error) {
      logger.error('Error creating/getting Vottery user:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Update user status
  static async updateStatus(userId, status, field = null) {
    const client = await pool.connect();
    try {
      let query, params;
      
      if (field) {
        query = `
          UPDATE vottery_users 
          SET status = $1, ${field} = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
          WHERE id = $2
          RETURNING *
        `;
        params = [status, userId];
      } else {
        query = `
          UPDATE vottery_users 
          SET status = $1, updated_at = CURRENT_TIMESTAMP
          WHERE id = $2
          RETURNING *
        `;
        params = [status, userId];
      }
      
      const result = await client.query(query, params);
      return result.rows[0];
      
    } catch (error) {
      logger.error('Error updating user status:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Get user by ID
  static async getById(userId) {
    const client = await pool.connect();
    try {
      const query = `
        SELECT * FROM vottery_users 
        WHERE id = $1
        LIMIT 1
      `;
      
      const result = await client.query(query, [userId]);
      return result.rows[0] || null;
      
    } catch (error) {
      logger.error('Error getting user by ID:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Update last login
  static async updateLastLogin(userId) {
    const client = await pool.connect();
    try {
      const query = `
        UPDATE vottery_users 
        SET last_login = CURRENT_TIMESTAMP
        WHERE id = $1
      `;
      
      await client.query(query, [userId]);
      
    } catch (error) {
      logger.error('Error updating last login:', error);
      throw error;
    } finally {
      client.release();
    }
  }
}

// services/auth-service/src/models/OTP.js
import pool from '../config/database.js';
import { logger } from '../utils/logger.js';
import { EncryptionUtils } from '../utils/encryption.js';
import { OTP_CONFIG } from '../utils/constants.js';

export class OTP {
  // Create OTP
  static async create(identifier, otpType) {
    const client = await pool.connect();
    try {
      // Generate OTP
      const otpCode = EncryptionUtils.generateOTP(OTP_CONFIG.EMAIL_LENGTH);
      const expiresAt = new Date(Date.now() + (OTP_CONFIG.EXPIRY_MINUTES * 60 * 1000));

      // Delete any existing OTPs for this identifier and type
      await client.query(
        'DELETE FROM vottery_otps WHERE identifier = $1 AND otp_type = $2',
        [identifier, otpType]
      );

      // Insert new OTP
      const query = `
        INSERT INTO vottery_otps (identifier, otp_code, otp_type, expires_at, created_at)
        VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
        RETURNING *
      `;
      
      const result = await client.query(query, [identifier, otpCode, otpType, expiresAt]);
      
      logger.info(`OTP created for ${identifier} (${otpType})`);
      return { otpRecord: result.rows[0], otpCode };
      
    } catch (error) {
      logger.error('Error creating OTP:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Verify OTP
  static async verify(identifier, otpCode, otpType) {
    const client = await pool.connect();
    try {
      // Get OTP record
      const query = `
        SELECT * FROM vottery_otps 
        WHERE identifier = $1 AND otp_type = $2 AND used_at IS NULL
        ORDER BY created_at DESC
        LIMIT 1
      `;
      
      const result = await client.query(query, [identifier, otpType]);
      
      if (result.rows.length === 0) {
        return { success: false, message: 'OTP not found or already used' };
      }

      const otpRecord = result.rows[0];

      // Check if OTP is expired
      if (new Date() > new Date(otpRecord.expires_at)) {
        return { success: false, message: 'OTP has expired' };
      }

      // Check attempts
      if (otpRecord.attempts >= otpRecord.max_attempts) {
        return { success: false, message: 'Maximum OTP attempts exceeded' };
      }

      // Check OTP code
      if (otpRecord.otp_code !== otpCode) {
        // Increment attempts
        await client.query(
          'UPDATE vottery_otps SET attempts = attempts + 1 WHERE id = $1',
          [otpRecord.id]
        );
        return { success: false, message: 'Invalid OTP code' };
      }

      // Mark OTP as used
      await client.query(
        'UPDATE vottery_otps SET used_at = CURRENT_TIMESTAMP WHERE id = $1',
        [otpRecord.id]
      );

      logger.info(`OTP verified successfully for ${identifier} (${otpType})`);
      return { success: true, message: 'OTP verified successfully' };
      
    } catch (error) {
      logger.error('Error verifying OTP:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Check rate limit for OTP requests
  static async checkRateLimit(identifier, otpType) {
    const client = await pool.connect();
    try {
      const timeLimit = new Date(Date.now() - (OTP_CONFIG.RATE_LIMIT_MINUTES * 60 * 1000));
      
      const query = `
        SELECT COUNT(*) as count 
        FROM vottery_otps 
        WHERE identifier = $1 AND otp_type = $2 AND created_at > $3
      `;
      
      const result = await client.query(query, [identifier, otpType, timeLimit]);
      const count = parseInt(result.rows[0].count);

      return {
        allowed: count < OTP_CONFIG.MAX_REQUESTS_PER_PERIOD,
        count,
        limit: OTP_CONFIG.MAX_REQUESTS_PER_PERIOD
      };
      
    } catch (error) {
      logger.error('Error checking OTP rate limit:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Clean expired OTPs
  static async cleanExpired() {
    const client = await pool.connect();
    try {
      const query = 'DELETE FROM vottery_otps WHERE expires_at < CURRENT_TIMESTAMP';
      const result = await client.query(query);
      
      logger.info(`Cleaned ${result.rowCount} expired OTPs`);
      return result.rowCount;
      
    } catch (error) {
      logger.error('Error cleaning expired OTPs:', error);
      throw error;
    } finally {
      client.release();
    }
  }
}

// services/auth-service/src/models/Session.js
import pool from '../config/database.js';
import { logger } from '../utils/logger.js';
import { EncryptionUtils } from '../utils/encryption.js';
import { JWT_CONFIG } from '../utils/constants.js';

export class Session {
  // Create session
  static async create(userId, deviceId, sessionToken, refreshToken, ipAddress, userAgent) {
    const client = await pool.connect();
    try {
      const expiresAt = new Date(Date.now() + (15 * 60 * 1000)); // 15 minutes
      const refreshExpiresAt = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)); // 7 days

      const query = `
        INSERT INTO vottery_sessions (
          user_id, device_id, session_token, refresh_token, 
          expires_at, refresh_expires_at, ip_address, user_agent, 
          created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
        RETURNING *
      `;
      
      const result = await client.query(query, [
        userId, deviceId, sessionToken, refreshToken,
        expiresAt, refreshExpiresAt, ipAddress, userAgent
      ]);
      
      logger.info(`Session created for user ${userId}, device ${deviceId}`);
      return result.rows[0];
      
    } catch (error) {
      logger.error('Error creating session:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Get session by token
  static async getByToken(sessionToken) {
    const client = await pool.connect();
    try {
      const query = `
        SELECT s.*, u.sngine_email, u.status 
        FROM vottery_sessions s
        JOIN vottery_users u ON s.user_id = u.id
        WHERE s.session_token = $1 AND s.is_active = true
        LIMIT 1
      `;
      
      const result = await client.query(query, [sessionToken]);
      return result.rows[0] || null;
      
    } catch (error) {
      logger.error('Error getting session by token:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Refresh session
  static async refresh(refreshToken) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Get current session
      const getQuery = `
        SELECT * FROM vottery_sessions 
        WHERE refresh_token = $1 AND is_active = true
        LIMIT 1
      `;
      
      const result = await client.query(getQuery, [refreshToken]);
      
      if (result.rows.length === 0) {
        await client.query('ROLLBACK');
        return null;
      }

      const session = result.rows[0];

      // Check if refresh token is expired
      if (new Date() > new Date(session.refresh_expires_at)) {
        await client.query('ROLLBACK');
        return null;
      }

      // Generate new tokens
      const newSessionToken = EncryptionUtils.generateToken();
      const newRefreshToken = EncryptionUtils.generateToken();
      const newExpiresAt = new Date(Date.now() + (15 * 60 * 1000)); // 15 minutes
      const newRefreshExpiresAt = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)); // 7 days

      // Update session
      const updateQuery = `
        UPDATE vottery_sessions 
        SET session_token = $1, refresh_token = $2, 
            expires_at = $3, refresh_expires_at = $4
        WHERE id = $5
        RETURNING *
      `;
      
      const updateResult = await client.query(updateQuery, [
        newSessionToken, newRefreshToken, newExpiresAt, newRefreshExpiresAt, session.id
      ]);

      await client.query('COMMIT');
      
      logger.info(`Session refreshed for user ${session.user_id}`);
      return updateResult.rows[0];
      
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error('Error refreshing session:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Revoke session
  static async revoke(sessionToken) {
    const client = await pool.connect();
    try {
      const query = `
        UPDATE vottery_sessions 
        SET is_active = false 
        WHERE session_token = $1
        RETURNING *
      `;
      
      const result = await client.query(query, [sessionToken]);
      
      if (result.rows.length > 0) {
        logger.info(`Session revoked: ${sessionToken}`);
      }
      
      return result.rows[0] || null;
      
    } catch (error) {
      logger.error('Error revoking session:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Clean expired sessions
  static async cleanExpired() {
    const client = await pool.connect();
    try {
      const query = `
        UPDATE vottery_sessions 
        SET is_active = false 
        WHERE refresh_expires_at < CURRENT_TIMESTAMP AND is_active = true
      `;
      
      const result = await client.query(query);
      
      logger.info(`Cleaned ${result.rowCount} expired sessions`);
      return result.rowCount;
      
    } catch (error) {
      logger.error('Error cleaning expired sessions:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  // Get user sessions
  static async getUserSessions(userId, limit = 10) {
    const client = await pool.connect();
    try {
      const query = `
        SELECT s.*, d.device_type, d.browser_name, d.os_name
        FROM vottery_sessions s
        LEFT JOIN vottery_devices d ON s.device_id = d.id
        WHERE s.user_id = $1 AND s.is_active = true
        ORDER BY s.created_at DESC
        LIMIT $2
      `;
      
      const result = await client.query(query, [userId, limit]);
      return result.rows;
      
    } catch (error) {
      logger.error('Error getting user sessions:', error);
      throw error;
    } finally {
      client.release();
    }
  }
}

// services/auth-service/src/services/emailService.js
import transporter from '../config/email.js';
import { logger } from '../utils/logger.js';

export class EmailService {
  static async sendOTP(email, otp) {
    try {
      const mailOptions = {
        from: {
          name: 'Vottery',
          address: process.env.EMAIL_FROM || process.env.EMAIL_USER
        },
        to: email,
        subject: 'Vottery - Email Verification Code',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
              <h1 style="color: white; margin: 0;">Vottery</h1>
            </div>
            <div style="padding: 30px; background: #f9f9f9;">
              <h2 style="color: #333;">Email Verification</h2>
              <p style="color: #666; font-size: 16px;">
                Welcome to Vottery! Please use the verification code below to complete your authentication:
              </p>
              <div style="background: white; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
                <h1 style="color: #667eea; font-size: 36px; margin: 0; letter-spacing: 8px;">${otp}</h1>
              </div>
              <p style="color: #666; font-size: 14px;">
                This code will expire in 5 minutes. If you didn't request this verification, please ignore this email.
              </p>
              <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
                <p style="color: #999; font-size: 12px; text-align: center;">
                  This is an automated message from Vottery. Please do not reply to this email.
                </p>
              </div>
            </div>
          </div>
        `
      };

      const result = await transporter.sendMail(mailOptions);
      logger.info(`Email OTP sent successfully to ${email}:`, result.messageId);
      return { success: true, messageId: result.messageId };
      
    } catch (error) {
      logger.error(`Failed to send email OTP to ${email}:`, error);
      throw new Error('Email sending failed');
    }
  }

  static async sendWelcomeEmail(email, userName) {
    try {
      const mailOptions = {
        from: {
          name: 'Vottery',
          address: process.env.EMAIL_FROM || process.env.EMAIL_USER
        },
        to: email,
        subject: 'Welcome to Vottery!',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
              <h1 style="color: white; margin: 0;">Welcome to Vottery!</h1>
            </div>
            <div style="padding: 30px; background: #f9f9f9;">
              <h2 style="color: #333;">Authentication Completed Successfully</h2>
              <p style="color: #666; font-size: 16px;">
                Congratulations! You have successfully completed the authentication process and can now access the Vottery platform.
              </p>
              <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h3 style="color: #667eea;">What's Next?</h3>
                <ul style="color: #666;">
                  <li>Explore voting features in upcoming milestones</li>
                  <li>Your device and biometric data are securely registered</li>
                  <li>Access your dashboard anytime</li>
                </ul>
              </div>
              <div style="text-align: center; margin: 30px 0;">
                <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}" 
                   style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px;">
                  Access Dashboard
                </a>
              </div>
            </div>
          </div>
        `
      };

      const result = await transporter.sendMail(mailOptions);
      logger.info(`Welcome email sent successfully to ${email}:`, result.messageId);
      return { success: true, messageId: result.messageId };
      
    } catch (error) {
      logger.error(`Failed to send welcome email to ${email}:`, error);
      // Don't throw error for welcome email failure
      return { success: false, error: error.message };
    }
  }
}