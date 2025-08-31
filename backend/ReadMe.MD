# Vottery Milestone-1 Backend Architecture & Implementation Plan

## Backend Folder Structure

```
vottery-backend/
├── services/
│   ├── auth-service/
│   │   ├── src/
│   │   │   ├── controllers/
│   │   │   │   ├── authController.js
│   │   │   │   └── otpController.js
│   │   │   ├── middleware/
│   │   │   │   ├── validation.js
│   │   │   │   ├── rateLimit.js
│   │   │   │   └── security.js
│   │   │   ├── models/
│   │   │   │   ├── User.js
│   │   │   │   ├── OTP.js
│   │   │   │   └── Session.js
│   │   │   ├── services/
│   │   │   │   ├── emailService.js
│   │   │   │   ├── smsService.js
│   │   │   │   └── tokenService.js
│   │   │   ├── utils/
│   │   │   │   ├── encryption.js
│   │   │   │   ├── validators.js
│   │   │   │   └── constants.js
│   │   │   ├── routes/
│   │   │   │   └── authRoutes.js
│   │   │   ├── config/
│   │   │   │   ├── database.js
│   │   │   │   ├── email.js
│   │   │   │   └── sms.js
│   │   │   └── app.js
│   │   ├── package.json
│   │   ├── Dockerfile
│   │   └── .env.example
│   │
│   ├── biometric-service/
│   │   ├── src/
│   │   │   ├── controllers/
│   │   │   │   └── biometricController.js
│   │   │   ├── models/
│   │   │   │   ├── Biometric.js
│   │   │   │   └── Device.js
│   │   │   ├── services/
│   │   │   │   ├── biometricService.js
│   │   │   │   └── deviceService.js
│   │   │   ├── utils/
│   │   │   │   ├── biometricUtils.js
│   │   │   │   └── deviceUtils.js
│   │   │   ├── routes/
│   │   │   │   └── biometricRoutes.js
│   │   │   └── app.js
│   │   ├── package.json
│   │   └── Dockerfile
│   │
│   └── user-service/
│       ├── src/
│       │   ├── controllers/
│       │   │   └── userController.js
│       │   ├── models/
│       │   │   └── VotteryUser.js
│       │   ├── services/
│       │   │   └── userService.js
│       │   ├── routes/
│       │   │   └── userRoutes.js
│       │   └── app.js
│       ├── package.json
│       └── Dockerfile
│
├── shared/
│   ├── database/
│   │   ├── config.js
│   │   ├── connection.js
│   │   └── migrations/
│   │       ├── 001_create_vottery_users.sql
│   │       ├── 002_create_vottery_devices.sql
│   │       ├── 003_create_vottery_biometrics.sql
│   │       ├── 004_create_vottery_sessions.sql
│   │       └── 005_create_vottery_audit_logs.sql
│   ├── middleware/
│   │   ├── cors.js
│   │   ├── helmet.js
│   │   └── logger.js
│   └── utils/
│       ├── encryption.js
│       ├── jwt.js
│       └── logger.js
│
├── gateway/
│   ├── src/
│   │   ├── middleware/
│   │   │   ├── auth.js
│   │   │   ├── proxy.js
│   │   │   └── rateLimit.js
│   │   ├── routes/
│   │   │   └── index.js
│   │   ├── config/
│   │   │   └── services.js
│   │   └── app.js
│   ├── package.json
│   └── Dockerfile
│
├── docker-compose.yml
├── docker-compose.dev.yml
├── nginx.conf
└── README.md
```

## Microservices Architecture Plan

### 1. Authentication Service (Port: 3001)
**Responsibilities:**
- Email and phone verification against existing SngEngine database
- OTP generation and verification (Email via Nodemailer, SMS via Twilio)
- JWT token management with refresh rotation
- Session management
- Rate limiting and security

**Key Features:**
- Direct PostgreSQL queries to existing `users` table (no sngine modifications)
- Separate `vottery_` prefixed tables for Vottery-specific data
- Email OTP via Nodemailer (SMTP/SendGrid)
- SMS OTP via Twilio API
- Encrypted OTP storage with expiration
- JWT with refresh token rotation
- Device-based session tracking

### 2. Biometric Service (Port: 3002)
**Responsibilities:**
- Biometric data capture and processing
- Device registration and fingerprinting
- Cross-platform biometric support (Web, iOS, Android)
- Encrypted biometric hash storage
- Device capability detection

**Key Features:**
- WebAuthn integration for web platforms
- Device fingerprinting using multiple parameters
- Encrypted biometric data storage
- Device type detection and registration
- IP tracking and geo-location
- Multiple device support per user

### 3. User Service (Port: 3003)
**Responsibilities:**
- Vottery user profile management
- Device management
- Security settings
- Dashboard data aggregation

**Key Features:**
- Links to existing SngEngine user via email/phone
- Manages Vottery-specific user data
- Device list and management
- Security audit logs
- User preferences and settings

### 4. API Gateway (Port: 3000)
**Responsibilities:**
- Route requests to appropriate microservices
- Authentication middleware
- CORS handling
- Rate limiting
- Load balancing

## Database Schema (PostgreSQL)

### Existing SngEngine Table (READ ONLY)
```sql
-- users table (existing - no modifications)
-- Access via email and user_phone fields
```

### New Vottery Tables

```sql
-- vottery_users
CREATE TABLE vottery_users (
    id SERIAL PRIMARY KEY,
    sngine_email VARCHAR(255) NOT NULL UNIQUE,
    sngine_phone VARCHAR(50) NOT NULL,
    email_verified_at TIMESTAMP,
    phone_verified_at TIMESTAMP,
    biometric_registered_at TIMESTAMP,
    status ENUM('pending', 'verified', 'active', 'suspended') DEFAULT 'pending',
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (sngine_email),
    INDEX idx_phone (sngine_phone)
);

-- vottery_devices
CREATE TABLE vottery_devices (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    device_fingerprint VARCHAR(255) NOT NULL UNIQUE,
    device_type VARCHAR(50) NOT NULL,
    browser_name VARCHAR(100),
    browser_version VARCHAR(50),
    os_name VARCHAR(100),
    os_version VARCHAR(50),
    screen_info JSON,
    ip_address INET,
    location JSON,
    is_active BOOLEAN DEFAULT true,
    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES vottery_users(id) ON DELETE CASCADE,
    INDEX idx_user_device (user_id, device_fingerprint),
    INDEX idx_fingerprint (device_fingerprint)
);

-- vottery_biometrics
CREATE TABLE vottery_biometrics (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    device_id INT NOT NULL,
    biometric_type VARCHAR(50) NOT NULL,
    biometric_hash TEXT NOT NULL,
    public_key TEXT,
    credential_id TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES vottery_users(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES vottery_devices(id) ON DELETE CASCADE,
    UNIQUE KEY uk_user_device_type (user_id, device_id, biometric_type)
);

-- vottery_sessions
CREATE TABLE vottery_sessions (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    device_id INT NOT NULL,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    refresh_token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    refresh_expires_at TIMESTAMP NOT NULL,
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES vottery_users(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES vottery_devices(id) ON DELETE CASCADE,
    INDEX idx_session_token (session_token),
    INDEX idx_refresh_token (refresh_token),
    INDEX idx_user_sessions (user_id, is_active)
);

-- vottery_otps
CREATE TABLE vottery_otps (
    id SERIAL PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL, -- email or phone
    otp_code VARCHAR(10) NOT NULL,
    otp_type ENUM('email', 'sms') NOT NULL,
    attempts INT DEFAULT 0,
    max_attempts INT DEFAULT 3,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_identifier_type (identifier, otp_type),
    INDEX idx_expires (expires_at)
);

-- vottery_audit_logs
CREATE TABLE vottery_audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INT,
    device_id INT,
    action VARCHAR(100) NOT NULL,
    details JSON,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_actions (user_id, action),
    INDEX idx_created_at (created_at)
);
```

## Security Implementation

### 1. Data Encryption
- **At Rest**: AES-256 encryption for sensitive data
- **In Transit**: TLS 1.3 for all communications
- **Biometric Data**: SHA-256 hashing with salt
- **Database**: Encrypted fields for PII data

### 2. Authentication Flow
1. **Frontend validates referrer** (document.referrer check)
2. **Backend verifies email/phone** against SngEngine database
3. **OTP generation** with 5-minute expiration
4. **Email OTP** via Nodemailer → **Phone OTP** via Twilio
5. **Biometric capture** → **Device registration**
6. **JWT token generation** with device binding

### 3. Rate Limiting & Security
- **OTP requests**: 3 per 15 minutes per identifier
- **Login attempts**: 5 per 15 minutes per IP
- **API calls**: 100 per minute per IP
- **Device registration**: 5 devices per user maximum

## Implementation Strategy

### Phase 1: Core Authentication (Week 1)
1. Setup PostgreSQL with Vottery tables
2. Implement Authentication Service
3. Configure Nodemailer and Twilio
4. OTP generation and verification

### Phase 2: Biometric Integration (Week 2)
1. Implement Biometric Service
2. Device fingerprinting and registration
3. WebAuthn integration
4. Cross-platform biometric support

### Phase 3: Integration & Security (Week 3)
1. API Gateway setup
2. JWT token management
3. Session management
4. Security middleware and rate limiting

### Phase 4: Testing & Optimization (Week 4)
1. Comprehensive testing
2. Performance optimization
3. Security audit
4. Documentation

## Technology Stack
- **Runtime**: Node.js 20+ with ES6 modules
- **Framework**: Express.js
- **Database**: PostgreSQL 15+ with connection pooling
- **ORM**: Pure SQL queries (no ORM for performance)
- **Email**: Nodemailer with SMTP/SendGrid
- **SMS**: Twilio API
- **Encryption**: Node.js Crypto API (native)
- **Authentication**: JWT with RS256 signing
- **Containerization**: Docker with multi-stage builds
- **Orchestration**: Docker Compose for development

This architecture ensures maximum security, scalability, and compliance with Milestone-1 requirements while preparing for Milestone-4 features.



THIS IS THE link backend link
https://claude.ai/public/artifacts/0ae6cc20-40b2-4ae2-bcf6-353dd7daf04a