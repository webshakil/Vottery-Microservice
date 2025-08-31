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
Microservices Architecture Plan
1. Authentication Service (Port: 3001)
Responsibilities:

Email and phone verification against existing SngEngine database
OTP generation and verification (Email via Nodemailer, SMS via Twilio)
JWT token management with refresh rotation
Session management
Rate limiting and security

Key Features:

Direct PostgreSQL queries to existing users table (no sngine modifications)
Separate vottery_ prefixed tables for Vottery-specific data
Email OTP via Nodemailer (SMTP/SendGrid)
SMS OTP via Twilio API
Encrypted OTP storage with expiration
JWT with refresh token rotation
Device-based session tracking

2. Biometric Service (Port: 3002)
Responsibilities:

Biometric data capture and processing
Device registration and fingerprinting
Cross-platform biometric support (Web, iOS, Android)
Encrypted biometric hash storage
Device capability detection

Key Features:

WebAuthn integration for web platforms
Device fingerprinting using multiple parameters
Encrypted biometric data storage
Device type detection and registration
IP tracking and geo-location
Multiple device support per user

3. User Service (Port: 3003)
Responsibilities:

Vottery user profile management
Device management
Security settings
Dashboard data aggregation

Key Features:

Links to existing SngEngine user via email/phone
Manages Vottery-specific user data
Device list and management
Security audit logs
User preferences and settings

4. API Gateway (Port: 3000)
Responsibilities:

Route requests to appropriate microservices
Authentication middleware
CORS handling
Rate limiting
Load balancing

Database Schema (PostgreSQL)
Existing SngEngine Table (READ ONLY)


backend solution
https://claude.ai/public/artifacts/0ae6cc20-40b2-4ae2-bcf6-353dd7daf04a