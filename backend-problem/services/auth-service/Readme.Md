# Vottery Backend Microservices Architecture - Milestone 1

## Microservices Structure

### 1. Authentication Service (Port: 3001)
**Purpose**: Handle OTP verification, biometric validation, and JWT token management
**Responsibilities**:
- Email OTP via Nodemailer
- SMS OTP via Twilio
- Biometric data capture and validation
- JWT token generation and refresh
- Device fingerprinting and registration
- Session management

### 2. User Management Service (Port: 3002)
**Purpose**: Manage user profiles, roles, and demographic data
**Responsibilities**:
- User profile creation and updates
- Role-based access control (RBAC)
- Demographics tracking and storage
- User activity logging
- Encrypted user data management

### 3. Security & Encryption Service (Port: 3003)
**Purpose**: Handle all cryptographic operations and security middleware
**Responsibilities**:
- End-to-end encryption (RSA/ElGamal)
- Digital signature generation/verification
- Cryptographic key management
- Input validation and sanitization
- Rate limiting and DDoS protection
- OWASP security compliance

### 4. Device & Session Service (Port: 3004)
**Purpose**: Manage device information, IP tracking, and session control
**Responsibilities**:
- Device type detection and registration
- IP address tracking and geolocation
- Device fingerprinting storage
- Session management across devices
- Device compatibility validation

## Project Folder Structure

```
vottery-backend/
├── services/
│   ├── authentication-service/
│   │   ├── src/
│   │   │   ├── controllers/
│   │   │   │   ├── otpController.js
│   │   │   │   ├── biometricController.js
│   │   │   │   └── authController.js
│   │   │   ├── middleware/
│   │   │   │   ├── authMiddleware.js
│   │   │   │   ├── rateLimitMiddleware.js
│   │   │   │   └── validationMiddleware.js
│   │   │   ├── services/
│   │   │   │   ├── otpService.js
│   │   │   │   ├── emailService.js
│   │   │   │   ├── smsService.js
│   │   │   │   └── biometricService.js
│   │   │   ├── models/
│   │   │   │   ├── OtpSession.js
│   │   │   │   └── BiometricData.js
│   │   │   ├── utils/
│   │   │   │   ├── jwtUtils.js
│   │   │   │   ├── cryptoUtils.js
│   │   │   │   └── deviceUtils.js
│   │   │   ├── routes/
│   │   │   │   ├── authRoutes.js
│   │   │   │   ├── otpRoutes.js
│   │   │   │   └── biometricRoutes.js
│   │   │   ├── config/
│   │   │   │   ├── database.js
│   │   │   │   ├── nodemailer.js
│   │   │   │   └── twilio.js
│   │   │   └── app.js
│   │   ├── package.json
│   │   └── Dockerfile
│   │
│   ├── user-management-service/
│   │   ├── src/
│   │   │   ├── controllers/
│   │   │   │   ├── userController.js
│   │   │   │   ├── profileController.js
│   │   │   │   └── roleController.js
│   │   │   ├── middleware/
│   │   │   │   ├── rbacMiddleware.js
│   │   │   │   ├── encryptionMiddleware.js
│   │   │   │   └── auditMiddleware.js
│   │   │   ├── services/
│   │   │   │   ├── userService.js
│   │   │   │   ├── profileService.js
│   │   │   │   └── demographicsService.js
│   │   │   ├── models/
│   │   │   │   ├── User.js
│   │   │   │   ├── UserProfile.js
│   │   │   │   ├── UserRole.js
│   │   │   │   └── Demographics.js
│   │   │   ├── utils/
│   │   │   │   ├── encryptionUtils.js
│   │   │   │   └── validationUtils.js
│   │   │   ├── routes/
│   │   │   │   ├── userRoutes.js
│   │   │   │   ├── profileRoutes.js
│   │   │   │   └── roleRoutes.js
│   │   │   ├── config/
│   │   │   │   └── database.js
│   │   │   └── app.js
│   │   ├── package.json
│   │   └── Dockerfile
│   │
│   ├── security-encryption-service/
│   │   ├── src/
│   │   │   ├── controllers/
│   │   │   │   ├── encryptionController.js
│   │   │   │   ├── keyController.js
│   │   │   │   └── signatureController.js
│   │   │   ├── middleware/
│   │   │   │   ├── securityMiddleware.js
│   │   │   │   ├── corsMiddleware.js
│   │   │   │   └── sanitizationMiddleware.js
│   │   │   ├── services/
│   │   │   │   ├── encryptionService.js
│   │   │   │   ├── keyManagementService.js
│   │   │   │   └── digitalSignatureService.js
│   │   │   ├── models/
│   │   │   │   ├── EncryptionKey.js
│   │   │   │   └── SecurityAudit.js
│   │   │   ├── utils/
│   │   │   │   ├── rsaUtils.js
│   │   │   │   ├── elgamalUtils.js
│   │   │   │   └── hashUtils.js
│   │   │   ├── routes/
│   │   │   │   ├── encryptionRoutes.js
│   │   │   │   └── securityRoutes.js
│   │   │   ├── config/
│   │   │   │   └── security.js
│   │   │   └── app.js
│   │   ├── package.json
│   │   └── Dockerfile
│   │
│   └── device-session-service/
│       ├── src/
│       │   ├── controllers/
│       │   │   ├── deviceController.js
│       │   │   ├── sessionController.js
│       │   │   └── trackingController.js
│       │   ├── middleware/
│       │   │   ├── deviceMiddleware.js
│       │   │   └── sessionMiddleware.js
│       │   ├── services/
│       │   │   ├── deviceService.js
│       │   │   ├── sessionService.js
│       │   │   ├── geoLocationService.js
│       │   │   └── fingerprintService.js
│       │   ├── models/
│       │   │   ├── Device.js
│       │   │   ├── Session.js
│       │   │   └── DeviceFingerprint.js
│       │   ├── utils/
│       │   │   ├── deviceDetection.js
│       │   │   ├── ipUtils.js
│       │   │   └── sessionUtils.js
│       │   ├── routes/
│       │   │   ├── deviceRoutes.js
│       │   │   └── sessionRoutes.js
│       │   ├── config/
│       │   │   └── database.js
│       │   └── app.js
│       ├── package.json
│       └── Dockerfile
├── shared/
│   ├── database/
│   │   ├── migrations/
│   │   ├── seeds/
│   │   └── connection.js
│   ├── utils/
│   │   ├── logger.js
│   │   ├── constants.js
│   │   └── helpers.js
│   └── middleware/
│       ├── corsMiddleware.js
│       └── errorHandler.js
├── gateway/
│   ├── src/
│   │   ├── routes/
│   │   │   └── index.js
│   │   ├── middleware/
│   │   │   ├── proxy.js
│   │   │   └── loadBalancer.js
│   │   └── app.js
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml
├── .env.example
├── README.md
└── package.json
```

## Implementation Strategy

### 1. Service Communication
- **API Gateway**: Routes requests to appropriate microservices
- **HTTP/REST**: Inter-service communication via RESTful APIs
- **Event-Driven**: Critical operations trigger events across services
- **Database Sharing**: All services share PostgreSQL database with proper isolation

### 2. Authentication Flow
```
Frontend (React) → API Gateway → Authentication Service
                ↓
     Email/SMS OTP Verification → User Management Service
                ↓
     Biometric Capture → Device/Session Service
                ↓
     Security Validation → Security/Encryption Service
```

### 3. Database Design
```sql
-- Users table (encrypted sensitive data)
users (id, email_hash, phone_hash, created_at, updated_at, status)

-- User Profiles (demographics and details)
user_profiles (id, user_id, encrypted_data, demographics, preferences)

-- OTP Sessions (temporary verification)
otp_sessions (id, user_id, email_otp, sms_otp, expires_at, verified)

-- Biometric Data (encrypted storage)
biometric_data (id, user_id, biometric_hash, device_type, created_at)

-- Devices (device tracking)
devices (id, user_id, device_id, device_type, ip_address, fingerprint)

-- Sessions (active sessions)
sessions (id, user_id, device_id, jwt_token, expires_at, active)
```

### 4. Security Implementation
- **End-to-End Encryption**: RSA/ElGamal for sensitive data
- **JWT Tokens**: Secure authentication with refresh rotation
- **Rate Limiting**: Prevent brute force attacks
- **Input Validation**: OWASP compliance
- **Biometric Hashing**: Secure biometric data storage
- **Device Fingerprinting**: Unique device identification

### 5. Technology Stack
- **Runtime**: Node.js (ES6+ modules)
- **Framework**: Express.js
- **Database**: PostgreSQL with encryption
- **ORM**: Sequelize or Prisma
- **Email**: Nodemailer
- **SMS**: Twilio
- **Encryption**: Node.js built-in crypto (modern APIs)
- **Authentication**: JWT
- **Validation**: Joi or Yup
- **Logging**: Winston
- **Monitoring**: Prometheus metrics

## Service Dependencies

1. **Authentication Service** depends on:
   - User Management Service (user validation)
   - Security Service (encryption)
   - Device Service (device registration)

2. **User Management Service** depends on:
   - Security Service (data encryption)

3. **Security Service** is standalone (core cryptographic operations)

4. **Device Service** depends on:
   - User Management Service (user association)

## API Endpoints Structure

### Authentication Service (3001)
```
POST /api/auth/send-otp          # Send email/SMS OTP
POST /api/auth/verify-otp        # Verify OTP codes
POST /api/auth/capture-biometric # Capture biometric data
POST /api/auth/refresh-token     # Refresh JWT token
GET  /api/auth/status            # Check auth status
```

### User Management Service (3002)
```
GET  /api/users/profile          # Get user profile
PUT  /api/users/profile          # Update profile
GET  /api/users/demographics     # Get demographics
POST /api/users/activity         # Log user activity
```

### Security Service (3003)
```
POST /api/security/encrypt       # Encrypt data
POST /api/security/decrypt       # Decrypt data
POST /api/security/sign          # Digital signature
POST /api/security/verify        # Verify signature
```

### Device Service (3004)
```
POST /api/devices/register       # Register device
GET  /api/devices/list           # List user devices
PUT  /api/devices/update         # Update device info
DELETE /api/devices/:id          # Remove device
```

This architecture ensures high security, scalability, and maintainability while meeting all Milestone-1 requirements.




dockerfile

# version: '3.8'

# services:
#   # PostgreSQL Database
#   postgres:
#     image: postgres:15-alpine
#     container_name: vottery-postgres
#     environment:
#       POSTGRES_DB: vottery_db
#       POSTGRES_USER: vottery_user
#       POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
#       POSTGRES_HOST_AUTH_METHOD: md5
#     ports:
#       - "5432:5432"
#     volumes:
#       - postgres_data:/var/lib/postgresql/data
#       - ./shared/database/init.sql:/docker-entrypoint-initdb.d/init.sql
#     networks:
#       - vottery-network
#     restart: unless-stopped

#   # Redis for Session Management
#   redis:
#     image: redis:7-alpine
#     container_name: vottery-redis
#     ports:
#       - "6379:6379"
#     volumes:
#       - redis_data:/data
#     networks:
#       - vottery-network
#     restart: unless-stopped

#   # API Gateway
#   api-gateway:
#     build:
#       context: ./gateway
#       dockerfile: Dockerfile
#     container_name: vottery-gateway
#     ports:
#       - "3000:3000"
#     environment:
#       - NODE_ENV=${NODE_ENV:-development}
#       - AUTH_SERVICE_URL=http://auth-service:3001
#       - USER_SERVICE_URL=http://user-service:3002
#       - SECURITY_SERVICE_URL=http://security-service:3003
#       - DEVICE_SERVICE_URL=http://device-service:3004
#     depends_on:
#       - auth-service
#       - user-service
#       - security-service
#       - device-service
#     networks:
#       - vottery-network
#     restart: unless-stopped

#   # Authentication Service
#   auth-service:
#     build:
#       context: ./services/authentication-service
#       dockerfile: Dockerfile
#     container_name: vottery-auth
#     ports:
#       - "3001:3001"
#     environment:
#       - NODE_ENV=${NODE_ENV:-development}
#       - DATABASE_URL=${DATABASE_URL}
#       - REDIS_URL=redis://redis:6379
#       - JWT_SECRET=${JWT_SECRET}
#       - JWT_REFRESH_SECRET=${JWT_REFRESH_SECRET}
#       - NODEMAILER_HOST=${NODEMAILER_HOST}
#       - NODEMAILER_PORT=${NODEMAILER_PORT}
#       - NODEMAILER_USER=${NODEMAILER_USER}
#       - NODEMAILER_PASS=${NODEMAILER_PASS}
#       - TWILIO_ACCOUNT_SID=${TWILIO_ACCOUNT_SID}
#       - TWILIO_AUTH_TOKEN=${TWILIO_AUTH_TOKEN}
#       - TWILIO_PHONE_NUMBER=${TWILIO_PHONE_NUMBER}
#       - ENCRYPTION_KEY=${ENCRYPTION_KEY}
#     depends_on:
#       - postgres
#       - redis
#     networks:
#       - vottery-network
#     restart: unless-stopped

#   # User Management Service
#   user-service:
#     build:
#       context: ./services/user-management-service
#       dockerfile: Dockerfile
#     container_name: vottery-user
#     ports:
#       - "3002:3002"
#     environment:
#       - NODE_ENV=${NODE_ENV:-development}
#       - DATABASE_URL=${DATABASE_URL}
#       - REDIS_URL=redis://redis:6379
#       - ENCRYPTION_KEY=${ENCRYPTION_KEY}
#       - SECURITY_SERVICE_URL=http://security-service:3003
#     depends_on:
#       - postgres
#       - redis
#       - security-service
#     networks:
#       - vottery-network
#     restart: unless-stopped

#   # Security & Encryption Service
#   security-service:
#     build:
#       context: ./services/security-encryption-service
#       dockerfile: Dockerfile
#     container_name: vottery-security
#     ports:
#       - "3003:3003"
#     environment:
#       - NODE_ENV=${NODE_ENV:-development}
#       - DATABASE_URL=${DATABASE_URL}
#       - RSA_KEY_SIZE=2048
#       - HASH_ALGORITHM=sha256
#       - ENCRYPTION_ALGORITHM=aes-256-gcm
#     depends_on:
#       - postgres
#     networks:
#       - vottery-network
#     restart: unless-stopped

#   # Device & Session Service
#   device-service:
#     build:
#       context: ./services/device-session-service
#       dockerfile: Dockerfile
#     container_name: vottery-device
#     ports:
#       - "3004:3004"
#     environment:
#       - NODE_ENV=${NODE_ENV:-development}
#       - DATABASE_URL=${DATABASE_URL}
#       - REDIS_URL=redis://redis:6379
#       - GEOLOCATION_API_KEY=${GEOLOCATION_API_KEY}
#     depends_on:
#       - postgres
#       - redis
#     networks:
#       - vottery-network
#     restart: unless-stopped

# volumes:
#   postgres_data:
#     driver: local
#   redis_data:
#     driver: local

# networks:
#   vottery-network:
#     driver: bridge




// services/authentication-service/package.json
{
  "name": "vottery-authentication-service",
  "version": "1.0.0",
  "type": "module",
  "description": "Vottery Authentication Microservice - OTP, Biometric & JWT Management",
  "main": "src/app.js",
  "scripts": {
    "start": "node src/app.js",
    "dev": "nodemon src/app.js",
    "test": "jest",
    "build": "echo 'No build step required'"
  },
  "dependencies": {
    "express": "^4.18.2",
    "express-rate-limit": "^7.1.5",
    "express-validator": "^7.0.1",
    "helmet": "^7.1.0",
    "cors": "^2.8.5",
    "compression": "^1.7.4",
    "jsonwebtoken": "^9.0.2",
    "bcryptjs": "^2.4.3",
    "nodemailer": "^6.9.7",
    "twilio": "^4.19.0",
    "pg": "^8.11.3",
    "redis": "^4.6.10",
    "joi": "^17.11.0",
    "winston": "^3.11.0",
    "morgan": "^1.10.0",
    "uuid": "^9.0.1",
    "dotenv": "^16.3.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.2",
    "jest": "^29.7.0",
    "supertest": "^6.3.3"
  }
}




you gave me frontend code based on that based on the pdf milestone-4 just give me milestone-1 frontend code with react js 19+ vite+ tailwind-4 and context api. I mean keep in mind milestone 4 but give me milestone-1 frontend code, as i have to show it to client. for milestone-1, in vottery no login, no registration, no user prompt to give email or password as i have no control on sngine. and do not like to ask sngine to give anything only i have the the shared postgresql database. so by react js ensure that the user came form sngine use document.referrer for sngine detection. actual scenerio is like i have two application one is sngine by php and another one is node js microservice(vottery.com). i have no control over sngine and do not like to talk with them. but i have full control over postgresql shared database. now i want that all user must come form sngine after registering( i need to make it 100% sure). if they do not come from sngine i will restrict them to visit www.vottery.com and give them message that you must come after registering sngine and give them redirecting link to sngine. but if they come from snginge i will match their email and phone by sending otp through nodemailer and twilio by Complete Authentication Flow Testing: 🔄 3-Step progressive form. if email and mobile otp match will take his biometric (web, desktop, laptop, tabl, ios, android) and take all device type and respective user based device id and all will save and interact to database. after that he will be able to visit dashboard provided that email and sms otp matched and give biometric(capable all device and device info and id).). do not seek any user id or referral from sngine nor ask any user to give his email or password. just make sure by react js that he is from sngine or not by document.referrer. if not from sngine restrict him and if from sngine go ahead. here is the milestone attached. so just give me milestone-1 frontend code keeping in mind milestone-4. and finally make sure it is highly secured frontend based on milestone-1. no backend code needed. milestone is added here. don't use any deprecated packages. PLease please keep in mind milestone-4 but give me milestone-1 code. and read carefully the milestone documents and give me frontedn folder structure.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        now i need backend code based on the above frontend condition and milestone-1 requirements. no need to verify in the backend that people are coming from the sngine or not, react js will handle it. now i need to verify email and phone otp by nodemailer and twilio, after that we will capture biometric and all like it (but if they come from snginge i will match their email and phone by sending otp through nodemailer and twilio by Complete Authentication Flow Testing: 🔄 3-Step progressive form. if email and mobile otp match will take his biometric (web, desktop, laptop, tab, ios, android) and take all device type, ip and respective user based device id and all will save and interact to database. after that he will be able to visit dashboard provided that email and sms otp matched and give biometric(capable all device and device info and id).). as frontend is ready now i want to test the backend based on the milestone-1. PLease please read all instruction carefully and give codes compatible with frontend (above) and milestone-1. do not use any depricated packages like crypto, and use es6 compatible like import and export deafult. it is node js microservice. first of all give me the folder structure and tell me how you want to implement it? in vottery no login, no registration, no user prompt to give email or password as i have no control on sngine. tell me how many microservices are needed for that and how you plan to implement in between the services? milestone is attached here. no forntend code only backend theory and frolder structure. so please combine the instruction and milestone one. as some changes in milestone-1 (mentioned above). but must be implemented the security.

