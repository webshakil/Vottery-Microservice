/ README.md
# Vottery Milestone 1 Frontend

## Overview
This is the complete React frontend implementation for Vottery Milestone 1, featuring secure authentication flow with SNGine integration, multi-factor verification, and biometric capture.

## Features Implemented
- ✅ SNGine referrer validation using document.referrer
- ✅ 3-step progressive authentication flow
- ✅ Email OTP verification via NodeMailer simulation
- ✅ SMS OTP verification via Twilio simulation  
- ✅ WebAuthn biometric capture with fallback
- ✅ Device fingerprinting and security metrics
- ✅ End-to-end encryption for sensitive data
- ✅ Responsive design with Tailwind CSS 4
- ✅ Context API for state management
- ✅ React 19+ with modern hooks
- ✅ Comprehensive error handling
- ✅ Security-first architecture

## Tech Stack
- **React 19+** - Modern React with latest features
- **Vite** - Fast build tool and dev server
- **Tailwind CSS 4** - Utility-first CSS framework
- **Context API** - State management
- **WebAuthn API** - Biometric authentication
- **FingerprintJS** - Device fingerprinting
- **CryptoJS** - Client-side encryption

## Project Structure
```
src/
├── components/
│   ├── auth/
│   │   ├── EmailVerification.jsx
│   │   ├── PhoneVerification.jsx
│   │   └── BiometricCapture.jsx
│   ├── AccessDenied.jsx
│   ├── AuthenticationFlow.jsx
│   ├── Dashboard.jsx
│   └── LoadingScreen.jsx
├── contexts/
│   ├── AuthContext.jsx
│   └── SecurityContext.jsx
├── hooks/
│   └── useDeviceDetection.js
├── utils/
│   └── security.js
├── App.jsx
├── main.jsx
└── index.css
```

## Security Features
- **Referrer Validation**: Ensures users come from SNGine
- **Multi-Factor Authentication**: Email + SMS + Biometric
- **Device Fingerprinting**: Unique device identification
- **End-to-End Encryption**: All sensitive data encrypted
- **Session Management**: Secure session handling
- **HTTPS Enforcement**: Security protocol validation
- **Input Sanitization**: XSS protection
- **CSRF Protection**: Cross-site request forgery prevention

## Authentication Flow
1. **Referrer Check**: Validates user came from SNGine
2. **Email Verification**: OTP sent via email (NodeMailer)
3. **Phone Verification**: OTP sent via SMS (Twilio)
4. **Biometric Capture**: WebAuthn with device fingerprinting
5. **Dashboard Access**: Full authentication completed

## Setup Instructions

### Prerequisites
- Node.js 18+ 
- npm or yarn
- HTTPS certificate (for WebAuthn)

### Installation
```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

### Environment Setup
The application expects to be accessed via HTTPS for full WebAuthn functionality. For development:

```bash
# Using local HTTPS
npm install -g local-ssl-proxy
local-ssl-proxy --source 3001 --target 3000
```

## Demo Credentials
- **Email OTP**: Use `123456` for testing
- **SMS OTP**: Use `123456` for testing  
- **Biometric**: WebAuthn simulation or fallback mode

## SNGine Integration
- Validates `document.referrer` against approved SNGine domains
- Blocks direct access to Vottery without SNGine referral
- Redirects unauthorized users to SNGine registration

## Database Integration Ready
- PostgreSQL schema ready for backend integration
- Encrypted data storage preparation
- User role and permission structure
- Device and biometric data models

## Next Milestones Preview
The dashboard shows upcoming features from Milestones 2-6:
- Election creation and management
- Multi-methodology voting system
- Payment processing integration
- 3D/4D lottery system
- Mobile applications
- AI recommendation engine

## Browser Support
- Chrome 88+ (recommended)
- Firefox 84+
- Safari 14+
- Edge 88+

## Security Considerations
- All biometric data is encrypted before storage
- Device fingerprints are hashed and salted
- Session tokens use secure random generation
- CSP headers recommended for production
- Rate limiting should be implemented server-side

## Contributing
This frontend is designed to work with the Vottery microservice architecture. Ensure all security protocols are maintained when making modifications.

## License
Proprietary - Vottery Platform
