-- Vottery Database Schema - Milestone 1
-- PostgreSQL Database with Encryption Support

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table (main user records with encrypted sensitive data)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_hash VARCHAR(255) UNIQUE NOT NULL, -- SHA-256 hash of email
    phone_hash VARCHAR(255) UNIQUE NOT NULL, -- SHA-256 hash of phone
    encrypted_email TEXT NOT NULL, -- Encrypted actual email
    encrypted_phone TEXT NOT NULL, -- Encrypted actual phone
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'suspended', 'deleted')),
    verification_level INTEGER DEFAULT 0, -- 0: none, 1: email, 2: phone, 3: biometric
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    sngine_referrer_verified BOOLEAN DEFAULT FALSE,
    terms_accepted BOOLEAN DEFAULT FALSE,
    privacy_accepted BOOLEAN DEFAULT FALSE
);

-- User profiles (demographics and extended information)
CREATE TABLE user_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_profile_data TEXT NOT NULL, -- JSON encrypted data
    demographic_country VARCHAR(3), -- ISO country code
    demographic_age_range VARCHAR(10), -- e.g., "25-34"
    demographic_gender VARCHAR(20),
    preferred_language VARCHAR(5) DEFAULT 'en',
    timezone VARCHAR(50),
    subscription_status VARCHAR(20) DEFAULT 'free' CHECK (subscription_status IN ('free', 'subscribed')),
    subscription_tier VARCHAR(20) DEFAULT 'basic',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User roles (RBAC system)
CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_type VARCHAR(50) NOT NULL CHECK (role_type IN (
        'voter', 'individual_creator', 'organization_creator',
        'admin', 'manager', 'moderator', 'auditor', 'editor', 'advertiser', 'analyst'
    )),
    permissions JSONB DEFAULT '{}',
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    assigned_by UUID REFERENCES users(id),
    is_active BOOLEAN DEFAULT TRUE
);

-- OTP sessions (temporary verification codes)
CREATE TABLE otp_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    email_hash VARCHAR(255) NOT NULL, -- For matching user
    phone_hash VARCHAR(255) NOT NULL, -- For matching user
    email_otp VARCHAR(10) NOT NULL,
    sms_otp VARCHAR(10) NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    sms_verified BOOLEAN DEFAULT FALSE,
    attempts_count INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET NOT NULL,
    user_agent TEXT,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'expired', 'failed'))
);

-- Biometric data storage (encrypted biometric hashes)
CREATE TABLE biometric_data (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    biometric_type VARCHAR(50) NOT NULL CHECK (biometric_type IN (
        'fingerprint', 'face_id', 'voice_print', 'iris_scan', 'web_biometric'
    )),
    encrypted_biometric_hash TEXT NOT NULL, -- Encrypted biometric template
    device_id UUID NOT NULL, -- Reference to device used for capture
    quality_score INTEGER DEFAULT 0, -- Biometric quality (0-100)
    template_version VARCHAR(10) DEFAULT '1.0',
    fallback_available BOOLEAN DEFAULT TRUE,
    verification_attempts INTEGER DEFAULT 0,
    last_verified TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Device information and fingerprinting
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255) UNIQUE NOT NULL, -- Unique device identifier
    device_type VARCHAR(50) NOT NULL CHECK (device_type IN (
        'web', 'desktop', 'laptop', 'tablet', 'ios', 'android', 'mobile'
    )),
    device_name VARCHAR(255),
    browser_name VARCHAR(100),
    browser_version VARCHAR(50),
    operating_system VARCHAR(100),
    os_version VARCHAR(50),
    screen_resolution VARCHAR(20),
    timezone VARCHAR(50),
    language VARCHAR(10),
    ip_address INET NOT NULL,
    ip_country VARCHAR(3), -- ISO country code from IP
    ip_region VARCHAR(100),
    ip_city VARCHAR(100),
    user_agent TEXT NOT NULL,
    device_fingerprint TEXT NOT NULL, -- Combined fingerprint hash
    biometric_capable BOOLEAN DEFAULT FALSE,
    biometric_types JSONB DEFAULT '[]', -- Available biometric types
    trust_score INTEGER DEFAULT 50, -- Device trust level (0-100)
    is_primary BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Active sessions management
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token VARCHAR(255) UNIQUE NOT NULL,
    jwt_token_id VARCHAR(255) UNIQUE NOT NULL, -- JWT jti claim
    ip_address INET NOT NULL,
    user_agent TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    refresh_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ended_at TIMESTAMP WITH TIME ZONE,
    end_reason VARCHAR(50) -- logout, timeout, revoked, expired
);

-- Encryption keys management
CREATE TABLE encryption_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_id VARCHAR(100) UNIQUE NOT NULL,
    key_type VARCHAR(50) NOT NULL CHECK (key_type IN (
        'rsa_public', 'rsa_private', 'elgamal_public', 'elgamal_private', 'aes_key'
    )),
    encrypted_key_data TEXT NOT NULL,
    key_size INTEGER NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE, -- NULL for system keys
    purpose VARCHAR(100) NOT NULL, -- 'user_data', 'biometric', 'system', etc.
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    rotated_at TIMESTAMP WITH TIME ZONE,
    predecessor_key_id UUID REFERENCES encryption_keys(id)
);

-- User activity audit log
CREATE TABLE user_activities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
    activity_type VARCHAR(100) NOT NULL,
    activity_details JSONB DEFAULT '{}',
    ip_address INET NOT NULL,
    user_agent TEXT,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    risk_score INTEGER DEFAULT 0, -- Security risk assessment (0-100)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Security audit trails
CREATE TABLE security_audits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_type VARCHAR(50) NOT NULL CHECK (audit_type IN (
        'authentication', 'authorization', 'encryption', 'key_rotation', 
        'biometric_capture', 'device_registration', 'suspicious_activity'
    )),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    event_details JSONB NOT NULL,
    severity VARCHAR(20) DEFAULT 'info' CHECK (severity IN ('low', 'medium', 'high', 'critical', 'info')),
    ip_address INET,
    user_agent TEXT,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Rate limiting tracking
CREATE TABLE rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identifier VARCHAR(255) NOT NULL, -- IP, user_id, or combination
    limit_type VARCHAR(50) NOT NULL, -- 'otp_request', 'login_attempt', 'api_call'
    current_count INTEGER DEFAULT 1,
    max_count INTEGER NOT NULL,
    window_start TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    window_duration INTERVAL NOT NULL,
    blocked_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- System configuration
CREATE TABLE system_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value JSONB NOT NULL,
    config_type VARCHAR(50) NOT NULL,
    description TEXT,
    is_encrypted BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID REFERENCES users(id)
);

-- Indexes for performance optimization
CREATE INDEX idx_users_email_hash ON users(email_hash);
CREATE INDEX idx_users_phone_hash ON users(phone_hash);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_verification_level ON users(verification_level);
CREATE INDEX idx_users_created_at ON users(created_at);

CREATE INDEX idx_user_profiles_user_id ON user_profiles(user_id);
CREATE INDEX idx_user_profiles_country ON user_profiles(demographic_country);
CREATE INDEX idx_user_profiles_subscription ON user_profiles(subscription_status);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_type ON user_roles(role_type);
CREATE INDEX idx_user_roles_active ON user_roles(is_active);

CREATE INDEX idx_otp_sessions_email_hash ON otp_sessions(email_hash);
CREATE INDEX idx_otp_sessions_phone_hash ON otp_sessions(phone_hash);
CREATE INDEX idx_otp_sessions_expires_at ON otp_sessions(expires_at);
CREATE INDEX idx_otp_sessions_status ON otp_sessions(status);
CREATE INDEX idx_otp_sessions_ip ON otp_sessions(ip_address);

CREATE INDEX idx_biometric_data_user_id ON biometric_data(user_id);
CREATE INDEX idx_biometric_data_device_id ON biometric_data(device_id);
CREATE INDEX idx_biometric_data_type ON biometric_data(biometric_type);
CREATE INDEX idx_biometric_data_active ON biometric_data(is_active);

CREATE INDEX idx_devices_user_id ON devices(user_id);
CREATE INDEX idx_devices_device_id ON devices(device_id);
CREATE INDEX idx_devices_type ON devices(device_type);
CREATE INDEX idx_devices_ip ON devices(ip_address);
CREATE INDEX idx_devices_active ON devices(is_active);
CREATE INDEX idx_devices_last_seen ON devices(last_seen);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_device_id ON sessions(device_id);
CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_sessions_refresh_token ON sessions(refresh_token);
CREATE INDEX idx_sessions_jwt_token_id ON sessions(jwt_token_id);
CREATE INDEX idx_sessions_active ON sessions(is_active);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

CREATE INDEX idx_encryption_keys_key_id ON encryption_keys(key_id);
CREATE INDEX idx_encryption_keys_user_id ON encryption_keys(user_id);
CREATE INDEX idx_encryption_keys_type ON encryption_keys(key_type);
CREATE INDEX idx_encryption_keys_active ON encryption_keys(is_active);

CREATE INDEX idx_user_activities_user_id ON user_activities(user_id);
CREATE INDEX idx_user_activities_device_id ON user_activities(device_id);
CREATE INDEX idx_user_activities_type ON user_activities(activity_type);
CREATE INDEX idx_user_activities_created_at ON user_activities(created_at);
CREATE INDEX idx_user_activities_ip ON user_activities(ip_address);

CREATE INDEX idx_security_audits_type ON security_audits(audit_type);
CREATE INDEX idx_security_audits_user_id ON security_audits(user_id);
CREATE INDEX idx_security_audits_severity ON security_audits(severity);
CREATE INDEX idx_security_audits_resolved ON security_audits(resolved);
CREATE INDEX idx_security_audits_created_at ON security_audits(created_at);

CREATE INDEX idx_rate_limits_identifier ON rate_limits(identifier);
CREATE INDEX idx_rate_limits_type ON rate_limits(limit_type);
CREATE INDEX idx_rate_limits_window_start ON rate_limits(window_start);
CREATE INDEX idx_rate_limits_blocked_until ON rate_limits(blocked_until);

-- Triggers for updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_profiles_updated_at BEFORE UPDATE ON user_profiles 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_biometric_data_updated_at BEFORE UPDATE ON biometric_data 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_devices_updated_at BEFORE UPDATE ON devices 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_rate_limits_updated_at BEFORE UPDATE ON rate_limits 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_system_configs_updated_at BEFORE UPDATE ON system_configs 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default system configurations
INSERT INTO system_configs (config_key, config_value, config_type, description) VALUES
('otp_expiry_minutes', '10', 'integer', 'OTP expiration time in minutes'),
('max_otp_attempts', '3', 'integer', 'Maximum OTP verification attempts'),
('session_timeout_hours', '1', 'integer', 'Session timeout in hours'),
('max_devices_per_user', '10', 'integer', 'Maximum devices per user'),
('biometric_required_default', 'false', 'boolean', 'Default biometric requirement for new elections'),
('rate_limit_otp_per_hour', '5', 'integer', 'Maximum OTP requests per hour per user'),
('min_trust_score', '30', 'integer', 'Minimum device trust score required'),
('encryption_key_rotation_days', '90', 'integer', 'Key rotation period in days');

-- Create views for common queries
CREATE VIEW active_users AS
SELECT u.*, up.demographic_country, up.subscription_status
FROM users u
LEFT JOIN user_profiles up ON u.id = up.user_id
WHERE u.status = 'verified';

CREATE VIEW user_device_summary AS
SELECT u.id as user_id, u.email_hash, 
       COUNT(d.id) as device_count,
       MAX(d.last_seen) as last_device_activity,
       COUNT(CASE WHEN d.biometric_capable = true THEN 1 END) as biometric_devices
FROM users u
LEFT JOIN devices d ON u.id = d.user_id AND d.is_active = true
GROUP BY u.id, u.email_hash;

-- Security functions
CREATE OR REPLACE FUNCTION clean_expired_sessions()
RETURNS INTEGER AS $
DECLARE
    cleaned_count INTEGER;
BEGIN
    UPDATE sessions 
    SET is_active = false, ended_at = NOW(), end_reason = 'expired'
    WHERE is_active = true AND expires_at < NOW();
    
    GET DIAGNOSTICS cleaned_count = ROW_COUNT;
    RETURN cleaned_count;
END;
$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION clean_expired_otp_sessions()
RETURNS INTEGER AS $
DECLARE
    cleaned_count INTEGER;
BEGIN
    UPDATE otp_sessions 
    SET status = 'expired'
    WHERE status = 'pending' AND expires_at < NOW();
    
    GET DIAGNOSTICS cleaned_count = ROW_COUNT;
    RETURN cleaned_count;
END;
$ LANGUAGE plpgsql;

-- Scheduled cleanup (requires pg_cron extension in production)
-- SELECT cron.schedule('cleanup-sessions', '0 * * * *', 'SELECT clean_expired_sessions();');
-- SELECT cron.schedule('cleanup-otp', '*/15 * * * *', 'SELECT clean_expired_otp_sessions();');








//later by myself vottery_prefixed

CREATE TABLE vottery_users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_hash VARCHAR(255) UNIQUE NOT NULL, -- SHA-256 hash of email
    phone_hash VARCHAR(255) UNIQUE NOT NULL, -- SHA-256 hash of phone
    encrypted_email TEXT NOT NULL, -- Encrypted actual email
    encrypted_phone TEXT NOT NULL, -- Encrypted actual phone
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'suspended', 'deleted')),
    verification_level INTEGER DEFAULT 0, -- 0: none, 1: email, 2: phone, 3: biometric
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    sngine_referrer_verified BOOLEAN DEFAULT FALSE,
    terms_accepted BOOLEAN DEFAULT FALSE,
    privacy_accepted BOOLEAN DEFAULT FALSE
);




vottery specific

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
