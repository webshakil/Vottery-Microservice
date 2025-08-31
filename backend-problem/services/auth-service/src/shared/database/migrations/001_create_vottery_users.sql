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
