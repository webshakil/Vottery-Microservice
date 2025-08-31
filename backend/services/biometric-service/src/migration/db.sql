# Database Schema Updates (add to existing migrations)
-- Additional tables for biometric service

-- WebAuthn challenges table
CREATE TABLE IF NOT EXISTS vottery_webauthn_challenges (
    user_id INT NOT NULL,
    device_id INT NOT NULL DEFAULT 0,
    challenge TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, device_id),
    FOREIGN KEY (user_id) REFERENCES vottery_users(id) ON DELETE CASCADE
);

-- Update existing vottery_devices table to add new columns
ALTER TABLE vottery_devices 
ADD COLUMN IF NOT EXISTS capabilities TEXT,
ADD COLUMN IF NOT EXISTS device_details TEXT,
ADD COLUMN IF NOT EXISTS trust_score INTEGER DEFAULT 50,
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Update existing vottery_biometrics table to add new columns  
ALTER TABLE vottery_biometrics
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_vottery_devices_user_active ON vottery_devices(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_vottery_biometrics_user_type ON vottery_biometrics(user_id, biometric_type, is_active);