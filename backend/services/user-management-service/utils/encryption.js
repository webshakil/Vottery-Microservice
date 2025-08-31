import crypto from 'crypto';
import bcrypt from 'bcryptjs'; // Make sure to install bcryptjs: npm i bcryptjs

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'vottery_encryption_key_32_chars!!'; // 32 chars
const ALGORITHM = 'aes-256-gcm';

/**
 * Encrypts a string using AES-256-GCM
 * Returns: iv:authTag:encryptedHex
 */
export const encryptSensitiveData = (text) => {
    try {
        if (!text) return null;

        // 16-byte initialization vector
        const iv = crypto.randomBytes(16);

        // Ensure key is 32 bytes using scryptSync
        const key = crypto.scryptSync(ENCRYPTION_KEY, 'salt', 32);

        // Create cipher
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

        // Optional: Additional authentication data (AAD)
        cipher.setAAD(Buffer.from('vottery'));

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        // Authentication tag
        const authTag = cipher.getAuthTag();

        // Return iv:authTag:encrypted
        return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
    } catch (error) {
        console.error('Encryption error:', error);
        return text; // fallback if encryption fails
    }
};

/**
 * Decrypts string encrypted with AES-256-GCM
 * Input format: iv:authTag:encryptedHex
 */
export const decryptSensitiveData = (encrypted) => {
    try {
        if (!encrypted || typeof encrypted !== 'string' || !encrypted.includes(':')) {
            return encrypted; // just return value as-is if it's null/plain/invalid
        }

        const [ivHex, authTagHex, encryptedHex] = encrypted.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');

        const key = crypto.scryptSync(ENCRYPTION_KEY, 'salt', 32);

        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAAD(Buffer.from('vottery'));
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error);
        return encrypted; // fallback: return original value instead of null
    }
};






// --------------------- PASSWORD & HASH ---------------------

export const hashPassword = async (password) => {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
};

export const verifyPassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
};

// --------------------- TOKEN & SIGNATURE ---------------------

export const generateSecureToken = (length = 32) => {
    return crypto.randomBytes(length).toString('hex');
};

export const generateDigitalSignature = (data, privateKey) => {
    try {
        const sign = crypto.createSign('RSA-SHA256');
        sign.update(JSON.stringify(data));
        sign.end();
        return sign.sign(privateKey, 'hex');
    } catch (error) {
        console.error('Digital signature error:', error);
        return null;
    }
};

export const verifyDigitalSignature = (data, signature, publicKey) => {
    try {
        const verify = crypto.createVerify('RSA-SHA256');
        verify.update(JSON.stringify(data));
        verify.end();
        return verify.verify(publicKey, signature, 'hex');
    } catch (error) {
        console.error('Signature verification error:', error);
        return false;
    }
};
