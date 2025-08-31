import { webcrypto } from 'node:crypto';
import { createHash, randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'node:crypto';

const { subtle } = webcrypto;

export class EncryptionUtils {
  static ALGORITHM = 'aes-256-gcm';
  static KEY_LENGTH = 32;
  static IV_LENGTH = 16;
  static TAG_LENGTH = 16;
  static SALT_LENGTH = 32;

  // Generate encryption key from password
  static generateKey(password = process.env.ENCRYPTION_KEY || 'default-key') {
    const salt = Buffer.from(process.env.ENCRYPTION_SALT || 'default-salt', 'utf8');
    return scryptSync(password, salt, this.KEY_LENGTH);
  }

  // Encrypt data
  static encrypt(text) {
    if (!text || typeof text !== 'string') return null;

    try {
      const key = this.generateKey();
      const iv = randomBytes(this.IV_LENGTH);
      const cipher = createCipheriv(this.ALGORITHM, key, iv);
      
      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const tag = cipher.getAuthTag();
      
      // Return: iv + tag + encrypted (all in hex)
      return iv.toString('hex') + tag.toString('hex') + encrypted;
    } catch (error) {
      throw new Error('Encryption failed');
    }
  }

  // Decrypt data
  static decrypt(encryptedData) {
    if (!encryptedData || typeof encryptedData !== 'string') return null;

    try {
      const key = this.generateKey();
      
      // Extract iv, tag, and encrypted data
      const iv = Buffer.from(encryptedData.slice(0, this.IV_LENGTH * 2), 'hex');
      const tag = Buffer.from(encryptedData.slice(this.IV_LENGTH * 2, (this.IV_LENGTH + this.TAG_LENGTH) * 2), 'hex');
      const encrypted = encryptedData.slice((this.IV_LENGTH + this.TAG_LENGTH) * 2);
      
      const decipher = createDecipheriv(this.ALGORITHM, key, iv);
      decipher.setAuthTag(tag);
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      throw new Error('Decryption failed');
    }
  }

  // Generate hash with salt
  static generateHash(data, salt = null) {
    if (!salt) {
      salt = randomBytes(this.SALT_LENGTH).toString('hex');
    }
    
    const hash = createHash('sha256')
      .update(data + salt)
      .digest('hex');
    
    return `${salt}:${hash}`;
  }

  // Verify hash
  static verifyHash(data, storedHash) {
    if (!storedHash || !storedHash.includes(':')) return false;
    
    const [salt, hash] = storedHash.split(':');
    const newHash = createHash('sha256')
      .update(data + salt)
      .digest('hex');
    
    return newHash === hash;
  }

  // Generate random token
  static generateToken(length = 32) {
    return randomBytes(length).toString('hex');
  }

  // Generate RSA key pair
  static async generateRSAKeyPair() {
    const keyPair = await subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['encrypt', 'decrypt']
    );

    const publicKey = await subtle.exportKey('spki', keyPair.publicKey);
    const privateKey = await subtle.exportKey('pkcs8', keyPair.privateKey);

    return {
      publicKey: Buffer.from(publicKey).toString('base64'),
      privateKey: Buffer.from(privateKey).toString('base64')
    };
  }

  // RSA Encrypt
  static async rsaEncrypt(data, publicKeyBase64) {
    const publicKeyBuffer = Buffer.from(publicKeyBase64, 'base64');
    const publicKey = await subtle.importKey(
      'spki',
      publicKeyBuffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );

    const encrypted = await subtle.encrypt(
      'RSA-OAEP',
      publicKey,
      new TextEncoder().encode(data)
    );

    return Buffer.from(encrypted).toString('base64');
  }

  // RSA Decrypt
  static async rsaDecrypt(encryptedData, privateKeyBase64) {
    const privateKeyBuffer = Buffer.from(privateKeyBase64, 'base64');
    const privateKey = await subtle.importKey(
      'pkcs8',
      privateKeyBuffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['decrypt']
    );

    const encryptedBuffer = Buffer.from(encryptedData, 'base64');
    const decrypted = await subtle.decrypt('RSA-OAEP', privateKey, encryptedBuffer);

    return new TextDecoder().decode(decrypted);
  }

  // Generate digital signature
  static async generateSignature(data, privateKeyBase64) {
    const privateKeyBuffer = Buffer.from(privateKeyBase64, 'base64');
    const privateKey = await subtle.importKey(
      'pkcs8',
      privateKeyBuffer,
      { name: 'RSA-PSS', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await subtle.sign(
      { name: 'RSA-PSS', saltLength: 32 },
      privateKey,
      new TextEncoder().encode(data)
    );

    return Buffer.from(signature).toString('base64');
  }

  // Verify digital signature
  static async verifySignature(data, signatureBase64, publicKeyBase64) {
    const publicKeyBuffer = Buffer.from(publicKeyBase64, 'base64');
    const publicKey = await subtle.importKey(
      'spki',
      publicKeyBuffer,
      { name: 'RSA-PSS', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signatureBuffer = Buffer.from(signatureBase64, 'base64');
    
    return await subtle.verify(
      { name: 'RSA-PSS', saltLength: 32 },
      publicKey,
      signatureBuffer,
      new TextEncoder().encode(data)
    );
  }
}