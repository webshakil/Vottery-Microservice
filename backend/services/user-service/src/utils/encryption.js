import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHash,
  pbkdf2Sync,
  generateKeyPairSync,
  publicEncrypt,
  privateDecrypt,
  createSign,
  createVerify,
  createHmac
} from 'node:crypto';
import { ENCRYPTION } from './constants.js';
//import { generateSecureToken } from './helpers.js';

/**
 * AES Encryption utilities
 */
export class AESEncryption {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.keyLength = 32; // 256 bits
    this.ivLength = 16;  // 128 bits
    this.tagLength = 16; // 128 bits
  }

  generateKey(password, salt = null) {
    if (!salt) {
      salt = randomBytes(32);
    } else if (typeof salt === 'string') {
      salt = Buffer.from(salt, 'hex');
    }
    return pbkdf2Sync(password, salt, ENCRYPTION.HASH_ROUNDS.PBKDF2, this.keyLength, 'sha512');
  }

  encrypt(plaintext, key) {
    try {
      const iv = randomBytes(this.ivLength);
      const cipher = createCipheriv(this.algorithm, key, iv);
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      const tag = cipher.getAuthTag();
      return { encrypted, iv: iv.toString('hex'), tag: tag.toString('hex'), algorithm: this.algorithm };
    } catch (error) {
      throw new Error(`AES encryption failed: ${error.message}`);
    }
  }

  decrypt(encryptedData, key) {
    try {
      const { encrypted, iv, tag, algorithm } = encryptedData;
      if (algorithm !== this.algorithm) throw new Error('Algorithm mismatch');
      const decipher = createDecipheriv(algorithm, key, Buffer.from(iv, 'hex'));
      decipher.setAuthTag(Buffer.from(tag, 'hex'));
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (error) {
      throw new Error(`AES decryption failed: ${error.message}`);
    }
  }

  encryptWithPassword(plaintext, password) {
    const salt = randomBytes(32);
    const key = this.generateKey(password, salt);
    const encrypted = this.encrypt(plaintext, key);
    return { ...encrypted, salt: salt.toString('hex') };
  }

  decryptWithPassword(encryptedData, password) {
    const { salt, ...restData } = encryptedData;
    const key = this.generateKey(password, salt);
    return this.decrypt(restData, key);
  }
}

/**
 * RSA Encryption utilities
 */
export class RSAEncryption {
  constructor() {
    this.keySize = ENCRYPTION.KEY_SIZES.RSA;
    this.padding = 'OAEP';
    this.hashFunction = 'sha256';
  }

  generateKeyPair() {
    try {
      const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: this.keySize,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      return { publicKey, privateKey, fingerprint: this.generateFingerprint(publicKey) };
    } catch (error) {
      throw new Error(`RSA key generation failed: ${error.message}`);
    }
  }

  generateFingerprint(publicKey) {
    const hash = createHash('sha256');
    hash.update(publicKey);
    return hash.digest('hex');
  }

  encrypt(plaintext, publicKey) {
    try {
      const buffer = Buffer.from(plaintext, 'utf8');
      const encrypted = publicEncrypt(
        { key: publicKey, padding: 1, oaepHash: this.hashFunction },
        buffer
      );
      return encrypted.toString('base64');
    } catch (error) {
      throw new Error(`RSA encryption failed: ${error.message}`);
    }
  }

  decrypt(encryptedData, privateKey) {
    try {
      const buffer = Buffer.from(encryptedData, 'base64');
      const decrypted = privateDecrypt({ key: privateKey, padding: 1, oaepHash: this.hashFunction }, buffer);
      return decrypted.toString('utf8');
    } catch (error) {
      throw new Error(`RSA decryption failed: ${error.message}`);
    }
  }

  sign(data, privateKey) {
    try {
      const sign = createSign('RSA-SHA256');
      sign.update(data);
      sign.end();
      const signature = sign.sign(privateKey);
      return signature.toString('base64');
    } catch (error) {
      throw new Error(`RSA signing failed: ${error.message}`);
    }
  }

  verify(data, signature, publicKey) {
    try {
      const verify = createVerify('RSA-SHA256');
      verify.update(data);
      verify.end();
      return verify.verify(publicKey, Buffer.from(signature, 'base64'));
    } catch (error) {
      throw new Error(`RSA verification failed: ${error.message}`);
    }
  }
}

/**
 * ElGamal Encryption (placeholder using RSA)
 */
export class ElGamalEncryption {
  constructor() {
    this.keySize = ENCRYPTION.KEY_SIZES.ELGAMAL;
  }

  generateKeyPair() {
    const keyPair = generateKeyPairSync('rsa', {
      modulusLength: this.keySize,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey, algorithm: 'ElGamal', fingerprint: this.generateFingerprint(keyPair.publicKey) };
  }

  generateFingerprint(publicKey) {
    const hash = createHash('sha256');
    hash.update(publicKey);
    return hash.digest('hex');
  }

  encrypt(plaintext, publicKey) {
    const rsa = new RSAEncryption();
    return rsa.encrypt(plaintext, publicKey);
  }

  decrypt(encryptedData, privateKey) {
    const rsa = new RSAEncryption();
    return rsa.decrypt(encryptedData, privateKey);
  }
}

/**
 * Threshold Cryptography (simplified)
 */
export class ThresholdCryptography {
  constructor() {
    this.keySize = ENCRYPTION.KEY_SIZES.THRESHOLD;
  }

  generateThresholdKeys(threshold, totalShares) {
    if (threshold > totalShares) throw new Error('Threshold cannot be greater than total shares');
    const masterKey = randomBytes(32);
    const shares = [];
    for (let i = 0; i < totalShares; i++) {
      shares.push({ id: i + 1, share: randomBytes(32).toString('hex'), threshold, totalShares });
    }
    return { shares, threshold, totalShares, masterKeyHash: createHash('sha256').update(masterKey).digest('hex') };
  }

  combineShares(shares) {
    if (!Array.isArray(shares) || shares.length === 0) throw new Error('Invalid shares provided');
    const threshold = shares[0].threshold;
    if (shares.length < threshold) throw new Error(`Insufficient shares: need ${threshold}, got ${shares.length}`);
    const combinedHash = createHash('sha256');
    shares.slice(0, threshold).forEach(share => combinedHash.update(share.share));
    return combinedHash.digest('hex');
  }

  thresholdEncrypt(plaintext, publicShares) {
    const aes = new AESEncryption();
    const sessionKey = randomBytes(32);
    const encryptedData = aes.encrypt(plaintext, sessionKey);
    const encryptedShares = publicShares.map(share => ({ id: share.id, encryptedKey: createHash('sha256').update(sessionKey.toString('hex') + share.share).digest('hex') }));
    return { ...encryptedData, encryptedShares, threshold: publicShares[0]?.threshold || 1 };
  }

  thresholdDecrypt(encryptedData, privateShares) {
    const { encryptedShares, threshold, ...aesData } = encryptedData;
    if (privateShares.length < threshold) throw new Error(`Insufficient private shares: need ${threshold}, got ${privateShares.length}`);
    const sessionKeyHash = createHash('sha256');
    for (let i = 0; i < threshold; i++) sessionKeyHash.update(privateShares[i].share);
    const sessionKey = Buffer.from(sessionKeyHash.digest('hex').substring(0, 64), 'hex');
    const aes = new AESEncryption();
    return aes.decrypt(aesData, sessionKey);
  }
}

/**
 * Hash utilities
 */
export class HashUtils {
  static sha256(data) {
    return createHash('sha256').update(data).digest('hex');
  }

  static sha512(data) {
    return createHash('sha512').update(data).digest('hex');
  }

  static hmac(data, key, algorithm = 'sha256') {
    return createHmac(algorithm, key).update(data).digest('hex');
  }

  static hashPassword(password, salt = null) {
    if (!salt) salt = randomBytes(16).toString('hex');
    const hash = pbkdf2Sync(password, salt, ENCRYPTION.HASH_ROUNDS.PBKDF2, 64, 'sha512').toString('hex');
    return { hash, salt };
  }

  static verifyPassword(password, hash, salt) {
    return this.hashPassword(password, salt).hash === hash;
  }
}

/**
 * Encryption Service wrapper
 */
export class EncryptionService {
  constructor() {
    this.aes = new AESEncryption();
    this.rsa = new RSAEncryption();
    this.elgamal = new ElGamalEncryption();
    this.threshold = new ThresholdCryptography();
  }

  encryptUserData(plaintext, userKey) {
    if (!plaintext) return null;
    const encrypted = this.aes.encryptWithPassword(plaintext, userKey);
    return JSON.stringify(encrypted);
  }

  decryptUserData(encryptedData, userKey) {
    if (!encryptedData) return null;
    const parsed = JSON.parse(encryptedData);
    return this.aes.decryptWithPassword(parsed, userKey);
  }

  deriveUserKey(password, salt) {
    return pbkdf2Sync(password, salt, ENCRYPTION.HASH_ROUNDS.PBKDF2, 32, 'sha512').toString('hex');
  }

  generateUserKeyPair(algorithm = 'rsa') {
    let keyPair;
    switch (algorithm.toLowerCase()) {
      case 'rsa': keyPair = this.rsa.generateKeyPair(); break;
      case 'elgamal': keyPair = this.elgamal.generateKeyPair(); break;
      default: throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    return { ...keyPair, algorithm: algorithm.toUpperCase(), createdAt: new Date().toISOString(), keyId: generateSecureToken(16) };
  }

  publicKeyEncrypt(plaintext, publicKey, algorithm = 'rsa') {
    switch (algorithm.toLowerCase()) {
      case 'rsa': return this.rsa.encrypt(plaintext, publicKey);
      case 'elgamal': return this.elgamal.encrypt(plaintext, publicKey);
      default: throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  privateKeyDecrypt(encryptedData, privateKey, algorithm = 'rsa') {
    switch (algorithm.toLowerCase()) {
      case 'rsa': return this.rsa.decrypt(encryptedData, privateKey);
      case 'elgamal': return this.elgamal.decrypt(encryptedData, privateKey);
      default: throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  createDigitalSignature(data, privateKey, algorithm = 'rsa') {
    let signature;
    const dataHash = HashUtils.sha256(data);
    switch (algorithm.toLowerCase()) {
      case 'rsa': signature = this.rsa.sign(data, privateKey); break;
      default: throw new Error(`Unsupported signature algorithm: ${algorithm}`);
    }
    return { signature, dataHash, algorithm: `${algorithm.toUpperCase()}-SHA256`, timestamp: new Date().toISOString(), signatureId: generateSecureToken(16) };
  }

  verifyDigitalSignature(data, signature, publicKey, algorithm = 'rsa') {
    switch (algorithm.toLowerCase()) {
      case 'rsa': return this.rsa.verify(data, signature, publicKey);
      default: throw new Error(`Unsupported signature algorithm: ${algorithm}`);
    }
  }

  generateToken(length = 32) {
    return randomBytes(length).toString('hex');
  }

  generateSalt(length = 16) {
    return randomBytes(length).toString('hex');
  }

  encryptForStorage(plaintext, masterKey = process.env.ENCRYPTION_MASTER_KEY) {
    if (!plaintext) return null;
    if (!masterKey) throw new Error('Master encryption key not configured');
    const key = Buffer.from(masterKey, 'hex');
    const encrypted = this.aes.encrypt(plaintext, key);
    return JSON.stringify(encrypted);
  }

  decryptFromStorage(encryptedData, masterKey = process.env.ENCRYPTION_MASTER_KEY) {
    if (!encryptedData) return null;
    if (!masterKey) throw new Error('Master encryption key not configured');
    const key = Buffer.from(masterKey, 'hex');
    const parsed = JSON.parse(encryptedData);
    return this.aes.decrypt(parsed, key);
  }

  generateKeyFingerprint(key) {
    return HashUtils.sha256(key);
  }
}

const aesEncryption = new AESEncryption();

export const encrypt = (text, key) => aesEncryption.encrypt(text, key);
export const decrypt = (data, key) => aesEncryption.decrypt(data, key);
// Default export
const encryptionService = new EncryptionService();
export default encryptionService;

