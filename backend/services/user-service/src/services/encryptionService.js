// services/encryptionService.js
import { randomBytes, createHash, generateKeyPairSync, publicEncrypt, privateDecrypt, createCipheriv, createDecipheriv } from 'node:crypto';
import bcrypt from 'bcryptjs';

class EncryptionService {
  constructor() {
    this.AES_KEY_SIZE = 32; // 256 bits
    this.RSA_KEY_SIZE = 2048;
    this.ELGAMAL_KEY_SIZE = 2048;
    this.HASH_ROUNDS = 12;
  }

  // RSA Key Generation
  generateRSAKeyPair() {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: this.RSA_KEY_SIZE,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey, fingerprint: this.generateKeyFingerprint(publicKey) };
  }

  encryptRSA(data, publicKey) {
    if (typeof data !== 'string') data = JSON.stringify(data);
    const buffer = Buffer.from(data, 'utf8');
    const encrypted = publicEncrypt(publicKey, buffer);
    return encrypted.toString('base64');
  }

  decryptRSA(encryptedData, privateKey) {
    const buffer = Buffer.from(encryptedData, 'base64');
    const decrypted = privateDecrypt(privateKey, buffer);
    return decrypted.toString('utf8');
  }

  // ElGamal (simplified using RSA)
  generateElGamalKeyPair() {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: this.ELGAMAL_KEY_SIZE,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey, fingerprint: this.generateKeyFingerprint(publicKey), algorithm: 'elgamal-rsa' };
  }

  encryptElGamal(data, publicKey) {
    const randomness = randomBytes(16).toString('hex');
    return this.encryptRSA(`${randomness}:${data}`, publicKey);
  }

  decryptElGamal(encryptedData, privateKey) {
    const decryptedWithRandomness = this.decryptRSA(encryptedData, privateKey);
    const [, originalData] = decryptedWithRandomness.split(':');
    return originalData;
  }

  // AES Encryption
  encryptAES(data, key) {
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return { encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
  }

  decryptAES(encryptedData, key, iv, authTag) {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  generateAESKey() {
    return randomBytes(this.AES_KEY_SIZE);
  }

  hashSHA256(data) {
    return createHash('sha256').update(data).digest('hex');
  }

  async hashPassword(password) {
    return await bcrypt.hash(password, this.HASH_ROUNDS);
  }

  async verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
  }

  generateKeyFingerprint(publicKey) {
    return createHash('sha256').update(publicKey).digest('hex').substring(0, 32);
  }

  generateSecureRandom(length = 32) {
    return randomBytes(length);
  }

  generateNonce() {
    return randomBytes(16).toString('hex');
  }

  // Encrypt profile data (hybrid AES + RSA)
  async encryptProfileData(data, userPublicKey) {
    const aesKey = this.generateAESKey();
    const encryptedData = this.encryptAES(JSON.stringify(data), aesKey);
    const encryptedAESKey = this.encryptRSA(aesKey.toString('hex'), userPublicKey);
    return { encryptedData: encryptedData.encrypted, encryptedKey: encryptedAESKey, iv: encryptedData.iv, authTag: encryptedData.authTag, algorithm: 'aes-256-gcm-rsa' };
  }

  async decryptProfileData(encryptedProfile, userPrivateKey) {
    const aesKey = Buffer.from(this.decryptRSA(encryptedProfile.encryptedKey, userPrivateKey), 'hex');
    const decryptedData = this.decryptAES(encryptedProfile.encryptedData, aesKey, encryptedProfile.iv, encryptedProfile.authTag);
    return JSON.parse(decryptedData);
  }
}

export default new EncryptionService();

// // services/encryptionService.js. this code has problem
// import { randomBytes, createHash, generateKeyPairSync, publicEncrypt, privateDecrypt } from 'node:crypto';
// import { promisify } from 'node:util';
// import bcrypt from 'bcryptjs';

// class EncryptionService {
//   constructor() {
//     this.AES_KEY_SIZE = 32; // 256 bits
//     this.RSA_KEY_SIZE = 2048;
//     this.ELGAMAL_KEY_SIZE = 2048;
//     this.HASH_ROUNDS = 12;
//   }

//   // RSA Key Generation
//   generateRSAKeyPair() {
//     try {
//       const { publicKey, privateKey } = generateKeyPairSync('rsa', {
//         modulusLength: this.RSA_KEY_SIZE,
//         publicKeyEncoding: {
//           type: 'spki',
//           format: 'pem'
//         },
//         privateKeyEncoding: {
//           type: 'pkcs8',
//           format: 'pem'
//         }
//       });

//       return {
//         publicKey,
//         privateKey,
//         fingerprint: this.generateKeyFingerprint(publicKey)
//       };
//     } catch (error) {
//       throw new Error(`RSA key generation failed: ${error.message}`);
//     }
//   }

//   // RSA Encryption
//   encryptRSA(data, publicKey) {
//     try {
//       if (typeof data !== 'string') {
//         data = JSON.stringify(data);
//       }
      
//       const buffer = Buffer.from(data, 'utf8');
//       const encrypted = publicEncrypt(publicKey, buffer);
//       return encrypted.toString('base64');
//     } catch (error) {
//       throw new Error(`RSA encryption failed: ${error.message}`);
//     }
//   }

//   // RSA Decryption
//   decryptRSA(encryptedData, privateKey) {
//     try {
//       const buffer = Buffer.from(encryptedData, 'base64');
//       const decrypted = privateDecrypt(privateKey, buffer);
//       return decrypted.toString('utf8');
//     } catch (error) {
//       throw new Error(`RSA decryption failed: ${error.message}`);
//     }
//   }

//   // ElGamal Key Generation (Simplified Implementation)
//   generateElGamalKeyPair() {
//     try {
//       // Using RSA as base for ElGamal-style encryption
//       const { publicKey, privateKey } = generateKeyPairSync('rsa', {
//         modulusLength: this.ELGAMAL_KEY_SIZE,
//         publicKeyEncoding: {
//           type: 'spki',
//           format: 'pem'
//         },
//         privateKeyEncoding: {
//           type: 'pkcs8',
//           format: 'pem'
//         }
//       });

//       return {
//         publicKey,
//         privateKey,
//         fingerprint: this.generateKeyFingerprint(publicKey),
//         algorithm: 'elgamal-rsa'
//       };
//     } catch (error) {
//       throw new Error(`ElGamal key generation failed: ${error.message}`);
//     }
//   }

//   // ElGamal Encryption (Using RSA as base)
//   encryptElGamal(data, publicKey) {
//     try {
//       // Add randomness for semantic security
//       const randomness = randomBytes(16).toString('hex');
//       const dataWithRandomness = `${randomness}:${data}`;
      
//       return this.encryptRSA(dataWithRandomness, publicKey);
//     } catch (error) {
//       throw new Error(`ElGamal encryption failed: ${error.message}`);
//     }
//   }

//   // ElGamal Decryption
//   decryptElGamal(encryptedData, privateKey) {
//     try {
//       const decryptedWithRandomness = this.decryptRSA(encryptedData, privateKey);
//       const [randomness, originalData] = decryptedWithRandomness.split(':');
//       return originalData;
//     } catch (error) {
//       throw new Error(`ElGamal decryption failed: ${error.message}`);
//     }
//   }

//   // AES Encryption for large data
//   encryptAES(data, key) {
//     try {
//       const { createCipheriv } = await import('node:crypto');
//       const iv = randomBytes(16);
//       const cipher = createCipheriv('aes-256-gcm', key, iv);
      
//       let encrypted = cipher.update(data, 'utf8', 'hex');
//       encrypted += cipher.final('hex');
      
//       const authTag = cipher.getAuthTag();
      
//       return {
//         encrypted,
//         iv: iv.toString('hex'),
//         authTag: authTag.toString('hex')
//       };
//     } catch (error) {
//       throw new Error(`AES encryption failed: ${error.message}`);
//     }
//   }

//   // AES Decryption
//   async decryptAES(encryptedData, key, iv, authTag) {
//     try {
//       const { createDecipheriv } = await import('node:crypto');
//       const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
//       decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      
//       let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
//       decrypted += decipher.final('utf8');
      
//       return decrypted;
//     } catch (error) {
//       throw new Error(`AES decryption failed: ${error.message}`);
//     }
//   }

//   // Generate secure random AES key
//   generateAESKey() {
//     return randomBytes(this.AES_KEY_SIZE);
//   }

//   // Hash functions
//   hashSHA256(data) {
//     return createHash('sha256').update(data).digest('hex');
//   }

//   // Bcrypt for passwords
//   async hashPassword(password) {
//     try {
//       return await bcrypt.hash(password, this.HASH_ROUNDS);
//     } catch (error) {
//       throw new Error(`Password hashing failed: ${error.message}`);
//     }
//   }

//   async verifyPassword(password, hash) {
//     try {
//       return await bcrypt.compare(password, hash);
//     } catch (error) {
//       throw new Error(`Password verification failed: ${error.message}`);
//     }
//   }

//   // Generate key fingerprint
//   generateKeyFingerprint(publicKey) {
//     return createHash('sha256').update(publicKey).digest('hex').substring(0, 32);
//   }

//   // Threshold Cryptography (Simplified Shamir's Secret Sharing)
//   generateThresholdShares(secret, threshold, totalShares) {
//     try {
//       const shares = [];
//       const secretNum = BigInt(`0x${Buffer.from(secret).toString('hex')}`);
      
//       // Generate random coefficients for polynomial
//       const coefficients = [secretNum];
//       for (let i = 1; i < threshold; i++) {
//         coefficients.push(BigInt(`0x${randomBytes(32).toString('hex')}`));
//       }
      
//       // Generate shares
//       for (let x = 1; x <= totalShares; x++) {
//         let y = coefficients[0];
//         let xPower = BigInt(x);
        
//         for (let i = 1; i < threshold; i++) {
//           y += coefficients[i] * xPower;
//           xPower *= BigInt(x);
//         }
        
//         shares.push({
//           x,
//           y: y.toString(16),
//           threshold,
//           created_at: new Date().toISOString()
//         });
//       }
      
//       return shares;
//     } catch (error) {
//       throw new Error(`Threshold share generation failed: ${error.message}`);
//     }
//   }

//   // Reconstruct secret from threshold shares
//   reconstructFromShares(shares) {
//     try {
//       if (shares.length < shares[0].threshold) {
//         throw new Error('Insufficient shares for reconstruction');
//       }
      
//       const threshold = shares[0].threshold;
//       const selectedShares = shares.slice(0, threshold);
      
//       let secret = BigInt(0);
      
//       for (let i = 0; i < threshold; i++) {
//         let numerator = BigInt(1);
//         let denominator = BigInt(1);
        
//         for (let j = 0; j < threshold; j++) {
//           if (i !== j) {
//             numerator *= BigInt(-selectedShares[j].x);
//             denominator *= BigInt(selectedShares[i].x - selectedShares[j].x);
//           }
//         }
        
//         const lagrangeCoeff = numerator / denominator;
//         secret += lagrangeCoeff * BigInt(`0x${selectedShares[i].y}`);
//       }
      
//       return Buffer.from(secret.toString(16), 'hex').toString();
//     } catch (error) {
//       throw new Error(`Secret reconstruction failed: ${error.message}`);
//     }
//   }

//   // Secure random generation
//   generateSecureRandom(length = 32) {
//     return randomBytes(length);
//   }

//   // Generate nonce
//   generateNonce() {
//     return randomBytes(16).toString('hex');
//   }

//   // Encrypt user profile data
//   async encryptProfileData(data, userPublicKey) {
//     try {
//       // For large data, use hybrid encryption (AES + RSA)
//       const aesKey = this.generateAESKey();
//       const encryptedData = await this.encryptAES(JSON.stringify(data), aesKey);
//       const encryptedAESKey = this.encryptRSA(aesKey.toString('hex'), userPublicKey);
      
//       return {
//         encryptedData: encryptedData.encrypted,
//         encryptedKey: encryptedAESKey,
//         iv: encryptedData.iv,
//         authTag: encryptedData.authTag,
//         algorithm: 'aes-256-gcm-rsa'
//       };
//     } catch (error) {
//       throw new Error(`Profile data encryption failed: ${error.message}`);
//     }
//   }

//   // Decrypt user profile data
//   async decryptProfileData(encryptedProfile, userPrivateKey) {
//     try {
//       const aesKey = Buffer.from(this.decryptRSA(encryptedProfile.encryptedKey, userPrivateKey), 'hex');
//       const decryptedData = await this.decryptAES(
//         encryptedProfile.encryptedData,
//         aesKey,
//         encryptedProfile.iv,
//         encryptedProfile.authTag
//       );
      
//       return JSON.parse(decryptedData);
//     } catch (error) {
//       throw new Error(`Profile data decryption failed: ${error.message}`);
//     }
//   }
// }

// export default new EncryptionService();