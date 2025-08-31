import { generateKeyPairSync, publicEncrypt, privateDecrypt, sign, verify, createHash } from 'node:crypto';
import  logger  from '../../utils/logger.js';
import encryptionConfig from '../../config/encryption.js';

class RSAEncryption {
  constructor() {
    this.config = encryptionConfig.rsa;
  }

  /**
   * Generate RSA key pair
   * @returns {Object} Object containing public and private keys
   */
  generateKeyPair() {
    try {
      const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: this.config.modulusLength,
        publicKeyEncoding: this.config.publicKeyEncoding,
        privateKeyEncoding: this.config.privateKeyEncoding
      });

      logger.info('RSA key pair generated successfully');
      return {
        publicKey,
        privateKey,
        algorithm: 'rsa',
        keySize: this.config.modulusLength
      };
    } catch (error) {
      logger.error('RSA key pair generation failed:', error);
      throw new Error('Failed to generate RSA key pair');
    }
  }

  /**
   * Encrypt data using RSA public key
   * @param {string|Buffer} data - Data to encrypt
   * @param {string} publicKey - RSA public key in PEM format
   * @returns {string} Base64 encoded encrypted data
   */
  encrypt(data, publicKey) {
    try {
      if (!data || !publicKey) {
        throw new Error('Data and public key are required');
      }

      const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
      const encrypted = publicEncrypt(
        {
          key: publicKey,
          padding: this.config.paddingScheme === 'pss' ? 
            crypto.constants.RSA_PKCS1_OAEP_PADDING : 
            crypto.constants.RSA_PKCS1_PADDING
        },
        buffer
      );

      return encrypted.toString('base64');
    } catch (error) {
      logger.error('RSA encryption failed:', error);
      throw new Error('RSA encryption failed');
    }
  }

  /**
   * Decrypt data using RSA private key
   * @param {string} encryptedData - Base64 encoded encrypted data
   * @param {string} privateKey - RSA private key in PEM format
   * @param {string} passphrase - Optional passphrase for private key
   * @returns {string} Decrypted data
   */
  decrypt(encryptedData, privateKey, passphrase) {
    try {
      if (!encryptedData || !privateKey) {
        throw new Error('Encrypted data and private key are required');
      }

      const buffer = Buffer.from(encryptedData, 'base64');
      const keyObject = passphrase ? { key: privateKey, passphrase } : privateKey;
      
      const decrypted = privateDecrypt(
        {
          key: keyObject,
          padding: this.config.paddingScheme === 'pss' ? 
            crypto.constants.RSA_PKCS1_OAEP_PADDING : 
            crypto.constants.RSA_PKCS1_PADDING
        },
        buffer
      );

      return decrypted.toString('utf8');
    } catch (error) {
      logger.error('RSA decryption failed:', error);
      throw new Error('RSA decryption failed');
    }
  }

  /**
   * Sign data using RSA private key
   * @param {string|Buffer} data - Data to sign
   * @param {string} privateKey - RSA private key in PEM format
   * @param {string} passphrase - Optional passphrase for private key
   * @returns {string} Base64 encoded signature
   */
  sign(data, privateKey, passphrase) {
    try {
      if (!data || !privateKey) {
        throw new Error('Data and private key are required');
      }

      const keyObject = passphrase ? { key: privateKey, passphrase } : privateKey;
      const signature = sign(this.config.signAlgorithm, Buffer.from(data), {
        key: keyObject,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        mgf: crypto.constants.RSA_MGF1,
        mgf1HashAlgorithm: this.config.mgf1HashAlgorithm
      });

      return signature.toString('base64');
    } catch (error) {
      logger.error('RSA signing failed:', error);
      throw new Error('RSA signing failed');
    }
  }

  /**
   * Verify signature using RSA public key
   * @param {string|Buffer} data - Original data
   * @param {string} signature - Base64 encoded signature
   * @param {string} publicKey - RSA public key in PEM format
   * @returns {boolean} Verification result
   */
  verify(data, signature, publicKey) {
    try {
      if (!data || !signature || !publicKey) {
        throw new Error('Data, signature, and public key are required');
      }

      const signatureBuffer = Buffer.from(signature, 'base64');
      const isValid = verify(
        this.config.signAlgorithm,
        Buffer.from(data),
        {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          mgf: crypto.constants.RSA_MGF1,
          mgf1HashAlgorithm: this.config.mgf1HashAlgorithm
        },
        signatureBuffer
      );

      return isValid;
    } catch (error) {
      logger.error('RSA verification failed:', error);
      return false;
    }
  }

  /**
   * Get key fingerprint
   * @param {string} key - Public or private key in PEM format
   * @returns {string} SHA-256 fingerprint of the key
   */
  getKeyFingerprint(key) {
    try {
      return createHash('sha256').update(key).digest('hex');
    } catch (error) {
      logger.error('Key fingerprint generation failed:', error);
      throw new Error('Failed to generate key fingerprint');
    }
  }
}

export default new RSAEncryption();

// import { generateKeyPairSync, publicEncrypt, privateDecrypt, sign, verify } from 'node:crypto';
// import { logger } from '../../utils/logger.js';
// import encryptionConfig from '../../config/encryption.js';

// class RSAEncryption {
//   constructor() {
//     this.config = encryptionConfig.rsa;
//   }

//   /**
//    * Generate RSA key pair
//    * @returns {Object} Object containing public and private keys
//    */
//   generateKeyPair() {
//     try {
//       const { publicKey, privateKey } = generateKeyPairSync('rsa', {
//         modulusLength: this.config.modulusLength,
//         publicKeyEncoding: this.config.publicKeyEncoding,
//         privateKeyEncoding: this.config.privateKeyEncoding
//       });

//       logger.info('RSA key pair generated successfully');
//       return {
//         publicKey,
//         privateKey,
//         algorithm: 'rsa',
//         keySize: this.config.modulusLength
//       };
//     } catch (error) {
//       logger.error('RSA key pair generation failed:', error);
//       throw new Error('Failed to generate RSA key pair');
//     }
//   }

//   /**
//    * Encrypt data using RSA public key
//    * @param {string|Buffer} data - Data to encrypt
//    * @param {string} publicKey - RSA public key in PEM format
//    * @returns {string} Base64 encoded encrypted data
//    */
//   encrypt(data, publicKey) {
//     try {
//       if (!data || !publicKey) {
//         throw new Error('Data and public key are required');
//       }

//       const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
//       const encrypted = publicEncrypt(
//         {
//           key: publicKey,
//           padding: this.config.paddingScheme === 'pss' ? 
//             crypto.constants.RSA_PKCS1_OAEP_PADDING : 
//             crypto.constants.RSA_PKCS1_PADDING
//         },
//         buffer
//       );

//       return encrypted.toString('base64');
//     } catch (error) {
//       logger.error('RSA encryption failed:', error);
//       throw new Error('RSA encryption failed');
//     }
//   }

//   /**
//    * Decrypt data using RSA private key
//    * @param {string} encryptedData - Base64 encoded encrypted data
//    * @param {string} privateKey - RSA private key in PEM format
//    * @param {string} passphrase - Optional passphrase for private key
//    * @returns {string} Decrypted data
//    */
//   decrypt(encryptedData, privateKey, passphrase) {
//     try {
//       if (!encryptedData || !privateKey) {
//         throw new Error('Encrypted data and private key are required');
//       }

//       const buffer = Buffer.from(encryptedData, 'base64');
//       const keyObject = passphrase ? { key: privateKey, passphrase } : privateKey;
      
//       const decrypted = privateDecrypt(
//         {
//           key: keyObject,
//           padding: this.config.paddingScheme === 'pss' ? 
//             crypto.constants.RSA_PKCS1_OAEP_PADDING : 
//             crypto.constants.RSA_PKCS1_PADDING
//         },
//         buffer
//       );

//       return decrypted.toString('utf8');
//     } catch (error) {
//       logger.error('RSA decryption failed:', error);
//       throw new Error('RSA decryption failed');
//     }
//   }

//   /**
//    * Sign data using RSA private key
//    * @param {string|Buffer} data - Data to sign
//    * @param {string} privateKey - RSA private key in PEM format
//    * @param {string} passphrase - Optional passphrase for private key
//    * @returns {string} Base64 encoded signature
//    */
//   sign(data, privateKey, passphrase) {
//     try {
//       if (!data || !privateKey) {
//         throw new Error('Data and private key are required');
//       }

//       const keyObject = passphrase ? { key: privateKey, passphrase } : privateKey;
//       const signature = sign(this.config.signAlgorithm, Buffer.from(data), {
//         key: keyObject,
//         padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
//         mgf: crypto.constants.RSA_MGF1,
//         mgf1HashAlgorithm: this.config.mgf1HashAlgorithm
//       });

//       return signature.toString('base64');
//     } catch (error) {
//       logger.error('RSA signing failed:', error);
//       throw new Error('RSA signing failed');
//     }
//   }

//   /**
//    * Verify signature using RSA public key
//    * @param {string|Buffer} data - Original data
//    * @param {string} signature - Base64 encoded signature
//    * @param {string} publicKey - RSA public key in PEM format
//    * @returns {boolean} Verification result
//    */
//   verify(data, signature, publicKey) {
//     try {
//       if (!data || !signature || !publicKey) {
//         throw new Error('Data, signature, and public key are required');
//       }

//       const signatureBuffer = Buffer.from(signature, 'base64');
//       const isValid = verify(
//         this.config.signAlgorithm,
//         Buffer.from(data),
//         {
//           key: publicKey,
//           padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
//           mgf: crypto.constants.RSA_MGF1,
//           mgf1HashAlgorithm: this.config.mgf1HashAlgorithm
//         },
//         signatureBuffer
//       );

//       return isValid;
//     } catch (error) {
//       logger.error('RSA verification failed:', error);
//       return false;
//     }
//   }

//   /**
//    * Get key fingerprint
//    * @param {string} key - Public or private key in PEM format
//    * @returns {string} SHA-256 fingerprint of the key
//    */
//   getKeyFingerprint(key) {
//     try {
//       const { createHash } = await import('node:crypto');
//       return createHash('sha256').update(key).digest('hex');
//     } catch (error) {
//       logger.error('Key fingerprint generation failed:', error);
//       throw new Error('Failed to generate key fingerprint');
//     }
//   }
// }

// export default new RSAEncryption();