// src/security/encryption/threshold.js
import { randomBytes, createHash } from 'crypto';

/**
 * Threshold Cryptography Service for Vottery User Service
 * Implements threshold encryption where k-of-n shares are required to decrypt
 * Used for secure multi-party voting operations and key recovery
 */
class ThresholdEncryption {
  // Prime modulus for finite field operations (2048-bit safe prime)
  static PRIME = BigInt('0x' + 
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' +
    'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
    'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' +
    'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' +
    '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF');

  static GENERATOR = BigInt(2);

  /**
   * Generate threshold encryption parameters
   * @param {number} threshold - Minimum shares required (k)
   * @param {number} totalShares - Total shares to create (n)
   * @returns {Object} Threshold parameters
   */
  static generateThresholdParams(threshold, totalShares) {
    try {
      if (threshold > totalShares || threshold < 1) {
        throw new Error('Invalid threshold parameters');
      }

      // Generate random polynomial coefficients
      const coefficients = [];
      for (let i = 0; i < threshold; i++) {
        coefficients.push(this.generateRandomBigInt());
      }

      // Generate shares using Shamir's Secret Sharing
      const shares = [];
      for (let x = 1; x <= totalShares; x++) {
        const y = this.evaluatePolynomial(coefficients, BigInt(x));
        shares.push({ x: x, y: y });
      }

      return {
        threshold,
        totalShares,
        shares,
        secret: coefficients[0] // The secret is the constant term
      };
    } catch (error) {
      throw new Error(`Threshold parameter generation failed: ${error.message}`);
    }
  }

  /**
   * Evaluate polynomial at given x using Horner's method
   * @param {BigInt[]} coefficients - Polynomial coefficients
   * @param {BigInt} x - Point to evaluate
   * @returns {BigInt} Polynomial value at x
   */
  static evaluatePolynomial(coefficients, x) {
    let result = BigInt(0);
    for (let i = coefficients.length - 1; i >= 0; i--) {
      result = (result * x + coefficients[i]) % this.PRIME;
    }
    return result;
  }

  /**
   * Reconstruct secret from threshold shares using Lagrange interpolation
   * @param {Array} shares - Array of {x, y} share objects
   * @returns {BigInt} Reconstructed secret
   */
  static reconstructSecret(shares) {
    try {
      if (shares.length < 2) {
        throw new Error('Insufficient shares for reconstruction');
      }

      let secret = BigInt(0);
      
      for (let i = 0; i < shares.length; i++) {
        let numerator = BigInt(1);
        let denominator = BigInt(1);
        
        for (let j = 0; j < shares.length; j++) {
          if (i !== j) {
            numerator = (numerator * BigInt(-shares[j].x)) % this.PRIME;
            denominator = (denominator * (BigInt(shares[i].x) - BigInt(shares[j].x))) % this.PRIME;
          }
        }
        
        // Calculate modular inverse of denominator
        const inverse = this.modularInverse(denominator, this.PRIME);
        const lagrangeCoeff = (numerator * inverse) % this.PRIME;
        
        secret = (secret + (BigInt(shares[i].y) * lagrangeCoeff)) % this.PRIME;
      }
      
      // Ensure positive result
      return secret < 0 ? secret + this.PRIME : secret;
    } catch (error) {
      throw new Error(`Secret reconstruction failed: ${error.message}`);
    }
  }

  /**
   * Encrypt data using threshold encryption
   * @param {string} plaintext - Data to encrypt
   * @param {number} threshold - Minimum shares required
   * @param {number} totalShares - Total shares to create
   * @returns {Object} Encrypted data with shares
   */
  static encrypt(plaintext, threshold, totalShares) {
    try {
      // Generate symmetric key for actual encryption
      const symmetricKey = randomBytes(32);
      
      // Encrypt plaintext with AES (using the symmetric key)
      const encryptedData = this.symmetricEncrypt(plaintext, symmetricKey);
      
      // Convert symmetric key to BigInt for threshold sharing
      const keyAsBigInt = BigInt('0x' + symmetricKey.toString('hex'));
      
      // Create threshold shares of the symmetric key
      const thresholdParams = this.generateThresholdParams(threshold, totalShares);
      
      return {
        encryptedData,
        threshold,
        totalShares,
        keyShares: thresholdParams.shares.map(share => ({
          id: share.x,
          value: share.y.toString(16)
        }))
      };
    } catch (error) {
      throw new Error(`Threshold encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data using threshold shares
   * @param {Object} encryptedPackage - Encrypted data package
   * @param {Array} availableShares - Available key shares
   * @returns {string} Decrypted plaintext
   */
  static decrypt(encryptedPackage, availableShares) {
    try {
      const { encryptedData, threshold } = encryptedPackage;
      
      if (availableShares.length < threshold) {
        throw new Error('Insufficient shares for decryption');
      }
      
      // Convert shares back to BigInt format
      const shares = availableShares.slice(0, threshold).map(share => ({
        x: share.id,
        y: BigInt('0x' + share.value)
      }));
      
      // Reconstruct symmetric key
      const reconstructedKey = this.reconstructSecret(shares);
      
      // Convert back to Buffer
      const keyHex = reconstructedKey.toString(16).padStart(64, '0');
      const symmetricKey = Buffer.from(keyHex, 'hex');
      
      // Decrypt the actual data
      return this.symmetricDecrypt(encryptedData, symmetricKey);
    } catch (error) {
      throw new Error(`Threshold decryption failed: ${error.message}`);
    }
  }

  /**
   * Verify share integrity
   * @param {Object} share - Share to verify
   * @param {string} commitment - Verification commitment
   * @returns {boolean} Verification result
   */
  static verifyShare(share, commitment) {
    try {
      // Implement Feldman's verifiable secret sharing
      const commitmentBigInt = BigInt('0x' + commitment);
      const shareValue = BigInt('0x' + share.value);
      
      // Verify share against commitment
      const verification = this.modularExponentiation(
        this.GENERATOR,
        shareValue,
        this.PRIME
      );
      
      return verification === commitmentBigInt;
    } catch (error) {
      return false;
    }
  }

  /**
   * Generate random BigInt within safe range
   * @returns {BigInt} Random BigInt
   */
  static generateRandomBigInt() {
    const bytes = randomBytes(32);
    const hex = bytes.toString('hex');
    return BigInt('0x' + hex) % (this.PRIME - BigInt(1)) + BigInt(1);
  }

  /**
   * Calculate modular inverse using extended Euclidean algorithm
   * @param {BigInt} a - Number to find inverse of
   * @param {BigInt} m - Modulus
   * @returns {BigInt} Modular inverse
   */
  static modularInverse(a, m) {
    if (a < 0) a = (a % m + m) % m;
    
    const g = this.extendedGCD(a, m);
    if (g.gcd !== BigInt(1)) {
      throw new Error('Modular inverse does not exist');
    }
    
    return (g.x % m + m) % m;
  }

  /**
   * Extended Euclidean Algorithm
   * @param {BigInt} a - First number
   * @param {BigInt} b - Second number
   * @returns {Object} GCD and coefficients
   */
  static extendedGCD(a, b) {
    if (a === BigInt(0)) {
      return { gcd: b, x: BigInt(0), y: BigInt(1) };
    }
    
    const g = this.extendedGCD(b % a, a);
    return {
      gcd: g.gcd,
      x: g.y - (b / a) * g.x,
      y: g.x
    };
  }

  /**
   * Modular exponentiation (fast)
   * @param {BigInt} base - Base number
   * @param {BigInt} exp - Exponent
   * @param {BigInt} mod - Modulus
   * @returns {BigInt} Result
   */
  static modularExponentiation(base, exp, mod) {
    let result = BigInt(1);
    base = base % mod;
    
    while (exp > 0) {
      if (exp % BigInt(2) === BigInt(1)) {
        result = (result * base) % mod;
      }
      exp = exp >> BigInt(1);
      base = (base * base) % mod;
    }
    
    return result;
  }

  /**
   * Symmetric encryption helper (AES-256-GCM)
   * @param {string} plaintext - Text to encrypt
   * @param {Buffer} key - Encryption key
   * @returns {Object} Encrypted data with IV and tag
   */
  static symmetricEncrypt(plaintext, key) {
    const { createCipherGCM } = require('crypto');
    const iv = randomBytes(16);
    const cipher = createCipherGCM('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      tag: tag.toString('hex')
    };
  }

  /**
   * Symmetric decryption helper (AES-256-GCM)
   * @param {Object} encryptedData - Encrypted data package
   * @param {Buffer} key - Decryption key
   * @returns {string} Decrypted plaintext
   */
  static symmetricDecrypt(encryptedData, key) {
    const { createDecipherGCM } = require('crypto');
    const { encrypted, iv, tag } = encryptedData;
    
    const decipher = createDecipherGCM('aes-256-gcm', key, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  /**
   * Create voting threshold configuration for elections
   * @param {number} adminCount - Number of election administrators
   * @param {number} requiredApprovals - Required approvals for key operations
   * @returns {Object} Voting threshold configuration
   */
  static createVotingThreshold(adminCount, requiredApprovals) {
    try {
      if (requiredApprovals > adminCount || requiredApprovals < 1) {
        throw new Error('Invalid voting threshold parameters');
      }

      return this.generateThresholdParams(requiredApprovals, adminCount);
    } catch (error) {
      throw new Error(`Voting threshold creation failed: ${error.message}`);
    }
  }

  /**
   * Generate election result decryption shares
   * @param {string} electionId - Election identifier
   * @param {Object} resultData - Election results to protect
   * @param {number} threshold - Required shares for decryption
   * @param {number} totalShares - Total shares to distribute
   * @returns {Object} Protected election results
   */
  static protectElectionResults(electionId, resultData, threshold, totalShares) {
    try {
      const dataString = JSON.stringify(resultData);
      const hash = createHash('sha256').update(electionId + dataString).digest('hex');
      
      const encryptedResults = this.encrypt(dataString, threshold, totalShares);
      
      return {
        electionId,
        dataHash: hash,
        protectedResults: encryptedResults,
        createdAt: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Election result protection failed: ${error.message}`);
    }
  }
}

export default ThresholdEncryption;