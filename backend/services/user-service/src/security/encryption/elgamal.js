import { randomBytes, createHash } from 'node:crypto';
import  logger  from '../../utils/logger.js';
import encryptionConfig from '../../config/encryption.js';

class ElGamalEncryption {
  constructor() {
    this.config = encryptionConfig.elgamal;
    this.keySize = this.config.keySize;
  }

  /**
   * Generate a large prime number (simplified for demonstration)
   * In production, use a cryptographically secure prime generation library
   * @param {number} bits - Number of bits for the prime
   * @returns {bigint} Large prime number
   */
  generateLargePrime(bits = this.keySize) {
    // This is a simplified implementation
    // In production, use a proper cryptographic library for prime generation
    const bytes = Math.ceil(bits / 8);
    let prime;
    
    do {
      const buffer = randomBytes(bytes);
      buffer[0] |= 0x80; // Ensure the number is large enough
      buffer[bytes - 1] |= 0x01; // Ensure the number is odd
      prime = BigInt('0x' + buffer.toString('hex'));
    } while (!this.isProbablyPrime(prime));
    
    return prime;
  }

  /**
   * Miller-Rabin primality test (simplified)
   * @param {bigint} n - Number to test
   * @param {number} k - Number of rounds
   * @returns {boolean} Whether the number is probably prime
   */
  isProbablyPrime(n, k = 5) {
    if (n === 2n || n === 3n) return true;
    if (n < 2n || n % 2n === 0n) return false;

    // Write n-1 as 2^r * d
    let r = 0n;
    let d = n - 1n;
    while (d % 2n === 0n) {
      r++;
      d /= 2n;
    }

    // Witness loop
    for (let i = 0; i < k; i++) {
      const a = BigInt(Math.floor(Math.random() * Number(n - 4n))) + 2n;
      let x = this.modPow(a, d, n);

      if (x === 1n || x === n - 1n) continue;

      let composite = true;
      for (let j = 0n; j < r - 1n; j++) {
        x = this.modPow(x, 2n, n);
        if (x === n - 1n) {
          composite = false;
          break;
        }
      }

      if (composite) return false;
    }

    return true;
  }

  /**
   * Modular exponentiation
   * @param {bigint} base 
   * @param {bigint} exponent 
   * @param {bigint} modulus 
   * @returns {bigint}
   */
  modPow(base, exponent, modulus) {
    let result = 1n;
    base = base % modulus;
    
    while (exponent > 0n) {
      if (exponent % 2n === 1n) {
        result = (result * base) % modulus;
      }
      exponent = exponent >> 1n;
      base = (base * base) % modulus;
    }
    
    return result;
  }

  /**
   * Find a primitive root modulo p
   * @param {bigint} p - Prime modulus
   * @returns {bigint} Primitive root
   */
  findPrimitiveRoot(p) {
    if (p === 2n) return 1n;
    
    const p1 = p - 1n;
    const factors = this.primeFactors(p1);
    
    for (let g = 2n; g < p; g++) {
      let isPrimitive = true;
      
      for (const factor of factors) {
        if (this.modPow(g, p1 / factor, p) === 1n) {
          isPrimitive = false;
          break;
        }
      }
      
      if (isPrimitive) return g;
    }
    
    return 2n; // Fallback
  }

  /**
   * Get prime factors (simplified)
   * @param {bigint} n 
   * @returns {Array<bigint>}
   */
  primeFactors(n) {
    const factors = [];
    let d = 2n;
    
    while (d * d <= n) {
      while (n % d === 0n) {
        factors.push(d);
        n /= d;
      }
      d++;
    }
    
    if (n > 1n) factors.push(n);
    return [...new Set(factors)];
  }

  /**
   * Generate ElGamal key pair
   * @returns {Object} Key pair object
   */
  generateKeyPair() {
    try {
      logger.info('Generating ElGamal key pair...');
      
      // Generate large prime p
      const p = this.generateLargePrime(this.keySize);
      
      // Find primitive root g
      const g = this.findPrimitiveRoot(p);
      
      // Generate private key x (random integer between 1 and p-2)
      const xBytes = randomBytes(32);
      const x = BigInt('0x' + xBytes.toString('hex')) % (p - 2n) + 1n;
      
      // Calculate public key y = g^x mod p
      const y = this.modPow(g, x, p);

      const keyPair = {
        publicKey: {
          p: p.toString(),
          g: g.toString(),
          y: y.toString(),
          algorithm: 'elgamal',
          keySize: this.keySize
        },
        privateKey: {
          p: p.toString(),
          g: g.toString(),
          x: x.toString(),
          algorithm: 'elgamal',
          keySize: this.keySize
        }
      };

      logger.info('ElGamal key pair generated successfully');
      return keyPair;
    } catch (error) {
      logger.error('ElGamal key pair generation failed:', error);
      throw new Error('Failed to generate ElGamal key pair');
    }
  }

  /**
   * Encrypt data using ElGamal public key
   * @param {string|Buffer} data - Data to encrypt
   * @param {Object} publicKey - ElGamal public key
   * @returns {Object} Encrypted data with c1 and c2 components
   */
  encrypt(data, publicKey) {
    try {
      if (!data || !publicKey) {
        throw new Error('Data and public key are required');
      }

      const { p, g, y } = publicKey;
      const pBig = BigInt(p);
      const gBig = BigInt(g);
      const yBig = BigInt(y);

      // Convert data to number (for simplicity, hash it first)
      const hash = createHash('sha256').update(data).digest();
      const m = BigInt('0x' + hash.toString('hex')) % pBig;

      // Generate random k
      const kBytes = randomBytes(32);
      const k = BigInt('0x' + kBytes.toString('hex')) % (pBig - 2n) + 1n;

      // Calculate c1 = g^k mod p
      const c1 = this.modPow(gBig, k, pBig);

      // Calculate c2 = m * y^k mod p
      const c2 = (m * this.modPow(yBig, k, pBig)) % pBig;

      return {
        c1: c1.toString(),
        c2: c2.toString(),
        algorithm: 'elgamal'
      };
    } catch (error) {
      logger.error('ElGamal encryption failed:', error);
      throw new Error('ElGamal encryption failed');
    }
  }

  /**
   * Decrypt data using ElGamal private key
   * @param {Object} ciphertext - Encrypted data with c1 and c2
   * @param {Object} privateKey - ElGamal private key
   * @returns {string} Decrypted data hash
   */
  decrypt(ciphertext, privateKey) {
    try {
      if (!ciphertext || !privateKey) {
        throw new Error('Ciphertext and private key are required');
      }

      const { c1, c2 } = ciphertext;
      const { p, x } = privateKey;
      const pBig = BigInt(p);
      const xBig = BigInt(x);
      const c1Big = BigInt(c1);
      const c2Big = BigInt(c2);

      // Calculate s = c1^x mod p
      const s = this.modPow(c1Big, xBig, pBig);

      // Calculate modular inverse of s
      const sInv = this.modInverse(s, pBig);

      // Calculate m = c2 * s^(-1) mod p
      const m = (c2Big * sInv) % pBig;

      return m.toString(16).padStart(64, '0');
    } catch (error) {
      logger.error('ElGamal decryption failed:', error);
      throw new Error('ElGamal decryption failed');
    }
  }

  /**
   * Calculate modular inverse using extended Euclidean algorithm
   * @param {bigint} a 
   * @param {bigint} m 
   * @returns {bigint}
   */
  modInverse(a, m) {
    if (a < 0n) a = ((a % m) + m) % m;
    
    const [gcd, x] = this.extendedGcd(a, m);
    
    if (gcd !== 1n) {
      throw new Error('Modular inverse does not exist');
    }
    
    return ((x % m) + m) % m;
  }

  /**
   * Extended Euclidean algorithm
   * @param {bigint} a 
   * @param {bigint} b 
   * @returns {Array} [gcd, x, y] where ax + by = gcd
   */
  extendedGcd(a, b) {
    if (a === 0n) return [b, 0n, 1n];
    
    const [gcd, x1, y1] = this.extendedGcd(b % a, a);
    const x = y1 - (b / a) * x1;
    const y = x1;
    
    return [gcd, x, y];
  }

  /**
   * Get key fingerprint
   * @param {Object} key - Public or private key
   * @returns {string} SHA-256 fingerprint
   */
  getKeyFingerprint(key) {
    try {
      const keyString = JSON.stringify(key);
      return createHash('sha256').update(keyString).digest('hex');
    } catch (error) {
      logger.error('ElGamal key fingerprint generation failed:', error);
      throw new Error('Failed to generate key fingerprint');
    }
  }
}

export default new ElGamalEncryption();