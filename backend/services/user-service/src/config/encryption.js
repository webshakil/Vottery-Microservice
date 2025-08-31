import { randomBytes, scryptSync } from 'node:crypto';

const encryptionConfig = {
  // AES Encryption Configuration
  aes: {
    algorithm: 'aes-256-gcm',
    keyLength: 32, // 256 bits
    ivLength: 16,  // 128 bits
    tagLength: 16, // 128 bits
    saltLength: 32 // 256 bits
  },

  // RSA Configuration
  rsa: {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: process.env.RSA_PASSPHRASE || 'vottery-rsa-passphrase'
    },
    // RSA signing configuration
    signAlgorithm: 'sha256',
    mgf1HashAlgorithm: 'sha256',
    paddingScheme: 'pss'
  },

  // ElGamal Configuration (for threshold cryptography)
  elgamal: {
    keySize: 2048,
    generator: 2,
    hashAlgorithm: 'sha256',
    randomBytes: 32
  },

  // Digital Signature Configuration
  signature: {
    algorithm: 'RSA-SHA256',
    hashAlgorithm: 'sha256',
    encoding: 'base64',
    keyFormat: 'pem'
  },

  // Key Derivation Configuration
  keyDerivation: {
    algorithm: 'pbkdf2',
    iterations: 100000,
    keyLength: 32,
    digest: 'sha256',
    saltLength: 32
  },

  // Threshold Cryptography Configuration
  threshold: {
    minShares: 3, // minimum shares required to decrypt
    totalShares: 5, // total shares to generate
    prime: '2^127-1', // Mersenne prime for finite field
    polynomial: {
      degree: 2 // threshold - 1
    }
  },

  // Hashing Configuration
  hashing: {
    algorithm: 'sha256',
    rounds: 12, // for bcrypt
    pepper: process.env.HASH_PEPPER || 'vottery-pepper-change-in-production',
    iterations: 100000 // for PBKDF2
  },

  // Encryption Key Management
  keyManagement: {
    masterKeyPath: process.env.MASTER_KEY_PATH || './keys/master.key',
    keyRotationInterval: 90 * 24 * 60 * 60 * 1000, // 90 days
    backupEncryption: true,
    keyEscrow: process.env.NODE_ENV === 'production',
    keyVersioning: true
  },

  // Database Encryption Configuration
  database: {
    encryptedFields: [
      'first_name_encrypted',
      'last_name_encrypted',
      'age_encrypted',
      'gender_encrypted',
      'country_encrypted',
      'city_encrypted',
      'preferences_encrypted',
      'bio_encrypted',
      'name_encrypted',
      'type_encrypted',
      'registration_number_encrypted'
    ],
    keyRotation: {
      enabled: true,
      intervalDays: 90,
      batchSize: 1000
    }
  },

  // Secure Random Configuration
  random: {
    bytesLength: 32,
    encoding: 'hex',
    secure: true
  },

  // Zero-Knowledge Proof Configuration
  zkp: {
    commitment: {
      algorithm: 'pedersen',
      generator: 'secp256k1'
    },
    proof: {
      type: 'schnorr',
      hashAlgorithm: 'sha256'
    }
  }
};

// Generate encryption keys helper
export const generateEncryptionKey = () => {
  return randomBytes(encryptionConfig.aes.keyLength);
};

// Generate salt helper
export const generateSalt = (length = encryptionConfig.aes.saltLength) => {
  return randomBytes(length);
};

// Derive key from password helper
export const deriveKey = (password, salt) => {
  return scryptSync(
    password,
    salt,
    encryptionConfig.keyDerivation.keyLength
  );
};

export default encryptionConfig;