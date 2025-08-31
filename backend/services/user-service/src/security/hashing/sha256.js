// // src/security/hashing/sha256.js
// import { createHash, createHmac } from 'crypto';

// /**
//  * SHA-256 Hashing Utility for Vottery User Service
//  * Provides secure hashing functionality for data integrity and verification
//  */
// class SHA256Hasher {
//   /**
//    * Generate SHA-256 hash of input data
//    * @param {string|Buffer} data - Data to hash
//    * @param {string} encoding - Output encoding (hex, base64, etc.)
//    * @returns {string} SHA-256 hash
//    */
//   static hash(data, encoding = 'hex') {
//     try {
//       return createHash('sha256')
//         .update(data, 'utf8')
//         .digest(encoding);
//     } catch (error) {
//       throw new Error(`SHA-256 hashing failed: ${error.message}`);
//     }
//   }

//   /**
//    * Generate SHA-256 hash with salt for enhanced security
//    * @param {string} data - Data to hash
//    * @param {string} salt - Salt value
//    * @param {string} encoding - Output encoding
//    * @returns {string} Salted SHA-256 hash
//    */
//   static hashWithSalt(data, salt, encoding = 'hex') {
//     try {
//       const saltedData = `${salt}${data}${salt}`;
//       return this.hash(saltedData, encoding);
//     } catch (error) {
//       throw new Error(`Salted SHA-256 hashing failed: ${error.message}`);
//     }
//   }

//   /**
//    * Generate HMAC-SHA256 for message authentication
//    * @param {string} data - Data to authenticate
//    * @param {string} key - Secret key
//    * @param {string} encoding - Output encoding
//    * @returns {string} HMAC-SHA256 signature
//    */
//   static hmac(data, key, encoding = 'hex') {
//     try {
//       return createHmac('sha256', key)
//         .update(data, 'utf8')
//         .digest(encoding);
//     } catch (error) {
//       throw new Error(`HMAC-SHA256 generation failed: ${error.message}`);
//     }
//   }

//   /**
//    * Verify HMAC-SHA256 signature
//    * @param {string} data - Original data
//    * @param {string} signature - HMAC signature to verify
//    * @param {string} key - Secret key
//    * @returns {boolean} Verification result
//    */
//   static verifyHmac(data, signature, key) {
//     try {
//       const expectedSignature = this.hmac(data, key);
//       return this.constantTimeCompare(signature, expectedSignature);
//     } catch (error) {
//       return false;
//     }
//   }

//   /**
//    * Generate SHA-256 fingerprint for keys or certificates
//    * @param {string|Buffer} data - Key or certificate data
//    * @returns {string} Formatted fingerprint
//    */
//   static generateFingerprint(data) {
//     try {
//       const hash = this.hash(data, 'hex');
//       // Format as fingerprint: XX:XX:XX:XX...
//       return hash.match(/.{2}/g).join(':').toUpperCase();
//     } catch (error) {
//       throw new Error(`Fingerprint generation failed: ${error.message}`);
//     }
//   }

//   /**
//    * Generate SHA-256 hash chain for audit trails
//    * @param {string} previousHash - Previous hash in chain
//    * @param {string} data - Current data to hash
//    * @returns {string} Chain hash
//    */
//   static generateChainHash(previousHash, data) {
//     try {
//       const combinedData = `${previousHash}${data}`;
//       return this.hash(combinedData);
//     } catch (error) {
//       throw new Error(`Chain hash generation failed: ${error.message}`);
//     }
//   }

//   /**
//    * Constant-time string comparison to prevent timing attacks
//    * @param {string} a - First string
//    * @param {string} b - Second string
//    * @returns {boolean} Comparison result
//    */
//   static constantTimeCompare(a, b) {
//     if (a.length !== b.length) {
//       return false;
//     }

//     let result = 0;
//     for (let i = 0; i < a.length; i++) {
//       result |= a.charCodeAt(i) ^ b.charCodeAt(i);
//     }
//     return result === 0;
//   }

//   /**
//    * Generate multiple hash rounds for key derivation
//    * @param {string} data - Input data
//    * @param {number} rounds - Number of hash rounds
//    * @param {string} salt - Optional salt
//    * @returns {string} Multi-round hash
//    */
//   static multiRoundHash(data, rounds = 10000, salt = '') {
//     try {
//       let result = salt + data;
//       for (let i = 0; i < rounds; i++) {
//         result = this.hash(result);
//       }
//       return result;
//     } catch (error) {
//       throw new Error(`Multi-round hashing failed: ${error.message}`);
//     }
//   }

//   /**
//    * Generate secure random salt
//    * @param {number} length - Salt length in bytes
//    * @returns {string} Random salt in hex
//    */
//   static generateSalt(length = 32) {
//     try {
//       const { randomBytes } = await import('crypto');
//       return randomBytes(length).toString('hex');
//     } catch (error) {
//       throw new Error(`Salt generation failed: ${error.message}`);
//     }
//   }

//   /**
//    * Hash election data for integrity verification
//    * @param {Object} electionData - Election data object
//    * @returns {string} Election integrity hash
//    */
//   static hashElectionData(electionData) {
//     try {
//       const canonicalData = JSON.stringify(electionData, Object.keys(electionData).sort());
//       return this.hash(canonicalData);
//     } catch (error) {
//       throw new Error(`Election data hashing failed: ${error.message}`);
//     }
//   }

//   /**
//    * Generate vote hash for verification receipts
//    * @param {Object} voteData - Vote data
//    * @param {string} voterHash - Anonymized voter identifier
//    * @returns {string} Vote verification hash
//    */
//   static generateVoteHash(voteData, voterHash) {
//     try {
//       const voteString = JSON.stringify({
//         vote: voteData,
//         voter: voterHash,
//         timestamp: Date.now()
//       });
//       return this.hash(voteString);
//     } catch (error) {
//       throw new Error(`Vote hash generation failed: ${error.message}`);
//     }
//   }
// }

// export default SHA256Hasher;