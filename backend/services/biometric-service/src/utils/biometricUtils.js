// import { createHash, randomBytes } from 'node:crypto';
// import { EncryptionUtils } from './encryption.js';

// export class BiometricUtils {
//   // Generate biometric hash
//   static generateHash(biometricData) {
//     if (!biometricData) throw new Error('Biometric data is required');
    
//     // Convert biometric data to string if it's an object/array
//     const dataString = typeof biometricData === 'string' ? 
//       biometricData : JSON.stringify(biometricData);
    
//     return EncryptionUtils.generateHash(dataString);
//   }

//   // Verify biometric hash
//   static verifyHash(providedData, storedHash) {
//     const dataString = typeof providedData === 'string' ? 
//       providedData : JSON.stringify(providedData);
    
//     return EncryptionUtils.verifyHash(dataString, storedHash);
//   }

//   // Extract biometric features (simplified)
//   static extractFeatures(biometricData) {
//     // This would be replaced with actual biometric feature extraction
//     // For now, we'll simulate feature extraction
//     if (biometricData.type === 'fingerprint') {
//       return this.extractFingerprintFeatures(biometricData);
//     } else if (biometricData.type === 'face') {
//       return this.extractFaceFeatures(biometricData);
//     }
    
//     return biometricData;
//   }

//   // Simulate fingerprint feature extraction
//   static extractFingerprintFeatures(fingerprintData) {
//     // In production, this would use actual biometric libraries
//     const features = {
//       minutiae: fingerprintData.minutiae || [],
//       ridgePattern: fingerprintData.ridgePattern || 'unknown',
//       corePoints: fingerprintData.corePoints || [],
//       deltaPoints: fingerprintData.deltaPoints || []
//     };
    
//     return JSON.stringify(features);
//   }

//   // Simulate face feature extraction
//   static extractFaceFeatures(faceData) {
//     // In production, this would use facial recognition libraries
//     const features = {
//       encodings: faceData.encodings || [],
//       landmarks: faceData.landmarks || [],
//       geometry: faceData.geometry || {}
//     };
    
//     return JSON.stringify(features);
//   }

//   // Calculate biometric similarity (for verification)
//   static calculateSimilarity(template1, template2) {
//     // Simple similarity calculation (in production, use proper algorithms)
//     if (template1 === template2) return 1.0;
    
//     try {
//       const t1 = JSON.parse(template1);
//       const t2 = JSON.parse(template2);
      
//       // Basic similarity calculation based on common properties
//       let similarity = 0;
//       let totalFeatures = 0;
      
//       for (const key in t1) {
//         if (t2.hasOwnProperty(key)) {
//           totalFeatures++;
//           if (JSON.stringify(t1[key]) === JSON.stringify(t2[key])) {
//             similarity++;
//           }
//         }
//       }
      
//       return totalFeatures > 0 ? similarity / totalFeatures : 0;
//     } catch {
//       return 0;
//     }
//   }

//   // Validate biometric data format
//   static validateBiometricData(data, type) {
//     if (!data) return false;
    
//     switch (type) {
//       case 'fingerprint':
//         return this.validateFingerprintData(data);
//       case 'face':
//         return this.validateFaceData(data);
//       case 'webauthn':
//         return this.validateWebAuthnData(data);
//       default:
//         return false;
//     }
//   }

//   static validateFingerprintData(data) {
//     // Basic validation for fingerprint data
//     return data && (
//       typeof data === 'string' || 
//       (typeof data === 'object' && data.type === 'fingerprint')
//     );
//   }

//   static validateFaceData(data) {
//     // Basic validation for face data
//     return data && (
//       typeof data === 'string' || 
//       (typeof data === 'object' && data.type === 'face')
//     );
//   }

//   static validateWebAuthnData(data) {
//     // Basic validation for WebAuthn data
//     return data && (
//       typeof data === 'string' || 
//       (typeof data === 'object' && (data.id || data.credentialId))
//     );
//   }
// }

// import { createHash, randomBytes } from 'node:crypto';
// import { EncryptionUtils } from './encryption.js';

// export class BiometricUtils {
//   // Generate biometric hash
//   static generateHash(biometricData) {
//     if (!biometricData) throw new Error('Biometric data is required');
    
//     // Convert biometric data to string if it's an object/array
//     const dataString = typeof biometricData === 'string' ? 
//       biometricData : JSON.stringify(biometricData);
    
//     return EncryptionUtils.generateHash(dataString);
//   }

//   // Verify biometric hash
//   static verifyHash(providedData, storedHash) {
//     const dataString = typeof providedData === 'string' ? 
//       providedData : JSON.stringify(providedData);
    
//     return EncryptionUtils.verifyHash(dataString, storedHash);
//   }

//   // Extract biometric features (simplified)
//   static extractFeatures(biometricData) {
//     // This would be replaced with actual biometric feature extraction
//     // For now, we'll simulate feature extraction
//     if (biometricData.type === 'fingerprint') {
//       return this.extractFingerprintFeatures(biometricData);
//     } else if (biometricData.type === 'face') {
//       return this.extractFaceFeatures(biometricData);
//     }
    
//     return biometricData;
//   }

//   // Simulate fingerprint feature extraction
//   static extractFingerprintFeatures(fingerprintData) {
//     // In production, this would use actual biometric libraries
//     const features = {
//       minutiae: fingerprintData.minutiae || [],
//       ridgePattern: fingerprintData.ridgePattern || 'unknown',
//       corePoints: fingerprintData.corePoints || [],
//       deltaPoints: fingerprintData.deltaPoints || []
//     };
    
//     return JSON.stringify(features);
//   }

//   // Simulate face feature extraction
//   static extractFaceFeatures(faceData) {
//     // In production, this would use facial recognition libraries
//     const features = {
//       encodings: faceData.encodings || [],
//       landmarks: faceData.landmarks || [],
//       geometry: faceData.geometry || {}
//     };
    
//     return JSON.stringify(features);
//   }

//   // Calculate biometric similarity (for verification)
//   static calculateSimilarity(template1, template2) {
//     // Simple similarity calculation (in production, use proper algorithms)
//     if (template1 === template2) return 1.0;
    
//     try {
//       const t1 = JSON.parse(template1);
//       const t2 = JSON.parse(template2);
      
//       // Basic similarity calculation based on common properties
//       let similarity = 0;
//       let totalFeatures = 0;
      
//       for (const key in t1) {
//         if (t2.hasOwnProperty(key)) {
//           totalFeatures++;
//           if (JSON.stringify(t1[key]) === JSON.stringify(t2[key])) {
//             similarity++;
//           }
//         }
//       }
      
//       return totalFeatures > 0 ? similarity / totalFeatures : 0;
//     } catch {
//       return 0;
//     }
//   }

//   // Validate biometric data format
//   static validateBiometricData(data, type) {
//     if (!data) return false;
    
//     switch (type) {
//       case 'fingerprint':
//         return this.validateFingerprintData(data);
//       case 'face':
//         return this.validateFaceData(data);
//       case 'webauthn':
//         return this.validateWebAuthnData(data);
//       case 'device_fingerprint': // ADD THIS CASE
//         return this.validateDeviceFingerprintData(data);
//       case 'voice': // ADD THIS CASE
//         return this.validateVoiceData(data);
//       case 'iris': // ADD THIS CASE
//         return this.validateIrisData(data);
//       default:
//         return false;
//     }
//   }

//   static validateFingerprintData(data) {
//     // Basic validation for fingerprint data
//     return data && (
//       typeof data === 'string' || 
//       (typeof data === 'object' && data.type === 'fingerprint')
//     );
//   }

//   static validateFaceData(data) {
//     // Basic validation for face data
//     return data && (
//       typeof data === 'string' || 
//       (typeof data === 'object' && data.type === 'face')
//     );
//   }

//   static validateWebAuthnData(data) {
//     // Basic validation for WebAuthn data
//     return data && (
//       typeof data === 'string' || 
//       (typeof data === 'object' && (data.id || data.credentialId))
//     );
//   }

//   // ADD THESE NEW VALIDATION METHODS
//   static validateDeviceFingerprintData(data) {
//     // Basic validation for device fingerprint data
//     return data && (
//       typeof data === 'string' || 
//       (typeof data === 'object' && (data.fingerprint || data.deviceInfo))
//     );
//   }

//   static validateVoiceData(data) {
//     // Basic validation for voice data
//     return data && (
//       typeof data === 'string' || 
//       (typeof data === 'object' && data.type === 'voice')
//     );
//   }

//   static validateIrisData(data) {
//     // Basic validation for iris data
//     return data && (
//       typeof data === 'string' || 
//       (typeof data === 'object' && data.type === 'iris')
//     );
//   }
// }


import { createHash, randomBytes } from 'node:crypto';
import { EncryptionUtils } from './encryption.js';

export class BiometricUtils {
  // Generate biometric hash
  static generateHash(biometricData) {
    if (!biometricData) throw new Error('Biometric data is required');
    
    // Convert biometric data to string if it's an object/array
    const dataString = typeof biometricData === 'string' ? 
      biometricData : JSON.stringify(biometricData);
    
    return EncryptionUtils.generateHash(dataString);
  }

  // Verify biometric hash
  static verifyHash(providedData, storedHash) {
    const dataString = typeof providedData === 'string' ? 
      providedData : JSON.stringify(providedData);
    
    return EncryptionUtils.verifyHash(dataString, storedHash);
  }

  // Extract biometric features (simplified)
  static extractFeatures(biometricData) {
    // This would be replaced with actual biometric feature extraction
    // For now, we'll simulate feature extraction
    if (biometricData.type === 'fingerprint') {
      return this.extractFingerprintFeatures(biometricData);
    } else if (biometricData.type === 'face') {
      return this.extractFaceFeatures(biometricData);
    }
    
    return biometricData;
  }

  // Simulate fingerprint feature extraction
  static extractFingerprintFeatures(fingerprintData) {
    // In production, this would use actual biometric libraries
    const features = {
      minutiae: fingerprintData.minutiae || [],
      ridgePattern: fingerprintData.ridgePattern || 'unknown',
      corePoints: fingerprintData.corePoints || [],
      deltaPoints: fingerprintData.deltaPoints || []
    };
    
    return JSON.stringify(features);
  }

  // Simulate face feature extraction
  static extractFaceFeatures(faceData) {
    // In production, this would use facial recognition libraries
    const features = {
      encodings: faceData.encodings || [],
      landmarks: faceData.landmarks || [],
      geometry: faceData.geometry || {}
    };
    
    return JSON.stringify(features);
  }

  // Calculate biometric similarity (for verification)
  static calculateSimilarity(template1, template2) {
    // Simple similarity calculation (in production, use proper algorithms)
    if (template1 === template2) return 1.0;
    
    try {
      const t1 = JSON.parse(template1);
      const t2 = JSON.parse(template2);
      
      // Basic similarity calculation based on common properties
      let similarity = 0;
      let totalFeatures = 0;
      
      for (const key in t1) {
        if (t2.hasOwnProperty(key)) {
          totalFeatures++;
          if (JSON.stringify(t1[key]) === JSON.stringify(t2[key])) {
            similarity++;
          }
        }
      }
      
      return totalFeatures > 0 ? similarity / totalFeatures : 0;
    } catch {
      return 0;
    }
  }

  // Validate biometric data format
  static validateBiometricData(data, type) {
    if (!data) return false;
    
    console.log(`Validating biometric data - Type: ${type}, Data:`, data);
    console.log(`Data type: ${typeof data}, Data length: ${data?.length}`);
    
    switch (type) {
      case 'fingerprint':
        return this.validateFingerprintData(data);
      case 'face':
        return this.validateFaceData(data);
      case 'webauthn':
        return this.validateWebAuthnData(data);
      case 'device_fingerprint':
        return this.validateDeviceFingerprintData(data);
      case 'voice':
        return this.validateVoiceData(data);
      case 'iris':
        return this.validateIrisData(data);
      default:
        console.log(`Unknown biometric type: ${type}`);
        return false;
    }
  }

  static validateFingerprintData(data) {
    // Basic validation for fingerprint data
    const isValid = data && (
      typeof data === 'string' || 
      (typeof data === 'object' && data.type === 'fingerprint')
    );
    console.log(`Fingerprint validation result: ${isValid}`);
    return isValid;
  }

  static validateFaceData(data) {
    // Basic validation for face data
    const isValid = data && (
      typeof data === 'string' || 
      (typeof data === 'object' && data.type === 'face')
    );
    console.log(`Face validation result: ${isValid}`);
    return isValid;
  }

  static validateWebAuthnData(data) {
    // Basic validation for WebAuthn data
    const isValid = data && (
      typeof data === 'string' || 
      (typeof data === 'object' && (data.id || data.credentialId))
    );
    console.log(`WebAuthn validation result: ${isValid}`);
    return isValid;
  }

  // FIXED: More permissive validation for device fingerprints
  static validateDeviceFingerprintData(data) {
    console.log(`Validating device fingerprint data:`, data);
    console.log(`Data type: ${typeof data}`);
    
    // Allow any non-empty string or object
    if (typeof data === 'string') {
      const isValid = data.length > 0;
      console.log(`String validation result: ${isValid}, length: ${data.length}`);
      return isValid;
    }
    
    if (typeof data === 'object' && data !== null) {
      const isValid = data.fingerprint || data.deviceInfo || Object.keys(data).length > 0;
      console.log(`Object validation result: ${isValid}, keys: ${Object.keys(data)}`);
      return isValid;
    }
    
    console.log(`Device fingerprint validation failed - invalid type or null/undefined`);
    return false;
  }

  static validateVoiceData(data) {
    // Basic validation for voice data
    const isValid = data && (
      typeof data === 'string' || 
      (typeof data === 'object' && data.type === 'voice')
    );
    console.log(`Voice validation result: ${isValid}`);
    return isValid;
  }

  static validateIrisData(data) {
    // Basic validation for iris data
    const isValid = data && (
      typeof data === 'string' || 
      (typeof data === 'object' && data.type === 'iris')
    );
    console.log(`Iris validation result: ${isValid}`);
    return isValid;
  }
}