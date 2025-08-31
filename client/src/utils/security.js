//this is also 5 steps with +880 sign proble
export const SecurityUtils = {
  // Generate secure random string
  generateSecureRandom: (length = 32) => {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  },
 
  // Validate email format
  isValidEmail: (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  },
 
  // Validate phone format - Works with any Twilio-supported country code
  isValidPhone: (phone) => {
    if (!phone || typeof phone !== 'string') return false;
    
    // Remove all spaces
    const cleanPhone = phone.replace(/\s/g, '');
    
    // E.164 format: + followed by country code and number
    // Total length can be 8-15 characters (including +)
    // This accommodates shortest numbers like +12345678 to longest like +123456789012345
    const e164Regex = /^\+[1-9]\d{7,14}$/;
    
    return e164Regex.test(cleanPhone);
  },
 
  // Sanitize input
  sanitizeInput: (input) => {
    if (typeof input !== 'string') return input;
    return input.replace(/[<>\"'&]/g, (match) => {
      const escapeMap = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;'
      };
      return escapeMap[match];
    });
  },
 
  // Generate CSP nonce
  generateCSPNonce: () => {
    return btoa(SecurityUtils.generateSecureRandom(16));
  },
 
  // Encrypt data using Web Crypto API
  encryptData: async (data) => {
    try {
      const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
           
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encodedData = new TextEncoder().encode(JSON.stringify(data));
           
      const encryptedData = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        encodedData
      );
           
      // Store key in session for decryption
      const exportedKey = await crypto.subtle.exportKey('raw', key);
      sessionStorage.setItem('vottery_encryption_key', btoa(String.fromCharCode(...new Uint8Array(exportedKey))));
           
      return btoa(String.fromCharCode(...new Uint8Array(iv))) + ':' + btoa(String.fromCharCode(...new Uint8Array(encryptedData)));
    } catch (error) {
      console.error('Encryption failed:', error);
      return btoa(JSON.stringify(data)); // Fallback to base64 encoding
    }
  },
 
  // Decrypt data using Web Crypto API
  decryptData: async (encryptedData) => {
    try {
      const keyData = sessionStorage.getItem('vottery_encryption_key');
      if (!keyData) throw new Error('Encryption key not found');
           
      const [ivBase64, dataBase64] = encryptedData.split(':');
      const iv = new Uint8Array(atob(ivBase64).split('').map(c => c.charCodeAt(0)));
      const data = new Uint8Array(atob(dataBase64).split('').map(c => c.charCodeAt(0)));
           
      const keyBuffer = new Uint8Array(atob(keyData).split('').map(c => c.charCodeAt(0)));
      const key = await crypto.subtle.importKey('raw', keyBuffer, 'AES-GCM', false, ['decrypt']);
           
      const decryptedData = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        data
      );
           
      return JSON.parse(new TextDecoder().decode(decryptedData));
    } catch (error) {
      console.error('Decryption failed:', error);
      // Fallback to base64 decoding
      try {
        return JSON.parse(atob(encryptedData));
      } catch {
        return encryptedData;
      }
    }
  }
};
// export const SecurityUtils = {
//   // Generate secure random string
//   generateSecureRandom: (length = 32) => {
//     const array = new Uint8Array(length);
//     crypto.getRandomValues(array);
//     return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
//   },
 
//   // Validate email format
//   isValidEmail: (email) => {
//     const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//     return emailRegex.test(email);
//   },
 
//   // Validate phone format - Works with any Twilio-supported country code
//   isValidPhone: (phone) => {
//     if (!phone || typeof phone !== 'string') return false;
    
//     // Remove all spaces
//     const cleanPhone = phone.replace(/\s/g, '');
    
//     // Must start with + and have 7-15 digits after + (ITU-T E.164 standard)
//     const e164Regex = /^\+[1-9]\d{6,14}$/;
    
//     return e164Regex.test(cleanPhone);
//   },
 
//   // Sanitize input
//   sanitizeInput: (input) => {
//     if (typeof input !== 'string') return input;
//     return input.replace(/[<>\"'&]/g, (match) => {
//       const escapeMap = {
//         '<': '&lt;',
//         '>': '&gt;',
//         '"': '&quot;',
//         "'": '&#x27;',
//         '&': '&amp;'
//       };
//       return escapeMap[match];
//     });
//   },
 
//   // Generate CSP nonce
//   generateCSPNonce: () => {
//     return btoa(SecurityUtils.generateSecureRandom(16));
//   },
 
//   // Encrypt data using Web Crypto API
//   encryptData: async (data) => {
//     try {
//       const key = await crypto.subtle.generateKey(
//         { name: 'AES-GCM', length: 256 },
//         false,
//         ['encrypt', 'decrypt']
//       );
           
//       const iv = crypto.getRandomValues(new Uint8Array(12));
//       const encodedData = new TextEncoder().encode(JSON.stringify(data));
           
//       const encryptedData = await crypto.subtle.encrypt(
//         { name: 'AES-GCM', iv },
//         key,
//         encodedData
//       );
           
//       // Store key in session for decryption
//       const exportedKey = await crypto.subtle.exportKey('raw', key);
//       sessionStorage.setItem('vottery_encryption_key', btoa(String.fromCharCode(...new Uint8Array(exportedKey))));
           
//       return btoa(String.fromCharCode(...new Uint8Array(iv))) + ':' + btoa(String.fromCharCode(...new Uint8Array(encryptedData)));
//     } catch (error) {
//       console.error('Encryption failed:', error);
//       return btoa(JSON.stringify(data)); // Fallback to base64 encoding
//     }
//   },
 
//   // Decrypt data using Web Crypto API
//   decryptData: async (encryptedData) => {
//     try {
//       const keyData = sessionStorage.getItem('vottery_encryption_key');
//       if (!keyData) throw new Error('Encryption key not found');
           
//       const [ivBase64, dataBase64] = encryptedData.split(':');
//       const iv = new Uint8Array(atob(ivBase64).split('').map(c => c.charCodeAt(0)));
//       const data = new Uint8Array(atob(dataBase64).split('').map(c => c.charCodeAt(0)));
           
//       const keyBuffer = new Uint8Array(atob(keyData).split('').map(c => c.charCodeAt(0)));
//       const key = await crypto.subtle.importKey('raw', keyBuffer, 'AES-GCM', false, ['decrypt']);
           
//       const decryptedData = await crypto.subtle.decrypt(
//         { name: 'AES-GCM', iv },
//         key,
//         data
//       );
           
//       return JSON.parse(new TextDecoder().decode(decryptedData));
//     } catch (error) {
//       console.error('Decryption failed:', error);
//       // Fallback to base64 decoding
//       try {
//         return JSON.parse(atob(encryptedData));
//       } catch {
//         return encryptedData;
//       }
//     }
//   }
// };
//this is 5 steps code
// export const SecurityUtils = {
//   // Generate secure random string
//   generateSecureRandom: (length = 32) => {
//     const array = new Uint8Array(length);
//     crypto.getRandomValues(array);
//     return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
//   },

//   // Validate email format
//   isValidEmail: (email) => {
//     const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//     return emailRegex.test(email);
//   },

//   // Validate phone format
//   isValidPhone: (phone) => {
//     const phoneRegex = /^[+]?[1-9]\d{1,14}$/;
//     return phoneRegex.test(phone.replace(/\s/g, ''));
//   },

//   // Sanitize input
//   sanitizeInput: (input) => {
//     if (typeof input !== 'string') return input;
//     return input.replace(/[<>\"'&]/g, (match) => {
//       const escapeMap = {
//         '<': '&lt;',
//         '>': '&gt;',
//         '"': '&quot;',
//         "'": '&#x27;',
//         '&': '&amp;'
//       };
//       return escapeMap[match];
//     });
//   },

//   // Generate CSP nonce
//   generateCSPNonce: () => {
//     return btoa(SecurityUtils.generateSecureRandom(16));
//   },

//   // Encrypt data using Web Crypto API
//   encryptData: async (data) => {
//     try {
//       const key = await crypto.subtle.generateKey(
//         { name: 'AES-GCM', length: 256 },
//         false,
//         ['encrypt', 'decrypt']
//       );
      
//       const iv = crypto.getRandomValues(new Uint8Array(12));
//       const encodedData = new TextEncoder().encode(JSON.stringify(data));
      
//       const encryptedData = await crypto.subtle.encrypt(
//         { name: 'AES-GCM', iv },
//         key,
//         encodedData
//       );
      
//       // Store key in session for decryption
//       const exportedKey = await crypto.subtle.exportKey('raw', key);
//       sessionStorage.setItem('vottery_encryption_key', btoa(String.fromCharCode(...new Uint8Array(exportedKey))));
      
//       return btoa(String.fromCharCode(...new Uint8Array(iv))) + ':' + btoa(String.fromCharCode(...new Uint8Array(encryptedData)));
//     } catch (error) {
//       console.error('Encryption failed:', error);
//       return btoa(JSON.stringify(data)); // Fallback to base64 encoding
//     }
//   },

//   // Decrypt data using Web Crypto API
//   decryptData: async (encryptedData) => {
//     try {
//       const keyData = sessionStorage.getItem('vottery_encryption_key');
//       if (!keyData) throw new Error('Encryption key not found');
      
//       const [ivBase64, dataBase64] = encryptedData.split(':');
//       const iv = new Uint8Array(atob(ivBase64).split('').map(c => c.charCodeAt(0)));
//       const data = new Uint8Array(atob(dataBase64).split('').map(c => c.charCodeAt(0)));
      
//       const keyBuffer = new Uint8Array(atob(keyData).split('').map(c => c.charCodeAt(0)));
//       const key = await crypto.subtle.importKey('raw', keyBuffer, 'AES-GCM', false, ['decrypt']);
      
//       const decryptedData = await crypto.subtle.decrypt(
//         { name: 'AES-GCM', iv },
//         key,
//         data
//       );
      
//       return JSON.parse(new TextDecoder().decode(decryptedData));
//     } catch (error) {
//       console.error('Decryption failed:', error);
//       // Fallback to base64 decoding
//       try {
//         return JSON.parse(atob(encryptedData));
//       } catch {
//         return encryptedData;
//       }
//     }
//   }
// };
//this is 3 steps code
// export const SecurityUtils = {
//     // Generate secure random string
//     generateSecureRandom: (length = 32) => {
//       const array = new Uint8Array(length);
//       crypto.getRandomValues(array);
//       return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
//     },
  
//     // Validate email format
//     isValidEmail: (email) => {
//       const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//       return emailRegex.test(email);
//     },
  
//     // Validate phone format
//     isValidPhone: (phone) => {
//       const phoneRegex = /^[+]?[1-9]\d{1,14}$/;
//       return phoneRegex.test(phone.replace(/\s/g, ''));
//     },
  
//     // Sanitize input
//     sanitizeInput: (input) => {
//       if (typeof input !== 'string') return input;
//       return input.replace(/[<>\"'&]/g, (match) => {
//         const escapeMap = {
//           '<': '&lt;',
//           '>': '&gt;',
//           '"': '&quot;',
//           "'": '&#x27;',
//           '&': '&amp;'
//         };
//         return escapeMap[match];
//       });
//     },
  
//     // Generate CSP nonce
//     generateCSPNonce: () => {
//       return btoa(SecurityUtils.generateSecureRandom(16));
//     }
//   };
  
  
 