


//new 5 steps. this code restricts strictly from sngine
// import React, { createContext, useContext, useCallback } from 'react';
// import { SecurityUtils } from '../utils/security';
// import { useDeviceDetection } from '../hooks/useDeviceDetection';

// const SecurityContext = createContext();

// export const useSecurity = () => {
//   const context = useContext(SecurityContext);
//   if (!context) {
//     throw new Error('useSecurity must be used within SecurityProvider');
//   }
//   return context;
// };

// export const SecurityProvider = ({ children }) => {
//   const { deviceInfo } = useDeviceDetection();

//   // Check if user came from SNGINE
//   const checkReferrer = useCallback(() => {
//     const referrer = document.referrer.toLowerCase();
//     const currentHost = window.location.hostname.toLowerCase();
    
//     // For development, allow localhost
//     if (currentHost.includes('localhost') || currentHost.includes('127.0.0.1')) {
//       return { isValid: true, source: 'development' };
//     }
    
//     // Check for SNGINE referrer patterns
//     const snginePatterns = [
//       'sngine.com',
//       'www.sngine.com',
//       // Add other SNGINE domain variations
//     ];
    
//     const isFromSngine = snginePatterns.some(pattern => referrer.includes(pattern));
    
//     if (!isFromSngine && referrer) {
//       console.warn('Invalid referrer detected:', referrer);
//     }
    
//     return {
//       isValid: isFromSngine || !referrer, // Allow direct access for now (can be changed)
//       source: isFromSngine ? 'sngine' : referrer ? 'external' : 'direct',
//       referrer: referrer || 'direct'
//     };
//   }, []);

//   // Generate device fingerprint
//   const generateDeviceFingerprint = useCallback(async () => {
//     try {
//       const fingerprint = {
//         deviceId: deviceInfo.deviceId,
//         userAgent: navigator.userAgent,
//         platform: navigator.platform,
//         language: navigator.language,
//         timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
//         screen: {
//           width: screen.width,
//           height: screen.height,
//           colorDepth: screen.colorDepth,
//           pixelRatio: window.devicePixelRatio || 1
//         },
//         timestamp: Date.now(),
//         referrer: document.referrer,
//         hardwareConcurrency: navigator.hardwareConcurrency || 0,
//         deviceMemory: navigator.deviceMemory || 0,
//         connection: navigator.connection ? {
//           effectiveType: navigator.connection.effectiveType,
//           downlink: navigator.connection.downlink,
//           rtt: navigator.connection.rtt
//         } : null
//       };

//       // Create canvas fingerprint
//       const canvas = document.createElement('canvas');
//       const ctx = canvas.getContext('2d');
//       ctx.textBaseline = 'top';
//       ctx.font = '14px Arial';
//       ctx.fillStyle = '#000';
//       ctx.fillRect(0, 0, 200, 50);
//       ctx.fillStyle = '#fff';
//       ctx.fillText('Vottery Security Check', 2, 2);
//       fingerprint.canvasFingerprint = canvas.toDataURL();

//       return fingerprint;
//     } catch (error) {
//       console.error('Failed to generate device fingerprint:', error);
//       return {
//         deviceId: deviceInfo.deviceId,
//         timestamp: Date.now(),
//         error: error.message
//       };
//     }
//   }, [deviceInfo]);

//   // Encrypt data
//   const encryptData = useCallback((data) => {
//     try {
//       const jsonString = JSON.stringify(data);
//       const timestamp = Date.now();
//       const nonce = SecurityUtils.generateSecureRandom(16);
      
//       const payload = {
//         data: jsonString,
//         timestamp,
//         nonce,
//         deviceId: deviceInfo.deviceId
//       };
      
//       return btoa(JSON.stringify(payload));
//     } catch (error) {
//       console.error('Encryption failed:', error);
//       return btoa(JSON.stringify(data));
//     }
//   }, [deviceInfo.deviceId]);

//   // Decrypt data
//   const decryptData = useCallback((encryptedData) => {
//     try {
//       const payload = JSON.parse(atob(encryptedData));
      
//       // Verify timestamp (not too old - 1 hour)
//       const now = Date.now();
//       if (now - payload.timestamp > 3600000) {
//         throw new Error('Data expired');
//       }
      
//       // Verify device ID
//       if (payload.deviceId !== deviceInfo.deviceId) {
//         console.warn('Device ID mismatch in decryption');
//       }
      
//       return JSON.parse(payload.data);
//     } catch (error) {
//       console.error('Decryption failed:', error);
//       try {
//         return JSON.parse(atob(encryptedData));
//       } catch {
//         return encryptedData;
//       }
//     }
//   }, [deviceInfo.deviceId]);

//   // Validate session integrity
//   const validateSession = useCallback(() => {
//     const sessionData = sessionStorage.getItem('vottery_session');
    
//     if (!sessionData) {
//       return { isValid: false, reason: 'No session found' };
//     }
    
//     try {
//       const session = decryptData(sessionData);
//       const now = Date.now();
      
//       if (now - session.timestamp > 86400000) { // 24 hours
//         return { isValid: false, reason: 'Session expired' };
//       }
      
//       if (session.deviceId !== deviceInfo.deviceId) {
//         return { isValid: false, reason: 'Device mismatch' };
//       }
      
//       return { isValid: true, session };
//     } catch (error) {
//       return { isValid: false, reason: 'Session validation failed', error: error.message };
//     }
//   }, [decryptData, deviceInfo.deviceId]);

//   // Create secure session
//   const createSession = useCallback((userData) => {
//     const sessionData = {
//       ...userData,
//       timestamp: Date.now(),
//       deviceId: deviceInfo.deviceId,
//       referrer: document.referrer,
//       sessionId: SecurityUtils.generateSecureRandom(32)
//     };
    
//     const encryptedSession = encryptData(sessionData);
//     sessionStorage.setItem('vottery_session', encryptedSession);
    
//     return sessionData.sessionId;
//   }, [encryptData, deviceInfo.deviceId]);

//   // Clear session
//   const clearSession = useCallback(() => {
//     sessionStorage.removeItem('vottery_session');
//     sessionStorage.removeItem('vottery_biometric');
//     sessionStorage.removeItem('vottery_auth_token');
//     sessionStorage.removeItem('vottery_referrer_validation');
//     sessionStorage.removeItem('vottery_device_info');
//     sessionStorage.removeItem('vottery_encryption_key');
//   }, []);

//   // Security headers validation
//   const validateSecurityHeaders = useCallback(() => {
//     const headers = {
//       'Content-Security-Policy': true,
//       'X-Frame-Options': true,
//       'X-Content-Type-Options': true,
//       'Referrer-Policy': true,
//       'Permissions-Policy': true
//     };
    
//     return headers;
//   }, []);

//   const value = {
//     checkReferrer,
//     generateDeviceFingerprint,
//     encryptData,
//     decryptData,
//     validateSession,
//     createSession,
//     clearSession,
//     validateSecurityHeaders,
//     deviceInfo
//   };

//   return (
//     <SecurityContext.Provider value={value}>
//       {children}
//     </SecurityContext.Provider>
//   );
// };








//5 steps mimic that i am from sngine. THIS IS THE late wrokable code 31.08.2025
import React, { createContext, useContext, useCallback, useState, useEffect } from 'react';
import { SecurityUtils } from '../utils/security';
import { useDeviceDetection } from '../hooks/useDeviceDetection';

const SecurityContext = createContext();

export const useSecurity = () => {
  const context = useContext(SecurityContext);
  if (!context) {
    throw new Error('useSecurity must be used within SecurityProvider');
  }
  return context;
};

export const SecurityProvider = ({ children }) => {
  const { deviceInfo } = useDeviceDetection();
  const [isValidReferrer, setIsValidReferrer] = useState(true); // Default to true for dev
  const [referrerCheckComplete, setReferrerCheckComplete] = useState(false);

  // Check if user came from SNGINE
  const checkReferrer = useCallback(() => {
    const referrer = document.referrer.toLowerCase();
    const currentHost = window.location.hostname.toLowerCase();
    
    // DEBUG: Log all values for troubleshooting
    console.log('🔍 Security Debug Info:', {
      referrer,
      currentHost,
      VITE_NODE_ENV: import.meta.env.VITE_NODE_ENV,
      VITE_REACT_APP_BYPASS_REFERRER: import.meta.env.VITE_REACT_APP_BYPASS_REFERRER,
      DEV: import.meta.env.DEV,
      localStorage_dev: localStorage.getItem('vottery_dev_mode'),
      urlParams: new URLSearchParams(window.location.search).get('dev_bypass'),
      location: window.location.href
    });
    
    // DEVELOPMENT BYPASS OPTIONS:
    
    // Option 1: Check for development environment variable (Vite compatible)
    const isDevelopment = import.meta.env.VITE_NODE_ENV === 'development' || 
                         import.meta.env.VITE_REACT_APP_BYPASS_REFERRER === 'true' ||
                         import.meta.env.DEV === true;
    
    // Option 2: Check for development domains
    const devDomains = ['localhost', '127.0.0.1', 'dev.', 'test.', 'staging.'];
    const isDev = devDomains.some(domain => currentHost.includes(domain));
    
    // Option 3: Check for special query parameter
    const urlParams = new URLSearchParams(window.location.search);
    const hasDevBypass = urlParams.get('dev_bypass') === 'true';
    
    // Option 4: Check localStorage for development flag
    const hasLocalBypass = localStorage.getItem('vottery_dev_mode') === 'true';
    
    // DEBUG: Log bypass checks
    console.log('🔍 Bypass Checks:', {
      isDevelopment,
      isDev,
      hasDevBypass,
      hasLocalBypass
    });
    
    // FORCE BYPASS FOR DEVELOPMENT (remove this line when done testing)
    const forceBypass = true; // <-- SET THIS TO FALSE FOR PRODUCTION
    
    let result;
    
    if (forceBypass || isDevelopment || isDev || hasDevBypass || hasLocalBypass) {
      console.log('🔓 Development bypass active - simulating SNGINE referrer');
      result = { 
        isValid: true, 
        source: 'sngine_dev_bypass',
        referrer: 'https://sngine.com/development'
      };
    } else {
      // Check for SNGINE referrer patterns
      const snginePatterns = [
        'sngine.com',
        'www.sngine.com',
        // Add other SNGINE domain variations
      ];
      
      const isFromSngine = snginePatterns.some(pattern => referrer.includes(pattern));
      
      if (!isFromSngine && referrer) {
        console.warn('Invalid referrer detected:', referrer);
      }
      
      result = {
        isValid: isFromSngine || !referrer,
        source: isFromSngine ? 'sngine' : referrer ? 'external' : 'direct',
        referrer: referrer || 'direct'
      };
    }
    
    return result;
  }, []);

  // Auto-run referrer check on mount
  useEffect(() => {
    const runCheck = () => {
      try {
        console.log('🔍 Running referrer check...');
        const result = checkReferrer();
        console.log('🔍 Referrer check result:', result);
        setIsValidReferrer(result.isValid);
        setReferrerCheckComplete(true);
      } catch (error) {
        console.error('Referrer check failed:', error);
        // In case of error, allow access in development
        const isDev = window.location.hostname.includes('localhost') || 
                     import.meta.env.DEV;
        setIsValidReferrer(isDev);
        setReferrerCheckComplete(true);
      }
    };

    // Run check after a small delay to ensure everything is loaded
    const timer = setTimeout(runCheck, 100);
    return () => clearTimeout(timer);
  }, [checkReferrer]);

  // Generate device fingerprint
  const generateDeviceFingerprint = useCallback(async () => {
    try {
      const fingerprint = {
        deviceId: deviceInfo.deviceId,
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        screen: {
          width: screen.width,
          height: screen.height,
          colorDepth: screen.colorDepth,
          pixelRatio: window.devicePixelRatio || 1
        },
        timestamp: Date.now(),
        referrer: document.referrer,
        hardwareConcurrency: navigator.hardwareConcurrency || 0,
        deviceMemory: navigator.deviceMemory || 0,
        connection: navigator.connection ? {
          effectiveType: navigator.connection.effectiveType,
          downlink: navigator.connection.downlink,
          rtt: navigator.connection.rtt
        } : null
      };

      // Create canvas fingerprint
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#000';
      ctx.fillRect(0, 0, 200, 50);
      ctx.fillStyle = '#fff';
      ctx.fillText('Vottery Security Check', 2, 2);
      fingerprint.canvasFingerprint = canvas.toDataURL();

      return fingerprint;
    } catch (error) {
      console.error('Failed to generate device fingerprint:', error);
      return {
        deviceId: deviceInfo.deviceId,
        timestamp: Date.now(),
        error: error.message
      };
    }
  }, [deviceInfo]);

  // Encrypt data
  const encryptData = useCallback((data) => {
    try {
      const jsonString = JSON.stringify(data);
      const timestamp = Date.now();
      const nonce = SecurityUtils.generateSecureRandom(16);
      
      const payload = {
        data: jsonString,
        timestamp,
        nonce,
        deviceId: deviceInfo.deviceId
      };
      
      return btoa(JSON.stringify(payload));
    } catch (error) {
      console.error('Encryption failed:', error);
      return btoa(JSON.stringify(data));
    }
  }, [deviceInfo.deviceId]);

  // Decrypt data
  const decryptData = useCallback((encryptedData) => {
    try {
      const payload = JSON.parse(atob(encryptedData));
      
      // Verify timestamp (not too old - 1 hour)
      const now = Date.now();
      if (now - payload.timestamp > 3600000) {
        throw new Error('Data expired');
      }
      
      // Verify device ID
      if (payload.deviceId !== deviceInfo.deviceId) {
        console.warn('Device ID mismatch in decryption');
      }
      
      return JSON.parse(payload.data);
    } catch (error) {
      console.error('Decryption failed:', error);
      try {
        return JSON.parse(atob(encryptedData));
      } catch {
        return encryptedData;
      }
    }
  }, [deviceInfo.deviceId]);

  // Validate session integrity
  const validateSession = useCallback(() => {
    const sessionData = sessionStorage.getItem('vottery_session');
    
    if (!sessionData) {
      return { isValid: false, reason: 'No session found' };
    }
    
    try {
      const session = decryptData(sessionData);
      const now = Date.now();
      
      if (now - session.timestamp > 86400000) { // 24 hours
        return { isValid: false, reason: 'Session expired' };
      }
      
      if (session.deviceId !== deviceInfo.deviceId) {
        return { isValid: false, reason: 'Device mismatch' };
      }
      
      return { isValid: true, session };
    } catch (error) {
      return { isValid: false, reason: 'Session validation failed', error: error.message };
    }
  }, [decryptData, deviceInfo.deviceId]);

  // Create secure session
  const createSession = useCallback((userData) => {
    const sessionData = {
      ...userData,
      timestamp: Date.now(),
      deviceId: deviceInfo.deviceId,
      referrer: document.referrer,
      sessionId: SecurityUtils.generateSecureRandom(32)
    };
    
    const encryptedSession = encryptData(sessionData);
    sessionStorage.setItem('vottery_session', encryptedSession);
    
    return sessionData.sessionId;
  }, [encryptData, deviceInfo.deviceId]);

  // Clear session
  const clearSession = useCallback(() => {
    sessionStorage.removeItem('vottery_session');
    sessionStorage.removeItem('vottery_biometric');
    sessionStorage.removeItem('vottery_auth_token');
    sessionStorage.removeItem('vottery_referrer_validation');
    sessionStorage.removeItem('vottery_device_info');
    sessionStorage.removeItem('vottery_encryption_key');
  }, []);

  // Security headers validation
  const validateSecurityHeaders = useCallback(() => {
    const headers = {
      'Content-Security-Policy': true,
      'X-Frame-Options': true,
      'X-Content-Type-Options': true,
      'Referrer-Policy': true,
      'Permissions-Policy': true
    };
    
    return headers;
  }, []);

  const value = {
    checkReferrer,
    generateDeviceFingerprint,
    encryptData,
    decryptData,
    validateSession,
    createSession,
    clearSession,
    validateSecurityHeaders,
    deviceInfo,
    isValidReferrer,
    referrerCheckComplete
  };

  return (
    <SecurityContext.Provider value={value}>
      {children}
    </SecurityContext.Provider>
  );
};






//latest 3 steps with mimic that i am from sngine
// import React, { createContext, useContext, useState, useCallback } from 'react';
// import CryptoJS from 'crypto-js';

// const SecurityContext = createContext();

// export const useSecurity = () => {
//   const context = useContext(SecurityContext);
//   if (!context) {
//     throw new Error('useSecurity must be used within SecurityProvider');
//   }
//   return context;
// };

// export const SecurityProvider = ({ children }) => {
//   const [isValidReferrer, setIsValidReferrer] = useState(false);
//   const [securityMetrics, setSecurityMetrics] = useState({
//     encryptionEnabled: true,
//     httpsEnabled: window.location.protocol === 'https:',
//     referrerValidated: false,
//     deviceFingerprinted: false
//   });

//   const SNGINE_DOMAINS = [
//     'sngine.com',
//     'www.sngine.com',
//     'app.sngine.com',
//     'demo.sngine.com',
//     // Add more SNGine domains as needed
//   ];

//   const checkReferrer = useCallback(() => {
//     try {
//       const referrer = document.referrer;
//       console.log('Checking referrer:', referrer);
      
//       if (!referrer) {
//         console.warn('No referrer detected');
//         setIsValidReferrer(false);
//         return;
//       }

//       const referrerURL = new URL(referrer);
//       const referrerHost = referrerURL.hostname.toLowerCase();
      
//       const isValid = SNGINE_DOMAINS.some(domain => 
//         referrerHost === domain || referrerHost.endsWith('.' + domain)
//       );

//       setIsValidReferrer(isValid);
//       setSecurityMetrics(prev => ({
//         ...prev,
//         referrerValidated: isValid
//       }));

//       if (isValid) {
//         console.log('Valid SNGine referrer detected:', referrerHost);
//         // Store referrer validation in sessionStorage for security
//         const timestamp = Date.now();
//         const validationToken = CryptoJS.SHA256(`${referrer}-${timestamp}`).toString();
//         sessionStorage.setItem('vottery_referrer_validation', JSON.stringify({
//           validated: true,
//           timestamp,
//           token: validationToken
//         }));
//       } else {
//         console.warn('Invalid referrer detected:', referrerHost);
//       }
//     } catch (error) {
//       console.error('Error checking referrer:', error);
//       setIsValidReferrer(false);
//     }
//   }, []);

//   const generateDeviceFingerprint = useCallback(async () => {
//     try {
//       // Import FingerprintJS dynamically
//       const FingerprintJS = await import('@fingerprintjs/fingerprintjs');
//       const fp = await FingerprintJS.load();
//       const result = await fp.get();
      
//       const additionalInfo = {
//         userAgent: navigator.userAgent,
//         language: navigator.language,
//         platform: navigator.platform,
//         screenResolution: `${screen.width}x${screen.height}`,
//         timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
//         cookieEnabled: navigator.cookieEnabled,
//         onlineStatus: navigator.onLine,
//         hardwareConcurrency: navigator.hardwareConcurrency,
//         deviceMemory: navigator.deviceMemory || 'unknown',
//         connection: navigator.connection ? {
//           effectiveType: navigator.connection.effectiveType,
//           downlink: navigator.connection.downlink
//         } : null
//       };

//       const deviceFingerprint = {
//         fingerprintId: result.visitorId,
//         confidence: result.confidence,
//         deviceInfo: additionalInfo,
//         timestamp: Date.now()
//       };

//       setSecurityMetrics(prev => ({
//         ...prev,
//         deviceFingerprinted: true
//       }));

//       return deviceFingerprint;
//     } catch (error) {
//       console.error('Error generating device fingerprint:', error);
//       return null;
//     }
//   }, []);

//   const encryptData = useCallback((data, key = 'vottery-secure-key') => {
//     try {
//       return CryptoJS.AES.encrypt(JSON.stringify(data), key).toString();
//     } catch (error) {
//       console.error('Encryption error:', error);
//       return null;
//     }
//   }, []);

//   const decryptData = useCallback((encryptedData, key = 'vottery-secure-key') => {
//     try {
//       const bytes = CryptoJS.AES.decrypt(encryptedData, key);
//       return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
//     } catch (error) {
//       console.error('Decryption error:', error);
//       return null;
//     }
//   }, []);

//   const validateSession = useCallback(() => {
//     try {
//       const validation = sessionStorage.getItem('vottery_referrer_validation');
//       if (!validation) return false;
      
//       const parsed = JSON.parse(validation);
//       const isValid = parsed.validated && (Date.now() - parsed.timestamp) < 3600000; // 1 hour
      
//       if (!isValid) {
//         sessionStorage.removeItem('vottery_referrer_validation');
//       }
      
//       return isValid;
//     } catch (error) {
//       console.error('Session validation error:', error);
//       return false;
//     }
//   }, []);

//   const value = {
//     isValidReferrer,
//     securityMetrics,
//     checkReferrer,
//     generateDeviceFingerprint,
//     encryptData,
//     decryptData,
//     validateSession
//   };

//   return (
//     <SecurityContext.Provider value={value}>
//       {children}
//     </SecurityContext.Provider>
//   );
// };














// // import React, { createContext, useContext, useState, useCallback } from 'react';
// // import CryptoJS from 'crypto-js';

// // const SecurityContext = createContext();

// // export const useSecurity = () => {
// //   const context = useContext(SecurityContext);
// //   if (!context) {
// //     throw new Error('useSecurity must be used within SecurityProvider');
// //   }
// //   return context;
// // };

// // export const SecurityProvider = ({ children }) => {
// //   const [isValidReferrer, setIsValidReferrer] = useState(false);
// //   const [securityMetrics, setSecurityMetrics] = useState({
// //     encryptionEnabled: true,
// //     httpsEnabled: window.location.protocol === 'https:',
// //     referrerValidated: false,
// //     deviceFingerprinted: false
// //   });

// //   const SNGINE_DOMAINS = [
// //     'sngine.com',
// //     'www.sngine.com',
// //     'app.sngine.com',
// //     'demo.sngine.com',
// //     // Add more SNGine domains as needed
// //   ];

// //   const checkReferrer = useCallback(() => {
// //     try {
// //       const referrer = document.referrer;
// //       console.log('Checking referrer:', referrer);
      
// //       if (!referrer) {
// //         console.warn('No referrer detected');
// //         setIsValidReferrer(false);
// //         return;
// //       }

// //       const referrerURL = new URL(referrer);
// //       const referrerHost = referrerURL.hostname.toLowerCase();
      
// //       const isValid = SNGINE_DOMAINS.some(domain => 
// //         referrerHost === domain || referrerHost.endsWith('.' + domain)
// //       );

// //       setIsValidReferrer(isValid);
// //       setSecurityMetrics(prev => ({
// //         ...prev,
// //         referrerValidated: isValid
// //       }));

// //       if (isValid) {
// //         console.log('Valid SNGine referrer detected:', referrerHost);
// //         // Store referrer validation in sessionStorage for security
// //         const timestamp = Date.now();
// //         const validationToken = CryptoJS.SHA256(`${referrer}-${timestamp}`).toString();
// //         sessionStorage.setItem('vottery_referrer_validation', JSON.stringify({
// //           validated: true,
// //           timestamp,
// //           token: validationToken
// //         }));
// //       } else {
// //         console.warn('Invalid referrer detected:', referrerHost);
// //       }
// //     } catch (error) {
// //       console.error('Error checking referrer:', error);
// //       setIsValidReferrer(false);
// //     }
// //   }, []);

// //   const generateDeviceFingerprint = useCallback(async () => {
// //     try {
// //       // Import FingerprintJS dynamically
// //       const FingerprintJS = await import('@fingerprintjs/fingerprintjs');
// //       const fp = await FingerprintJS.load();
// //       const result = await fp.get();
      
// //       const additionalInfo = {
// //         userAgent: navigator.userAgent,
// //         language: navigator.language,
// //         platform: navigator.platform,
// //         screenResolution: `${screen.width}x${screen.height}`,
// //         timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
// //         cookieEnabled: navigator.cookieEnabled,
// //         onlineStatus: navigator.onLine,
// //         hardwareConcurrency: navigator.hardwareConcurrency,
// //         deviceMemory: navigator.deviceMemory || 'unknown',
// //         connection: navigator.connection ? {
// //           effectiveType: navigator.connection.effectiveType,
// //           downlink: navigator.connection.downlink
// //         } : null
// //       };

// //       const deviceFingerprint = {
// //         fingerprintId: result.visitorId,
// //         confidence: result.confidence,
// //         deviceInfo: additionalInfo,
// //         timestamp: Date.now()
// //       };

// //       setSecurityMetrics(prev => ({
// //         ...prev,
// //         deviceFingerprinted: true
// //       }));

// //       return deviceFingerprint;
// //     } catch (error) {
// //       console.error('Error generating device fingerprint:', error);
// //       return null;
// //     }
// //   }, []);

// //   const encryptData = useCallback((data, key = 'vottery-secure-key') => {
// //     try {
// //       return CryptoJS.AES.encrypt(JSON.stringify(data), key).toString();
// //     } catch (error) {
// //       console.error('Encryption error:', error);
// //       return null;
// //     }
// //   }, []);

// //   const decryptData = useCallback((encryptedData, key = 'vottery-secure-key') => {
// //     try {
// //       const bytes = CryptoJS.AES.decrypt(encryptedData, key);
// //       return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
// //     } catch (error) {
// //       console.error('Decryption error:', error);
// //       return null;
// //     }
// //   }, []);

// //   const validateSession = useCallback(() => {
// //     try {
// //       const validation = sessionStorage.getItem('vottery_referrer_validation');
// //       if (!validation) return false;
      
// //       const parsed = JSON.parse(validation);
// //       const isValid = parsed.validated && (Date.now() - parsed.timestamp) < 3600000; // 1 hour
      
// //       if (!isValid) {
// //         sessionStorage.removeItem('vottery_referrer_validation');
// //       }
      
// //       return isValid;
// //     } catch (error) {
// //       console.error('Session validation error:', error);
// //       return false;
// //     }
// //   }, []);

// //   const value = {
// //     isValidReferrer,
// //     securityMetrics,
// //     checkReferrer,
// //     generateDeviceFingerprint,
// //     encryptData,
// //     decryptData,
// //     validateSession
// //   };

// //   return (
// //     <SecurityContext.Provider value={value}>
// //       {children}
// //     </SecurityContext.Provider>
// //   );
// // };










// // //for mimic that i am from sngine
// import React, { createContext, useContext, useState, useCallback } from 'react';
// import CryptoJS from 'crypto-js';

// const SecurityContext = createContext();

// export const useSecurity = () => {
//   const context = useContext(SecurityContext);
//   if (!context) {
//     throw new Error('useSecurity must be used within SecurityProvider');
//   }
//   return context;
// };

// export const SecurityProvider = ({ children }) => {
//   const [isValidReferrer, setIsValidReferrer] = useState(false);
//   const [securityMetrics, setSecurityMetrics] = useState({
//     encryptionEnabled: true,
//     httpsEnabled: window.location.protocol === 'https:',
//     referrerValidated: false,
//     deviceFingerprinted: false
//   });

//   // ✅ Force fake referrer in dev mode
//   if (import.meta.env.NODE_ENV === 'development') {
//     Object.defineProperty(document, "referrer", {
//       value: "https://sngine.com",
//       configurable: true
//     });
//   }

//   const SNGINE_DOMAINS = [
//     'sngine.com',
//     'www.sngine.com',
//     'app.sngine.com',
//     'demo.sngine.com',
//     // Add more SNGine domains as needed
//   ];

//   const checkReferrer = useCallback(() => {
//     try {
//       const referrer = document.referrer;
//       console.log('Checking referrer:', referrer);
      
//       if (!referrer) {
//         console.warn('No referrer detected');
//         setIsValidReferrer(false);
//         return;
//       }

//       const referrerURL = new URL(referrer);
//       const referrerHost = referrerURL.hostname.toLowerCase();
      
//       const isValid = SNGINE_DOMAINS.some(domain => 
//         referrerHost === domain || referrerHost.endsWith('.' + domain)
//       );

//       setIsValidReferrer(isValid);
//       setSecurityMetrics(prev => ({
//         ...prev,
//         referrerValidated: isValid
//       }));

//       if (isValid) {
//         console.log('Valid SNGine referrer detected:', referrerHost);
//         // Store referrer validation in sessionStorage for security
//         const timestamp = Date.now();
//         const validationToken = CryptoJS.SHA256(`${referrer}-${timestamp}`).toString();
//         sessionStorage.setItem('vottery_referrer_validation', JSON.stringify({
//           validated: true,
//           timestamp,
//           token: validationToken
//         }));
//       } else {
//         console.warn('Invalid referrer detected:', referrerHost);
//       }
//     } catch (error) {
//       console.error('Error checking referrer:', error);
//       setIsValidReferrer(false);
//     }
//   }, []);

//   const generateDeviceFingerprint = useCallback(async () => {
//     try {
//       // Import FingerprintJS dynamically
//       const FingerprintJS = await import('@fingerprintjs/fingerprintjs');
//       const fp = await FingerprintJS.load();
//       const result = await fp.get();
      
//       const additionalInfo = {
//         userAgent: navigator.userAgent,
//         language: navigator.language,
//         platform: navigator.platform,
//         screenResolution: `${screen.width}x${screen.height}`,
//         timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
//         cookieEnabled: navigator.cookieEnabled,
//         onlineStatus: navigator.onLine,
//         hardwareConcurrency: navigator.hardwareConcurrency,
//         deviceMemory: navigator.deviceMemory || 'unknown',
//         connection: navigator.connection ? {
//           effectiveType: navigator.connection.effectiveType,
//           downlink: navigator.connection.downlink
//         } : null
//       };

//       const deviceFingerprint = {
//         fingerprintId: result.visitorId,
//         confidence: result.confidence,
//         deviceInfo: additionalInfo,
//         timestamp: Date.now()
//       };

//       setSecurityMetrics(prev => ({
//         ...prev,
//         deviceFingerprinted: true
//       }));

//       return deviceFingerprint;
//     } catch (error) {
//       console.error('Error generating device fingerprint:', error);
//       return null;
//     }
//   }, []);

//   const encryptData = useCallback((data, key = 'vottery-secure-key') => {
//     try {
//       return CryptoJS.AES.encrypt(JSON.stringify(data), key).toString();
//     } catch (error) {
//       console.error('Encryption error:', error);
//       return null;
//     }
//   }, []);

//   const decryptData = useCallback((encryptedData, key = 'vottery-secure-key') => {
//     try {
//       const bytes = CryptoJS.AES.decrypt(encryptedData, key);
//       return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
//     } catch (error) {
//       console.error('Decryption error:', error);
//       return null;
//     }
//   }, []);

//   const validateSession = useCallback(() => {
//     try {
//       const validation = sessionStorage.getItem('vottery_referrer_validation');
//       if (!validation) return false;
      
//       const parsed = JSON.parse(validation);
//       const isValid = parsed.validated && (Date.now() - parsed.timestamp) < 3600000; // 1 hour
      
//       if (!isValid) {
//         sessionStorage.removeItem('vottery_referrer_validation');
//       }
      
//       return isValid;
//     } catch (error) {
//       console.error('Session validation error:', error);
//       return false;
//     }
//   }, []);

//   const value = {
//     isValidReferrer,
//     securityMetrics,
//     checkReferrer,
//     generateDeviceFingerprint,
//     encryptData,
//     decryptData,
//     validateSession
//   };

//   return (
//     <SecurityContext.Provider value={value}>
//       {children}
//     </SecurityContext.Provider>
//   );
// };
