
// import { createHash } from 'node:crypto';

// export class DeviceUtils {
//   // Generate unique device fingerprint
//   static generateFingerprint(deviceInfo) {
//     const fingerprintData = {
//       userAgent: deviceInfo.userAgent || '',
//       screen: deviceInfo.screen || {},
//       timezone: deviceInfo.timezone || '',
//       language: deviceInfo.language || '',
//       platform: deviceInfo.platform || '',
//       hardwareConcurrency: deviceInfo.hardwareConcurrency || 0,
//       deviceMemory: deviceInfo.deviceMemory || 0,
//       colorDepth: deviceInfo.colorDepth || 0,
//       pixelRatio: deviceInfo.pixelRatio || 1,
//       // Network info
//       connection: deviceInfo.connection || {},
//       // Browser specific
//       browser: deviceInfo.browser || {},
//       os: deviceInfo.os || {},
//       device: deviceInfo.device || {}
//     };

//     const fingerprintString = JSON.stringify(fingerprintData, Object.keys(fingerprintData).sort());
    
//     return createHash('sha256')
//       .update(fingerprintString)
//       .digest('hex');
//   }

//   // Detect device type from user agent and device info
//   static detectDeviceType(deviceInfo) {
//     const userAgent = deviceInfo.userAgent || '';
//     const platform = deviceInfo.platform || '';
    
//     // Mobile devices
//     if (/iPhone|iPad|iPod/i.test(userAgent)) return 'ios';
//     if (/Android/i.test(userAgent)) return 'android';
//     if (/Mobile|Tablet/i.test(userAgent)) return 'mobile';
    
//     // Desktop
//     if (/Windows/i.test(platform)) return 'windows';
//     if (/Mac/i.test(platform)) return 'macos';
//     if (/Linux/i.test(platform)) return 'linux';
    
//     return 'unknown';
//   }

//   // Extract browser information
//   static extractBrowserInfo(userAgent) {
//     const browsers = [
//       { name: 'Chrome', regex: /Chrome\/([0-9.]+)/ },
//       { name: 'Firefox', regex: /Firefox\/([0-9.]+)/ },
//       { name: 'Safari', regex: /Safari\/([0-9.]+)/ },
//       { name: 'Edge', regex: /Edge\/([0-9.]+)/ },
//       { name: 'Opera', regex: /Opera\/([0-9.]+)/ }
//     ];

//     for (const browser of browsers) {
//       const match = userAgent.match(browser.regex);
//       if (match) {
//         return {
//           name: browser.name,
//           version: match[1]
//         };
//       }
//     }

//     return { name: 'Unknown', version: '0.0.0' };
//   }

//   // Extract OS information
//   static extractOSInfo(userAgent, platform) {
//     const osPatterns = [
//       { name: 'iOS', regex: /iPhone OS ([0-9_]+)/ },
//       { name: 'Android', regex: /Android ([0-9.]+)/ },
//       { name: 'Windows', regex: /Windows NT ([0-9.]+)/ },
//       { name: 'macOS', regex: /Mac OS X ([0-9_]+)/ },
//       { name: 'Linux', regex: /Linux/ }
//     ];

//     for (const os of osPatterns) {
//       const match = userAgent.match(os.regex);
//       if (match) {
//         return {
//           name: os.name,
//           version: match[1] ? match[1].replace(/_/g, '.') : 'Unknown'
//         };
//       }
//     }

//     return { name: platform || 'Unknown', version: 'Unknown' };
//   }

//   // Get device capabilities
//   static getDeviceCapabilities(deviceInfo) {
//     return {
//       touchScreen: deviceInfo.touchScreen || false,
//       geolocation: deviceInfo.geolocation || false,
//       camera: deviceInfo.camera || false,
//       microphone: deviceInfo.microphone || false,
//       notifications: deviceInfo.notifications || false,
//       bluetooth: deviceInfo.bluetooth || false,
//       nfc: deviceInfo.nfc || false,
//       biometrics: {
//         fingerprint: deviceInfo.fingerprint || false,
//         faceId: deviceInfo.faceId || false,
//         voiceRecognition: deviceInfo.voiceRecognition || false
//       },
//       storage: {
//         localStorage: deviceInfo.localStorage || false,
//         sessionStorage: deviceInfo.sessionStorage || false,
//         indexedDB: deviceInfo.indexedDB || false
//       }
//     };
//   }

//   // Validate device data
//   static validateDeviceData(deviceData) {
//     const required = ['userId', 'deviceInfo'];
    
//     for (const field of required) {
//       if (!deviceData[field]) {
//         throw new Error(`Missing required field: ${field}`);
//       }
//     }

//     if (!deviceData.deviceInfo || typeof deviceData.deviceInfo !== 'object') {
//       throw new Error('deviceInfo must be an object');
//     }

//     return true;
//   }

//   // Calculate device trust score
//   static calculateTrustScore(deviceInfo, userHistory = {}) {
//     let score = 50; // Base score

//     // Device age (older = more trusted)
//     if (userHistory.registrationDate) {
//       const daysSinceRegistration = (Date.now() - new Date(userHistory.registrationDate)) / (1000 * 60 * 60 * 24);
//       score += Math.min(daysSinceRegistration * 0.5, 30);
//     }

//     // Usage frequency
//     if (userHistory.loginCount > 10) score += 10;
//     if (userHistory.loginCount > 50) score += 10;

//     // Security features
//     if (deviceInfo.biometrics?.fingerprint || deviceInfo.biometrics?.faceId) score += 15;
//     if (deviceInfo.screenLock) score += 10;

//     // Suspicious indicators
//     if (deviceInfo.vpn) score -= 10;
//     if (deviceInfo.proxy) score -= 15;
//     if (deviceInfo.emulator) score -= 30;

//     return Math.max(0, Math.min(100, score));
//   }
// }



// import { createHash } from 'node:crypto';

// export class DeviceUtils {
//   // Generate unique device fingerprint - updated to handle your device structure
//   static generateFingerprint(data) {
//     const { userAgent, ipAddress, deviceInfo } = data;
    
//     console.log('Generating fingerprint for:', { userAgent, ipAddress, deviceInfo });
    
//     // Create fingerprint based on your actual device structure
//     const fingerprintData = {
//       type: deviceInfo.type,
//       browserName: deviceInfo.browser?.name || userAgent,
//       browserVersion: deviceInfo.browser?.version,
//       osName: deviceInfo.os?.name,
//       osVersion: deviceInfo.os?.version,
//       screenWidth: deviceInfo.screen?.width,
//       screenHeight: deviceInfo.screen?.height,
//       colorDepth: deviceInfo.screen?.colorDepth,
//       pixelRatio: deviceInfo.screen?.pixelRatio,
//       deviceType: deviceInfo.device?.type
//     };
    
//     const fingerprintString = JSON.stringify(fingerprintData, Object.keys(fingerprintData).sort());
//     console.log('Fingerprint string:', fingerprintString);
    
//     const fingerprint = createHash('sha256').update(fingerprintString).digest('hex');
//     console.log('Generated fingerprint:', fingerprint);
    
//     return fingerprint;
//   }

//   // Detect device type from user agent and device info
//   static detectDeviceType(deviceInfo) {
//     const userAgent = deviceInfo.userAgent || '';
//     const platform = deviceInfo.platform || '';
    
//     // Mobile devices
//     if (/iPhone|iPad|iPod/i.test(userAgent)) return 'ios';
//     if (/Android/i.test(userAgent)) return 'android';
//     if (/Mobile|Tablet/i.test(userAgent)) return 'mobile';
    
//     // Desktop
//     if (/Windows/i.test(platform)) return 'windows';
//     if (/Mac/i.test(platform)) return 'macos';
//     if (/Linux/i.test(platform)) return 'linux';
    
//     return 'unknown';
//   }

//   // Extract browser information
//   static extractBrowserInfo(userAgent) {
//     const browsers = [
//       { name: 'Chrome', regex: /Chrome\/([0-9.]+)/ },
//       { name: 'Firefox', regex: /Firefox\/([0-9.]+)/ },
//       { name: 'Safari', regex: /Safari\/([0-9.]+)/ },
//       { name: 'Edge', regex: /Edge\/([0-9.]+)/ },
//       { name: 'Opera', regex: /Opera\/([0-9.]+)/ }
//     ];

//     for (const browser of browsers) {
//       const match = userAgent.match(browser.regex);
//       if (match) {
//         return {
//           name: browser.name,
//           version: match[1]
//         };
//       }
//     }

//     return { name: 'Unknown', version: '0.0.0' };
//   }

//   // Extract OS information
//   static extractOSInfo(userAgent, platform) {
//     const osPatterns = [
//       { name: 'iOS', regex: /iPhone OS ([0-9_]+)/ },
//       { name: 'Android', regex: /Android ([0-9.]+)/ },
//       { name: 'Windows', regex: /Windows NT ([0-9.]+)/ },
//       { name: 'macOS', regex: /Mac OS X ([0-9_]+)/ },
//       { name: 'Linux', regex: /Linux/ }
//     ];

//     for (const os of osPatterns) {
//       const match = userAgent.match(os.regex);
//       if (match) {
//         return {
//           name: os.name,
//           version: match[1] ? match[1].replace(/_/g, '.') : 'Unknown'
//         };
//       }
//     }

//     return { name: platform || 'Unknown', version: 'Unknown' };
//   }

//   // Extract device information for database storage
//   static extractDeviceInfo(deviceInfo) {
//     return {
//       device_type: deviceInfo.type || 'unknown',
//       browser_name: deviceInfo.browser?.name || 'unknown',
//       browser_version: deviceInfo.browser?.version || 'unknown',
//       os_name: deviceInfo.os?.name || 'unknown',
//       os_version: deviceInfo.os?.version || 'unknown',
//       screen_info: {
//         width: deviceInfo.screen?.width,
//         height: deviceInfo.screen?.height,
//         colorDepth: deviceInfo.screen?.colorDepth,
//         pixelRatio: deviceInfo.screen?.pixelRatio
//       }
//     };
//   }

//   // Get device capabilities
//   static getDeviceCapabilities(deviceInfo) {
//     return {
//       touchScreen: deviceInfo.touchScreen || false,
//       geolocation: deviceInfo.geolocation || false,
//       camera: deviceInfo.camera || false,
//       microphone: deviceInfo.microphone || false,
//       notifications: deviceInfo.notifications || false,
//       bluetooth: deviceInfo.bluetooth || false,
//       nfc: deviceInfo.nfc || false,
//       biometrics: {
//         fingerprint: deviceInfo.fingerprint || false,
//         faceId: deviceInfo.faceId || false,
//         voiceRecognition: deviceInfo.voiceRecognition || false
//       },
//       storage: {
//         localStorage: deviceInfo.localStorage || false,
//         sessionStorage: deviceInfo.sessionStorage || false,
//         indexedDB: deviceInfo.indexedDB || false
//       }
//     };
//   }

//   // Updated validation - NO LONGER REQUIRES userId since it's resolved in controller
//   static validateDeviceData(deviceData) {
//     console.log('DeviceUtils.validateDeviceData called with:', deviceData);
    
//     // Remove userId requirement since it's resolved in controller
//     const { deviceInfo, location, capabilities } = deviceData;
    
//     // Validate deviceInfo
//     if (!deviceInfo || typeof deviceInfo !== 'object') {
//       throw new Error('deviceInfo must be an object');
//     }

//     // Validate required deviceInfo fields based on your actual structure
//     if (!deviceInfo.type) {
//       throw new Error('Device type is required');
//     }

//     if (!deviceInfo.browser || typeof deviceInfo.browser !== 'object') {
//       throw new Error('Browser information is required');
//     }

//     if (!deviceInfo.os || typeof deviceInfo.os !== 'object') {
//       throw new Error('OS information is required');
//     }

//     if (!deviceInfo.screen || typeof deviceInfo.screen !== 'object') {
//       throw new Error('Screen information is required');
//     }

//     // Validate location if provided
//     if (location && typeof location !== 'object') {
//       throw new Error('Location must be an object');
//     }

//     // Validate capabilities if provided
//     if (capabilities && !Array.isArray(capabilities)) {
//       throw new Error('Capabilities must be an array');
//     }

//     console.log('Device data validation passed');
//     return true;
//   }

//   // Calculate device trust score
//   static calculateTrustScore(deviceInfo, userHistory = {}) {
//     let score = 50; // Base score

//     // Device age (older = more trusted)
//     if (userHistory.registrationDate) {
//       const daysSinceRegistration = (Date.now() - new Date(userHistory.registrationDate)) / (1000 * 60 * 60 * 24);
//       score += Math.min(daysSinceRegistration * 0.5, 30);
//     }

//     // Usage frequency
//     if (userHistory.loginCount > 10) score += 10;
//     if (userHistory.loginCount > 50) score += 10;

//     // Security features
//     if (deviceInfo.biometrics?.fingerprint || deviceInfo.biometrics?.faceId) score += 15;
//     if (deviceInfo.screenLock) score += 10;

//     // Suspicious indicators
//     if (deviceInfo.vpn) score -= 10;
//     if (deviceInfo.proxy) score -= 15;
//     if (deviceInfo.emulator) score -= 30;

//     return Math.max(0, Math.min(100, score));
//   }
// }


import { createHash } from 'node:crypto';

export class DeviceUtils {
  // Generate unique device fingerprint - updated to handle your device structure
  static generateFingerprint(data) {
    const { userAgent, ipAddress, deviceInfo } = data;
    
    console.log('Generating fingerprint for:', { userAgent, ipAddress, deviceInfo });
    
    // Create fingerprint based on your actual device structure
    const fingerprintData = {
      type: deviceInfo.type,
      browserName: deviceInfo.browser?.name || userAgent,
      browserVersion: deviceInfo.browser?.version,
      osName: deviceInfo.os?.name,
      osVersion: deviceInfo.os?.version,
      screenWidth: deviceInfo.screen?.width,
      screenHeight: deviceInfo.screen?.height,
      colorDepth: deviceInfo.screen?.colorDepth,
      pixelRatio: deviceInfo.screen?.pixelRatio,
      deviceType: deviceInfo.device?.type
    };
    
    const fingerprintString = JSON.stringify(fingerprintData, Object.keys(fingerprintData).sort());
    console.log('Fingerprint string:', fingerprintString);
    
    const fingerprint = createHash('sha256').update(fingerprintString).digest('hex');
    console.log('Generated fingerprint:', fingerprint);
    
    return fingerprint;
  }

  // Detect device type from user agent and device info
  static detectDeviceType(deviceInfo) {
    const userAgent = deviceInfo.userAgent || '';
    const platform = deviceInfo.platform || '';
    
    // Mobile devices
    if (/iPhone|iPad|iPod/i.test(userAgent)) return 'ios';
    if (/Android/i.test(userAgent)) return 'android';
    if (/Mobile|Tablet/i.test(userAgent)) return 'mobile';
    
    // Desktop
    if (/Windows/i.test(platform)) return 'windows';
    if (/Mac/i.test(platform)) return 'macos';
    if (/Linux/i.test(platform)) return 'linux';
    
    return 'unknown';
  }

  // Extract browser information
  static extractBrowserInfo(userAgent) {
    const browsers = [
      { name: 'Chrome', regex: /Chrome\/([0-9.]+)/ },
      { name: 'Firefox', regex: /Firefox\/([0-9.]+)/ },
      { name: 'Safari', regex: /Safari\/([0-9.]+)/ },
      { name: 'Edge', regex: /Edge\/([0-9.]+)/ },
      { name: 'Opera', regex: /Opera\/([0-9.]+)/ }
    ];

    for (const browser of browsers) {
      const match = userAgent.match(browser.regex);
      if (match) {
        return {
          name: browser.name,
          version: match[1]
        };
      }
    }

    return { name: 'Unknown', version: '0.0.0' };
  }

  // Extract OS information
  static extractOSInfo(userAgent, platform) {
    const osPatterns = [
      { name: 'iOS', regex: /iPhone OS ([0-9_]+)/ },
      { name: 'Android', regex: /Android ([0-9.]+)/ },
      { name: 'Windows', regex: /Windows NT ([0-9.]+)/ },
      { name: 'macOS', regex: /Mac OS X ([0-9_]+)/ },
      { name: 'Linux', regex: /Linux/ }
    ];

    for (const os of osPatterns) {
      const match = userAgent.match(os.regex);
      if (match) {
        return {
          name: os.name,
          version: match[1] ? match[1].replace(/_/g, '.') : 'Unknown'
        };
      }
    }

    return { name: platform || 'Unknown', version: 'Unknown' };
  }

  // Extract device information for database storage
  static extractDeviceInfo(deviceInfo) {
    return {
      device_type: deviceInfo.type || 'unknown',
      browser_name: deviceInfo.browser?.name || 'unknown',
      browser_version: deviceInfo.browser?.version || 'unknown',
      os_name: deviceInfo.os?.name || 'unknown',
      os_version: deviceInfo.os?.version || 'unknown',
      screen_info: {
        width: deviceInfo.screen?.width,
        height: deviceInfo.screen?.height,
        colorDepth: deviceInfo.screen?.colorDepth,
        pixelRatio: deviceInfo.screen?.pixelRatio
      }
    };
  }

  // Get device capabilities
  static getDeviceCapabilities(deviceInfo) {
    return {
      touchScreen: deviceInfo.touchScreen || false,
      geolocation: deviceInfo.geolocation || false,
      camera: deviceInfo.camera || false,
      microphone: deviceInfo.microphone || false,
      notifications: deviceInfo.notifications || false,
      bluetooth: deviceInfo.bluetooth || false,
      nfc: deviceInfo.nfc || false,
      biometrics: {
        fingerprint: deviceInfo.fingerprint || false,
        faceId: deviceInfo.faceId || false,
        voiceRecognition: deviceInfo.voiceRecognition || false
      },
      storage: {
        localStorage: deviceInfo.localStorage || false,
        sessionStorage: deviceInfo.sessionStorage || false,
        indexedDB: deviceInfo.indexedDB || false
      }
    };
  }

  // Updated validation - NO LONGER REQUIRES userId since it's resolved in controller
  static validateDeviceData(deviceData) {
    console.log('DeviceUtils.validateDeviceData called with:', deviceData);
    
    // Remove userId requirement since it's resolved in controller
    const { deviceInfo, location, capabilities } = deviceData;
    
    // Validate deviceInfo
    if (!deviceInfo || typeof deviceInfo !== 'object') {
      throw new Error('deviceInfo must be an object');
    }

    // Validate required deviceInfo fields based on your actual structure
    if (!deviceInfo.type) {
      throw new Error('Device type is required');
    }

    if (!deviceInfo.browser || typeof deviceInfo.browser !== 'object') {
      throw new Error('Browser information is required');
    }

    if (!deviceInfo.os || typeof deviceInfo.os !== 'object') {
      throw new Error('OS information is required');
    }

    if (!deviceInfo.screen || typeof deviceInfo.screen !== 'object') {
      throw new Error('Screen information is required');
    }

    // Validate location if provided
    if (location && typeof location !== 'object') {
      throw new Error('Location must be an object');
    }

    // Validate capabilities if provided
    if (capabilities && typeof capabilities !== 'object') {
      throw new Error('Capabilities must be an object');
    }

    console.log('Device data validation passed');
    return true;
  }

  // Calculate device trust score
  static calculateTrustScore(deviceInfo, userHistory = {}) {
    let score = 50; // Base score

    // Device age (older = more trusted)
    if (userHistory.registrationDate) {
      const daysSinceRegistration = (Date.now() - new Date(userHistory.registrationDate)) / (1000 * 60 * 60 * 24);
      score += Math.min(daysSinceRegistration * 0.5, 30);
    }

    // Usage frequency
    if (userHistory.loginCount > 10) score += 10;
    if (userHistory.loginCount > 50) score += 10;

    // Security features
    if (deviceInfo.biometrics?.fingerprint || deviceInfo.biometrics?.faceId) score += 15;
    if (deviceInfo.screenLock) score += 10;

    // Suspicious indicators
    if (deviceInfo.vpn) score -= 10;
    if (deviceInfo.proxy) score -= 15;
    if (deviceInfo.emulator) score -= 30;

    return Math.max(0, Math.min(100, score));
  }
}



