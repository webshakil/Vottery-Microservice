//this is 5 steps code
import { useState, useEffect } from 'react';

export const useDeviceDetection = () => {
  const [deviceInfo, setDeviceInfo] = useState({
    type: 'unknown',
    os: 'unknown',
    browser: 'unknown',
    isMobile: false,
    isTablet: false,
    isDesktop: false,
    supportsWebAuthn: false,
    supportsTouchID: false,
    supportsFaceID: false,
    supportsFingerprint: false,
    deviceId: null,
    screenInfo: {
      width: 0,
      height: 0,
      colorDepth: 0,
      pixelRatio: 1
    },
    timezone: 'UTC',
    language: 'en',
    platform: 'unknown'
  });

  const detectDevice = () => {
    const userAgent = navigator.userAgent.toLowerCase();
    const platform = navigator.platform.toLowerCase();
    
    // Device type detection
    const isMobile = /android|iphone|ipod|blackberry|iemobile|opera mini/i.test(userAgent);
    const isTablet = /ipad|android(?!.*mobile)|kindle|silk/i.test(userAgent);
    const isDesktop = !isMobile && !isTablet;
    
    // OS detection
    let os = 'unknown';
    if (/windows/i.test(userAgent)) os = 'Windows';
    else if (/mac/i.test(userAgent)) os = 'macOS';
    else if (/linux/i.test(userAgent)) os = 'Linux';
    else if (/android/i.test(userAgent)) os = 'Android';
    else if (/iphone|ipad|ipod/i.test(userAgent)) os = 'iOS';
    
    // Browser detection
    let browser = 'unknown';
    if (/chrome/i.test(userAgent) && !/edge/i.test(userAgent)) browser = 'Chrome';
    else if (/firefox/i.test(userAgent)) browser = 'Firefox';
    else if (/safari/i.test(userAgent) && !/chrome/i.test(userAgent)) browser = 'Safari';
    else if (/edge/i.test(userAgent)) browser = 'Edge';
    else if (/opera/i.test(userAgent)) browser = 'Opera';
    
    // Biometric support detection
    const supportsWebAuthn = !!window.PublicKeyCredential;
    const supportsTouchID = os === 'iOS' && supportsWebAuthn;
    const supportsFaceID = os === 'iOS' && supportsWebAuthn;
    const supportsFingerprint = (os === 'Android' || os === 'Windows') && supportsWebAuthn;
    
    // Generate device fingerprint
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Vottery Device Fingerprint', 2, 2);
    
    const canvasFingerprint = canvas.toDataURL();
    
    const fingerprint = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      screen.colorDepth,
      new Date().getTimezoneOffset(),
      navigator.hardwareConcurrency || 'unknown',
      navigator.deviceMemory || 'unknown',
      canvasFingerprint.slice(-50) // Last 50 chars of canvas fingerprint
    ].join('|');
    
    // Create device ID hash
    const deviceId = btoa(fingerprint).replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
    
    return {
      type: isMobile ? 'mobile' : isTablet ? 'tablet' : 'desktop',
      os,
      browser,
      isMobile,
      isTablet,
      isDesktop,
      supportsWebAuthn,
      supportsTouchID,
      supportsFaceID,
      supportsFingerprint,
      deviceId,
      screenInfo: {
        width: screen.width,
        height: screen.height,
        colorDepth: screen.colorDepth,
        pixelRatio: window.devicePixelRatio || 1
      },
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language,
      platform: navigator.platform
    };
  };

  useEffect(() => {
    const info = detectDevice();
    setDeviceInfo(info);
    
    // Store device info in session
    sessionStorage.setItem('vottery_device_info', JSON.stringify(info));
  }, []);

  const getBiometricCapabilities = () => {
    const { type, os, supportsWebAuthn, supportsTouchID, supportsFaceID, supportsFingerprint } = deviceInfo;
    
    const capabilities = [];
    
    if (supportsWebAuthn) {
      if (supportsTouchID) capabilities.push('Touch ID');
      if (supportsFaceID) capabilities.push('Face ID');
      if (supportsFingerprint) capabilities.push('Fingerprint');
      
      if (capabilities.length === 0) {
        capabilities.push('Platform Authentication');
      }
    }
    
    return capabilities;
  };

  const getDeviceTypeIcon = () => {
    const { type } = deviceInfo;
    switch (type) {
      case 'mobile':
        return '📱';
      case 'tablet':
        return '📱'; // Using same icon for tablet
      case 'desktop':
        return '💻';
      default:
        return '🖥️';
    }
  };

  return {
    deviceInfo,
    getBiometricCapabilities,
    getDeviceTypeIcon,
    isReady: deviceInfo.deviceId !== null
  };
};
//this is 3 steps code
// import { useState, useEffect } from 'react';
  
// export const useDeviceDetection = () => {
//   const [deviceInfo, setDeviceInfo] = useState(null);

//   useEffect(() => {
//     const detectDevice = () => {
//       const userAgent = navigator.userAgent;
//       let deviceType = 'Unknown';
//       let os = 'Unknown';
//       let browser = 'Unknown';

//       // Detect OS
//       if (/Windows NT/.test(userAgent)) os = 'Windows';
//       else if (/Mac OS X/.test(userAgent)) os = 'macOS';
//       else if (/Linux/.test(userAgent)) os = 'Linux';
//       else if (/iPhone|iPad|iPod/.test(userAgent)) os = 'iOS';
//       else if (/Android/.test(userAgent)) os = 'Android';

//       // Detect Device Type
//       if (/iPhone|iPod/.test(userAgent)) deviceType = 'iPhone';
//       else if (/iPad/.test(userAgent)) deviceType = 'iPad';
//       else if (/Android/.test(userAgent)) {
//         deviceType = /Mobile/.test(userAgent) ? 'Android Phone' : 'Android Tablet';
//       } else if (/Windows NT/.test(userAgent)) {
//         deviceType = 'Windows PC';
//       } else if (/Mac OS X/.test(userAgent)) {
//         deviceType = 'Mac';
//       }

//       // Detect Browser
//       if (/Chrome/.test(userAgent) && !/Edge/.test(userAgent)) browser = 'Chrome';
//       else if (/Firefox/.test(userAgent)) browser = 'Firefox';
//       else if (/Safari/.test(userAgent) && !/Chrome/.test(userAgent)) browser = 'Safari';
//       else if (/Edge/.test(userAgent)) browser = 'Edge';

//       setDeviceInfo({
//         deviceType,
//         os,
//         browser,
//         userAgent,
//         screen: {
//           width: window.screen.width,
//           height: window.screen.height,
//           colorDepth: window.screen.colorDepth,
//           pixelDepth: window.screen.pixelDepth
//         },
//         viewport: {
//           width: window.innerWidth,
//           height: window.innerHeight
//         },
//         timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
//         language: navigator.language,
//         languages: navigator.languages,
//         cookieEnabled: navigator.cookieEnabled,
//         doNotTrack: navigator.doNotTrack,
//         hardwareConcurrency: navigator.hardwareConcurrency,
//         deviceMemory: navigator.deviceMemory,
//         connection: navigator.connection ? {
//           effectiveType: navigator.connection.effectiveType,
//           downlink: navigator.connection.downlink,
//           rtt: navigator.connection.rtt
//         } : null
//       });
//     };

//     detectDevice();
//     window.addEventListener('resize', detectDevice);
    
//     return () => window.removeEventListener('resize', detectDevice);
//   }, []);

//   return deviceInfo;
// };