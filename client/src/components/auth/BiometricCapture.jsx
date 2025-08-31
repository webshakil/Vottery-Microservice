//step 5 for successful biometirc
import React, { useState, useEffect, useMemo } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useDeviceDetection } from '../../hooks/useDeviceDetection';
import { toast } from 'react-hot-toast';

const BiometricCapture = () => {
  const { isLoading, completeAuthentication, currentStep } = useAuth();
  const { deviceInfo, getBiometricCapabilities, getDeviceTypeIcon, isReady } = useDeviceDetection();
  const [captureStatus, setCaptureStatus] = useState('ready'); // ready, capturing, success, error
  const [error, setError] = useState('');
  const [biometricInfo, setBiometricInfo] = useState(null);

  // Memoize the capabilities to prevent recreation on every render
  const biometricCapabilities = useMemo(() => {
    if (!isReady) return [];
    return getBiometricCapabilities();
  }, [isReady, deviceInfo.supportsWebAuthn, deviceInfo.supportsTouchID, deviceInfo.supportsFaceID, deviceInfo.supportsFingerprint]);

  // Fixed useEffect with proper dependencies
  useEffect(() => {
    if (isReady && biometricCapabilities.length >= 0) {
      setBiometricInfo({
        deviceType: deviceInfo.type,
        os: deviceInfo.os,
        browser: deviceInfo.browser,
        capabilities: biometricCapabilities,
        hasWebAuthn: deviceInfo.supportsWebAuthn
      });
    }
  }, [isReady, deviceInfo.type, deviceInfo.os, deviceInfo.browser, deviceInfo.supportsWebAuthn, biometricCapabilities]);

  // Handle biometric capture - Updated to use completeAuthentication
  const handleCaptureBiometric = async () => {
    try {
      setCaptureStatus('capturing');
      setError('');
      
      // Call the complete authentication which handles device registration,
      // biometric registration, and WebAuthn in the backend
      await completeAuthentication();
      
      setCaptureStatus('success');
      toast.success('Authentication completed successfully!');
    } catch (error) {
      setCaptureStatus('error');
      setError(error.message);
      toast.error(error.message);
    }
  };

  // Get status color
  const getStatusColor = () => {
    switch (captureStatus) {
      case 'capturing':
        return 'text-yellow-600';
      case 'success':
        return 'text-green-600';
      case 'error':
        return 'text-red-600';
      default:
        return 'text-gray-600';
    }
  };

  // Get status message
  const getStatusMessage = () => {
    switch (captureStatus) {
      case 'capturing':
        return 'Processing authentication...';
      case 'success':
        return 'Authentication completed successfully!';
      case 'error':
        return error || 'Authentication failed';
      default:
        return 'Ready to complete authentication';
    }
  };

  // Only show this component when it's the current step
  if (currentStep !== 5) {
    return null;
  }

  if (!isReady || !biometricInfo) {
    return (
      <div className="bg-white rounded-lg shadow-lg p-8">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Detecting device capabilities...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-lg p-8">
      <div className="text-center mb-6">
        <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-purple-100 mb-4">
          <svg className="h-6 w-6 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
        </div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Final Authentication Step</h2>
        <p className="text-gray-600">
          Complete device registration and biometric authentication
        </p>
      </div>

      {/* Device Information */}
      <div className="bg-gray-50 rounded-lg p-4 mb-6">
        <h3 className="text-sm font-medium text-gray-900 mb-3">Device Information</h3>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-gray-500">Device Type:</span>
            <span className="ml-2 font-medium">
              {getDeviceTypeIcon()} {biometricInfo.deviceType}
            </span>
          </div>
          <div>
            <span className="text-gray-500">OS:</span>
            <span className="ml-2 font-medium">{biometricInfo.os}</span>
          </div>
          <div>
            <span className="text-gray-500">Browser:</span>
            <span className="ml-2 font-medium">{biometricInfo.browser}</span>
          </div>
          <div>
            <span className="text-gray-500">WebAuthn:</span>
            <span className="ml-2 font-medium">
              {biometricInfo.hasWebAuthn ? '✅ Supported' : '❌ Not Supported'}
            </span>
          </div>
        </div>
      </div>

      {/* Biometric Capabilities */}
      <div className="bg-blue-50 rounded-lg p-4 mb-6">
        <h3 className="text-sm font-medium text-gray-900 mb-3">Authentication Methods</h3>
        {biometricInfo.capabilities.length > 0 ? (
          <div className="space-y-2">
            {biometricInfo.capabilities.map((capability, index) => (
              <div key={index} className="flex items-center text-sm">
                <span className="text-green-500 mr-2">✓</span>
                <span className="text-gray-700">{capability}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex items-center text-sm">
            <span className="text-yellow-500 mr-2">⚠</span>
            <span className="text-gray-700">
              Device fingerprint authentication will be used
            </span>
          </div>
        )}
      </div>

      {/* Error Display */}
      {error && captureStatus === 'error' && (
        <div className="mb-4 bg-red-50 border border-red-200 rounded-lg p-3">
          <div className="flex">
            <svg className="h-5 w-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div className="ml-3">
              <p className="text-sm text-red-700">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Status Display */}
      <div className="text-center mb-6">
        <div className={`text-sm font-medium ${getStatusColor()}`}>
          {captureStatus === 'capturing' && (
            <div className="flex items-center justify-center mb-2">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-yellow-600 mr-2"></div>
            </div>
          )}
          {captureStatus === 'success' && (
            <div className="flex items-center justify-center mb-2">
              <svg className="h-5 w-5 text-green-600 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            </div>
          )}
          {captureStatus === 'error' && (
            <div className="flex items-center justify-center mb-2">
              <svg className="h-5 w-5 text-red-600 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </div>
          )}
          {getStatusMessage()}
        </div>
      </div>

      {/* Complete Authentication Button */}
      {captureStatus !== 'success' && (
        <button
          onClick={handleCaptureBiometric}
          disabled={isLoading || captureStatus === 'capturing'}
          className="w-full bg-purple-600 hover:bg-purple-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white font-medium py-3 px-4 rounded-lg transition duration-200"
        >
          {captureStatus === 'capturing' ? (
            <div className="flex items-center justify-center">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
              Completing Authentication...
            </div>
          ) : (
            <>
              <span className="mr-2">🔐</span>
              Complete Authentication
            </>
          )}
        </button>
      )}

      {/* Success State */}
      {captureStatus === 'success' && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
          <div className="flex items-center">
            <svg className="h-5 w-5 text-green-400 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <p className="text-sm font-medium text-green-800">Authentication Complete</p>
              <p className="text-sm text-green-700">
                Redirecting to dashboard...
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Instructions */}
      <div className="mt-6">
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <h4 className="text-sm font-medium text-yellow-800 mb-2">What happens next:</h4>
          <ul className="text-sm text-yellow-700 space-y-1">
            <li>• Your device will be registered securely</li>
            <li>• Biometric data will be captured and encrypted</li>
            {biometricInfo.hasWebAuthn && (
              <li>• WebAuthn credentials will be created for future logins</li>
            )}
            <li>• All data is encrypted and stored securely</li>
            <li>• You'll be redirected to your dashboard</li>
          </ul>
        </div>
      </div>

      {/* Security Information */}
      <div className="mt-4 text-center">
        <div className="inline-flex items-center space-x-4 text-xs text-gray-500">
          <span className="flex items-center">
            <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            End-to-End Encrypted
          </span>
          <span className="flex items-center">
            <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Secure Authentication
          </span>
        </div>
      </div>
    </div>
  );
};

export default BiometricCapture;
//this is also 5 steps to solve the circular dependency
// import React, { useState, useEffect, useMemo } from 'react';
// import { useAuth } from '../../contexts/AuthContext';
// import { useDeviceDetection } from '../../hooks/useDeviceDetection';
// import { toast } from 'react-hot-toast';

// const BiometricCapture = () => {
//   const { isLoading, captureBiometric, currentStep } = useAuth();
//   const { deviceInfo, getBiometricCapabilities, getDeviceTypeIcon, isReady } = useDeviceDetection();
//   const [captureStatus, setCaptureStatus] = useState('ready'); // ready, capturing, success, error
//   const [error, setError] = useState('');
//   const [biometricInfo, setBiometricInfo] = useState(null);

//   // Memoize the capabilities to prevent recreation on every render
//   const biometricCapabilities = useMemo(() => {
//     if (!isReady) return [];
//     return getBiometricCapabilities();
//   }, [isReady, deviceInfo.supportsWebAuthn, deviceInfo.supportsTouchID, deviceInfo.supportsFaceID, deviceInfo.supportsFingerprint]);

//   // Fixed useEffect with proper dependencies
//   useEffect(() => {
//     if (isReady && biometricCapabilities.length >= 0) {
//       setBiometricInfo({
//         deviceType: deviceInfo.type,
//         os: deviceInfo.os,
//         browser: deviceInfo.browser,
//         capabilities: biometricCapabilities,
//         hasWebAuthn: deviceInfo.supportsWebAuthn
//       });
//     }
//   }, [isReady, deviceInfo.type, deviceInfo.os, deviceInfo.browser, deviceInfo.supportsWebAuthn, biometricCapabilities]);

//   // Handle biometric capture
//   const handleCaptureBiometric = async () => {
//     try {
//       setCaptureStatus('capturing');
//       setError('');
      
//       await captureBiometric();
      
//       setCaptureStatus('success');
//       toast.success('Biometric data captured successfully!');
//     } catch (error) {
//       setCaptureStatus('error');
//       setError(error.message);
//       toast.error(error.message);
//     }
//   };

//   // Get status color
//   const getStatusColor = () => {
//     switch (captureStatus) {
//       case 'capturing':
//         return 'text-yellow-600';
//       case 'success':
//         return 'text-green-600';
//       case 'error':
//         return 'text-red-600';
//       default:
//         return 'text-gray-600';
//     }
//   };

//   // Get status message
//   const getStatusMessage = () => {
//     switch (captureStatus) {
//       case 'capturing':
//         return 'Capturing biometric data...';
//       case 'success':
//         return 'Biometric data captured successfully!';
//       case 'error':
//         return error || 'Failed to capture biometric data';
//       default:
//         return 'Ready to capture biometric data';
//     }
//   };

//   // Only show this component when it's the current step
//   if (currentStep !== 5) {
//     return null;
//   }

//   if (!isReady || !biometricInfo) {
//     return (
//       <div className="bg-white rounded-lg shadow-lg p-8">
//         <div className="text-center">
//           <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600 mx-auto mb-4"></div>
//           <p className="text-gray-600">Detecting device capabilities...</p>
//         </div>
//       </div>
//     );
//   }

//   return (
//     <div className="bg-white rounded-lg shadow-lg p-8">
//       <div className="text-center mb-6">
//         <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-purple-100 mb-4">
//           <svg className="h-6 w-6 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
//           </svg>
//         </div>
//         <h2 className="text-2xl font-bold text-gray-900 mb-2">Biometric Authentication</h2>
//         <p className="text-gray-600">
//           Complete the final security step by capturing your biometric data
//         </p>
//       </div>

//       {/* Device Information */}
//       <div className="bg-gray-50 rounded-lg p-4 mb-6">
//         <h3 className="text-sm font-medium text-gray-900 mb-3">Device Information</h3>
//         <div className="grid grid-cols-2 gap-4 text-sm">
//           <div>
//             <span className="text-gray-500">Device Type:</span>
//             <span className="ml-2 font-medium">
//               {getDeviceTypeIcon()} {biometricInfo.deviceType}
//             </span>
//           </div>
//           <div>
//             <span className="text-gray-500">OS:</span>
//             <span className="ml-2 font-medium">{biometricInfo.os}</span>
//           </div>
//           <div>
//             <span className="text-gray-500">Browser:</span>
//             <span className="ml-2 font-medium">{biometricInfo.browser}</span>
//           </div>
//           <div>
//             <span className="text-gray-500">WebAuthn:</span>
//             <span className="ml-2 font-medium">
//               {biometricInfo.hasWebAuthn ? '✅ Supported' : '❌ Not Supported'}
//             </span>
//           </div>
//         </div>
//       </div>

//       {/* Biometric Capabilities */}
//       <div className="bg-blue-50 rounded-lg p-4 mb-6">
//         <h3 className="text-sm font-medium text-gray-900 mb-3">Available Biometric Methods</h3>
//         {biometricInfo.capabilities.length > 0 ? (
//           <div className="space-y-2">
//             {biometricInfo.capabilities.map((capability, index) => (
//               <div key={index} className="flex items-center text-sm">
//                 <span className="text-green-500 mr-2">✓</span>
//                 <span className="text-gray-700">{capability}</span>
//               </div>
//             ))}
//           </div>
//         ) : (
//           <div className="flex items-center text-sm">
//             <span className="text-yellow-500 mr-2">⚠</span>
//             <span className="text-gray-700">
//               No native biometric methods detected. Fallback mode will be used.
//             </span>
//           </div>
//         )}
//       </div>

//       {/* Error Display */}
//       {error && captureStatus === 'error' && (
//         <div className="mb-4 bg-red-50 border border-red-200 rounded-lg p-3">
//           <div className="flex">
//             <svg className="h-5 w-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
//             </svg>
//             <div className="ml-3">
//               <p className="text-sm text-red-700">{error}</p>
//             </div>
//           </div>
//         </div>
//       )}

//       {/* Status Display */}
//       <div className="text-center mb-6">
//         <div className={`text-sm font-medium ${getStatusColor()}`}>
//           {captureStatus === 'capturing' && (
//             <div className="flex items-center justify-center mb-2">
//               <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-yellow-600 mr-2"></div>
//             </div>
//           )}
//           {captureStatus === 'success' && (
//             <div className="flex items-center justify-center mb-2">
//               <svg className="h-5 w-5 text-green-600 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
//               </svg>
//             </div>
//           )}
//           {captureStatus === 'error' && (
//             <div className="flex items-center justify-center mb-2">
//               <svg className="h-5 w-5 text-red-600 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
//               </svg>
//             </div>
//           )}
//           {getStatusMessage()}
//         </div>
//       </div>

//       {/* Capture Button */}
//       {captureStatus !== 'success' && (
//         <button
//           onClick={handleCaptureBiometric}
//           disabled={isLoading || captureStatus === 'capturing'}
//           className="w-full bg-purple-600 hover:bg-purple-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white font-medium py-3 px-4 rounded-lg transition duration-200"
//         >
//           {captureStatus === 'capturing' ? (
//             <div className="flex items-center justify-center">
//               <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
//               Capturing Biometric Data...
//             </div>
//           ) : (
//             <>
//               {biometricInfo.capabilities.length > 0 ? (
//                 <>
//                   <span className="mr-2">🔒</span>
//                   Capture {biometricInfo.capabilities[0]}
//                 </>
//               ) : (
//                 <>
//                   <span className="mr-2">🔐</span>
//                   Capture Device Fingerprint
//                 </>
//               )}
//             </>
//           )}
//         </button>
//       )}

//       {/* Success State */}
//       {captureStatus === 'success' && (
//         <div className="bg-green-50 border border-green-200 rounded-lg p-4">
//           <div className="flex items-center">
//             <svg className="h-5 w-5 text-green-400 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
//             </svg>
//             <div>
//               <p className="text-sm font-medium text-green-800">Biometric Authentication Complete</p>
//               <p className="text-sm text-green-700">
//                 Your device and biometric data have been securely captured and encrypted.
//               </p>
//             </div>
//           </div>
//         </div>
//       )}

//       {/* Instructions */}
//       <div className="mt-6">
//         <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
//           <h4 className="text-sm font-medium text-yellow-800 mb-2">Instructions:</h4>
//           <ul className="text-sm text-yellow-700 space-y-1">
//             {biometricInfo.capabilities.includes('Touch ID') && (
//               <li>• Place your finger on the Touch ID sensor when prompted</li>
//             )}
//             {biometricInfo.capabilities.includes('Face ID') && (
//               <li>• Look at your device's camera for Face ID recognition</li>
//             )}
//             {biometricInfo.capabilities.includes('Fingerprint') && (
//               <li>• Use your device's fingerprint scanner when prompted</li>
//             )}
//             {biometricInfo.capabilities.length === 0 && (
//               <li>• Your device will be fingerprinted for security purposes</li>
//             )}
//             <li>• This data is encrypted and used only for authentication</li>
//           </ul>
//         </div>
//       </div>

//       {/* Security Information */}
//       <div className="mt-4 text-center">
//         <div className="inline-flex items-center space-x-4 text-xs text-gray-500">
//           <span className="flex items-center">
//             <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
//             </svg>
//             End-to-End Encrypted
//           </span>
//           <span className="flex items-center">
//             <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
//             </svg>
//             Secure Authentication
//           </span>
//         </div>
//       </div>
//     </div>
//   );
// };

// export default BiometricCapture;
//this is 5 steps code

// import React, { useState, useEffect } from 'react';
// import { useAuth } from '../../contexts/AuthContext';
// import { useDeviceDetection } from '../../hooks/useDeviceDetection';
// import { toast } from 'react-hot-toast';

// const BiometricCapture = () => {
//   const { isLoading, captureBiometric, currentStep } = useAuth();
//   const { deviceInfo, getBiometricCapabilities, getDeviceTypeIcon, isReady } = useDeviceDetection();
//   const [captureStatus, setCaptureStatus] = useState('ready'); // ready, capturing, success, error
//   const [error, setError] = useState('');
//   const [biometricInfo, setBiometricInfo] = useState(null);

//   useEffect(() => {
//     if (isReady) {
//       const capabilities = getBiometricCapabilities();
//       setBiometricInfo({
//         deviceType: deviceInfo.type,
//         os: deviceInfo.os,
//         browser: deviceInfo.browser,
//         capabilities: capabilities,
//         hasWebAuthn: deviceInfo.supportsWebAuthn
//       });
//     }
//   }, [isReady, deviceInfo, getBiometricCapabilities]);

//   // Handle biometric capture
//   const handleCaptureBiometric = async () => {
//     try {
//       setCaptureStatus('capturing');
//       setError('');
      
//       await captureBiometric();
      
//       setCaptureStatus('success');
//       toast.success('Biometric data captured successfully!');
//     } catch (error) {
//       setCaptureStatus('error');
//       setError(error.message);
//       toast.error(error.message);
//     }
//   };

//   // Get status color
//   const getStatusColor = () => {
//     switch (captureStatus) {
//       case 'capturing':
//         return 'text-yellow-600';
//       case 'success':
//         return 'text-green-600';
//       case 'error':
//         return 'text-red-600';
//       default:
//         return 'text-gray-600';
//     }
//   };

//   // Get status message
//   const getStatusMessage = () => {
//     switch (captureStatus) {
//       case 'capturing':
//         return 'Capturing biometric data...';
//       case 'success':
//         return 'Biometric data captured successfully!';
//       case 'error':
//         return error || 'Failed to capture biometric data';
//       default:
//         return 'Ready to capture biometric data';
//     }
//   };

//   // Only show this component when it's the current step
//   if (currentStep !== 5) {
//     return null;
//   }

//   if (!isReady || !biometricInfo) {
//     return (
//       <div className="bg-white rounded-lg shadow-lg p-8">
//         <div className="text-center">
//           <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600 mx-auto mb-4"></div>
//           <p className="text-gray-600">Detecting device capabilities...</p>
//         </div>
//       </div>
//     );
//   }

//   return (
//     <div className="bg-white rounded-lg shadow-lg p-8">
//       <div className="text-center mb-6">
//         <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-purple-100 mb-4">
//           <svg className="h-6 w-6 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
//           </svg>
//         </div>
//         <h2 className="text-2xl font-bold text-gray-900 mb-2">Biometric Authentication</h2>
//         <p className="text-gray-600">
//           Complete the final security step by capturing your biometric data
//         </p>
//       </div>

//       {/* Device Information */}
//       <div className="bg-gray-50 rounded-lg p-4 mb-6">
//         <h3 className="text-sm font-medium text-gray-900 mb-3">Device Information</h3>
//         <div className="grid grid-cols-2 gap-4 text-sm">
//           <div>
//             <span className="text-gray-500">Device Type:</span>
//             <span className="ml-2 font-medium">
//               {getDeviceTypeIcon()} {biometricInfo.deviceType}
//             </span>
//           </div>
//           <div>
//             <span className="text-gray-500">OS:</span>
//             <span className="ml-2 font-medium">{biometricInfo.os}</span>
//           </div>
//           <div>
//             <span className="text-gray-500">Browser:</span>
//             <span className="ml-2 font-medium">{biometricInfo.browser}</span>
//           </div>
//           <div>
//             <span className="text-gray-500">WebAuthn:</span>
//             <span className="ml-2 font-medium">
//               {biometricInfo.hasWebAuthn ? '✅ Supported' : '❌ Not Supported'}
//             </span>
//           </div>
//         </div>
//       </div>

//       {/* Biometric Capabilities */}
//       <div className="bg-blue-50 rounded-lg p-4 mb-6">
//         <h3 className="text-sm font-medium text-gray-900 mb-3">Available Biometric Methods</h3>
//         {biometricInfo.capabilities.length > 0 ? (
//           <div className="space-y-2">
//             {biometricInfo.capabilities.map((capability, index) => (
//               <div key={index} className="flex items-center text-sm">
//                 <span className="text-green-500 mr-2">✓</span>
//                 <span className="text-gray-700">{capability}</span>
//               </div>
//             ))}
//           </div>
//         ) : (
//           <div className="flex items-center text-sm">
//             <span className="text-yellow-500 mr-2">⚠</span>
//             <span className="text-gray-700">
//               No native biometric methods detected. Fallback mode will be used.
//             </span>
//           </div>
//         )}
//       </div>

//       {/* Error Display */}
//       {error && captureStatus === 'error' && (
//         <div className="mb-4 bg-red-50 border border-red-200 rounded-lg p-3">
//           <div className="flex">
//             <svg className="h-5 w-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
//             </svg>
//             <div className="ml-3">
//               <p className="text-sm text-red-700">{error}</p>
//             </div>
//           </div>
//         </div>
//       )}

//       {/* Status Display */}
//       <div className="text-center mb-6">
//         <div className={`text-sm font-medium ${getStatusColor()}`}>
//           {captureStatus === 'capturing' && (
//             <div className="flex items-center justify-center mb-2">
//               <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-yellow-600 mr-2"></div>
//             </div>
//           )}
//           {captureStatus === 'success' && (
//             <div className="flex items-center justify-center mb-2">
//               <svg className="h-5 w-5 text-green-600 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
//               </svg>
//             </div>
//           )}
//           {captureStatus === 'error' && (
//             <div className="flex items-center justify-center mb-2">
//               <svg className="h-5 w-5 text-red-600 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
//               </svg>
//             </div>
//           )}
//           {getStatusMessage()}
//         </div>
//       </div>

//       {/* Capture Button */}
//       {captureStatus !== 'success' && (
//         <button
//           onClick={handleCaptureBiometric}
//           disabled={isLoading || captureStatus === 'capturing'}
//           className="w-full bg-purple-600 hover:bg-purple-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white font-medium py-3 px-4 rounded-lg transition duration-200"
//         >
//           {captureStatus === 'capturing' ? (
//             <div className="flex items-center justify-center">
//               <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
//               Capturing Biometric Data...
//             </div>
//           ) : (
//             <>
//               {biometricInfo.capabilities.length > 0 ? (
//                 <>
//                   <span className="mr-2">🔒</span>
//                   Capture {biometricInfo.capabilities[0]}
//                 </>
//               ) : (
//                 <>
//                   <span className="mr-2">🔐</span>
//                   Capture Device Fingerprint
//                 </>
//               )}
//             </>
//           )}
//         </button>
//       )}

//       {/* Success State */}
//       {captureStatus === 'success' && (
//         <div className="bg-green-50 border border-green-200 rounded-lg p-4">
//           <div className="flex items-center">
//             <svg className="h-5 w-5 text-green-400 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
//             </svg>
//             <div>
//               <p className="text-sm font-medium text-green-800">Biometric Authentication Complete</p>
//               <p className="text-sm text-green-700">
//                 Your device and biometric data have been securely captured and encrypted.
//               </p>
//             </div>
//           </div>
//         </div>
//       )}

//       {/* Instructions */}
//       <div className="mt-6">
//         <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
//           <h4 className="text-sm font-medium text-yellow-800 mb-2">Instructions:</h4>
//           <ul className="text-sm text-yellow-700 space-y-1">
//             {biometricInfo.capabilities.includes('Touch ID') && (
//               <li>• Place your finger on the Touch ID sensor when prompted</li>
//             )}
//             {biometricInfo.capabilities.includes('Face ID') && (
//               <li>• Look at your device's camera for Face ID recognition</li>
//             )}
//             {biometricInfo.capabilities.includes('Fingerprint') && (
//               <li>• Use your device's fingerprint scanner when prompted</li>
//             )}
//             {biometricInfo.capabilities.length === 0 && (
//               <li>• Your device will be fingerprinted for security purposes</li>
//             )}
//             <li>• This data is encrypted and used only for authentication</li>
//           </ul>
//         </div>
//       </div>

//       {/* Security Information */}
//       <div className="mt-4 text-center">
//         <div className="inline-flex items-center space-x-4 text-xs text-gray-500">
//           <span className="flex items-center">
//             <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
//             </svg>
//             End-to-End Encrypted
//           </span>
//           <span className="flex items-center">
//             <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
//             </svg>
//             Secure Authentication
//           </span>
//         </div>
//       </div>
//     </div>
//   );
// };

// export default BiometricCapture;




//this is 3 steps code
// import React, { useState, useEffect } from 'react';
// import { useAuth } from '../../contexts/AuthContext';

// const BiometricCapture = () => {
//   const { isLoading, captureBiometric, dispatch } = useAuth();
//   const [deviceInfo, setDeviceInfo] = useState(null);
//   const [biometricSupport, setBiometricSupport] = useState(null);
//   const [error, setError] = useState('');
//   const [captureComplete, setCaptureComplete] = useState(false);

//   useEffect(() => {
//     detectDeviceCapabilities();
//   }, []);

//   const detectDeviceCapabilities = async () => {
//     const info = {
//       userAgent: navigator.userAgent,
//       platform: navigator.platform,
//       language: navigator.language,
//       cookieEnabled: navigator.cookieEnabled,
//       onlineStatus: navigator.onLine,
//       screenResolution: `${screen.width}x${screen.height}`,
//       timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
//       deviceMemory: navigator.deviceMemory || 'unknown',
//       hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
//     };

//     // Detect device type
//     const ua = navigator.userAgent;
//     if (/iPad|iPhone|iPod/.test(ua)) {
//       info.deviceType = 'iOS';
//       info.biometricType = 'Face ID / Touch ID';
//     } else if (/Android/.test(ua)) {
//       info.deviceType = 'Android';
//       info.biometricType = 'Fingerprint';
//     } else if (/Windows/.test(ua)) {
//       info.deviceType = 'Windows';
//       info.biometricType = 'Windows Hello';
//     } else if (/Mac/.test(ua)) {
//       info.deviceType = 'macOS';
//       info.biometricType = 'Touch ID';
//     } else {
//       info.deviceType = 'Desktop/Laptop';
//       info.biometricType = 'WebAuthn';
//     }

//     setDeviceInfo(info);

//     // Check WebAuthn support
//     if (window.PublicKeyCredential) {
//       try {
//         const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
//         setBiometricSupport({
//           webAuthnSupported: true,
//           platformAuthenticator: available,
//           conditionalMediation: await PublicKeyCredential.isConditionalMediationAvailable?.() || false
//         });
//       } catch (error) {
//         setBiometricSupport({
//           webAuthnSupported: true,
//           platformAuthenticator: false,
//           conditionalMediation: false
//         });
//       }
//     } else {
//       setBiometricSupport({
//         webAuthnSupported: false,
//         platformAuthenticator: false,
//         conditionalMediation: false
//       });
//     }
//   };

//   const handleCaptureBiometric = async () => {
//     try {
//       setError('');
//       await captureBiometric();
//       setCaptureComplete(true);
      
//       // Auto-complete after success
//       setTimeout(() => {
//         dispatch({ type: 'SET_STEP', payload: 4 }); // This will trigger completion
//       }, 2000);
//     } catch (error) {
//       setError(error.message);
//     }
//   };

//   const getBiometricIcon = () => {
//     if (!deviceInfo) return null;

//     switch (deviceInfo.deviceType) {
//       case 'iOS':
//         return (
//           <svg className="w-8 h-8" viewBox="0 0 24 24" fill="currentColor">
//             <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
//           </svg>
//         );
//       case 'Android':
//         return (
//           <svg className="w-8 h-8" viewBox="0 0 24 24" fill="currentColor">
//             <path d="M17.81 4.47c-.08 0-.16-.02-.23-.06C15.66 3.42 14 3 12.01 3c-1.98 0-3.86.47-5.57 1.41-.24.13-.54.04-.68-.2-.13-.24-.04-.55.2-.68C7.82 2.52 9.86 2 12.01 2c2.13 0 3.99.47 6.03 1.52.25.13.34.43.21.67-.09.18-.26.28-.44.28zM3.5 9.72c-.1 0-.2-.03-.29-.09-.23-.16-.28-.47-.12-.7.99-1.4 2.25-2.5 3.75-3.27C9.98 4.04 14 4.03 17.15 5.65c1.5.77 2.76 1.86 3.75 3.25.16.22.11.54-.12.7-.23.16-.54.11-.7-.12-.9-1.26-2.04-2.25-3.39-2.94-2.87-1.47-6.54-1.47-9.4.01-1.36.7-2.5 1.7-3.4 2.96-.08.14-.23.21-.39.21zm6.25 12.07c-.13 0-.26-.05-.35-.15-.87-.87-1.34-1.43-2.01-2.64-.69-1.21-1.18-2.74-1.18-4.22 0-2.27 1.86-4.13 4.14-4.13S14.5 12.5 14.5 14.78c0 1.47-.49 3.01-1.18 4.22-.67 1.21-1.14 1.77-2.01 2.64-.09.1-.22.15-.35.15z"/>
//           </svg>
//         );
//       default:
//         return (
//           <svg className="w-8 h-8" viewBox="0 0 24 24" fill="currentColor">
//             <path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,7C13.4,7 14.8,8.6 14.8,10V11.5C15.4,11.5 16,12.4 16,13V16C16,17.4 15.4,18 14.8,18H9.2C8.6,18 8,17.4 8,16V13C8,12.4 8.6,11.5 9.2,11.5V10C9.2,8.6 10.6,7 12,7M12,8.2C11.2,8.2 10.5,8.7 10.5,10V11.5H13.5V10C13.5,8.7 12.8,8.2 12,8.2Z"/>
//           </svg>
//         );
//     }
//   };

//   if (!deviceInfo || biometricSupport === null) {
//     return (
//       <div className="bg-white rounded-lg shadow-lg p-8">
//         <div className="text-center">
//           <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600 mx-auto mb-4"></div>
//           <p className="text-gray-600">Detecting device capabilities...</p>
//         </div>
//       </div>
//     );
//   }

//   return (
//     <div className="bg-white rounded-lg shadow-lg p-8">
//       <div className="text-center mb-6">
//         <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-primary-100 mb-4 text-primary-600">
//           {getBiometricIcon()}
//         </div>
//         <h2 className="text-2xl font-bold text-gray-900 mb-2">Biometric Verification</h2>
//         <p className="text-gray-600">
//           {captureComplete ? 'Biometric data captured successfully!' : 'Capture your biometric data for secure access'}
//         </p>
//       </div>

//       {error && (
//         <div className="mb-4 bg-red-50 border border-red-200 rounded-lg p-3">
//           <p className="text-sm text-red-700">{error}</p>
//         </div>
//       )}

//       {/* Device Information */}
//       <div className="bg-gray-50 rounded-lg p-4 mb-6">
//         <h3 className="text-sm font-medium text-gray-700 mb-3">Device Information</h3>
//         <div className="grid grid-cols-1 gap-2 text-sm">
//           <div className="flex justify-between">
//             <span className="text-gray-600">Device Type:</span>
//             <span className="font-medium">{deviceInfo.deviceType}</span>
//           </div>
//           <div className="flex justify-between">
//             <span className="text-gray-600">Biometric Type:</span>
//             <span className="font-medium">{deviceInfo.biometricType}</span>
//           </div>
//           <div className="flex justify-between">
//             <span className="text-gray-600">Screen:</span>
//             <span className="font-medium">{deviceInfo.screenResolution}</span>
//           </div>
//           <div className="flex justify-between">
//             <span className="text-gray-600">Platform:</span>
//             <span className="font-medium">{deviceInfo.platform}</span>
//           </div>
//         </div>
//       </div>

//       {/* Biometric Support Status */}
//       <div className="bg-blue-50 rounded-lg p-4 mb-6">
//         <h3 className="text-sm font-medium text-blue-900 mb-3">Security Features</h3>
//         <div className="space-y-2">
//           <div className="flex items-center">
//             <div className={`w-2 h-2 rounded-full mr-2 ${biometricSupport.webAuthnSupported ? 'bg-green-500' : 'bg-red-500'}`}></div>
//             <span className="text-sm text-blue-800">WebAuthn Support</span>
//           </div>
//           <div className="flex items-center">
//             <div className={`w-2 h-2 rounded-full mr-2 ${biometricSupport.platformAuthenticator ? 'bg-green-500' : 'bg-yellow-500'}`}></div>
//             <span className="text-sm text-blue-800">Platform Authenticator</span>
//           </div>
//           <div className="flex items-center">
//             <div className={`w-2 h-2 rounded-full mr-2 ${window.location.protocol === 'https:' ? 'bg-green-500' : 'bg-red-500'}`}></div>
//             <span className="text-sm text-blue-800">HTTPS Secure</span>
//           </div>
//         </div>
//       </div>

//       {captureComplete ? (
//         <div className="text-center">
//           <div className="mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-green-100 mb-4">
//             <svg className="h-8 w-8 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
//             </svg>
//           </div>
//           <h3 className="text-lg font-medium text-gray-900 mb-2">Verification Complete!</h3>
//           <p className="text-gray-600">
//             Redirecting to your dashboard...
//           </p>
//         </div>
//       ) : (
//         <div className="space-y-4">
//           <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
//             <div className="flex">
//               <svg className="h-5 w-5 text-yellow-400 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
//               </svg>
//               <div>
//                 <h4 className="text-sm font-medium text-yellow-800">Biometric Capture Process</h4>
//                 <p className="text-sm text-yellow-700 mt-1">
//                   {biometricSupport.platformAuthenticator 
//                     ? `Use your device's ${deviceInfo.biometricType} to complete verification.`
//                     : 'A secure fallback method will be used for biometric capture.'
//                   }
//                 </p>
//               </div>
//             </div>
//           </div>

//           <button
//             onClick={handleCaptureBiometric}
//             disabled={isLoading}
//             className="w-full btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
//           >
//             {isLoading ? (
//               <div className="flex items-center justify-center">
//                 <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
//                 Capturing Biometric...
//               </div>
//             ) : (
//               <div className="flex items-center justify-center">
//                 <svg className="w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                   <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
//                 </svg>
//                 Capture Biometric Data
//               </div>
//             )}
//           </button>

//           <div className="text-center">
//             <p className="text-xs text-gray-500">
//               Your biometric data is encrypted and stored securely
//             </p>
//           </div>
//         </div>
//       )}
//     </div>
//   );
// };

// export default BiometricCapture;