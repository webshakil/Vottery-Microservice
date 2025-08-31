import React, { useState } from 'react';
//import { useAuth } from '../contexts/AuthContext';
import EmailVerification from './auth/EmailVerification';
import PhoneVerification from './auth/PhoneVerification';
import BiometricCapture from './auth/BiometricCapture';
import FallbackSecurity from './auth/FallbackSecurity';
import SecurityQuestionsSetup from './SecurityQuestionsSetup';
import ProfileCreation from './ProfileCreation';
import { useAuth } from '../contexts/AuthContext';


const AuthenticationFlow = () => {
  const { 
    currentStep, 
    emailVerified, 
    phoneVerified, 
    biometricVerified,
    profileCreated,
    securityQuestionsSetup,
    error,
    isLoading,
    isAuthenticated,
    fallbackStep,
    fallbackQuestions
  } = useAuth();
  
  const [showProgress, setShowProgress] = useState(true);

  // If user is authenticated, redirect to dashboard
  if (isAuthenticated && profileCreated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-green-50 via-blue-50 to-purple-50 flex items-center justify-center">
        <div className="bg-white rounded-lg shadow-lg p-8 text-center max-w-md">
          <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
            <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Authentication Complete!</h2>
          <p className="text-gray-600 mb-4">Welcome to Vottery Dashboard</p>
          <button 
            onClick={() => window.location.reload()}
            className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition duration-200"
          >
            Continue to Dashboard
          </button>
        </div>
      </div>
    );
  }

  // Get step status for progress indicator (now includes security-questions step)
  const getStepStatus = (step) => {
    switch (step) {
      case 1: // Email Input
        return currentStep === 1 ? 'active' : currentStep > 1 ? 'completed' : 'pending';
      case 2: // Email OTP
        return emailVerified ? 'completed' : currentStep === 2 ? 'active' : 'pending';
      case 3: // Phone Input
        return currentStep === 3 ? 'active' : currentStep > 3 ? 'completed' : 'pending';
      case 4: // Phone OTP
        return phoneVerified ? 'completed' : currentStep === 4 ? 'active' : 'pending';
      case 5: // Security Questions Setup
        return securityQuestionsSetup ? 'completed' : currentStep === 'security-questions' ? 'active' : 'pending';
      case 6: // Biometric/Fallback Security
        // If fallback step is active, show as active
        if (fallbackStep) {
          return 'active';
        }
        return biometricVerified ? 'completed' : currentStep === 5 ? 'active' : 'pending';
      case 7: // Profile Creation
        return profileCreated ? 'completed' : currentStep === 6 ? 'active' : 'pending';
      default:
        return 'pending';
    }
  };

  // Render step icon based on status
  const renderStepIcon = (step, status) => {
    if (status === 'completed') {
      return (
        <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center shadow-lg">
          <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        </div>
      );
    } else if (status === 'active') {
      return (
        <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center shadow-lg animate-pulse">
          <span className="text-white font-bold text-sm">{step}</span>
        </div>
      );
    } else {
      return (
        <div className="w-8 h-8 bg-gray-300 rounded-full flex items-center justify-center">
          <span className="text-gray-600 font-medium text-sm">{step}</span>
        </div>
      );
    }
  };

  // Get step labels
  const getStepLabel = (step) => {
    switch (step) {
      case 1: return 'Email Input';
      case 2: return 'Email OTP';
      case 3: return 'Phone Input';
      case 4: return 'Phone OTP';
      case 5: return 'Security Questions';
      case 6: 
        if (fallbackStep) {
          return 'Fallback Security';
        }
        return 'Biometric Auth';
      case 7: return 'Profile Setup';
      default: return `Step ${step}`;
    }
  };

  // Render current step component
  const renderCurrentStep = () => {
    // Handle fallback security steps
    if (fallbackStep) {
      return <FallbackSecurity />;
    }

    // Handle security questions setup
    if (currentStep === 'security-questions') {
      return <SecurityQuestionsSetup />;
    }

    if (currentStep === 1 || currentStep === 2) {
      return <EmailVerification />;
    } else if (currentStep === 3 || currentStep === 4) {
      return <PhoneVerification />;
    } else if (currentStep === 5) {
      return <BiometricCapture />;
    } else if (currentStep === 6) {
      return <ProfileCreation />;
    } else {
      return <EmailVerification />; // Default fallback
    }
  };

  // Calculate overall progress (7 steps now)
  const calculateProgress = () => {
    let progress = 0;
    if (currentStep > 1) progress += 14.29; // Email input completed
    if (emailVerified) progress += 14.29;   // Email OTP completed
    if (currentStep > 3) progress += 14.29; // Phone input completed
    if (phoneVerified) progress += 14.29;   // Phone OTP completed
    if (securityQuestionsSetup) progress += 14.29; // Security questions completed
    if (biometricVerified) progress += 14.29; // Biometric completed
    if (profileCreated) progress += 14.27; // Profile completed (totals 100%)
    return Math.round(progress);
  };

  // Get current step description for all steps including security questions
  const getCurrentStepDescription = () => {
    if (fallbackStep === 'setup') {
      return 'Setting up fallback security questions...';
    } else if (fallbackStep === 'answer') {
      return 'Answer security questions to complete authentication';
    } else if (currentStep === 'security-questions') {
      return 'Set up 3 security questions for account backup authentication';
    } else if (currentStep === 1) {
      return 'Enter your registered email address';
    } else if (currentStep === 2) {
      return 'Verify the OTP sent to your email';
    } else if (currentStep === 3) {
      return 'Enter your registered phone number';
    } else if (currentStep === 4) {
      return 'Verify the OTP sent to your phone and email. Sometimes SMS OTPs delay, so we also sent the same OTP to your email';
    } else if (currentStep === 5) {
      return 'Complete biometric authentication or fallback security';
    } else if (currentStep === 6) {
      return 'Complete your profile to access the dashboard';
    }
    return '';
  };

  // Get current step for display purposes
  const getCurrentStepForDisplay = () => {
    if (currentStep === 'security-questions') return 'Security Questions';
    if (fallbackStep) return 'Fallback Security';
    return getStepLabel(currentStep);
  };

  // Get step count for display
  const getCurrentStepCount = () => {
    if (currentStep === 'security-questions') return '5/7';
    if (fallbackStep) return '6/7';
    return `${currentStep}/7`;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">
            Welcome to Vottery
          </h1>
          <p className="text-lg text-gray-600 mb-4">
            Complete the 7-step verification process to access your dashboard
          </p>
          <div className="inline-flex items-center px-4 py-2 bg-blue-100 text-blue-800 rounded-full text-sm font-medium">
            <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Secured by SNGINE Authentication
          </div>
        </div>

        {/* Fallback Security Notice */}
        {fallbackStep && (
          <div className="mb-6 max-w-md mx-auto">
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
              <div className="flex">
                <svg className="h-5 w-5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
                <div className="ml-3">
                  <p className="text-sm text-amber-800">
                    {fallbackStep === 'setup' && 'WebAuthn not available. Setting up fallback security questions for authentication.'}
                    {fallbackStep === 'answer' && 'Please answer the security questions to complete your authentication.'}
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Progress Steps */}
        {showProgress && (
          <div className="mb-8">
            <div className="flex justify-center">
              <div className="flex items-center space-x-4">
                {/* All 7 steps */}
                {[1, 2, 3, 4, 5, 6, 7].map((step, index) => (
                  <React.Fragment key={step}>
                    {/* Step Icon */}
                    <div className="flex flex-col items-center">
                      {renderStepIcon(step, getStepStatus(step))}
                      <div className="mt-2 text-center">
                        <span className="text-xs font-medium text-gray-700 block">
                          {getStepLabel(step)}
                        </span>
                      </div>
                    </div>
                    
                    {/* Connector Line (except for last step) */}
                    {index < 6 && (
                      <div className={`h-px w-12 transition-colors duration-300 ${
                        getStepStatus(step + 1) !== 'pending' ? 'bg-green-500' : 'bg-gray-300'
                      }`}></div>
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>

            {/* Progress Bar */}
            <div className="mt-6 max-w-md mx-auto">
              <div className="flex justify-between text-xs text-gray-500 mb-1">
                <span>Progress</span>
                <span>{calculateProgress()}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div 
                  className="bg-gradient-to-r from-blue-500 to-purple-600 h-2 rounded-full transition-all duration-500 ease-out"
                  style={{ width: `${calculateProgress()}%` }}
                ></div>
              </div>
            </div>

            {/* Current Step Description */}
            <div className="mt-4 text-center">
              <p className="text-sm text-gray-600">{getCurrentStepDescription()}</p>
            </div>

            {/* Toggle Progress Visibility */}
            <div className="text-center mt-4">
              <button
                onClick={() => setShowProgress(!showProgress)}
                className="text-sm text-gray-500 hover:text-gray-700 transition duration-200"
              >
                Hide Progress
              </button>
            </div>
          </div>
        )}

        {!showProgress && (
          <div className="text-center mb-8">
            <button
              onClick={() => setShowProgress(true)}
              className="text-sm text-gray-500 hover:text-gray-700 transition duration-200"
            >
              Show Progress
            </button>
          </div>
        )}

        {/* Global Error Display */}
        {error && (
          <div className="mb-6 max-w-md mx-auto">
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <div className="flex">
                <svg className="h-5 w-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div className="ml-3">
                  <p className="text-sm text-red-700">{error}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Main Content */}
        <div className="max-w-md mx-auto">
          {isLoading && currentStep === 1 && !fallbackStep ? (
            <div className="bg-white rounded-lg shadow-lg p-8 text-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
              <p className="text-gray-600">Initializing authentication...</p>
            </div>
          ) : (
            renderCurrentStep()
          )}
        </div>

        {/* Current Step Indicator */}
        <div className="mt-6 text-center">
          <div className="inline-flex items-center px-3 py-1 bg-gray-100 rounded-full text-sm text-gray-600">
            <span className="font-medium">Current Step:</span>
            <span className="ml-2">
              {getCurrentStepForDisplay()}
            </span>
            <span className="ml-2 text-gray-400">
              ({getCurrentStepCount()})
            </span>
          </div>
        </div>

        {/* Security Badges */}
        <div className="mt-8 text-center">
          <div className="inline-flex flex-wrap items-center justify-center gap-4">
            <span className="inline-flex items-center px-3 py-1 bg-green-100 text-green-800 text-xs font-medium rounded-full">
              <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              End-to-End Encrypted
            </span>
            <span className="inline-flex items-center px-3 py-1 bg-blue-100 text-blue-800 text-xs font-medium rounded-full">
              <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              SNGINE Protected
            </span>
            <span className="inline-flex items-center px-3 py-1 bg-purple-100 text-purple-800 text-xs font-medium rounded-full">
              <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
              </svg>
              {fallbackStep ? 'Fallback Secured' : 'Biometric Secured'}
            </span>
          </div>
        </div>

        {/* Help Section */}
        <div className="mt-8 max-w-md mx-auto">
          <div className="bg-gray-50 rounded-lg p-4 text-center">
            <h3 className="text-sm font-medium text-gray-900 mb-2">Need Help?</h3>
            <p className="text-xs text-gray-600 mb-3">
              {currentStep === 'security-questions' 
                ? 'Security questions provide backup authentication when biometric methods are unavailable'
                : fallbackStep 
                  ? 'Fallback security questions are used when biometric authentication is unavailable'
                  : 'Make sure your email and phone number are registered in SNGINE database'
              }
            </p>
            <div className="flex justify-center space-x-4 text-xs">
              <a href="#" className="text-blue-600 hover:text-blue-700">Contact Support</a>
              <span className="text-gray-300">|</span>
              <a href="#" className="text-blue-600 hover:text-blue-700">FAQ</a>
            </div>
          </div>
        </div>

        {/* Step Instructions */}
        <div className="mt-6 max-w-md mx-auto">
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h4 className="text-sm font-medium text-blue-800 mb-2">Authentication Steps:</h4>
            <ol className="text-sm text-blue-700 space-y-1">
              <li className={`flex items-center ${currentStep >= 1 ? 'font-medium' : ''}`}>
                <span className="mr-2">{currentStep > 1 ? '✅' : currentStep === 1 ? '🔄' : '⏳'}</span>
                Step 1: Enter your registered email
              </li>
              <li className={`flex items-center ${currentStep >= 2 ? 'font-medium' : ''}`}>
                <span className="mr-2">{emailVerified ? '✅' : currentStep === 2 ? '🔄' : '⏳'}</span>
                Step 2: Verify email OTP
              </li>
              <li className={`flex items-center ${currentStep >= 3 ? 'font-medium' : ''}`}>
                <span className="mr-2">{currentStep > 3 ? '✅' : currentStep === 3 ? '🔄' : '⏳'}</span>
                Step 3: Enter your registered phone
              </li>
              <li className={`flex items-center ${currentStep >= 4 ? 'font-medium' : ''}`}>
                <span className="mr-2">{phoneVerified ? '✅' : currentStep === 4 ? '🔄' : '⏳'}</span>
                Step 4: Verify SMS OTP
              </li>
              <li className={`flex items-center ${currentStep === 'security-questions' ? 'font-medium' : ''}`}>
                <span className="mr-2">{securityQuestionsSetup ? '✅' : currentStep === 'security-questions' ? '🔄' : '⏳'}</span>
                Step 5: Set up security questions
              </li>
              <li className={`flex items-center ${currentStep >= 5 || fallbackStep ? 'font-medium' : ''}`}>
                <span className="mr-2">{biometricVerified ? '✅' : (currentStep === 5 || fallbackStep) ? '🔄' : '⏳'}</span>
                Step 6: Complete biometric authentication {fallbackStep && '(Fallback Security)'}
              </li>
              <li className={`flex items-center ${currentStep >= 6 ? 'font-medium' : ''}`}>
                <span className="mr-2">{profileCreated ? '✅' : currentStep === 6 ? '🔄' : '⏳'}</span>
                Step 7: Complete profile setup
              </li>
            </ol>
            
            {(currentStep === 'security-questions' || fallbackStep) && (
              <div className="mt-3 pt-3 border-t border-blue-200">
                <p className="text-xs text-blue-600 font-medium">
                  {currentStep === 'security-questions' && '🔐 Setting up security questions for backup authentication'}
                  {fallbackStep === 'setup' && '🔒 Fallback Security Active: Setting up security questions'}
                  {fallbackStep === 'answer' && '🔒 Fallback Security Active: Answer security questions'}
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AuthenticationFlow;

// // //7 steps
// import React, { useState } from 'react';
// import { useAuth } from '../contexts/AuthContext';
// import EmailVerification from './auth/EmailVerification';
// import PhoneVerification from './auth/PhoneVerification';
// import BiometricCapture from './auth/BiometricCapture';
// import FallbackSecurity from './auth/FallbackSecurity';
// import ProfileCreation from './ProfileCreation';

// const AuthenticationFlow = () => {
//   const { 
//     currentStep, 
//     emailVerified, 
//     phoneVerified, 
//     biometricVerified,
//     profileCreated,
//     error,
//     isLoading,
//     isAuthenticated,
//     fallbackStep,
//     fallbackQuestions
//   } = useAuth();
  
//   const [showProgress, setShowProgress] = useState(true);

//   // If user is authenticated, redirect to dashboard
//   if (isAuthenticated && profileCreated) {
//     return (
//       <div className="min-h-screen bg-gradient-to-br from-green-50 via-blue-50 to-purple-50 flex items-center justify-center">
//         <div className="bg-white rounded-lg shadow-lg p-8 text-center max-w-md">
//           <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
//             <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
//             </svg>
//           </div>
//           <h2 className="text-2xl font-bold text-gray-900 mb-2">Authentication Complete!</h2>
//           <p className="text-gray-600 mb-4">Welcome to Vottery Dashboard</p>
//           <button 
//             onClick={() => window.location.reload()}
//             className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition duration-200"
//           >
//             Continue to Dashboard
//           </button>
//         </div>
//       </div>
//     );
//   }

//   // Get step status for progress indicator (6 steps total now, with fallback security handling)
//   const getStepStatus = (step) => {
//     switch (step) {
//       case 1: // Email Input
//         return currentStep === 1 ? 'active' : currentStep > 1 ? 'completed' : 'pending';
//       case 2: // Email OTP
//         return emailVerified ? 'completed' : currentStep === 2 ? 'active' : 'pending';
//       case 3: // Phone Input
//         return currentStep === 3 ? 'active' : currentStep > 3 ? 'completed' : 'pending';
//       case 4: // Phone OTP
//         return phoneVerified ? 'completed' : currentStep === 4 ? 'active' : 'pending';
//       case 5: // Biometric/Fallback Security
//         // If fallback step is active, show as active
//         if (fallbackStep) {
//           return 'active';
//         }
//         return biometricVerified ? 'completed' : currentStep === 5 ? 'active' : 'pending';
//       case 6: // Profile Creation
//         return profileCreated ? 'completed' : currentStep === 6 ? 'active' : 'pending';
//       default:
//         return 'pending';
//     }
//   };

//   // Render step icon based on status
//   const renderStepIcon = (step, status) => {
//     if (status === 'completed') {
//       return (
//         <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center shadow-lg">
//           <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
//           </svg>
//         </div>
//       );
//     } else if (status === 'active') {
//       return (
//         <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center shadow-lg animate-pulse">
//           <span className="text-white font-bold text-sm">{step}</span>
//         </div>
//       );
//     } else {
//       return (
//         <div className="w-8 h-8 bg-gray-300 rounded-full flex items-center justify-center">
//           <span className="text-gray-600 font-medium text-sm">{step}</span>
//         </div>
//       );
//     }
//   };

//   // Get step labels
//   const getStepLabel = (step) => {
//     switch (step) {
//       case 1: return 'Email Input';
//       case 2: return 'Email OTP';
//       case 3: return 'Phone Input';
//       case 4: return 'Phone OTP';
//       case 5: 
//         if (fallbackStep) {
//           return 'Fallback Security';
//         }
//         return 'Biometric Auth';
//       case 6: return 'Profile Setup';
//       default: return `Step ${step}`;
//     }
//   };

//   // Render current step component
//   const renderCurrentStep = () => {
//     // Handle fallback security steps
//     if (fallbackStep) {
//       return <FallbackSecurity />;
//     }

//     if (currentStep === 1 || currentStep === 2) {
//       return <EmailVerification />;
//     } else if (currentStep === 3 || currentStep === 4) {
//       return <PhoneVerification />;
//     } else if (currentStep === 5) {
//       return <BiometricCapture />;
//     } else if (currentStep === 6) {
//       return <ProfileCreation />;
//     } else {
//       return <EmailVerification />; // Default fallback
//     }
//   };

//   // Calculate overall progress (6 steps now)
//   const calculateProgress = () => {
//     let progress = 0;
//     if (currentStep > 1) progress += 16.67; // Email input completed
//     if (emailVerified) progress += 16.67;   // Email OTP completed
//     if (currentStep > 3) progress += 16.67; // Phone input completed
//     if (phoneVerified) progress += 16.67;   // Phone OTP completed
//     if (biometricVerified) progress += 16.67; // Biometric completed
//     if (profileCreated) progress += 16.65; // Profile completed (totals 100%)
//     return Math.round(progress);
//   };

//   // Get current step description for fallback handling
//   const getCurrentStepDescription = () => {
//     if (fallbackStep === 'setup') {
//       return 'Setting up fallback security questions...';
//     } else if (fallbackStep === 'answer') {
//       return 'Answer security questions to complete authentication';
//     } else if (currentStep === 1) {
//       return 'Enter your registered email address';
//     } else if (currentStep === 2) {
//       return 'Verify the OTP sent to your email';
//     } else if (currentStep === 3) {
//       return 'Enter your registered phone number';
//     } else if (currentStep === 4) {
//       return 'Verify the OTP sent to your phone and email. Sometimes SMS OTPs delay, so we also sent the same OTP to your email';
//     } else if (currentStep === 5) {
//       return 'Complete biometric authentication or fallback security';
//     } else if (currentStep === 6) {
//       return 'Complete your profile to access the dashboard';
//     }
//     return '';
//   };

//   return (
//     <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 py-12 px-4 sm:px-6 lg:px-8">
//       <div className="max-w-4xl mx-auto">
//         {/* Header */}
//         <div className="text-center mb-8">
//           <h1 className="text-4xl font-bold text-gray-900 mb-2">
//             Welcome to Vottery
//           </h1>
//           <p className="text-lg text-gray-600 mb-4">
//             Complete the 6-step verification process to access your dashboard
//           </p>
//           <div className="inline-flex items-center px-4 py-2 bg-blue-100 text-blue-800 rounded-full text-sm font-medium">
//             <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
//             </svg>
//             Secured by SNGINE Authentication
//           </div>
//         </div>

//         {/* Fallback Security Notice */}
//         {fallbackStep && (
//           <div className="mb-6 max-w-md mx-auto">
//             <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
//               <div className="flex">
//                 <svg className="h-5 w-5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                   <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z" />
//                 </svg>
//                 <div className="ml-3">
//                   <p className="text-sm text-amber-800">
//                     {fallbackStep === 'setup' && 'WebAuthn not available. Setting up fallback security questions for authentication.'}
//                     {fallbackStep === 'answer' && 'Please answer the security questions to complete your authentication.'}
//                   </p>
//                 </div>
//               </div>
//             </div>
//           </div>
//         )}

//         {/* Progress Steps */}
//         {showProgress && (
//           <div className="mb-8">
//             <div className="flex justify-center">
//               <div className="flex items-center space-x-4">
//                 {/* All 6 steps */}
//                 {[1, 2, 3, 4, 5, 6].map((step, index) => (
//                   <React.Fragment key={step}>
//                     {/* Step Icon */}
//                     <div className="flex flex-col items-center">
//                       {renderStepIcon(step, getStepStatus(step))}
//                       <div className="mt-2 text-center">
//                         <span className="text-xs font-medium text-gray-700 block">
//                           {getStepLabel(step)}
//                         </span>
//                       </div>
//                     </div>
                    
//                     {/* Connector Line (except for last step) */}
//                     {index < 5 && (
//                       <div className={`h-px w-12 transition-colors duration-300 ${
//                         getStepStatus(step + 1) !== 'pending' ? 'bg-green-500' : 'bg-gray-300'
//                       }`}></div>
//                     )}
//                   </React.Fragment>
//                 ))}
//               </div>
//             </div>

//             {/* Progress Bar */}
//             <div className="mt-6 max-w-md mx-auto">
//               <div className="flex justify-between text-xs text-gray-500 mb-1">
//                 <span>Progress</span>
//                 <span>{calculateProgress()}%</span>
//               </div>
//               <div className="w-full bg-gray-200 rounded-full h-2">
//                 <div 
//                   className="bg-gradient-to-r from-blue-500 to-purple-600 h-2 rounded-full transition-all duration-500 ease-out"
//                   style={{ width: `${calculateProgress()}%` }}
//                 ></div>
//               </div>
//             </div>

//             {/* Current Step Description */}
//             <div className="mt-4 text-center">
//               <p className="text-sm text-gray-600">{getCurrentStepDescription()}</p>
//             </div>

//             {/* Toggle Progress Visibility */}
//             <div className="text-center mt-4">
//               <button
//                 onClick={() => setShowProgress(!showProgress)}
//                 className="text-sm text-gray-500 hover:text-gray-700 transition duration-200"
//               >
//                 Hide Progress
//               </button>
//             </div>
//           </div>
//         )}

//         {!showProgress && (
//           <div className="text-center mb-8">
//             <button
//               onClick={() => setShowProgress(true)}
//               className="text-sm text-gray-500 hover:text-gray-700 transition duration-200"
//             >
//               Show Progress
//             </button>
//           </div>
//         )}

//         {/* Global Error Display */}
//         {error && (
//           <div className="mb-6 max-w-md mx-auto">
//             <div className="bg-red-50 border border-red-200 rounded-lg p-4">
//               <div className="flex">
//                 <svg className="h-5 w-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                   <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
//                 </svg>
//                 <div className="ml-3">
//                   <p className="text-sm text-red-700">{error}</p>
//                 </div>
//               </div>
//             </div>
//           </div>
//         )}

//         {/* Main Content */}
//         <div className="max-w-md mx-auto">
//           {isLoading && currentStep === 1 && !fallbackStep ? (
//             <div className="bg-white rounded-lg shadow-lg p-8 text-center">
//               <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
//               <p className="text-gray-600">Initializing authentication...</p>
//             </div>
//           ) : (
//             renderCurrentStep()
//           )}
//         </div>

//         {/* Current Step Indicator */}
//         <div className="mt-6 text-center">
//           <div className="inline-flex items-center px-3 py-1 bg-gray-100 rounded-full text-sm text-gray-600">
//             <span className="font-medium">Current Step:</span>
//             <span className="ml-2">
//               {fallbackStep ? 'Fallback Security' : getStepLabel(currentStep)}
//             </span>
//             <span className="ml-2 text-gray-400">
//               {!fallbackStep && `(${currentStep}/6)`}
//             </span>
//           </div>
//         </div>

//         {/* Security Badges */}
//         <div className="mt-8 text-center">
//           <div className="inline-flex flex-wrap items-center justify-center gap-4">
//             <span className="inline-flex items-center px-3 py-1 bg-green-100 text-green-800 text-xs font-medium rounded-full">
//               <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
//               </svg>
//               End-to-End Encrypted
//             </span>
//             <span className="inline-flex items-center px-3 py-1 bg-blue-100 text-blue-800 text-xs font-medium rounded-full">
//               <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
//               </svg>
//               SNGINE Protected
//             </span>
//             <span className="inline-flex items-center px-3 py-1 bg-purple-100 text-purple-800 text-xs font-medium rounded-full">
//               <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
//               </svg>
//               {fallbackStep ? 'Fallback Secured' : 'Biometric Secured'}
//             </span>
//           </div>
//         </div>

//         {/* Help Section */}
//         <div className="mt-8 max-w-md mx-auto">
//           <div className="bg-gray-50 rounded-lg p-4 text-center">
//             <h3 className="text-sm font-medium text-gray-900 mb-2">Need Help?</h3>
//             <p className="text-xs text-gray-600 mb-3">
//               {fallbackStep 
//                 ? 'Fallback security questions are used when biometric authentication is unavailable'
//                 : 'Make sure your email and phone number are registered in SNGINE database'
//               }
//             </p>
//             <div className="flex justify-center space-x-4 text-xs">
//               <a href="#" className="text-blue-600 hover:text-blue-700">Contact Support</a>
//               <span className="text-gray-300">|</span>
//               <a href="#" className="text-blue-600 hover:text-blue-700">FAQ</a>
//             </div>
//           </div>
//         </div>

//         {/* Step Instructions */}
//         <div className="mt-6 max-w-md mx-auto">
//           <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
//             <h4 className="text-sm font-medium text-blue-800 mb-2">Authentication Steps:</h4>
//             <ol className="text-sm text-blue-700 space-y-1">
//               <li className={`flex items-center ${currentStep >= 1 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{currentStep > 1 ? '✅' : currentStep === 1 ? '🔄' : '⏳'}</span>
//                 Step 1: Enter your registered email
//               </li>
//               <li className={`flex items-center ${currentStep >= 2 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{emailVerified ? '✅' : currentStep === 2 ? '🔄' : '⏳'}</span>
//                 Step 2: Verify email OTP
//               </li>
//               <li className={`flex items-center ${currentStep >= 3 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{currentStep > 3 ? '✅' : currentStep === 3 ? '🔄' : '⏳'}</span>
//                 Step 3: Enter your registered phone
//               </li>
//               <li className={`flex items-center ${currentStep >= 4 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{phoneVerified ? '✅' : currentStep === 4 ? '🔄' : '⏳'}</span>
//                 Step 4: Verify SMS OTP
//               </li>
//               <li className={`flex items-center ${currentStep >= 5 || fallbackStep ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{biometricVerified ? '✅' : (currentStep === 5 || fallbackStep) ? '🔄' : '⏳'}</span>
//                 Step 5: Complete biometric authentication {fallbackStep && '(Fallback Security)'}
//               </li>
//               <li className={`flex items-center ${currentStep >= 6 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{profileCreated ? '✅' : currentStep === 6 ? '🔄' : '⏳'}</span>
//                 Step 6: Complete profile setup
//               </li>
//             </ol>
            
//             {fallbackStep && (
//               <div className="mt-3 pt-3 border-t border-blue-200">
//                 <p className="text-xs text-blue-600 font-medium">
//                   🔒 Fallback Security Active: {fallbackStep === 'setup' ? 'Setting up security questions' : 'Answer security questions'}
//                 </p>
//               </div>
//             )}
//           </div>
//         </div>
//       </div>
//     </div>
//   );
// };

// export default AuthenticationFlow;




// import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react';
// import { useSecurity } from './SecurityContext';
// import { SecurityUtils } from '../utils/security';
// import { toast } from 'react-hot-toast';

// const AuthContext = createContext();

// export const useAuth = () => {
//   const context = useContext(AuthContext);
//   if (!context) {
//     throw new Error('useAuth must be used within AuthProvider');
//   }
//   return context;
// };

// // Token Management Utility
// const TokenManager = {
//   setTokens: (accessToken, refreshToken, expiryInfo) => {
//     const expiryData = typeof expiryInfo === 'object' ? expiryInfo : { 
//       accessToken: expiryInfo || '7d', 
//       refreshToken: expiryInfo || '7d' 
//     };
    
//     localStorage.setItem('vottery_access_token', accessToken);
//     localStorage.setItem('vottery_refresh_token', refreshToken);
//     localStorage.setItem('vottery_token_expiry', JSON.stringify(expiryData));
//     localStorage.setItem('vottery_token_timestamp', Date.now().toString());
//   },

//   getAccessToken: () => localStorage.getItem('vottery_access_token'),
  
//   getRefreshToken: () => localStorage.getItem('vottery_refresh_token'),
  
//   clearTokens: () => {
//     localStorage.removeItem('vottery_access_token');
//     localStorage.removeItem('vottery_refresh_token');
//     localStorage.removeItem('vottery_token_expiry');
//     localStorage.removeItem('vottery_token_timestamp');
//     localStorage.removeItem('vottery_user_data');
//     localStorage.removeItem('vottery_user_id');
//   },

//   isTokenExpired: () => {
//     const timestamp = localStorage.getItem('vottery_token_timestamp');
//     if (!timestamp) return true;
    
//     // Assuming 7 days expiry (7 * 24 * 60 * 60 * 1000)
//     const tokenAge = Date.now() - parseInt(timestamp);
//     const maxAge = 7 * 24 * 60 * 60 * 1000;
    
//     return tokenAge >= maxAge;
//   }
// };

// // ----------------------------------------------------
// // Reducer & initial state
// // ----------------------------------------------------
// const authReducer = (state, action) => {
//   switch (action.type) {
//     case 'SET_LOADING':
//       return { ...state, isLoading: action.payload };
//     case 'SET_STEP':
//       return { ...state, currentStep: action.payload };
//     case 'SET_EMAIL':
//       return { ...state, email: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_PHONE':
//       return { ...state, phone: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_EMAIL_VERIFIED':
//       return { ...state, emailVerified: action.payload };
//     case 'SET_PHONE_VERIFIED':
//       return { ...state, phoneVerified: action.payload };
//     case 'SET_BIOMETRIC_VERIFIED':
//       return { ...state, biometricVerified: action.payload };
//     case 'SET_PROFILE_CREATED':
//       return { ...state, profileCreated: action.payload };
//     case 'SET_AUTHENTICATED':
//       return { ...state, isAuthenticated: action.payload };
//     case 'SET_USER_DATA':
//       return { ...state, userData: action.payload };
//     case 'SET_USER_ID':
//       return { ...state, userId: action.payload };
//     case 'SET_ERROR':
//       return { ...state, error: action.payload };
//     case 'SET_REFERRER_VALID':
//       return { ...state, isValidReferrer: action.payload, referrerInfo: action.referrerInfo };
//     case 'SET_SECURITY_QUESTIONS_SETUP':
//       return { ...state, securityQuestionsSetup: action.payload };
//     case 'SET_FALLBACK_QUESTIONS':
//       return { ...state, fallbackQuestions: action.payload };
//     case 'SET_KEYS_REGISTERED':
//       return { ...state, keysRegistered: action.payload };
//     case 'RESET_AUTH':
//       return {
//         ...state,
//         currentStep: 1,
//         email: '',
//         phone: '',
//         emailVerified: false,
//         phoneVerified: false,
//         biometricVerified: false,
//         profileCreated: false,
//         securityQuestionsSetup: false,
//         keysRegistered: false,
//         fallbackQuestions: [],
//         error: null,
//         isAuthenticated: false,
//         userData: null,
//         userId: null
//       };
//     case 'SET_OTP_SENT':
//       return { ...state, otpSent: action.payload };
//     case 'SET_RESEND_COOLDOWN':
//       return { ...state, resendCooldown: action.payload };
//     default:
//       return state;
//   }
// };

// const initialState = {
//   isAuthenticated: false,
//   isLoading: false,
//   currentStep: 1,
//   email: '',
//   phone: '',
//   emailVerified: false,
//   phoneVerified: false,
//   biometricVerified: false,
//   profileCreated: false,
//   securityQuestionsSetup: false,
//   keysRegistered: false,
//   userData: null,
//   userId: null,
//   fallbackQuestions: [],
//   error: null,
//   isValidReferrer: false,
//   referrerInfo: null,
//   otpSent: false,
//   resendCooldown: 0
// };

// // ----------------------------------------------------
// // Utilities
// // ----------------------------------------------------
// const b64ToBytes = (b64) => {
//   const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
//   const pad = normalized.length % 4 === 2 ? '==' : normalized.length % 4 === 3 ? '=' : '';
//   const str = atob(normalized + pad);
//   const bytes = new Uint8Array(str.length);
//   for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
//   return bytes;
// };

// const createApiRequest = (BASE) => {
//   return async (endpoint, options = {}) => {
//     const isAbsolute = /^https?:\/\//i.test(endpoint);
//     const url = isAbsolute ? endpoint : `${BASE}${endpoint}`;

//     const config = {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//         'X-Requested-With': 'XMLHttpRequest',
//         'X-Referrer': typeof document !== 'undefined' ? document.referrer : '',
//         ...(options.headers || {})
//       },
//       ...options
//     };

//     // Add Authorization header if access token exists
//     const accessToken = TokenManager.getAccessToken();
//     if (accessToken && !config.headers.Authorization) {
//       config.headers.Authorization = `Bearer ${accessToken}`;
//     }

//     if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
//       config.body = JSON.stringify(config.body);
//     }

//     try {
//       const response = await fetch(url, config);
//       const data = await response.json().catch(() => null);

//       if (!response.ok) {
//         const error = new Error((data && data.message) || `HTTP error! status: ${response.status}`);
//         error.response = { data };
//         throw error;
//       }

//       return data;
//     } catch (error) {
//       console.error(`API request failed for ${url}:`, error);
//       if (error.response) throw error;
//       throw new Error('Network error. Please check your connection and try again.');
//     }
//   };
// };

// export const AuthProvider = ({ children }) => {
//   const [state, dispatch] = useReducer(authReducer, initialState);
//   const securityContext = useSecurity();

//   // Safe access to security functions with fallbacks
//   const {
//     checkReferrer = () => ({ isValid: false, referrer: '', error: 'Security context unavailable' }),
//     encryptData = (data) => JSON.stringify(data),
//     decryptData = (data) => JSON.parse(data),
//     generateDeviceFingerprint = () => Promise.resolve('fallback-fingerprint'),
//     createSession = () => {},
//     clearSession = () => {}
//   } = securityContext || {};

//   const API_BASE_3001 = import.meta.env?.VITE_API_BASE_URL || 'http://localhost:3001';
//   const API_BASE_3002 = import.meta.env?.VITE_BIOMETRIC_API_BASE_URL || 'http://localhost:3002';
//   const API_BASE_3003 = import.meta.env?.VITE_USER_API_BASE_URL || 'http://localhost:3003';

//   const api3001 = useCallback(createApiRequest(API_BASE_3001), [API_BASE_3001]);
//   const api3002 = useCallback(createApiRequest(API_BASE_3002), [API_BASE_3002]);
//   const api3003 = useCallback(createApiRequest(API_BASE_3003), [API_BASE_3003]);

//   // ----------------------------------------------------
//   // Check existing authentication on load
//   // ----------------------------------------------------
//   useEffect(() => {
//     const checkExistingAuth = () => {
//       const accessToken = TokenManager.getAccessToken();
//       const userData = localStorage.getItem('vottery_user_data');
//       const userId = localStorage.getItem('vottery_user_id');
      
//       if (accessToken && !TokenManager.isTokenExpired() && userData && userId) {
//         try {
//           const parsedUserData = JSON.parse(userData);
//           dispatch({ type: 'SET_USER_DATA', payload: parsedUserData });
//           dispatch({ type: 'SET_USER_ID', payload: parseInt(userId) });
//           dispatch({ type: 'SET_EMAIL', payload: parsedUserData.sngine_email });
//           dispatch({ type: 'SET_PHONE', payload: parsedUserData.sngine_phone });
//           dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
//           dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//           dispatch({ type: 'SET_AUTHENTICATED', payload: true });
//         } catch (error) {
//           console.warn('Failed to parse user data, clearing tokens');
//           TokenManager.clearTokens();
//         }
//       }
//     };

//     checkExistingAuth();
//   }, []);

//   // ----------------------------------------------------
//   // Referrer check
//   // ----------------------------------------------------
//   useEffect(() => {
//     try {
//       const referrerInfo = checkReferrer();
//       dispatch({ type: 'SET_REFERRER_VALID', payload: referrerInfo.isValid, referrerInfo });

//       if (referrerInfo.isValid) {
//         const validationData = encryptData({
//           referrer: referrerInfo.referrer,
//           timestamp: Date.now(),
//           validated: true
//         });
//         sessionStorage.setItem('vottery_referrer_validation', validationData);
//       }
//     } catch (error) {
//       console.warn('Referrer check failed:', error);
//       dispatch({ type: 'SET_REFERRER_VALID', payload: false, referrerInfo: { error: error.message } });
//     }
//   }, [checkReferrer, encryptData]);

//   // ----------------------------------------------------
//   // Get User ID from check-user endpoint
//   // ----------------------------------------------------
//   const getUserId = useCallback(async (email, phone) => {
//     try {
//       const response = await api3001('/api/auth/check-user', {
//         body: {
//           sngine_email: email,
//           sngine_phone: phone,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success && response?.user?.id) {
//         const userId = response.user.id;
//         dispatch({ type: 'SET_USER_ID', payload: userId });
//         localStorage.setItem('vottery_user_id', userId.toString());
//         return userId;
//       }
      
//       throw new Error(response?.message || 'User not found');
//     } catch (error) {
//       console.error('Get user ID error:', error);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.biometricVerified, state.userId, state.email, state.phone, api3003, createSession]);

//   // ----------------------------------------------------
//   // Token refresh utility
//   // ----------------------------------------------------
//   const refreshAccessToken = useCallback(async () => {
//     try {
//       const refreshToken = TokenManager.getRefreshToken();
//       if (!refreshToken) throw new Error('No refresh token available');

//       const response = await api3001('/api/auth/refresh', {
//         body: { refreshToken }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken,
//           response.tokenExpiry
//         );
//         return response.accessToken;
//       }

//       throw new Error('Token refresh failed');
//     } catch (error) {
//       console.error('Token refresh failed:', error);
//       logout();
//       throw error;
//     }
//   }, [api3001]);

//   // ----------------------------------------------------
//   // Navigation helpers
//   // ----------------------------------------------------
//   const goBackStep = useCallback(() => {
//     if (state.currentStep === 2) dispatch({ type: 'SET_STEP', payload: 1 });
//     else if (state.currentStep === 4) dispatch({ type: 'SET_STEP', payload: 3 });
//     else if (state.currentStep === 5) dispatch({ type: 'SET_STEP', payload: 4 });
//     else if (state.currentStep === 6) dispatch({ type: 'SET_STEP', payload: 5 });
//     else if (state.currentStep === 7) dispatch({ type: 'SET_STEP', payload: 6 });
//   }, [state.currentStep]);

//   const logout = useCallback(() => {
//     TokenManager.clearTokens();
//     clearSession();
//     sessionStorage.removeItem('vottery_referrer_validation');
//     dispatch({ type: 'RESET_AUTH' });
//     toast.success('Logged out successfully');
//   }, [clearSession]);

//   const resetAuth = useCallback(() => {
//     TokenManager.clearTokens();
//     dispatch({ type: 'RESET_AUTH' });
//   }, []);

//   // ----------------------------------------------------
//   // Context value
//   // ----------------------------------------------------
//   const value = {
//     ...state,
//     dispatch,
//     sendEmailOTP,
//     verifyEmailOTP,
//     sendPhoneOTP,
//     verifyPhoneOTP,
//     completeAuthentication,
//     completeProfileCreation,
//     setupSecurityQuestion,
//     getSecurityQuestions,
//     verifySecurityQuestions,
//     refreshAccessToken,
//     goBackStep,
//     logout,
//     resetAuth,
//     getUserId,
//     // Token utilities
//     getAccessToken: TokenManager.getAccessToken,
//     getRefreshToken: TokenManager.getRefreshToken,
//     isTokenExpired: TokenManager.isTokenExpired
//   };

//   return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
// };?.message || 'Failed to get user ID');
//     }
//   }, [api3001]);

//   // ----------------------------------------------------
//   // STEP 1: Send email OTP
//   // ----------------------------------------------------
//   const sendEmailOTP = useCallback(async (email) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!SecurityUtils.isValidEmail(email)) {
//         throw new Error('Invalid email format');
//       }

//       const response = await api3001('/api/auth/send-email-otp', {
//         body: {
//           email: SecurityUtils.sanitizeInput(email),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL', payload: email });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 2 });
//         toast.success('OTP sent to your email successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // ----------------------------------------------------
//   // STEP 2: Verify email OTP
//   // ----------------------------------------------------
//   const verifyEmailOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-email-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 3 });
//         toast.success('Email verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // ----------------------------------------------------
//   // STEP 3: Send phone OTP
//   // ----------------------------------------------------
//   const sendPhoneOTP = useCallback(async (phone) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       let cleanPhone = phone.trim();
//       if (!cleanPhone.startsWith('+') && /^\d/.test(cleanPhone)) cleanPhone = '+' + cleanPhone;
//       if (cleanPhone.startsWith('+')) cleanPhone = '+' + cleanPhone.substring(1).replace(/\D/g, '');

//       if (!SecurityUtils.isValidPhone(cleanPhone)) {
//         throw new Error('Invalid phone number format');
//       }

//       const response = await api3001('/api/auth/send-sms-otp', {
//         body: {
//           phone: cleanPhone,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE', payload: cleanPhone });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 4 });
//         toast.success('OTP sent to your phone successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // ----------------------------------------------------
//   // STEP 4: Verify phone OTP
//   // ----------------------------------------------------
//   const verifyPhoneOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-sms-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
        
//         // Get user ID after phone verification
//         try {
//           await getUserId(state.email, state.phone);
//           dispatch({ type: 'SET_STEP', payload: 5 });
//           toast.success('Phone verified successfully');
//         } catch (userIdError) {
//           console.error('Failed to get user ID:', userIdError);
//           // Continue anyway, we'll handle this in biometric step
//           dispatch({ type: 'SET_STEP', payload: 5 });
//           toast.success('Phone verified successfully');
//         }
        
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001, getUserId, state.email, state.phone]);

//   // ----------------------------------------------------
//   // STEP 5: Complete Biometric Authentication
//   // ----------------------------------------------------
//   const completeAuthentication = useCallback(async () => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.emailVerified || !state.phoneVerified) {
//         throw new Error('Email and phone verification must be completed first');
//       }

//       // Get user ID if not already set
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId(state.email, state.phone);
//       }

//       const deviceFingerprint = await generateDeviceFingerprint();

//       const deviceInfo = {
//         type: /mobile/i.test(navigator.userAgent) ? 'mobile' :
//               /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop',
//         browser: { name: navigator.userAgent, version: navigator.appVersion },
//         os: { name: navigator.platform, version: navigator.platform },
//         screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1 },
//         device: { type: /mobile/i.test(navigator.userAgent) ? 'mobile' : /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop' }
//       };

//       const capabilities = { hasWebAuthn: !!window.PublicKeyCredential, platform: navigator.platform, userAgent: navigator.userAgent };
//       const location = { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, language: navigator.language };

//       const deviceResponse = await api3002('/api/biometric/device/register', {
//         body: { sngine_email: state.email, sngine_phone: state.phone, deviceInfo, location, capabilities, referrer: document.referrer, timestamp: Date.now() }
//       });

//       if (!deviceResponse?.success || !deviceResponse?.device?.id) {
//         throw new Error(deviceResponse?.message || 'Device registration failed');
//       }

//       const deviceId = deviceResponse.device.id;

//       const biometricData = { deviceFingerprint, userAgent: navigator.userAgent, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, timestamp: Date.now(), capabilities };

//       const biometricResponse = await api3002('/api/biometric/register', {
//         body: { sngine_email: state.email, sngine_phone: state.phone, deviceId, biometricType: 'device_fingerprint', biometricData, referrer: document.referrer, timestamp: Date.now() }
//       });

//       if (!biometricResponse?.success) throw new Error(biometricResponse?.message || 'Biometric registration failed');

//       let webauthnRegistered = false;

//       if (window.PublicKeyCredential && capabilities.hasWebAuthn) {
//         try {
//           console.log('Attempting WebAuthn registration...');
//           const begin = await api3002('/api/biometric/webauthn/register/begin', {
//             body: { 
//               sngine_email: state.email, 
//               sngine_phone: state.phone, 
//               deviceId, 
//               referrer: document.referrer, 
//               timestamp: Date.now() 
//             }
//           });

//           if (begin?.success && begin?.options) {
//             console.log('WebAuthn begin successful, creating credential...');
//             const publicKey = { ...begin.options, challenge: b64ToBytes(begin.options.challenge), user: { ...begin.options.user, id: b64ToBytes(begin.options.user.id) } };
//             const credential = await navigator.credentials.create({ publicKey });

//             if (credential) {
//               console.log('WebAuthn credential created, finishing registration...');
//               const attestationObject = new Uint8Array(credential.response.attestationObject || []);
//               const clientDataJSON = new Uint8Array(credential.response.clientDataJSON || []);

//               const finish = await api3002('/api/biometric/webauthn/register/finish', {
//                 body: { 
//                   sngine_email: state.email, 
//                   sngine_phone: state.phone, 
//                   deviceId, 
//                   credential: { 
//                     id: credential.id, 
//                     rawId: Array.from(new Uint8Array(credential.rawId)), 
//                     response: { 
//                       attestationObject: Array.from(attestationObject), 
//                       clientDataJSON: Array.from(clientDataJSON) 
//                     }, 
//                     type: credential.type 
//                   }, 
//                   referrer: document.referrer, 
//                   timestamp: Date.now() 
//                 }
//               });

//               if (finish?.success) {
//                 webauthnRegistered = true;
//                 console.log('WebAuthn registration completed successfully');
//               } else {
//                 console.warn('WebAuthn finish failed:', finish?.message);
//               }
//             }
//           } else {
//             console.warn('WebAuthn begin failed:', begin?.message);
//           }
//         } catch (webAuthNError) {
//           console.warn('WebAuthn registration failed, continuing without it:', webAuthNError);
//         }
//       } else {
//         console.log('WebAuthn not supported on this device/browser');
//       }

//       // Register encryption keys for fallback security
//       try {
//         const keysResponse = await api3003(`/api/biometric/register-keys/${userId}`, {
//           method: 'POST',
//           body: {
//             referrer: document.referrer,
//             timestamp: Date.now()
//           }
//         });

//         if (keysResponse?.success && keysResponse?.keys) {
//           dispatch({ type: 'SET_KEYS_REGISTERED', payload: true });
//           console.log('Encryption keys registered successfully');
//         } else {
//           console.warn('Keys registration failed:', keysResponse?.message);
//         }
//       } catch (keysError) {
//         console.warn('Keys registration failed:', keysError);
//       }

//       dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//       dispatch({ type: 'SET_STEP', payload: 6 }); // Move to security questions setup
//       toast.success('Biometric authentication completed successfully!');

//       return { success: true, message: 'Biometric authentication completed', deviceId, webauthnRegistered, userId };

//     } catch (error) {
//       console.error('Complete authentication error:', error);
//       const errorMessage = error?.message || 'Authentication failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.email, state.phone, state.emailVerified, state.phoneVerified, state.userId, generateDeviceFingerprint, api3002, api3003, getUserId]);

//   // ----------------------------------------------------
//   // STEP 6: Setup Security Questions (Fallback)
//   // ----------------------------------------------------
//   const setupSecurityQuestion = useCallback(async (question, answer) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       const userId = state.userId;
//       if (!userId) {
//         throw new Error('User ID not found. Please complete previous steps.');
//       }

//       const response = await api3003(`/api/biometric/add-question/${userId}`, {
//         method: 'POST',
//         body: {
//           question: SecurityUtils.sanitizeInput(question),
//           answer: SecurityUtils.sanitizeInput(answer),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success && response?.question) {
//         toast.success('Security question added successfully');
//         return response;
//       }

//       throw new Error(response?.message || 'Failed to add security question');
//     } catch (error) {
//       const errorMessage = error?.message || 'Failed to add security question';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.userId, api3003]);

//   // ----------------------------------------------------
//   // Get Security Questions
//   // ----------------------------------------------------
//   const getSecurityQuestions = useCallback(async () => {
//     try {
//       const userId = state.userId;
//       if (!userId) {
//         throw new Error('User ID not found');
//       }

//       const response = await api3003(`/api/biometric/questions/${userId}`, {
//         method: 'GET'
//       });

//       if (response?.success && response?.questions) {
//         dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: response.questions });
//         return response.questions;
//       }

//       return [];
//     } catch (error) {
//       console.error('Failed to get security questions:', error);
//       return [];
//     }
//   }, [state.userId, api3003]);

//   // ----------------------------------------------------
//   // Verify Security Questions
//   // ----------------------------------------------------
//   const verifySecurityQuestions = useCallback(async (answers) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       const userId = state.userId;
//       if (!userId) {
//         throw new Error('User ID not found');
//       }

//       const response = await api3003(`/api/biometric/verify/${userId}`, {
//         method: 'POST',
//         body: {
//           answers: answers,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_SECURITY_QUESTIONS_SETUP', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 7 }); // Move to profile creation
//         toast.success('Security questions verified successfully');
//         return response;
//       }

//       throw new Error(response?.message || 'Security questions verification failed');
//     } catch (error) {
//       const errorMessage = error?.message || 'Security questions verification failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.userId, api3003]);

//   // ----------------------------------------------------
//   // STEP 7: Complete Profile Creation
//   // ----------------------------------------------------
//   const completeProfileCreation = useCallback(async (profileData) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.biometricVerified) {
//         throw new Error('Biometric verification must be completed first');
//       }

//       const userId = state.userId;
//       if (!userId) {
//         throw new Error('User ID not found');
//       }

//       const response = await api3003('/api/users/create', {
//         body: {
//           user_id: userId,
//           sngine_email: state.email,
//           sngine_phone: state.phone,
//           ...profileData,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         // Store tokens
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken,
//           response.tokenExpiry
//         );

//         // Store user data
//         localStorage.setItem('vottery_user_data', JSON.stringify(response.data));

//         // Update state
//         dispatch({ type: 'SET_USER_DATA', payload: response.data });
//         dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//         dispatch({ type: 'SET_AUTHENTICATED', payload: true });

//         // Create session
//         const sessionData = {
//           userId: response.data.id,
//           email: response.data.sngine_email,
//           phone: response.data.sngine_phone,
//           userType: response.data.user_type,
//           adminRole: response.data.admin_role,
//           subscriptionStatus: response.data.subscription_status,
//           authenticated: true,
//           profileCreated: true,
//           timestamp: Date.now()
//         };

//         createSession(sessionData);
//         toast.success('Profile created successfully! Welcome to Vottery!');

//         return response;
//       }

//       throw new Error(response?.message || 'Profile creation failed');
//     } catch (error) {
//       console.error('Profile creation error:', error);
//       const errorMessage = error?.message || 'Profile creation failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(error



//this is new and finishing touch
// import React, { useState } from 'react';
// import { useAuth } from '../contexts/AuthContext';
// import EmailVerification from './auth/EmailVerification';
// import PhoneVerification from './auth/PhoneVerification';
// import BiometricCapture from './auth/BiometricCapture';
// import ProfileCreation from './ProfileCreation';

// const AuthenticationFlow = () => {
//   const { 
//     currentStep, 
//     emailVerified, 
//     phoneVerified, 
//     biometricVerified,
//     profileCreated,
//     error,
//     isLoading,
//     isAuthenticated
//   } = useAuth();
  
//   const [showProgress, setShowProgress] = useState(true);

//   // If user is authenticated, redirect to dashboard
//   if (isAuthenticated && profileCreated) {
//     return (
//       <div className="min-h-screen bg-gradient-to-br from-green-50 via-blue-50 to-purple-50 flex items-center justify-center">
//         <div className="bg-white rounded-lg shadow-lg p-8 text-center max-w-md">
//           <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
//             <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
//             </svg>
//           </div>
//           <h2 className="text-2xl font-bold text-gray-900 mb-2">Authentication Complete!</h2>
//           <p className="text-gray-600 mb-4">Welcome to Vottery Dashboard</p>
//           <button 
//             onClick={() => window.location.reload()}
//             className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition duration-200"
//           >
//             Continue to Dashboard
//           </button>
//         </div>
//       </div>
//     );
//   }

//   // Get step status for progress indicator (6 steps total now)
//   const getStepStatus = (step) => {
//     switch (step) {
//       case 1: // Email Input
//         return currentStep === 1 ? 'active' : currentStep > 1 ? 'completed' : 'pending';
//       case 2: // Email OTP
//         return emailVerified ? 'completed' : currentStep === 2 ? 'active' : 'pending';
//       case 3: // Phone Input
//         return currentStep === 3 ? 'active' : currentStep > 3 ? 'completed' : 'pending';
//       case 4: // Phone OTP
//         return phoneVerified ? 'completed' : currentStep === 4 ? 'active' : 'pending';
//       case 5: // Biometric
//         return biometricVerified ? 'completed' : currentStep === 5 ? 'active' : 'pending';
//       case 6: // Profile Creation
//         return profileCreated ? 'completed' : currentStep === 6 ? 'active' : 'pending';
//       default:
//         return 'pending';
//     }
//   };

//   // Render step icon based on status
//   const renderStepIcon = (step, status) => {
//     if (status === 'completed') {
//       return (
//         <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center shadow-lg">
//           <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
//           </svg>
//         </div>
//       );
//     } else if (status === 'active') {
//       return (
//         <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center shadow-lg animate-pulse">
//           <span className="text-white font-bold text-sm">{step}</span>
//         </div>
//       );
//     } else {
//       return (
//         <div className="w-8 h-8 bg-gray-300 rounded-full flex items-center justify-center">
//           <span className="text-gray-600 font-medium text-sm">{step}</span>
//         </div>
//       );
//     }
//   };

//   // Get step labels
//   const getStepLabel = (step) => {
//     switch (step) {
//       case 1: return 'Email Input';
//       case 2: return 'Email OTP';
//       case 3: return 'Phone Input';
//       case 4: return 'Phone OTP';
//       case 5: return 'Biometric Auth';
//       case 6: return 'Profile Setup';
//       default: return `Step ${step}`;
//     }
//   };

//   // Render current step component
//   const renderCurrentStep = () => {
//     if (currentStep === 1 || currentStep === 2) {
//       return <EmailVerification />;
//     } else if (currentStep === 3 || currentStep === 4) {
//       return <PhoneVerification />;
//     } else if (currentStep === 5) {
//       return <BiometricCapture />;
//     } else if (currentStep === 6) {
//       return <ProfileCreation />;
//     } else {
//       return <EmailVerification />; // Default fallback
//     }
//   };

//   // Calculate overall progress (6 steps now)
//   const calculateProgress = () => {
//     let progress = 0;
//     if (currentStep > 1) progress += 16.67; // Email input completed
//     if (emailVerified) progress += 16.67;   // Email OTP completed
//     if (currentStep > 3) progress += 16.67; // Phone input completed
//     if (phoneVerified) progress += 16.67;   // Phone OTP completed
//     if (biometricVerified) progress += 16.67; // Biometric completed
//     if (profileCreated) progress += 16.65; // Profile completed (totals 100%)
//     return Math.round(progress);
//   };

//   return (
//     <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 py-12 px-4 sm:px-6 lg:px-8">
//       <div className="max-w-4xl mx-auto">
//         {/* Header */}
//         <div className="text-center mb-8">
//           <h1 className="text-4xl font-bold text-gray-900 mb-2">
//             Welcome to Vottery
//           </h1>
//           <p className="text-lg text-gray-600 mb-4">
//             Complete the 6-step verification process to access your dashboard
//           </p>
//           <div className="inline-flex items-center px-4 py-2 bg-blue-100 text-blue-800 rounded-full text-sm font-medium">
//             <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
//             </svg>
//             Secured by SNGINE Authentication
//           </div>
//         </div>

//         {/* Progress Steps */}
//         {showProgress && (
//           <div className="mb-8">
//             <div className="flex justify-center">
//               <div className="flex items-center space-x-4">
//                 {/* All 6 steps */}
//                 {[1, 2, 3, 4, 5, 6].map((step, index) => (
//                   <React.Fragment key={step}>
//                     {/* Step Icon */}
//                     <div className="flex flex-col items-center">
//                       {renderStepIcon(step, getStepStatus(step))}
//                       <div className="mt-2 text-center">
//                         <span className="text-xs font-medium text-gray-700 block">
//                           {getStepLabel(step)}
//                         </span>
//                       </div>
//                     </div>
                    
//                     {/* Connector Line (except for last step) */}
//                     {index < 5 && (
//                       <div className={`h-px w-12 transition-colors duration-300 ${
//                         getStepStatus(step + 1) !== 'pending' ? 'bg-green-500' : 'bg-gray-300'
//                       }`}></div>
//                     )}
//                   </React.Fragment>
//                 ))}
//               </div>
//             </div>

//             {/* Progress Bar */}
//             <div className="mt-6 max-w-md mx-auto">
//               <div className="flex justify-between text-xs text-gray-500 mb-1">
//                 <span>Progress</span>
//                 <span>{calculateProgress()}%</span>
//               </div>
//               <div className="w-full bg-gray-200 rounded-full h-2">
//                 <div 
//                   className="bg-gradient-to-r from-blue-500 to-purple-600 h-2 rounded-full transition-all duration-500 ease-out"
//                   style={{ width: `${calculateProgress()}%` }}
//                 ></div>
//               </div>
//             </div>

//             {/* Toggle Progress Visibility */}
//             <div className="text-center mt-4">
//               <button
//                 onClick={() => setShowProgress(!showProgress)}
//                 className="text-sm text-gray-500 hover:text-gray-700 transition duration-200"
//               >
//                 Hide Progress
//               </button>
//             </div>
//           </div>
//         )}

//         {!showProgress && (
//           <div className="text-center mb-8">
//             <button
//               onClick={() => setShowProgress(true)}
//               className="text-sm text-gray-500 hover:text-gray-700 transition duration-200"
//             >
//               Show Progress
//             </button>
//           </div>
//         )}

//         {/* Global Error Display */}
//         {error && (
//           <div className="mb-6 max-w-md mx-auto">
//             <div className="bg-red-50 border border-red-200 rounded-lg p-4">
//               <div className="flex">
//                 <svg className="h-5 w-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                   <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
//                 </svg>
//                 <div className="ml-3">
//                   <p className="text-sm text-red-700">{error}</p>
//                 </div>
//               </div>
//             </div>
//           </div>
//         )}

//         {/* Main Content */}
//         <div className="max-w-md mx-auto">
//           {isLoading && currentStep === 1 ? (
//             <div className="bg-white rounded-lg shadow-lg p-8 text-center">
//               <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
//               <p className="text-gray-600">Initializing authentication...</p>
//             </div>
//           ) : (
//             renderCurrentStep()
//           )}
//         </div>

//         {/* Current Step Indicator */}
//         <div className="mt-6 text-center">
//           <div className="inline-flex items-center px-3 py-1 bg-gray-100 rounded-full text-sm text-gray-600">
//             <span className="font-medium">Current Step:</span>
//             <span className="ml-2">
//               {getStepLabel(currentStep)}
//             </span>
//             <span className="ml-2 text-gray-400">
//               ({currentStep}/6)
//             </span>
//           </div>
//         </div>

//         {/* Security Badges */}
//         <div className="mt-8 text-center">
//           <div className="inline-flex flex-wrap items-center justify-center gap-4">
//             <span className="inline-flex items-center px-3 py-1 bg-green-100 text-green-800 text-xs font-medium rounded-full">
//               <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
//               </svg>
//               End-to-End Encrypted
//             </span>
//             <span className="inline-flex items-center px-3 py-1 bg-blue-100 text-blue-800 text-xs font-medium rounded-full">
//               <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
//               </svg>
//               SNGINE Protected
//             </span>
//             <span className="inline-flex items-center px-3 py-1 bg-purple-100 text-purple-800 text-xs font-medium rounded-full">
//               <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
//               </svg>
//               Biometric Secured
//             </span>
//           </div>
//         </div>

//         {/* Help Section */}
//         <div className="mt-8 max-w-md mx-auto">
//           <div className="bg-gray-50 rounded-lg p-4 text-center">
//             <h3 className="text-sm font-medium text-gray-900 mb-2">Need Help?</h3>
//             <p className="text-xs text-gray-600 mb-3">
//               Make sure your email and phone number are registered in SNGINE database
//             </p>
//             <div className="flex justify-center space-x-4 text-xs">
//               <a href="#" className="text-blue-600 hover:text-blue-700">Contact Support</a>
//               <span className="text-gray-300">|</span>
//               <a href="#" className="text-blue-600 hover:text-blue-700">FAQ</a>
//             </div>
//           </div>
//         </div>

//         {/* Step Instructions */}
//         <div className="mt-6 max-w-md mx-auto">
//           <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
//             <h4 className="text-sm font-medium text-blue-800 mb-2">Authentication Steps:</h4>
//             <ol className="text-sm text-blue-700 space-y-1">
//               <li className={`flex items-center ${currentStep >= 1 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{currentStep > 1 ? '✅' : currentStep === 1 ? '🔄' : '⏳'}</span>
//                 Step 1: Enter your registered email
//               </li>
//               <li className={`flex items-center ${currentStep >= 2 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{emailVerified ? '✅' : currentStep === 2 ? '🔄' : '⏳'}</span>
//                 Step 2: Verify email OTP
//               </li>
//               <li className={`flex items-center ${currentStep >= 3 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{currentStep > 3 ? '✅' : currentStep === 3 ? '🔄' : '⏳'}</span>
//                 Step 3: Enter your registered phone
//               </li>
//               <li className={`flex items-center ${currentStep >= 4 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{phoneVerified ? '✅' : currentStep === 4 ? '🔄' : '⏳'}</span>
//                 Step 4: Verify SMS OTP
//               </li>
//               <li className={`flex items-center ${currentStep >= 5 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{biometricVerified ? '✅' : currentStep === 5 ? '🔄' : '⏳'}</span>
//                 Step 5: Complete biometric authentication
//               </li>
//               <li className={`flex items-center ${currentStep >= 6 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{profileCreated ? '✅' : currentStep === 6 ? '🔄' : '⏳'}</span>
//                 Step 6: Complete profile setup
//               </li>
//             </ol>
//           </div>
//         </div>
//       </div>
//     </div>
//   );
// };

// export default AuthenticationFlow;
//This is successufl for old
// //5 steps perfect
// import React, { useState } from 'react';
// import { useAuth } from '../contexts/AuthContext';
// import EmailVerification from './auth/EmailVerification';
// import PhoneVerification from './auth/PhoneVerification';
// import BiometricCapture from './auth/BiometricCapture';

// const AuthenticationFlow = () => {
//   const { 
//     currentStep, 
//     emailVerified, 
//     phoneVerified, 
//     biometricVerified, 
//     error,
//     isLoading,
//     isAuthenticated
//   } = useAuth();
  
//   const [showProgress, setShowProgress] = useState(true);

//   // If user is authenticated, redirect to dashboard
//   if (isAuthenticated) {
//     return (
//       <div className="min-h-screen bg-gradient-to-br from-green-50 via-blue-50 to-purple-50 flex items-center justify-center">
//         <div className="bg-white rounded-lg shadow-lg p-8 text-center max-w-md">
//           <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
//             <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
//             </svg>
//           </div>
//           <h2 className="text-2xl font-bold text-gray-900 mb-2">Authentication Complete!</h2>
//           <p className="text-gray-600 mb-4">Welcome to Vottery Dashboard</p>
//           <button 
//             onClick={() => window.location.reload()}
//             className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition duration-200"
//           >
//             Continue to Dashboard
//           </button>
//         </div>
//       </div>
//     );
//   }

//   // Get step status for progress indicator (5 steps total)
//   const getStepStatus = (step) => {
//     switch (step) {
//       case 1: // Email Input
//         return currentStep === 1 ? 'active' : currentStep > 1 ? 'completed' : 'pending';
//       case 2: // Email OTP
//         return emailVerified ? 'completed' : currentStep === 2 ? 'active' : 'pending';
//       case 3: // Phone Input
//         return currentStep === 3 ? 'active' : currentStep > 3 ? 'completed' : 'pending';
//       case 4: // Phone OTP
//         return phoneVerified ? 'completed' : currentStep === 4 ? 'active' : 'pending';
//       case 5: // Biometric
//         return biometricVerified ? 'completed' : currentStep === 5 ? 'active' : 'pending';
//       default:
//         return 'pending';
//     }
//   };

//   // Render step icon based on status
//   const renderStepIcon = (step, status) => {
//     if (status === 'completed') {
//       return (
//         <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center shadow-lg">
//           <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
//           </svg>
//         </div>
//       );
//     } else if (status === 'active') {
//       return (
//         <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center shadow-lg animate-pulse">
//           <span className="text-white font-bold text-sm">{step}</span>
//         </div>
//       );
//     } else {
//       return (
//         <div className="w-8 h-8 bg-gray-300 rounded-full flex items-center justify-center">
//           <span className="text-gray-600 font-medium text-sm">{step}</span>
//         </div>
//       );
//     }
//   };

//   // Get step labels
//   const getStepLabel = (step) => {
//     switch (step) {
//       case 1: return 'Email Input';
//       case 2: return 'Email OTP';
//       case 3: return 'Phone Input';
//       case 4: return 'Phone OTP';
//       case 5: return 'Biometric Auth';
//       default: return `Step ${step}`;
//     }
//   };

//   // Render current step component
//   const renderCurrentStep = () => {
//     if (currentStep === 1 || currentStep === 2) {
//       return <EmailVerification />;
//     } else if (currentStep === 3 || currentStep === 4) {
//       return <PhoneVerification />;
//     } else if (currentStep === 5) {
//       return <BiometricCapture />;
//     } else {
//       return <EmailVerification />; // Default fallback
//     }
//   };

//   // Calculate overall progress
//   const calculateProgress = () => {
//     let progress = 0;
//     if (currentStep > 1) progress += 20; // Email input completed
//     if (emailVerified) progress += 20;   // Email OTP completed
//     if (currentStep > 3) progress += 20; // Phone input completed
//     if (phoneVerified) progress += 20;   // Phone OTP completed
//     if (biometricVerified) progress += 20; // Biometric completed
//     return progress;
//   };

//   return (
//     <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 py-12 px-4 sm:px-6 lg:px-8">
//       <div className="max-w-4xl mx-auto">
//         {/* Header */}
//         <div className="text-center mb-8">
//           <h1 className="text-4xl font-bold text-gray-900 mb-2">
//             Welcome to Vottery
//           </h1>
//           <p className="text-lg text-gray-600 mb-4">
//             Complete the 5-step verification process to access your dashboard
//           </p>
//           <div className="inline-flex items-center px-4 py-2 bg-blue-100 text-blue-800 rounded-full text-sm font-medium">
//             <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
//             </svg>
//             Secured by SNGINE Authentication
//           </div>
//         </div>

//         {/* Progress Steps */}
//         {showProgress && (
//           <div className="mb-8">
//             <div className="flex justify-center">
//               <div className="flex items-center space-x-4">
//                 {/* All 5 steps */}
//                 {[1, 2, 3, 4, 5].map((step, index) => (
//                   <React.Fragment key={step}>
//                     {/* Step Icon */}
//                     <div className="flex flex-col items-center">
//                       {renderStepIcon(step, getStepStatus(step))}
//                       <div className="mt-2 text-center">
//                         <span className="text-xs font-medium text-gray-700 block">
//                           {getStepLabel(step)}
//                         </span>
//                       </div>
//                     </div>
                    
//                     {/* Connector Line (except for last step) */}
//                     {index < 4 && (
//                       <div className={`h-px w-12 transition-colors duration-300 ${
//                         getStepStatus(step + 1) !== 'pending' ? 'bg-green-500' : 'bg-gray-300'
//                       }`}></div>
//                     )}
//                   </React.Fragment>
//                 ))}
//               </div>
//             </div>

//             {/* Progress Bar */}
//             <div className="mt-6 max-w-md mx-auto">
//               <div className="flex justify-between text-xs text-gray-500 mb-1">
//                 <span>Progress</span>
//                 <span>{calculateProgress()}%</span>
//               </div>
//               <div className="w-full bg-gray-200 rounded-full h-2">
//                 <div 
//                   className="bg-gradient-to-r from-blue-500 to-purple-600 h-2 rounded-full transition-all duration-500 ease-out"
//                   style={{ width: `${calculateProgress()}%` }}
//                 ></div>
//               </div>
//             </div>

//             {/* Toggle Progress Visibility */}
//             <div className="text-center mt-4">
//               <button
//                 onClick={() => setShowProgress(!showProgress)}
//                 className="text-sm text-gray-500 hover:text-gray-700 transition duration-200"
//               >
//                 Hide Progress
//               </button>
//             </div>
//           </div>
//         )}

//         {!showProgress && (
//           <div className="text-center mb-8">
//             <button
//               onClick={() => setShowProgress(true)}
//               className="text-sm text-gray-500 hover:text-gray-700 transition duration-200"
//             >
//               Show Progress
//             </button>
//           </div>
//         )}

//         {/* Global Error Display */}
//         {error && (
//           <div className="mb-6 max-w-md mx-auto">
//             <div className="bg-red-50 border border-red-200 rounded-lg p-4">
//               <div className="flex">
//                 <svg className="h-5 w-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                   <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
//                 </svg>
//                 <div className="ml-3">
//                   <p className="text-sm text-red-700">{error}</p>
//                 </div>
//               </div>
//             </div>
//           </div>
//         )}

//         {/* Main Content */}
//         <div className="max-w-md mx-auto">
//           {isLoading && currentStep === 1 ? (
//             <div className="bg-white rounded-lg shadow-lg p-8 text-center">
//               <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
//               <p className="text-gray-600">Initializing authentication...</p>
//             </div>
//           ) : (
//             renderCurrentStep()
//           )}
//         </div>

//         {/* Current Step Indicator */}
//         <div className="mt-6 text-center">
//           <div className="inline-flex items-center px-3 py-1 bg-gray-100 rounded-full text-sm text-gray-600">
//             <span className="font-medium">Current Step:</span>
//             <span className="ml-2">
//               {getStepLabel(currentStep)}
//             </span>
//             <span className="ml-2 text-gray-400">
//               ({currentStep}/5)
//             </span>
//           </div>
//         </div>

//         {/* Security Badges */}
//         <div className="mt-8 text-center">
//           <div className="inline-flex flex-wrap items-center justify-center gap-4">
//             <span className="inline-flex items-center px-3 py-1 bg-green-100 text-green-800 text-xs font-medium rounded-full">
//               <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
//               </svg>
//               End-to-End Encrypted
//             </span>
//             <span className="inline-flex items-center px-3 py-1 bg-blue-100 text-blue-800 text-xs font-medium rounded-full">
//               <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
//               </svg>
//               SNGINE Protected
//             </span>
//             <span className="inline-flex items-center px-3 py-1 bg-purple-100 text-purple-800 text-xs font-medium rounded-full">
//               <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
//               </svg>
//               Biometric Secured
//             </span>
//           </div>
//         </div>

//         {/* Help Section */}
//         <div className="mt-8 max-w-md mx-auto">
//           <div className="bg-gray-50 rounded-lg p-4 text-center">
//             <h3 className="text-sm font-medium text-gray-900 mb-2">Need Help?</h3>
//             <p className="text-xs text-gray-600 mb-3">
//               Make sure your email and phone number are registered in SNGINE database
//             </p>
//             <div className="flex justify-center space-x-4 text-xs">
//               <a href="#" className="text-blue-600 hover:text-blue-700">Contact Support</a>
//               <span className="text-gray-300">|</span>
//               <a href="#" className="text-blue-600 hover:text-blue-700">FAQ</a>
//             </div>
//           </div>
//         </div>

//         {/* Step Instructions */}
//         <div className="mt-6 max-w-md mx-auto">
//           <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
//             <h4 className="text-sm font-medium text-blue-800 mb-2">Authentication Steps:</h4>
//             <ol className="text-sm text-blue-700 space-y-1">
//               <li className={`flex items-center ${currentStep >= 1 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{currentStep > 1 ? '✅' : currentStep === 1 ? '🔄' : '⏳'}</span>
//                 Step 1: Enter your registered email
//               </li>
//               <li className={`flex items-center ${currentStep >= 2 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{emailVerified ? '✅' : currentStep === 2 ? '🔄' : '⏳'}</span>
//                 Step 2: Verify email OTP
//               </li>
//               <li className={`flex items-center ${currentStep >= 3 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{currentStep > 3 ? '✅' : currentStep === 3 ? '🔄' : '⏳'}</span>
//                 Step 3: Enter your registered phone
//               </li>
//               <li className={`flex items-center ${currentStep >= 4 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{phoneVerified ? '✅' : currentStep === 4 ? '🔄' : '⏳'}</span>
//                 Step 4: Verify SMS OTP
//               </li>
//               <li className={`flex items-center ${currentStep >= 5 ? 'font-medium' : ''}`}>
//                 <span className="mr-2">{biometricVerified ? '✅' : currentStep === 5 ? '🔄' : '⏳'}</span>
//                 Step 5: Complete biometric authentication
//               </li>
//             </ol>
//           </div>
//         </div>
//       </div>
//     </div>
//   );
// };

// export default AuthenticationFlow;
// //this is 5 steps
// // import React, { useState } from 'react';
// // import { useAuth } from '../contexts/AuthContext';
// // import EmailVerification from './auth/EmailVerification';
// // import PhoneVerification from './auth/PhoneVerification';
// // import BiometricCapture from './auth/BiometricCapture';

// // const AuthenticationFlow = () => {
// //   const { 
// //     currentStep, 
// //     emailVerified, 
// //     phoneVerified, 
// //     biometricVerified, 
// //     error,
// //     isLoading 
// //   } = useAuth();
  
// //   const [showProgress, setShowProgress] = useState(true);

// //   // Get step status for progress indicator
// //   const getStepStatus = (step) => {
// //     switch (step) {
// //       case 1:
// //         return emailVerified ? 'completed' : (currentStep === 1 || currentStep === 2) ? 'active' : 'pending';
// //       case 2:
// //         return phoneVerified ? 'completed' : (currentStep === 3 || currentStep === 4) ? 'active' : 'pending';
// //       case 3:
// //         return biometricVerified ? 'completed' : currentStep === 5 ? 'active' : 'pending';
// //       default:
// //         return 'pending';
// //     }
// //   };

// //   // Render step icon based on status
// //   const renderStepIcon = (step, status) => {
// //     if (status === 'completed') {
// //       return (
// //         <div className="w-10 h-10 bg-green-500 rounded-full flex items-center justify-center shadow-lg">
// //           <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
// //             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
// //           </svg>
// //         </div>
// //       ); // <-- Close the div and return properly
// //     } else if (status === 'active') {
// //       return (
// //         <div className="w-10 h-10 bg-blue-600 rounded-full flex items-center justify-center shadow-lg animate-pulse">
// //           <span className="text-white font-bold">{step}</span>
// //         </div>
// //       );
// //     } else {
// //       return (
// //         <div className="w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center">
// //           <span className="text-gray-600 font-medium">{step}</span>
// //         </div>
// //       );
// //     }
// //   };

// //   // Get step labels
// //   const getStepLabel = (step) => {
// //     switch (step) {
// //       case 1:
// //         return 'Email Verification';
// //       case 2:
// //         return 'Phone Verification';
// //       case 3:
// //         return 'Biometric Authentication';
// //       default:
// //         return `Step ${step}`;
// //     }
// //   };

// //   // Render current step component
// //   const renderCurrentStep = () => {
// //     if (currentStep === 1 || currentStep === 2) {
// //       return <EmailVerification />;
// //     } else if (currentStep === 3 || currentStep === 4) {
// //       return <PhoneVerification />;
// //     } else if (currentStep === 5) {
// //       return <BiometricCapture />;
// //     } else {
// //       return <EmailVerification />; // Default fallback
// //     }
// //   };

// //   return (
// //     <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 py-12 px-4 sm:px-6 lg:px-8">
// //       <div className="max-w-4xl mx-auto">
// //         {/* Header */}
// //         <div className="text-center mb-8">
// //           <h1 className="text-4xl font-bold text-gray-900 mb-2">
// //             Welcome to Vottery
// //           </h1>
// //           <p className="text-lg text-gray-600 mb-4">
// //             Complete the 5-step verification process to access your dashboard
// //           </p>
// //           <div className="inline-flex items-center px-4 py-2 bg-blue-100 text-blue-800 rounded-full text-sm font-medium">
// //             <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
// //               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
// //             </svg>
// //             Secured by SNGINE Authentication
// //           </div>
// //         </div>

// //         {/* Progress Steps */}
// //         {showProgress && (
// //           <div className="mb-8">
// //             <div className="flex justify-center">
// //               <div className="flex items-center space-x-8">
// //                 {/* Step 1 - Email Verification */}
// //                 <div className="flex flex-col items-center">
// //                   {renderStepIcon(1, getStepStatus(1))}
// //                   <div className="mt-3 text-center">
// //                     <span className="text-sm font-medium text-gray-700 block">
// //                       {getStepLabel(1)}
// //                     </span>
// //                     <span className="text-xs text-gray-500 block mt-1">
// //                       Steps 1-2
// //                     </span>
// //                   </div>
// //                 </div>
                
// //                 {/* Connector Line 1 */}
// //                 <div className={`h-px w-16 transition-colors duration-300 ${
// //                   getStepStatus(2) !== 'pending' ? 'bg-green-500' : 'bg-gray-300'
// //                 }`}></div>
                
// //                 {/* Step 2 - Phone Verification */}
// //                 <div className="flex flex-col items-center">
// //                   {renderStepIcon(2, getStepStatus(2))}
// //                   <div className="mt-3 text-center">
// //                     <span className="text-sm font-medium text-gray-700 block">
// //                       {getStepLabel(2)}
// //                     </span>
// //                     <span className="text-xs text-gray-500 block mt-1">
// //                       Steps 3-4
// //                     </span>
// //                   </div>
// //                 </div>
                
// //                 {/* Connector Line 2 */}
// //                 <div className={`h-px w-16 transition-colors duration-300 ${
// //                   getStepStatus(3) !== 'pending' ? 'bg-green-500' : 'bg-gray-300'
// //                 }`}></div>
                
// //                 {/* Step 3 - Biometric */}
// //                 <div className="flex flex-col items-center">
// //                   {renderStepIcon(3, getStepStatus(3))}
// //                   <div className="mt-3 text-center">
// //                     <span className="text-sm font-medium text-gray-700 block">
// //                       {getStepLabel(3)}
// //                     </span>
// //                     <span className="text-xs text-gray-500 block mt-1">
// //                       Step 5
// //                     </span>
// //                   </div>
// //                 </div>
// //               </div>
// //             </div>

// //             {/* Progress Bar */}
// //             <div className="mt-6 max-w-md mx-auto">
// //               <div className="flex justify-between text-xs text-gray-500 mb-1">
// //                 <span>Progress</span>
// //                 <span>{Math.round(((emailVerified ? 1 : 0) + (phoneVerified ? 1 : 0) + (biometricVerified ? 1 : 0)) / 3 * 100)}%</span>
// //               </div>
// //               <div className="w-full bg-gray-200 rounded-full h-2">
// //                 <div 
// //                   className="bg-gradient-to-r from-blue-500 to-purple-600 h-2 rounded-full transition-all duration-500 ease-out"
// //                   style={{
// //                     width: `${((emailVerified ? 1 : 0) + (phoneVerified ? 1 : 0) + (biometricVerified ? 1 : 0)) / 3 * 100}%`
// //                   }}
// //                 ></div>
// //               </div>
// //             </div>

// //             {/* Toggle Progress Visibility */}
// //             <div className="text-center mt-4">
// //               <button
// //                 onClick={() => setShowProgress(!showProgress)}
// //                 className="text-sm text-gray-500 hover:text-gray-700 transition duration-200"
// //               >
// //                 {showProgress ? 'Hide Progress' : 'Show Progress'}
// //               </button>
// //             </div>
// //           </div>
// //         )}

// //         {/* Global Error Display */}
// //         {error && (
// //           <div className="mb-6 max-w-md mx-auto">
// //             <div className="bg-red-50 border border-red-200 rounded-lg p-4">
// //               <div className="flex">
// //                 <svg className="h-5 w-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
// //                   <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
// //                 </svg>
// //                 <div className="ml-3">
// //                   <p className="text-sm text-red-700">{error}</p>
// //                 </div>
// //               </div>
// //             </div>
// //           </div>
// //         )}

// //         {/* Main Content */}
// //         <div className="max-w-md mx-auto">
// //           {isLoading && currentStep === 1 ? (
// //             <div className="bg-white rounded-lg shadow-lg p-8 text-center">
// //               <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
// //               <p className="text-gray-600">Verifying your SNGINE credentials...</p>
// //             </div>
// //           ) : (
// //             renderCurrentStep()
// //           )}
// //         </div>

// //         {/* Current Step Indicator */}
// //         <div className="mt-6 text-center">
// //           <div className="inline-flex items-center px-3 py-1 bg-gray-100 rounded-full text-sm text-gray-600">
// //             <span className="font-medium">Current Step:</span>
// //             <span className="ml-2">
// //               {currentStep <= 2 && 'Email Verification'}
// //               {(currentStep === 3 || currentStep === 4) && 'Phone Verification'}
// //               {currentStep === 5 && 'Biometric Authentication'}
// //             </span>
// //             <span className="ml-2 text-gray-400">
// //               ({currentStep}/5)
// //             </span>
// //           </div>
// //         </div>

// //         {/* Security Badges */}
// //         <div className="mt-8 text-center">
// //           <div className="inline-flex flex-wrap items-center justify-center gap-4">
// //             <span className="inline-flex items-center px-3 py-1 bg-green-100 text-green-800 text-xs font-medium rounded-full">
// //               <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
// //                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
// //               </svg>
// //               End-to-End Encrypted
// //             </span>
// //             <span className="inline-flex items-center px-3 py-1 bg-blue-100 text-blue-800 text-xs font-medium rounded-full">
// //               <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
// //                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
// //               </svg>
// //               SNGINE Protected
// //             </span>
// //             <span className="inline-flex items-center px-3 py-1 bg-purple-100 text-purple-800 text-xs font-medium rounded-full">
// //               <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
// //                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
// //               </svg>
// //               Biometric Secured
// //             </span>
// //           </div>
// //         </div>

// //         {/* Help Section */}
// //         <div className="mt-8 max-w-md mx-auto">
// //           <div className="bg-gray-50 rounded-lg p-4 text-center">
// //             <h3 className="text-sm font-medium text-gray-900 mb-2">Need Help?</h3>
// //             <p className="text-xs text-gray-600 mb-3">
// //               Make sure your email and phone number are registered in SNGINE database
// //             </p>
// //             <div className="flex justify-center space-x-4 text-xs">
// //               <a href="#" className="text-blue-600 hover:text-blue-700">Contact Support</a>
// //               <span className="text-gray-300">|</span>
// //               <a href="#" className="text-blue-600 hover:text-blue-700">FAQ</a>
// //             </div>
// //           </div>
// //         </div>
// //       </div>
// //     </div>
// //   );
// // };

// // export default AuthenticationFlow;




// //this is 3 steps
// // import React, { useState, useEffect } from 'react';
// // import { useAuth } from '../contexts/AuthContext';
// // import EmailVerification from './auth/EmailVerification';
// // import PhoneVerification from './auth/PhoneVerification';
// // import BiometricCapture from './auth/BiometricCapture';

// // const AuthenticationFlow = () => {
// //   const { currentStep, emailVerified, phoneVerified, biometricVerified, completeAuthentication, error } = useAuth();
// //   const [showProgress, setShowProgress] = useState(true);

// //   useEffect(() => {
// //     if (emailVerified && phoneVerified && biometricVerified) {
// //       completeAuthentication();
// //     }
// //   }, [emailVerified, phoneVerified, biometricVerified, completeAuthentication]);

// //   const getStepStatus = (step) => {
// //     switch (step) {
// //       case 1:
// //         return emailVerified ? 'completed' : currentStep === 1 ? 'active' : 'pending';
// //       case 2:
// //         return phoneVerified ? 'completed' : currentStep === 2 ? 'active' : 'pending';
// //       case 3:
// //         return biometricVerified ? 'completed' : currentStep === 3 ? 'active' : 'pending';
// //       default:
// //         return 'pending';
// //     }
// //   };

// //   const renderStepIcon = (step, status) => {
// //     if (status === 'completed') {
// //       return (
// //         <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
// //           <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
// //             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
// //           </svg>
// //         </div>
// //       );
// //     } else if (status === 'active') {
// //       return (
// //         <div className="w-8 h-8 bg-primary-600 rounded-full flex items-center justify-center">
// //           <span className="text-white font-medium">{step}</span>
// //         </div>
// //       );
// //     } else {
// //       return (
// //         <div className="w-8 h-8 bg-gray-300 rounded-full flex items-center justify-center">
// //           <span className="text-gray-600 font-medium">{step}</span>
// //         </div>
// //       );
// //     }
// //   };

// //   const renderCurrentStep = () => {
// //     switch (currentStep) {
// //       case 1:
// //         return <EmailVerification />;
// //       case 2:
// //         return <PhoneVerification />;
// //       case 3:
// //         return <BiometricCapture />;
// //       default:
// //         return <EmailVerification />;
// //     }
// //   };

// //   return (
// //     <div className="min-h-screen bg-gradient-to-br from-primary-50 to-blue-50 py-12 px-4 sm:px-6 lg:px-8">
// //       <div className="max-w-4xl mx-auto">
// //         {/* Header */}
// //         <div className="text-center mb-8">
// //           <h1 className="text-3xl font-bold text-gray-900 mb-2">
// //             Welcome to Vottery
// //           </h1>
// //           <p className="text-gray-600">
// //             Complete the 3-step verification process to access your dashboard
// //           </p>
// //         </div>

// //         {/* Progress Steps */}
// //         {showProgress && (
// //           <div className="mb-8">
// //             <div className="flex justify-center">
// //               <div className="flex items-center space-x-8">
// //                 {/* Step 1 */}
// //                 <div className="flex flex-col items-center">
// //                   {renderStepIcon(1, getStepStatus(1))}
// //                   <span className="text-sm font-medium text-gray-700 mt-2">Email OTP</span>
// //                 </div>
                
// //                 <div className={`h-px w-16 ${getStepStatus(2) !== 'pending' ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                
// //                 {/* Step 2 */}
// //                 <div className="flex flex-col items-center">
// //                   {renderStepIcon(2, getStepStatus(2))}
// //                   <span className="text-sm font-medium text-gray-700 mt-2">Phone OTP</span>
// //                 </div>
                
// //                 <div className={`h-px w-16 ${getStepStatus(3) !== 'pending' ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                
// //                 {/* Step 3 */}
// //                 <div className="flex flex-col items-center">
// //                   {renderStepIcon(3, getStepStatus(3))}
// //                   <span className="text-sm font-medium text-gray-700 mt-2">Biometric</span>
// //                 </div>
// //               </div>
// //             </div>
// //           </div>
// //         )}

// //         {/* Error Display */}
// //         {error && (
// //           <div className="mb-6 bg-red-50 border border-red-200 rounded-lg p-4">
// //             <div className="flex">
// //               <svg className="h-5 w-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
// //                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
// //               </svg>
// //               <div className="ml-3">
// //                 <p className="text-sm text-red-700">{error}</p>
// //               </div>
// //             </div>
// //           </div>
// //         )}

// //         {/* Main Content */}
// //         <div className="max-w-md mx-auto">
// //           {renderCurrentStep()}
// //         </div>

// //         {/* Security Badge */}
// //         <div className="mt-8 text-center">
// //           <div className="inline-flex items-center space-x-4">
// //             <span className="security-badge">
// //               <svg className="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
// //                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
// //               </svg>
// //               Secure Authentication
// //             </span>
// //             <span className="security-badge">
// //               <svg className="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
// //                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
// //               </svg>
// //               End-to-End Encrypted
// //             </span>
// //           </div>
// //         </div>
// //       </div>
// //     </div>
// //   );
// // };

// // export default AuthenticationFlow;