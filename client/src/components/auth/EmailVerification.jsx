//5 steps perfect
import React, { useState, useRef, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { SecurityUtils } from '../../utils/security';
import { toast } from 'react-hot-toast';

const EmailVerification = () => {
  const { isLoading, sendEmailOTP, verifyEmailOTP, currentStep, email, goBackStep } = useAuth();
  const [localEmail, setLocalEmail] = useState(email || '');
  const [otp, setOtp] = useState(['', '', '', '', '', '']);
  const [timeLeft, setTimeLeft] = useState(0);
  const [error, setError] = useState('');
  const otpRefs = useRef([]);

  // Timer effect for OTP expiry
  useEffect(() => {
    let interval = null;
    if (timeLeft > 0) {
      interval = setInterval(() => {
        setTimeLeft(timeLeft => timeLeft - 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [timeLeft]);

  // STEP 1: Handle email input and send OTP
  const handleSendOTP = async (e) => {
    e.preventDefault();
    
    const sanitizedEmail = SecurityUtils.sanitizeInput(localEmail.trim());
    
    // Frontend validation
    if (!sanitizedEmail) {
      setError('Email is required');
      toast.error('Email is required');
      return;
    }

    if (!SecurityUtils.isValidEmail(sanitizedEmail)) {
      setError('Please enter a valid email address');
      toast.error('Please enter a valid email address');
      return;
    }

    try {
      setError('');
      await sendEmailOTP(sanitizedEmail);
      setTimeLeft(300); // 5 minutes
      // Focus first OTP input
      setTimeout(() => {
        otpRefs.current[0]?.focus();
      }, 100);
    } catch (error) {
      setError(error.message);
      // Keep user on step 1 - don't advance if backend says email not in database
    }
  };

  // Handle OTP input changes
  const handleOtpChange = (index, value) => {
    if (value.length > 1) return;
    
    // Only allow digits
    if (value && !/^\d$/.test(value)) return;
    
    const newOtp = [...otp];
    newOtp[index] = value;
    setOtp(newOtp);

    // Auto-focus next input
    if (value && index < 5) {
      otpRefs.current[index + 1]?.focus();
    }

    // Auto-verify if all fields are filled
    if (newOtp.every(digit => digit !== '') && newOtp.join('').length === 6) {
      handleVerifyOTP(newOtp.join(''));
    }
  };

  // Handle backspace in OTP inputs
  const handleKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !otp[index] && index > 0) {
      otpRefs.current[index - 1]?.focus();
    }
  };

  // Handle OTP paste
  const handlePaste = (e) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text');
    const digits = pastedData.replace(/\D/g, '').substring(0, 6);
    
    if (digits.length === 6) {
      const newOtp = digits.split('');
      setOtp(newOtp);
      handleVerifyOTP(digits);
    }
  };

  // STEP 2: Verify OTP
  const handleVerifyOTP = async (otpCode) => {
    try {
      setError('');
      await verifyEmailOTP(otpCode);
      // If successful, AuthContext will advance to step 3
    } catch (error) {
      setError(error.message);
      setOtp(['', '', '', '', '', '']);
      otpRefs.current[0]?.focus();
      // Keep user on step 2 - don't advance if OTP is incorrect
    }
  };

  // Format time display
  const formatTime = (seconds) => {
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${minutes}:${secs.toString().padStart(2, '0')}`;
  };

  // Resend OTP
  const handleResendOTP = async () => {
    try {
      setError('');
      setOtp(['', '', '', '', '', '']);
      await sendEmailOTP(localEmail);
      setTimeLeft(300);
      toast.success('New OTP sent to your email');
    } catch (error) {
      setError(error.message);
    }
  };

  // Go back to email input
  const handleGoBack = () => {
    goBackStep();
    setOtp(['', '', '', '', '', '']);
    setError('');
    setTimeLeft(0);
  };

  // Only show this component when it's step 1 or 2
  if (currentStep !== 1 && currentStep !== 2) {
    return null;
  }

  return (
    <div className="bg-white rounded-lg shadow-lg p-8">
      <div className="text-center mb-6">
        <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 mb-4">
          <svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
        </div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">
          {currentStep === 1 ? 'Step 1: Email Verification' : 'Step 2: Verify Email OTP'}
        </h2>
        <p className="text-gray-600">
          {currentStep === 1 
            ? 'Enter your email to receive a verification code' 
            : 'Enter the 6-digit code sent to your email'
          }
        </p>
      </div>

      {error && (
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

      {currentStep === 1 ? (
        // STEP 1: Email Input Form
        <form onSubmit={handleSendOTP} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Email Address *
            </label>
            <input
              type="email"
              value={localEmail}
              onChange={(e) => setLocalEmail(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200"
              placeholder="Enter your email address"
              required
              disabled={isLoading}
              autoComplete="email"
            />
            <p className="text-xs text-gray-500 mt-1">
              This email must be registered in SNGINE database
            </p>
          </div>

          <button
            type="submit"
            disabled={isLoading || !localEmail.trim()}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white font-medium py-3 px-4 rounded-lg transition duration-200"
          >
            {isLoading ? (
              <div className="flex items-center justify-center">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                Checking Email & Sending OTP...
              </div>
            ) : (
              'Send Verification Code'
            )}
          </button>
        </form>
      ) : (
        // STEP 2: OTP Verification Form
        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-3 text-center">
              Enter Verification Code
            </label>
            <div className="flex justify-center space-x-2" onPaste={handlePaste}>
              {otp.map((digit, index) => (
                <input
                  key={index}
                  ref={el => otpRefs.current[index] = el}
                  type="text"
                  maxLength={1}
                  value={digit}
                  onChange={(e) => handleOtpChange(index, e.target.value)}
                  onKeyDown={(e) => handleKeyDown(index, e)}
                  className="w-12 h-12 text-center border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-lg font-medium transition duration-200"
                  disabled={isLoading}
                  inputMode="numeric"
                />
              ))}
            </div>
            <p className="text-xs text-gray-500 mt-2 text-center">
              Paste the 6-digit code or enter manually
            </p>
          </div>

          <div className="text-center space-y-3">
            <p className="text-sm text-gray-600">
              Code sent to: <span className="font-medium">{email}</span>
            </p>
            
            {timeLeft > 0 ? (
              <p className="text-sm text-gray-500">
                Resend code in {formatTime(timeLeft)}
              </p>
            ) : (
              <button
                onClick={handleResendOTP}
                disabled={isLoading}
                className="text-sm text-blue-600 hover:text-blue-700 font-medium disabled:opacity-50 disabled:cursor-not-allowed transition duration-200"
              >
                Resend verification code
              </button>
            )}
          </div>

          <div className="text-center">
            <button
              onClick={handleGoBack}
              className="text-sm text-gray-500 hover:text-gray-700 transition duration-200"
              disabled={isLoading}
            >
              ← Change email address
            </button>
          </div>
        </div>
      )}

      {/* Demo Instructions */}
      <div className="mt-6 text-center">
        <div className="bg-gray-50 border border-gray-200 rounded-lg p-3">
          <p className="text-xs text-gray-600">
            <span className="font-medium">Demo Mode:</span> Use OTP code{' '}
            <span className="font-mono bg-gray-200 px-1 rounded">123456</span> for testing
          </p>
        </div>
      </div>
    </div>
  );
};

export default EmailVerification;


//new 5 steps code
// import React, { useState, useRef, useEffect } from 'react';
// import { useAuth } from '../../contexts/AuthContext';
// import { SecurityUtils } from '../../utils/security';
// import { toast } from 'react-hot-toast';

// const EmailVerification = () => {
//   const { email, isLoading, sendEmailOTP, verifyEmailOTP, setEmailAndAdvance, currentStep } = useAuth();
//   const [localEmail, setLocalEmail] = useState(email);
//   const [otp, setOtp] = useState(['', '', '', '', '', '']);
//   const [otpSent, setOtpSent] = useState(false);
//   const [timeLeft, setTimeLeft] = useState(0);
//   const [error, setError] = useState('');
//   const otpRefs = useRef([]);

//   // Timer effect for OTP expiry
//   useEffect(() => {
//     let interval = null;
//     if (timeLeft > 0) {
//       interval = setInterval(() => {
//         setTimeLeft(timeLeft => timeLeft - 1);
//       }, 1000);
//     }
//     return () => clearInterval(interval);
//   }, [timeLeft]);

//   // Handle email input and send OTP
//   const handleSendOTP = async (e) => {
//     e.preventDefault();
    
//     const sanitizedEmail = SecurityUtils.sanitizeInput(localEmail);
    
//     if (!SecurityUtils.isValidEmail(sanitizedEmail)) {
//       setError('Please enter a valid email address');
//       toast.error('Please enter a valid email address');
//       return;
//     }

//     try {
//       setError('');
//       setEmailAndAdvance(sanitizedEmail);
//       await sendEmailOTP(sanitizedEmail);
//       setOtpSent(true);
//       setTimeLeft(300); // 5 minutes
//       // Focus first OTP input
//       setTimeout(() => {
//         otpRefs.current[0]?.focus();
//       }, 100);
//     } catch (error) {
//       setError(error.message);
//     }
//   };

//   // Handle OTP input changes
//   const handleOtpChange = (index, value) => {
//     if (value.length > 1) return;
    
//     // Only allow digits
//     if (value && !/^\d$/.test(value)) return;
    
//     const newOtp = [...otp];
//     newOtp[index] = value;
//     setOtp(newOtp);

//     // Auto-focus next input
//     if (value && index < 5) {
//       otpRefs.current[index + 1]?.focus();
//     }

//     // Auto-verify if all fields are filled
//     if (newOtp.every(digit => digit !== '') && newOtp.join('').length === 6) {
//       handleVerifyOTP(newOtp.join(''));
//     }
//   };

//   // Handle backspace in OTP inputs
//   const handleKeyDown = (index, e) => {
//     if (e.key === 'Backspace' && !otp[index] && index > 0) {
//       otpRefs.current[index - 1]?.focus();
//     }
//   };

//   // Handle OTP paste
//   const handlePaste = (e) => {
//     e.preventDefault();
//     const pastedData = e.clipboardData.getData('text');
//     const digits = pastedData.replace(/\D/g, '').substring(0, 6);
    
//     if (digits.length === 6) {
//       const newOtp = digits.split('');
//       setOtp(newOtp);
//       handleVerifyOTP(digits);
//     }
//   };

//   // Verify OTP
//   const handleVerifyOTP = async (otpCode) => {
//     try {
//       setError('');
//       await verifyEmailOTP(localEmail, otpCode);
//     } catch (error) {
//       setError(error.message);
//       setOtp(['', '', '', '', '', '']);
//       otpRefs.current[0]?.focus();
//     }
//   };

//   // Format time display
//   const formatTime = (seconds) => {
//     const minutes = Math.floor(seconds / 60);
//     const secs = seconds % 60;
//     return `${minutes}:${secs.toString().padStart(2, '0')}`;
//   };

//   // Resend OTP
//   const handleResendOTP = async () => {
//     try {
//       setError('');
//       setOtp(['', '', '', '', '', '']);
//       await sendEmailOTP(localEmail);
//       setTimeLeft(300);
//       toast.success('New OTP sent to your email');
//     } catch (error) {
//       setError(error.message);
//     }
//   };

//   // Only show this component when it's the current step
//   if (currentStep !== 1 && currentStep !== 2) {
//     return null;
//   }

//   return (
//     <div className="bg-white rounded-lg shadow-lg p-8">
//       <div className="text-center mb-6">
//         <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 mb-4">
//           <svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
//           </svg>
//         </div>
//         <h2 className="text-2xl font-bold text-gray-900 mb-2">
//           {currentStep === 1 ? 'Email Verification' : 'Verify Email OTP'}
//         </h2>
//         <p className="text-gray-600">
//           {currentStep === 1 
//             ? 'Enter your email to receive a verification code' 
//             : 'Enter the 6-digit code sent to your email'
//           }
//         </p>
//       </div>

//       {error && (
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

//       {currentStep === 1 ? (
//         // Email Input Form
//         <form onSubmit={handleSendOTP} className="space-y-4">
//           <div>
//             <label className="block text-sm font-medium text-gray-700 mb-2">
//               Email Address *
//             </label>
//             <input
//               type="email"
//               value={localEmail}
//               onChange={(e) => setLocalEmail(e.target.value)}
//               className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200"
//               placeholder="Enter your email address"
//               required
//               disabled={isLoading}
//               autoComplete="email"
//             />
//             <p className="text-xs text-gray-500 mt-1">
//               This email must be registered in SNGINE database
//             </p>
//           </div>

//           <button
//             type="submit"
//             disabled={isLoading || !localEmail}
//             className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white font-medium py-3 px-4 rounded-lg transition duration-200"
//           >
//             {isLoading ? (
//               <div className="flex items-center justify-center">
//                 <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
//                 Sending OTP...
//               </div>
//             ) : (
//               'Send Verification Code'
//             )}
//           </button>
//         </form>
//       ) : (
//         // OTP Verification Form
//         <div className="space-y-6">
//           <div>
//             <label className="block text-sm font-medium text-gray-700 mb-3 text-center">
//               Enter Verification Code
//             </label>
//             <div className="flex justify-center space-x-2" onPaste={handlePaste}>
//               {otp.map((digit, index) => (
//                 <input
//                   key={index}
//                   ref={el => otpRefs.current[index] = el}
//                   type="text"
//                   maxLength={1}
//                   value={digit}
//                   onChange={(e) => handleOtpChange(index, e.target.value)}
//                   onKeyDown={(e) => handleKeyDown(index, e)}
//                   className="w-12 h-12 text-center border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-lg font-medium transition duration-200"
//                   disabled={isLoading}
//                   inputMode="numeric"
//                 />
//               ))}
//             </div>
//             <p className="text-xs text-gray-500 mt-2 text-center">
//               Paste the 6-digit code or enter manually
//             </p>
//           </div>

//           <div className="text-center space-y-3">
//             <p className="text-sm text-gray-600">
//               Code sent to: <span className="font-medium">{localEmail}</span>
//             </p>
            
//             {timeLeft > 0 ? (
//               <p className="text-sm text-gray-500">
//                 Resend code in {formatTime(timeLeft)}
//               </p>
//             ) : (
//               <button
//                 onClick={handleResendOTP}
//                 disabled={isLoading}
//                 className="text-sm text-blue-600 hover:text-blue-700 font-medium disabled:opacity-50 disabled:cursor-not-allowed transition duration-200"
//               >
//                 Resend verification code
//               </button>
//             )}
//           </div>

//           <div className="text-center">
//             <button
//               onClick={() => {
//                 setOtpSent(false);
//                 setOtp(['', '', '', '', '', '']);
//                 setError('');
//                 setTimeLeft(0);
//               }}
//               className="text-sm text-gray-500 hover:text-gray-700 transition duration-200"
//             >
//               Change email address
//             </button>
//           </div>
//         </div>
//       )}

//       {/* Demo Instructions */}
//       <div className="mt-6 text-center">
//         <div className="bg-gray-50 border border-gray-200 rounded-lg p-3">
//           <p className="text-xs text-gray-600">
//             <span className="font-medium">Demo Mode:</span> Use OTP code{' '}
//             <span className="font-mono bg-gray-200 px-1 rounded">123456</span> for testing
//           </p>
//         </div>
//       </div>
//     </div>
//   );
// };

// export default EmailVerification;






//this is also step 5 but to solve after otp it does not go to next steps
// import React, { useState, useRef, useEffect } from 'react';
// import { useAuth } from '../../contexts/AuthContext';
// import { SecurityUtils } from '../../utils/security';
// import { toast } from 'react-hot-toast';

// const EmailVerification = () => {
//   const { email, isLoading, sendEmailOTP, verifyEmailOTP, setEmailAndAdvance, currentStep } = useAuth();
//   const [localEmail, setLocalEmail] = useState(email);
//   const [otp, setOtp] = useState(['', '', '', '', '', '']);
//   const [otpSent, setOtpSent] = useState(false);
//   const [timeLeft, setTimeLeft] = useState(0);
//   const [error, setError] = useState('');
//   const otpRefs = useRef([]);

//   // Timer effect for OTP expiry
//   useEffect(() => {
//     let interval = null;
//     if (timeLeft > 0) {
//       interval = setInterval(() => {
//         setTimeLeft(timeLeft => timeLeft - 1);
//       }, 1000);
//     }
//     return () => clearInterval(interval);
//   }, [timeLeft]);

//   // Handle email input and send OTP
//   const handleSendOTP = async (e) => {
//     e.preventDefault();
    
//     const sanitizedEmail = SecurityUtils.sanitizeInput(localEmail);
    
//     if (!SecurityUtils.isValidEmail(sanitizedEmail)) {
//       setError('Please enter a valid email address');
//       toast.error('Please enter a valid email address');
//       return;
//     }

//     try {
//       setError('');
//       setEmailAndAdvance(sanitizedEmail);
//       await sendEmailOTP(sanitizedEmail);
//       setOtpSent(true);
//       setTimeLeft(300); // 5 minutes
//       // Focus first OTP input
//       setTimeout(() => {
//         otpRefs.current[0]?.focus();
//       }, 100);
//     } catch (error) {
//       setError(error.message);
//     }
//   };

//   // Handle OTP input changes
//   const handleOtpChange = (index, value) => {
//     if (value.length > 1) return;
    
//     // Only allow digits
//     if (value && !/^\d$/.test(value)) return;
    
//     const newOtp = [...otp];
//     newOtp[index] = value;
//     setOtp(newOtp);

//     // Auto-focus next input
//     if (value && index < 5) {
//       otpRefs.current[index + 1]?.focus();
//     }

//     // Auto-verify if all fields are filled
//     if (newOtp.every(digit => digit !== '') && newOtp.join('').length === 6) {
//       handleVerifyOTP(newOtp.join(''));
//     }
//   };

//   // Handle backspace in OTP inputs
//   const handleKeyDown = (index, e) => {
//     if (e.key === 'Backspace' && !otp[index] && index > 0) {
//       otpRefs.current[index - 1]?.focus();
//     }
//   };

//   // Handle OTP paste
//   const handlePaste = (e) => {
//     e.preventDefault();
//     const pastedData = e.clipboardData.getData('text');
//     const digits = pastedData.replace(/\D/g, '').substring(0, 6);
    
//     if (digits.length === 6) {
//       const newOtp = digits.split('');
//       setOtp(newOtp);
//       handleVerifyOTP(digits);
//     }
//   };

//   // Verify OTP
//   const handleVerifyOTP = async (otpCode) => {
//     try {
//       setError('');
//       await verifyEmailOTP(localEmail, otpCode);
//       // Don't need to manually change step here - AuthContext handles it
//       toast.success('Email verified successfully! Moving to phone verification...');
//     } catch (error) {
//       setError(error.message);
//       setOtp(['', '', '', '', '', '']);
//       otpRefs.current[0]?.focus();
//     }
//   };

//   // Format time display
//   const formatTime = (seconds) => {
//     const minutes = Math.floor(seconds / 60);
//     const secs = seconds % 60;
//     return `${minutes}:${secs.toString().padStart(2, '0')}`;
//   };

//   // Resend OTP
//   const handleResendOTP = async () => {
//     try {
//       setError('');
//       setOtp(['', '', '', '', '', '']);
//       await sendEmailOTP(localEmail);
//       setTimeLeft(300);
//       toast.success('New OTP sent to your email');
//     } catch (error) {
//       setError(error.message);
//     }
//   };

//   // FIXED: Only show this component when it's step 1 or 2
//   if (currentStep !== 1 && currentStep !== 2) {
//     return null;
//   }

//   // ADDED: Automatically show OTP form if we're on step 2
//   useEffect(() => {
//     if (currentStep === 2 && !otpSent) {
//       setOtpSent(true);
//       setTimeLeft(300);
//       setTimeout(() => {
//         otpRefs.current[0]?.focus();
//       }, 100);
//     }
//   }, [currentStep, otpSent]);

//   return (
//     <div className="bg-white rounded-lg shadow-lg p-8">
//       <div className="text-center mb-6">
//         <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 mb-4">
//           <svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
//           </svg>
//         </div>
//         <h2 className="text-2xl font-bold text-gray-900 mb-2">
//           {currentStep === 1 ? 'Email Verification' : 'Verify Email OTP'}
//         </h2>
//         <p className="text-gray-600">
//           {currentStep === 1 
//             ? 'Enter your email to receive a verification code' 
//             : 'Enter the 6-digit code sent to your email'
//           }
//         </p>
//       </div>

//       {error && (
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

//       {currentStep === 1 ? (
//         // Email Input Form
//         <form onSubmit={handleSendOTP} className="space-y-4">
//           <div>
//             <label className="block text-sm font-medium text-gray-700 mb-2">
//               Email Address *
//             </label>
//             <input
//               type="email"
//               value={localEmail}
//               onChange={(e) => setLocalEmail(e.target.value)}
//               className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200"
//               placeholder="Enter your email address"
//               required
//               disabled={isLoading}
//               autoComplete="email"
//             />
//             <p className="text-xs text-gray-500 mt-1">
//               This email must be registered in SNGINE database
//             </p>
//           </div>

//           <button
//             type="submit"
//             disabled={isLoading || !localEmail}
//             className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white font-medium py-3 px-4 rounded-lg transition duration-200"
//           >
//             {isLoading ? (
//               <div className="flex items-center justify-center">
//                 <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
//                 Sending OTP...
//               </div>
//             ) : (
//               'Send Verification Code'
//             )}
//           </button>
//         </form>
//       ) : (
//         // OTP Verification Form
//         <div className="space-y-6">
//           <div>
//             <label className="block text-sm font-medium text-gray-700 mb-3 text-center">
//               Enter Verification Code
//             </label>
//             <div className="flex justify-center space-x-2" onPaste={handlePaste}>
//               {otp.map((digit, index) => (
//                 <input
//                   key={index}
//                   ref={el => otpRefs.current[index] = el}
//                   type="text"
//                   maxLength={1}
//                   value={digit}
//                   onChange={(e) => handleOtpChange(index, e.target.value)}
//                   onKeyDown={(e) => handleKeyDown(index, e)}
//                   className="w-12 h-12 text-center border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-lg font-medium transition duration-200"
//                   disabled={isLoading}
//                   inputMode="numeric"
//                 />
//               ))}
//             </div>
//             <p className="text-xs text-gray-500 mt-2 text-center">
//               Paste the 6-digit code or enter manually
//             </p>
//           </div>

//           <div className="text-center space-y-3">
//             <p className="text-sm text-gray-600">
//               Code sent to: <span className="font-medium">{localEmail}</span>
//             </p>
            
//             {timeLeft > 0 ? (
//               <p className="text-sm text-gray-500">
//                 Resend code in {formatTime(timeLeft)}
//               </p>
//             ) : (
//               <button
//                 onClick={handleResendOTP}
//                 disabled={isLoading}
//                 className="text-sm text-blue-600 hover:text-blue-700 font-medium disabled:opacity-50 disabled:cursor-not-allowed transition duration-200"
//               >
//                 Resend verification code
//               </button>
//             )}
//           </div>

//           <div className="text-center">
//             <button
//               onClick={() => {
//                 setOtpSent(false);
//                 setOtp(['', '', '', '', '', '']);
//                 setError('');
//                 setTimeLeft(0);
//               }}
//               className="text-sm text-gray-500 hover:text-gray-700 transition duration-200"
//             >
//               Change email address
//             </button>
//           </div>
//         </div>
//       )}

//       {/* Demo Instructions */}
//       <div className="mt-6 text-center">
//         <div className="bg-gray-50 border border-gray-200 rounded-lg p-3">
//           <p className="text-xs text-gray-600">
//             <span className="font-medium">Demo Mode:</span> Use OTP code{' '}
//             <span className="font-mono bg-gray-200 px-1 rounded">123456</span> for testing
//           </p>
//         </div>
//       </div>
//     </div>
//   );
// };
// export default EmailVerification
//old 3 steps code
// import React, { useState, useRef, useEffect } from 'react';
// import { useAuth } from '../../contexts/AuthContext';

// const EmailVerification = () => {
//   const { email, isLoading, sendEmailOTP, verifyEmailOTP, dispatch } = useAuth();
//   const [localEmail, setLocalEmail] = useState(email);
//   const [otp, setOtp] = useState(['', '', '', '', '', '']);
//   const [otpSent, setOtpSent] = useState(false);
//   const [timeLeft, setTimeLeft] = useState(0);
//   const [error, setError] = useState('');
//   const otpRefs = useRef([]);

//   useEffect(() => {
//     let interval = null;
//     if (timeLeft > 0) {
//       interval = setInterval(() => {
//         setTimeLeft(timeLeft => timeLeft - 1);
//       }, 1000);
//     }
//     return () => clearInterval(interval);
//   }, [timeLeft]);

//   const validateEmail = (email) => {
//     const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//     return re.test(email);
//   };

//   const handleSendOTP = async (e) => {
//     e.preventDefault();
    
//     if (!validateEmail(localEmail)) {
//       setError('Please enter a valid email address');
//       return;
//     }

//     try {
//       setError('');
//       dispatch({ type: 'SET_EMAIL', payload: localEmail });
//       await sendEmailOTP(localEmail);
//       setOtpSent(true);
//       setTimeLeft(300); // 5 minutes
//       otpRefs.current[0]?.focus();
//     } catch (error) {
//       setError(error.message);
//     }
//   };

//   const handleOtpChange = (index, value) => {
//     if (value.length > 1) return;
    
//     const newOtp = [...otp];
//     newOtp[index] = value;
//     setOtp(newOtp);

//     // Auto-focus next input
//     if (value && index < 5) {
//       otpRefs.current[index + 1]?.focus();
//     }

//     // Auto-verify if all fields are filled
//     if (newOtp.every(digit => digit !== '') && newOtp.join('').length === 6) {
//       handleVerifyOTP(newOtp.join(''));
//     }
//   };

//   const handleKeyDown = (index, e) => {
//     if (e.key === 'Backspace' && !otp[index] && index > 0) {
//       otpRefs.current[index - 1]?.focus();
//     }
//   };

//   const handleVerifyOTP = async (otpCode) => {
//     try {
//       setError('');
//       await verifyEmailOTP(localEmail, otpCode);
//       dispatch({ type: 'SET_STEP', payload: 2 });
//     } catch (error) {
//       setError(error.message);
//       setOtp(['', '', '', '', '', '']);
//       otpRefs.current[0]?.focus();
//     }
//   };

//   const formatTime = (seconds) => {
//     const minutes = Math.floor(seconds / 60);
//     const secs = seconds % 60;
//     return `${minutes}:${secs.toString().padStart(2, '0')}`;
//   };

//   const handleResendOTP = async () => {
//     try {
//       setError('');
//       setOtp(['', '', '', '', '', '']);
//       await sendEmailOTP(localEmail);
//       setTimeLeft(300);
//     } catch (error) {
//       setError(error.message);
//     }
//   };

//   return (
//     <div className="bg-white rounded-lg shadow-lg p-8">
//       <div className="text-center mb-6">
//         <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-primary-100 mb-4">
//           <svg className="h-6 w-6 text-primary-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
//           </svg>
//         </div>
//         <h2 className="text-2xl font-bold text-gray-900 mb-2">Email Verification</h2>
//         <p className="text-gray-600">
//           {!otpSent ? 'Enter your email to receive a verification code' : 'Enter the 6-digit code sent to your email'}
//         </p>
//       </div>

//       {error && (
//         <div className="mb-4 bg-red-50 border border-red-200 rounded-lg p-3">
//           <p className="text-sm text-red-700">{error}</p>
//         </div>
//       )}

//       {!otpSent ? (
//         <form onSubmit={handleSendOTP} className="space-y-4">
//           <div>
//             <label className="block text-sm font-medium text-gray-700 mb-2">
//               Email Address
//             </label>
//             <input
//               type="email"
//               value={localEmail}
//               onChange={(e) => setLocalEmail(e.target.value)}
//               className="form-input"
//               placeholder="Enter your email address"
//               required
//               disabled={isLoading}
//             />
//           </div>

//           <button
//             type="submit"
//             disabled={isLoading || !localEmail}
//             className="w-full btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
//           >
//             {isLoading ? (
//               <div className="flex items-center justify-center">
//                 <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
//                 Sending OTP...
//               </div>
//             ) : (
//               'Send Verification Code'
//             )}
//           </button>
//         </form>
//       ) : (
//         <div className="space-y-6">
//           <div>
//             <label className="block text-sm font-medium text-gray-700 mb-3 text-center">
//               Enter Verification Code
//             </label>
//             <div className="flex justify-center space-x-2">
//               {otp.map((digit, index) => (
//                 <input
//                   key={index}
//                   ref={el => otpRefs.current[index] = el}
//                   type="text"
//                   maxLength={1}
//                   value={digit}
//                   onChange={(e) => handleOtpChange(index, e.target.value)}
//                   onKeyDown={(e) => handleKeyDown(index, e)}
//                   className="w-12 h-12 text-center border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent text-lg font-medium"
//                   disabled={isLoading}
//                 />
//               ))}
//             </div>
//           </div>

//           <div className="text-center">
//             <p className="text-sm text-gray-600 mb-2">
//               Code sent to: <span className="font-medium">{localEmail}</span>
//             </p>
            
//             {timeLeft > 0 ? (
//               <p className="text-sm text-gray-500">
//                 Resend code in {formatTime(timeLeft)}
//               </p>
//             ) : (
//               <button
//                 onClick={handleResendOTP}
//                 disabled={isLoading}
//                 className="text-sm text-primary-600 hover:text-primary-700 font-medium"
//               >
//                 Resend verification code
//               </button>
//             )}
//           </div>

//           <div className="text-center">
//             <button
//               onClick={() => {
//                 setOtpSent(false);
//                 setOtp(['', '', '', '', '', '']);
//                 setError('');
//                 setTimeLeft(0);
//               }}
//               className="text-sm text-gray-500 hover:text-gray-700"
//             >
//               Change email address
//             </button>
//           </div>
//         </div>
//       )}

//       <div className="mt-6 text-center">
//         <p className="text-xs text-gray-500">
//           Demo: Use OTP code <span className="font-mono bg-gray-100 px-1">123456</span> for testing
//         </p>
//       </div>
//     </div>
//   );
// };

// export default EmailVerification;