//5 steps perfect
import React, { useState, useRef, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { SecurityUtils } from '../../utils/security';
import { toast } from 'react-hot-toast';

const PhoneVerification = () => {
  const { isLoading, sendPhoneOTP, verifyPhoneOTP, currentStep, phone, goBackStep } = useAuth();
  const [localPhone, setLocalPhone] = useState(phone || '');
  const [otp, setOtp] = useState(['', '', '', '', '', '']);
  const [timeLeft, setTimeLeft] = useState(0);
  const [error, setError] = useState('');
  const otpRefs = useRef([]);
console.log("localPhone===?", localPhone)
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

  // Format phone number for display
  const formatPhoneDisplay = (phone) => {
    const cleaned = phone.replace(/\D/g, '');
    if (cleaned.length >= 10) {
      // Format as +X XXX-XXX-XXXX for display
      if (cleaned.length === 10) {
        return `+1 ${cleaned.substring(0, 3)}-${cleaned.substring(3, 6)}-${cleaned.substring(6)}`;
      } else if (cleaned.length === 11 && cleaned.startsWith('1')) {
        return `+1 ${cleaned.substring(1, 4)}-${cleaned.substring(4, 7)}-${cleaned.substring(7)}`;
      } else {
        return `+${cleaned.substring(0, cleaned.length - 10)} ${cleaned.substring(cleaned.length - 10, cleaned.length - 7)}-${cleaned.substring(cleaned.length - 7, cleaned.length - 4)}-${cleaned.substring(cleaned.length - 4)}`;
      }
    }
    return phone;
  };

  // STEP 3: Handle phone input and send SMS OTP - FIXED
  const handleSendOTP = async (e) => {
    e.preventDefault();
    
    // Clean phone but preserve the + sign - FIXED THIS PART
    let cleanPhone = localPhone.trim();
    
    // If phone doesn't start with +, but starts with a digit, add + to make it E.164 format
    if (!cleanPhone.startsWith('+') && /^\d/.test(cleanPhone)) {
      cleanPhone = '+' + cleanPhone;
    }
    
    // Remove any non-digit characters except the leading +
    if (cleanPhone.startsWith('+')) {
      const phoneDigitsOnly = cleanPhone.substring(1).replace(/\D/g, '');
      cleanPhone = '+' + phoneDigitsOnly;
    }
    
    const sanitizedPhone = SecurityUtils.sanitizeInput(cleanPhone);
    
    // Frontend validation
    if (!sanitizedPhone) {
      setError('Phone number is required');
      toast.error('Phone number is required');
      return;
    }

    if (!SecurityUtils.isValidPhone(sanitizedPhone)) {
      setError('Please enter a valid phone number with country code');
      toast.error('Please enter a valid phone number with country code');
      return;
    }

    try {
      setError('');
      await sendPhoneOTP(sanitizedPhone);
      setTimeLeft(300); // 5 minutes
      // Focus first OTP input
      setTimeout(() => {
        otpRefs.current[0]?.focus();
      }, 100);
    } catch (error) {
      setError(error.message);
      // Keep user on step 3 - don't advance if backend says phone not in database
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

  // STEP 4: Verify SMS OTP
  const handleVerifyOTP = async (otpCode) => {
    try {
      setError('');
      await verifyPhoneOTP(otpCode);
      // If successful, AuthContext will advance to step 5
    } catch (error) {
      setError(error.message);
      setOtp(['', '', '', '', '', '']);
      otpRefs.current[0]?.focus();
      // Keep user on step 4 - don't advance if OTP is incorrect
    }
  };

  // Format time display
  const formatTime = (seconds) => {
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${minutes}:${secs.toString().padStart(2, '0')}`;
  };

  // Resend SMS OTP
  const handleResendOTP = async () => {
    try {
      setError('');
      setOtp(['', '', '', '', '', '']);
      await sendPhoneOTP(localPhone);
      setTimeLeft(300);
      toast.success('New OTP sent to your phone');
    } catch (error) {
      setError(error.message);
    }
  };
  // Go back to phone input
  const handleGoBack = () => {
    goBackStep();
    setOtp(['', '', '', '', '', '']);
    setError('');
    setTimeLeft(0);
  };

  // Only show this component when it's step 3 or 4
  if (currentStep !== 3 && currentStep !== 4) {
    return null;
  }

  return (
    <div className="bg-white rounded-lg shadow-lg p-8">
      <div className="text-center mb-6">
        <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
          <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
          </svg>
        </div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">
          {currentStep === 3 ? 'Step 3: Phone Verification' : 'Step 4: Verify Phone OTP'}
        </h2>
        <p className="text-gray-600">
          {currentStep === 3 
            ? 'Enter your phone number to receive a verification code' 
            : 'Enter the 6-digit code sent to your phone'
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

      {currentStep === 3 ? (
        // STEP 3: Phone Input Form
        <form onSubmit={handleSendOTP} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Phone Number *
            </label>
            <input
              type="tel"
              value={localPhone}
              onChange={(e) => setLocalPhone(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent transition duration-200"
              placeholder="Enter your phone number with country code"
              required
              disabled={isLoading}
              autoComplete="tel"
            />
            <p className="text-xs text-gray-500 mt-1 space-y-1">
              <span className="block">Include country code (e.g., +1 for US, +880 for BD)</span>
              <span className="block">This phone must be registered in SNGINE database</span>
            </p>
          </div>

          <button
            type="submit"
            disabled={isLoading || !localPhone.trim()}
            className="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white font-medium py-3 px-4 rounded-lg transition duration-200"
          >
            {isLoading ? (
              <div className="flex items-center justify-center">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                Checking Phone & Sending OTP...
              </div>
            ) : (
              'Send Verification Code'
            )}
          </button>
        </form>
      ) : (
        // STEP 4: SMS OTP Verification Form
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
                  className="w-12 h-12 text-center border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent text-lg font-medium transition duration-200"
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
              Code sent to: <span className="font-medium">{formatPhoneDisplay(phone)}</span>
            </p>
            
            {timeLeft > 0 ? (
              <p className="text-sm text-gray-500">
                Resend code in {formatTime(timeLeft)}
              </p>
            ) : (
              <button
                onClick={handleResendOTP}
                disabled={isLoading}
                className="text-sm text-green-600 hover:text-green-700 font-medium disabled:opacity-50 disabled:cursor-not-allowed transition duration-200"
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
              ← Change phone number
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

export default PhoneVerification;
// import React, { useState, useRef, useEffect } from 'react';
// import { useAuth } from '../../contexts/AuthContext';
// import { SecurityUtils } from '../../utils/security';
// import { toast } from 'react-hot-toast';

// const PhoneVerification = () => {
//   const { isLoading, sendPhoneOTP, verifyPhoneOTP, currentStep, phone, goBackStep } = useAuth();
//   const [localPhone, setLocalPhone] = useState(phone || '');
//   const [otp, setOtp] = useState(['', '', '', '', '', '']);
//   const [timeLeft, setTimeLeft] = useState(0);
//   const [error, setError] = useState('');
//   const otpRefs = useRef([]);
// console.log("localPhone===?", localPhone)
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

//   // Format phone number for display
//   const formatPhoneDisplay = (phone) => {
//     const cleaned = phone.replace(/\D/g, '');
//     if (cleaned.length >= 10) {
//       // Format as +X XXX-XXX-XXXX for display
//       if (cleaned.length === 10) {
//         return `+1 ${cleaned.substring(0, 3)}-${cleaned.substring(3, 6)}-${cleaned.substring(6)}`;
//       } else if (cleaned.length === 11 && cleaned.startsWith('1')) {
//         return `+1 ${cleaned.substring(1, 4)}-${cleaned.substring(4, 7)}-${cleaned.substring(7)}`;
//       } else {
//         return `+${cleaned.substring(0, cleaned.length - 10)} ${cleaned.substring(cleaned.length - 10, cleaned.length - 7)}-${cleaned.substring(cleaned.length - 7, cleaned.length - 4)}-${cleaned.substring(cleaned.length - 4)}`;
//       }
//     }
//     return phone;
//   };

//   // STEP 3: Handle phone input and send SMS OTP
//   const handleSendOTP = async (e) => {
//     e.preventDefault();
    
//     const cleanPhone = localPhone.replace(/\D/g, '');
//     const sanitizedPhone = SecurityUtils.sanitizeInput(cleanPhone);
    
//     // Frontend validation
//     if (!sanitizedPhone) {
//       setError('Phone number is required');
//       toast.error('Phone number is required');
//       return;
//     }

//     if (!SecurityUtils.isValidPhone(sanitizedPhone)) {
//       setError('Please enter a valid phone number with country code');
//       toast.error('Please enter a valid phone number with country code');
//       return;
//     }

//     try {
//       setError('');
//       await sendPhoneOTP(sanitizedPhone);
//       setTimeLeft(300); // 5 minutes
//       // Focus first OTP input
//       setTimeout(() => {
//         otpRefs.current[0]?.focus();
//       }, 100);
//     } catch (error) {
//       setError(error.message);
//       // Keep user on step 3 - don't advance if backend says phone not in database
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

//   // STEP 4: Verify SMS OTP
//   const handleVerifyOTP = async (otpCode) => {
//     try {
//       setError('');
//       await verifyPhoneOTP(otpCode);
//       // If successful, AuthContext will advance to step 5
//     } catch (error) {
//       setError(error.message);
//       setOtp(['', '', '', '', '', '']);
//       otpRefs.current[0]?.focus();
//       // Keep user on step 4 - don't advance if OTP is incorrect
//     }
//   };

//   // Format time display
//   const formatTime = (seconds) => {
//     const minutes = Math.floor(seconds / 60);
//     const secs = seconds % 60;
//     return `${minutes}:${secs.toString().padStart(2, '0')}`;
//   };

//   // Resend SMS OTP
//   const handleResendOTP = async () => {
//     try {
//       setError('');
//       setOtp(['', '', '', '', '', '']);
//       await sendPhoneOTP(localPhone);
//       setTimeLeft(300);
//       toast.success('New OTP sent to your phone');
//     } catch (error) {
//       setError(error.message);
//     }
//   };
//   // Go back to phone input
//   const handleGoBack = () => {
//     goBackStep();
//     setOtp(['', '', '', '', '', '']);
//     setError('');
//     setTimeLeft(0);
//   };

//   // Only show this component when it's step 3 or 4
//   if (currentStep !== 3 && currentStep !== 4) {
//     return null;
//   }

//   return (
//     <div className="bg-white rounded-lg shadow-lg p-8">
//       <div className="text-center mb-6">
//         <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
//           <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
//           </svg>
//         </div>
//         <h2 className="text-2xl font-bold text-gray-900 mb-2">
//           {currentStep === 3 ? 'Step 3: Phone Verification' : 'Step 4: Verify Phone OTP'}
//         </h2>
//         <p className="text-gray-600">
//           {currentStep === 3 
//             ? 'Enter your phone number to receive a verification code' 
//             : 'Enter the 6-digit code sent to your phone'
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

//       {currentStep === 3 ? (
//         // STEP 3: Phone Input Form
//         <form onSubmit={handleSendOTP} className="space-y-4">
//           <div>
//             <label className="block text-sm font-medium text-gray-700 mb-2">
//               Phone Number *
//             </label>
//             <input
//               type="tel"
//               value={localPhone}
//               onChange={(e) => setLocalPhone(e.target.value)}
//               className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent transition duration-200"
//               placeholder="Enter your phone number with country code"
//               required
//               disabled={isLoading}
//               autoComplete="tel"
//             />
//             <p className="text-xs text-gray-500 mt-1 space-y-1">
//               <span className="block">Include country code (e.g., +1 for US, +880 for BD)</span>
//               <span className="block">This phone must be registered in SNGINE database</span>
//             </p>
//           </div>

//           <button
//             type="submit"
//             disabled={isLoading || !localPhone.trim()}
//             className="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white font-medium py-3 px-4 rounded-lg transition duration-200"
//           >
//             {isLoading ? (
//               <div className="flex items-center justify-center">
//                 <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
//                 Checking Phone & Sending OTP...
//               </div>
//             ) : (
//               'Send Verification Code'
//             )}
//           </button>
//         </form>
//       ) : (
//         // STEP 4: SMS OTP Verification Form
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
//                   className="w-12 h-12 text-center border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent text-lg font-medium transition duration-200"
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
//               Code sent to: <span className="font-medium">{formatPhoneDisplay(phone)}</span>
//             </p>
            
//             {timeLeft > 0 ? (
//               <p className="text-sm text-gray-500">
//                 Resend code in {formatTime(timeLeft)}
//               </p>
//             ) : (
//               <button
//                 onClick={handleResendOTP}
//                 disabled={isLoading}
//                 className="text-sm text-green-600 hover:text-green-700 font-medium disabled:opacity-50 disabled:cursor-not-allowed transition duration-200"
//               >
//                 Resend verification code
//               </button>
//             )}
//           </div>

//           <div className="text-center">
//             <button
//               onClick={handleGoBack}
//               className="text-sm text-gray-500 hover:text-gray-700 transition duration-200"
//               disabled={isLoading}
//             >
//               ← Change phone number
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

// export default PhoneVerification;
//this is 5 steps code
// import React, { useState, useRef, useEffect } from 'react';
// import { useAuth } from '../../contexts/AuthContext';
// import { SecurityUtils } from '../../utils/security';
// import { toast } from 'react-hot-toast';

// const PhoneVerification = () => {
//   const { phone, isLoading, sendPhoneOTP, verifyPhoneOTP, setPhoneAndAdvance, currentStep } = useAuth();
//   const [localPhone, setLocalPhone] = useState(phone);
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

//   // Format phone number for display
//   const formatPhoneDisplay = (phone) => {
//     const cleaned = phone.replace(/\D/g, '');
//     if (cleaned.length >= 10) {
//       // Format as +X XXX-XXX-XXXX for display
//       if (cleaned.length === 10) {
//         return `+1 ${cleaned.substring(0, 3)}-${cleaned.substring(3, 6)}-${cleaned.substring(6)}`;
//       } else if (cleaned.length === 11 && cleaned.startsWith('1')) {
//         return `+1 ${cleaned.substring(1, 4)}-${cleaned.substring(4, 7)}-${cleaned.substring(7)}`;
//       } else {
//         return `+${cleaned.substring(0, cleaned.length - 10)} ${cleaned.substring(cleaned.length - 10, cleaned.length - 7)}-${cleaned.substring(cleaned.length - 7, cleaned.length - 4)}-${cleaned.substring(cleaned.length - 4)}`;
//       }
//     }
//     return phone;
//   };

//   // Handle phone input and send OTP
//   const handleSendOTP = async (e) => {
//     e.preventDefault();
    
//     const cleanPhone = localPhone.replace(/\D/g, '');
//     const sanitizedPhone = SecurityUtils.sanitizeInput(cleanPhone);
    
//     if (!SecurityUtils.isValidPhone(sanitizedPhone)) {
//       setError('Please enter a valid phone number with country code');
//       toast.error('Please enter a valid phone number with country code');
//       return;
//     }

//     try {
//       setError('');
//       setPhoneAndAdvance(sanitizedPhone);
//       await sendPhoneOTP(sanitizedPhone);
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
//       await verifyPhoneOTP(localPhone, otpCode);
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
//       await sendPhoneOTP(localPhone);
//       setTimeLeft(300);
//       toast.success('New OTP sent to your phone');
//     } catch (error) {
//       setError(error.message);
//     }
//   };

//   // Only show this component when it's the current step
//   if (currentStep !== 3 && currentStep !== 4) {
//     return null;
//   }

//   return (
//     <div className="bg-white rounded-lg shadow-lg p-8">
//       <div className="text-center mb-6">
//         <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
//           <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
//           </svg>
//         </div>
//         <h2 className="text-2xl font-bold text-gray-900 mb-2">
//           {currentStep === 3 ? 'Phone Verification' : 'Verify Phone OTP'}
//         </h2>
//         <p className="text-gray-600">
//           {currentStep === 3 
//             ? 'Enter your phone number to receive a verification code' 
//             : 'Enter the 6-digit code sent to your phone'
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

//       {currentStep === 3 ? (
//         // Phone Input Form
//         <form onSubmit={handleSendOTP} className="space-y-4">
//           <div>
//             <label className="block text-sm font-medium text-gray-700 mb-2">
//               Phone Number *
//             </label>
//             <input
//               type="tel"
//               value={localPhone}
//               onChange={(e) => setLocalPhone(e.target.value)}
//               className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent transition duration-200"
//               placeholder="Enter your phone number with country code"
//               required
//               disabled={isLoading}
//               autoComplete="tel"
//             />
//             <p className="text-xs text-gray-500 mt-1 space-y-1">
//               <span className="block">Include country code (e.g., +1 for US, +880 for BD)</span>
//               <span className="block">This phone must be registered in SNGINE database</span>
//             </p>
//           </div>

//           <button
//             type="submit"
//             disabled={isLoading || !localPhone}
//             className="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white font-medium py-3 px-4 rounded-lg transition duration-200"
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
//                   className="w-12 h-12 text-center border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent text-lg font-medium transition duration-200"
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
//               Code sent to: <span className="font-medium">{formatPhoneDisplay(localPhone)}</span>
//             </p>
            
//             {timeLeft > 0 ? (
//               <p className="text-sm text-gray-500">
//                 Resend code in {formatTime(timeLeft)}
//               </p>
//             ) : (
//               <button
//                 onClick={handleResendOTP}
//                 disabled={isLoading}
//                 className="text-sm text-green-600 hover:text-green-700 font-medium disabled:opacity-50 disabled:cursor-not-allowed transition duration-200"
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
//               Change phone number
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

// export default PhoneVerification;



//this is 3 steps code
// import React, { useState, useRef, useEffect } from 'react';
// import { useAuth } from '../../contexts/AuthContext';

// const PhoneVerification = () => {
//   const { phone, isLoading, sendPhoneOTP, verifyPhoneOTP, dispatch } = useAuth();
//   const [localPhone, setLocalPhone] = useState(phone);
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

//   const validatePhone = (phone) => {
//     const re = /^[+]?[1-9]\d{1,14}$/;
//     return re.test(phone.replace(/\s/g, ''));
//   };

//   const formatPhone = (phone) => {
//     // Basic formatting for display
//     const cleaned = phone.replace(/\D/g, '');
//     if (cleaned.length >= 10) {
//       return cleaned.replace(/(\d{3})(\d{3})(\d{4})/, '$1-$2-$3');
//     }
//     return phone;
//   };

//   const handleSendOTP = async (e) => {
//     e.preventDefault();
    
//     const cleanPhone = localPhone.replace(/\D/g, '');
//     if (!validatePhone(cleanPhone)) {
//       setError('Please enter a valid phone number');
//       return;
//     }

//     try {
//       setError('');
//       dispatch({ type: 'SET_PHONE', payload: cleanPhone });
//       await sendPhoneOTP(cleanPhone);
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
//       await verifyPhoneOTP(localPhone, otpCode);
//       dispatch({ type: 'SET_STEP', payload: 3 });
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
//       await sendPhoneOTP(localPhone);
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
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
//           </svg>
//         </div>
//         <h2 className="text-2xl font-bold text-gray-900 mb-2">Phone Verification</h2>
//         <p className="text-gray-600">
//           {!otpSent ? 'Enter your phone number to receive a verification code' : 'Enter the 6-digit code sent to your phone'}
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
//               Phone Number
//             </label>
//             <input
//               type="tel"
//               value={localPhone}
//               onChange={(e) => setLocalPhone(e.target.value)}
//               className="form-input"
//               placeholder="Enter your phone number"
//               required
//               disabled={isLoading}
//             />
//             <p className="text-xs text-gray-500 mt-1">
//               Include country code (e.g., +1 for US, +880 for BD)
//             </p>
//           </div>

//           <button
//             type="submit"
//             disabled={isLoading || !localPhone}
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
//               Code sent to: <span className="font-medium">{formatPhone(localPhone)}</span>
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
//               Change phone number
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

// export default PhoneVerification;