//latest 7 steps with mandatory fallback security question
import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';

const FallbackSecurity = () => {
  const { 
    fallbackStep, 
    fallbackQuestions, 
    setupFallbackSecurity, 
    verifyFallbackSecurity,
    getFallbackQuestions,
    isLoading,
    error,
    user
  } = useAuth();

  const [answers, setAnswers] = useState([]);
  const [currentQuestion, setCurrentQuestion] = useState(null);
  const [currentAnswer, setCurrentAnswer] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (fallbackStep === 'setup' && user?.id) {
      // Automatically setup fallback security
      setupFallbackSecurity().catch(console.error);
    } else if (fallbackStep === 'answer' && fallbackQuestions.length === 0 && user?.id) {
      // Get existing questions if we need to answer them
      getFallbackQuestions().catch(console.error);
    }
  }, [fallbackStep, setupFallbackSecurity, getFallbackQuestions, fallbackQuestions.length, user?.id]);

  useEffect(() => {
    if (fallbackQuestions.length > 0 && fallbackStep === 'answer') {
      setCurrentQuestion(fallbackQuestions[0]);
      setAnswers([{ questionId: 1, answer: '' }]);
    }
  }, [fallbackQuestions, fallbackStep]);

  const handleAnswerSubmit = async (e) => {
    e.preventDefault();
    
    if (!currentAnswer.trim()) {
      alert('Please provide an answer to the security question.');
      return;
    }

    setIsSubmitting(true);
    const updatedAnswers = [{ questionId: 1, answer: currentAnswer.trim() }];
    
    try {
      await verifyFallbackSecurity(updatedAnswers);
    } catch (error) {
      console.error('Failed to verify fallback security:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleAnswerChange = (e) => {
    setCurrentAnswer(e.target.value);
  };

  const handleRetrySetup = () => {
    if (user?.id) {
      setupFallbackSecurity().catch(console.error);
    }
  };

  const handleRetryQuestions = () => {
    if (user?.id) {
      getFallbackQuestions().catch(console.error);
    }
  };

  // Setup phase
  if (fallbackStep === 'setup') {
    return (
      <div className="bg-white rounded-lg shadow-lg p-8">
        <div className="text-center mb-6">
          <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-amber-100 mb-4">
            <svg className="h-6 w-6 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
          </div>
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Setting Up Security Questions</h2>
          <p className="text-gray-600">
            We're setting up security questions as a backup authentication method. These questions will help secure your account if biometric authentication ever fails or becomes unavailable.
          </p>
        </div>

        {isLoading ? (
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Setting up your security questions...</p>
          </div>
        ) : error ? (
          <div className="text-center">
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
              <div className="flex items-center justify-center mb-2">
                <svg className="h-5 w-5 text-red-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
                <h3 className="text-sm font-medium text-red-800">Setup Failed</h3>
              </div>
              <p className="text-sm text-red-700 mb-3">{error}</p>
              <button
                onClick={handleRetrySetup}
                className="bg-red-100 hover:bg-red-200 text-red-800 font-medium py-2 px-4 rounded-md transition-colors duration-200"
              >
                Retry Setup
              </button>
            </div>
          </div>
        ) : (
          <div className="text-center">
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4">
              <p className="text-sm text-blue-800">
                Please wait while we set up your security questions. These backup questions ensure your account remains accessible even if biometric authentication is unavailable.
              </p>
            </div>
          </div>
        )}
      </div>
    );
  }

  // Answer phase
  if (fallbackStep === 'answer' && currentQuestion) {
    return (
      <div className="bg-white rounded-lg shadow-lg p-8">
        <div className="text-center mb-6">
          <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 mb-4">
            <svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Security Verification</h2>
          <p className="text-gray-600">
            Please answer the security question to verify your identity.
          </p>
        </div>

        <form onSubmit={handleAnswerSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-3">
              Security Question
            </label>
            <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 mb-4">
              <p className="text-gray-800 font-medium">{currentQuestion}</p>
            </div>
            
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Your Answer
            </label>
            <input
              type="text"
              value={currentAnswer}
              onChange={handleAnswerChange}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="Enter your answer..."
              required
              disabled={isSubmitting}
              autoComplete="off"
            />
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <div className="flex items-center">
                <svg className="h-5 w-5 text-red-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
                <p className="text-sm text-red-700">{error}</p>
              </div>
            </div>
          )}

          <div className="flex justify-end space-x-3">
            <button
              type="submit"
              disabled={isSubmitting || !currentAnswer.trim()}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-medium py-2 px-6 rounded-lg transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
            >
              {isSubmitting ? (
                <div className="flex items-center">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Verifying...
                </div>
              ) : (
                'Verify Answer'
              )}
            </button>
          </div>
        </form>

        <div className="mt-6 pt-6 border-t border-gray-200">
          <p className="text-xs text-gray-500 text-center">
            Your answers are encrypted and securely stored. They are used only for account verification purposes.
          </p>
        </div>
      </div>
    );
  }

  // Loading questions
  if (fallbackStep === 'answer' && isLoading) {
    return (
      <div className="bg-white rounded-lg shadow-lg p-8">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <h2 className="text-xl font-bold text-gray-900 mb-2">Loading Security Questions</h2>
          <p className="text-gray-600">Please wait while we fetch your security questions...</p>
        </div>
      </div>
    );
  }

  // Error state for questions
  if (fallbackStep === 'answer' && error && !currentQuestion) {
    return (
      <div className="bg-white rounded-lg shadow-lg p-8">
        <div className="text-center">
          <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100 mb-4">
            <svg className="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
          </div>
          <h2 className="text-xl font-bold text-gray-900 mb-2">Error Loading Questions</h2>
          <p className="text-gray-600 mb-4">{error}</p>
          <button
            onClick={handleRetryQuestions}
            className="bg-red-100 hover:bg-red-200 text-red-800 font-medium py-2 px-4 rounded-md transition-colors duration-200"
          >
            Retry Loading Questions
          </button>
        </div>
      </div>
    );
  }

  // Default state
  return (
    <div className="bg-white rounded-lg shadow-lg p-8">
      <div className="text-center">
        <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-gray-100 mb-4">
          <svg className="h-6 w-6 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
        </div>
        <h2 className="text-xl font-bold text-gray-900 mb-2">Fallback Security</h2>
        <p className="text-gray-600">Initializing security setup...</p>
      </div>
    </div>
  );
};

export default FallbackSecurity;
// import React, { useState, useEffect } from 'react';
// import { useAuth } from '../../contexts/AuthContext';

// const FallbackSecurity = () => {
//   const { 
//     fallbackStep, 
//     fallbackQuestions, 
//     setupFallbackSecurity, 
//     verifyFallbackSecurity,
//     getFallbackQuestions,
//     isLoading,
//     error,
//     user
//   } = useAuth();

//   const [answers, setAnswers] = useState([]);
//   const [currentQuestion, setCurrentQuestion] = useState(null);
//   const [currentAnswer, setCurrentAnswer] = useState('');
//   const [isSubmitting, setIsSubmitting] = useState(false);

//   useEffect(() => {
//     if (fallbackStep === 'setup' && user?.id) {
//       // Automatically setup fallback security
//       setupFallbackSecurity().catch(console.error);
//     } else if (fallbackStep === 'answer' && fallbackQuestions.length === 0 && user?.id) {
//       // Get existing questions if we need to answer them
//       getFallbackQuestions().catch(console.error);
//     }
//   }, [fallbackStep, setupFallbackSecurity, getFallbackQuestions, fallbackQuestions.length, user?.id]);

//   useEffect(() => {
//     if (fallbackQuestions.length > 0 && fallbackStep === 'answer') {
//       setCurrentQuestion(fallbackQuestions[0]);
//       setAnswers([{ questionId: 1, answer: '' }]);
//     }
//   }, [fallbackQuestions, fallbackStep]);

//   const handleAnswerSubmit = async (e) => {
//     e.preventDefault();
    
//     if (!currentAnswer.trim()) {
//       alert('Please provide an answer to the security question.');
//       return;
//     }

//     setIsSubmitting(true);
//     const updatedAnswers = [{ questionId: 1, answer: currentAnswer.trim() }];
    
//     try {
//       await verifyFallbackSecurity(updatedAnswers);
//     } catch (error) {
//       console.error('Failed to verify fallback security:', error);
//     } finally {
//       setIsSubmitting(false);
//     }
//   };

//   const handleAnswerChange = (e) => {
//     setCurrentAnswer(e.target.value);
//   };

//   const handleRetrySetup = () => {
//     if (user?.id) {
//       setupFallbackSecurity().catch(console.error);
//     }
//   };

//   const handleRetryQuestions = () => {
//     if (user?.id) {
//       getFallbackQuestions().catch(console.error);
//     }
//   };

//   // Setup phase
//   if (fallbackStep === 'setup') {
//     return (
//       <div className="bg-white rounded-lg shadow-lg p-8">
//         <div className="text-center mb-6">
//           <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-amber-100 mb-4">
//             <svg className="h-6 w-6 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z" />
//             </svg>
//           </div>
//           <h2 className="text-2xl font-bold text-gray-900 mb-2">Setting Up Fallback Security</h2>
//           <p className="text-gray-600">
//             Biometric authentication is not available on your device. We're setting up fallback security questions to ensure your account remains secure.
//           </p>
//         </div>

//         {isLoading ? (
//           <div className="text-center">
//             <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
//             <p className="text-gray-600">Setting up your security questions...</p>
//           </div>
//         ) : error ? (
//           <div className="text-center">
//             <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
//               <div className="flex items-center justify-center mb-2">
//                 <svg className="h-5 w-5 text-red-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
//                   <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
//                 </svg>
//                 <h3 className="text-sm font-medium text-red-800">Setup Failed</h3>
//               </div>
//               <p className="text-sm text-red-700 mb-3">{error}</p>
//               <button
//                 onClick={handleRetrySetup}
//                 className="bg-red-100 hover:bg-red-200 text-red-800 font-medium py-2 px-4 rounded-md transition-colors duration-200"
//               >
//                 Retry Setup
//               </button>
//             </div>
//           </div>
//         ) : (
//           <div className="text-center">
//             <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4">
//               <p className="text-sm text-blue-800">
//                 Please wait while we generate your security questions. This process ensures your account remains protected even without biometric authentication.
//               </p>
//             </div>
//           </div>
//         )}
//       </div>
//     );
//   }

//   // Answer phase
//   if (fallbackStep === 'answer' && currentQuestion) {
//     return (
//       <div className="bg-white rounded-lg shadow-lg p-8">
//         <div className="text-center mb-6">
//           <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 mb-4">
//             <svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
//             </svg>
//           </div>
//           <h2 className="text-2xl font-bold text-gray-900 mb-2">Security Verification</h2>
//           <p className="text-gray-600">
//             Please answer the security question to verify your identity.
//           </p>
//         </div>

//         <form onSubmit={handleAnswerSubmit} className="space-y-6">
//           <div>
//             <label className="block text-sm font-medium text-gray-700 mb-3">
//               Security Question
//             </label>
//             <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 mb-4">
//               <p className="text-gray-800 font-medium">{currentQuestion}</p>
//             </div>
            
//             <label className="block text-sm font-medium text-gray-700 mb-2">
//               Your Answer
//             </label>
//             <input
//               type="text"
//               value={currentAnswer}
//               onChange={handleAnswerChange}
//               className="w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
//               placeholder="Enter your answer..."
//               required
//               disabled={isSubmitting}
//               autoComplete="off"
//             />
//           </div>

//           {error && (
//             <div className="bg-red-50 border border-red-200 rounded-lg p-4">
//               <div className="flex items-center">
//                 <svg className="h-5 w-5 text-red-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
//                   <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
//                 </svg>
//                 <p className="text-sm text-red-700">{error}</p>
//               </div>
//             </div>
//           )}

//           <div className="flex justify-end space-x-3">
//             <button
//               type="submit"
//               disabled={isSubmitting || !currentAnswer.trim()}
//               className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-medium py-2 px-6 rounded-lg transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
//             >
//               {isSubmitting ? (
//                 <div className="flex items-center">
//                   <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
//                   Verifying...
//                 </div>
//               ) : (
//                 'Verify Answer'
//               )}
//             </button>
//           </div>
//         </form>

//         <div className="mt-6 pt-6 border-t border-gray-200">
//           <p className="text-xs text-gray-500 text-center">
//             Your answers are encrypted and securely stored. They are used only for account verification purposes.
//           </p>
//         </div>
//       </div>
//     );
//   }

//   // Loading questions
//   if (fallbackStep === 'answer' && isLoading) {
//     return (
//       <div className="bg-white rounded-lg shadow-lg p-8">
//         <div className="text-center">
//           <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
//           <h2 className="text-xl font-bold text-gray-900 mb-2">Loading Security Questions</h2>
//           <p className="text-gray-600">Please wait while we fetch your security questions...</p>
//         </div>
//       </div>
//     );
//   }

//   // Error state for questions
//   if (fallbackStep === 'answer' && error && !currentQuestion) {
//     return (
//       <div className="bg-white rounded-lg shadow-lg p-8">
//         <div className="text-center">
//           <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100 mb-4">
//             <svg className="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z" />
//             </svg>
//           </div>
//           <h2 className="text-xl font-bold text-gray-900 mb-2">Error Loading Questions</h2>
//           <p className="text-gray-600 mb-4">{error}</p>
//           <button
//             onClick={handleRetryQuestions}
//             className="bg-red-100 hover:bg-red-200 text-red-800 font-medium py-2 px-4 rounded-md transition-colors duration-200"
//           >
//             Retry Loading Questions
//           </button>
//         </div>
//       </div>
//     );
//   }

//   // Default state
//   return (
//     <div className="bg-white rounded-lg shadow-lg p-8">
//       <div className="text-center">
//         <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-gray-100 mb-4">
//           <svg className="h-6 w-6 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z" />
//           </svg>
//         </div>
//         <h2 className="text-xl font-bold text-gray-900 mb-2">Fallback Security</h2>
//         <p className="text-gray-600">Initializing security setup...</p>
//       </div>
//     </div>
//   );
// };

// export default FallbackSecurity;