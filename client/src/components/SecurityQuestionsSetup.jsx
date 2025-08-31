//to solve security question problem
import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';

const SecurityQuestionsSetup = () => {
  const { saveSecurityQuestions, isLoading, error, goBackStep, dispatch } = useAuth();

  const [questions, setQuestions] = useState([
    { question: '', answer: '' },
    { question: '', answer: '' },
    { question: '', answer: '' }
  ]);

  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Predefined security questions for user to choose from
  const predefinedQuestions = [
    "What was the name of your first pet?",
    "What is your mother's maiden name?",
    "What city were you born in?",
    "What was the name of your first school?",
    "What is your favorite movie?",
    "What was your childhood nickname?",
    "What street did you live on in third grade?",
    "What is the name of your favorite teacher?",
    "What was the make of your first car?",
    "What is your favorite food?",
    "What was the name of your first boss?",
    "What is your favorite book?",
    "What was your favorite subject in school?",
    "What is the name of the hospital where you were born?",
    "What is your favorite color?"
  ];

  const handleQuestionChange = (index, field, value) => {
    const updatedQuestions = [...questions];
    updatedQuestions[index][field] = value;
    setQuestions(updatedQuestions);
  };

  const handlePredefinedQuestionSelect = (index, selectedQuestion) => {
    const updatedQuestions = [...questions];
    updatedQuestions[index].question = selectedQuestion;
    setQuestions(updatedQuestions);
  };

  const validateCurrentQuestion = () => {
    const current = questions[currentQuestionIndex];
    if (!current.question.trim()) {
      alert('Please select a security question.');
      return false;
    }
    if (!current.answer.trim()) {
      alert('Please provide an answer to the security question.');
      return false;
    }
    if (current.answer.trim().length < 2) {
      alert('Answer must be at least 2 characters long.');
      return false;
    }
    return true;
  };

  const handleNext = () => {
    if (validateCurrentQuestion()) {
      if (currentQuestionIndex < 2) {
        setCurrentQuestionIndex(currentQuestionIndex + 1);
      }
    }
  };

  const handlePrevious = () => {
    if (currentQuestionIndex > 0) {
      setCurrentQuestionIndex(currentQuestionIndex - 1);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Validate all questions
    for (let i = 0; i < questions.length; i++) {
      if (!questions[i].question.trim() || !questions[i].answer.trim()) {
        setCurrentQuestionIndex(i);
        alert(`Please complete question ${i + 1}.`);
        return;
      }
    }

    // Check for duplicate questions
    const questionTexts = questions.map(q => q.question.trim().toLowerCase());
    const uniqueQuestions = [...new Set(questionTexts)];
    if (uniqueQuestions.length !== questions.length) {
      alert('Please ensure all security questions are different.');
      return;
    }

    setIsSubmitting(true);
    
    try {
      // Prepare questions and answers for API
      const questionsAndAnswers = questions.map(q => ({
        question: q.question.trim(),
        answer: q.answer.trim()
      }));

      await saveSecurityQuestions(questionsAndAnswers);
      
      // Explicitly move to the next step after successful save
      // Add a small delay to ensure state is updated
      setTimeout(() => {
        dispatch({ type: 'SET_STEP', payload: 5 }); // Move to biometric step
      }, 100);
      
    } catch (error) {
      console.error('Failed to save security questions:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const currentQuestion = questions[currentQuestionIndex];
  const isLastQuestion = currentQuestionIndex === 2;
  const isFirstQuestion = currentQuestionIndex === 0;

  return (
    <div className="bg-white rounded-lg shadow-lg p-8">
      <div className="text-center mb-6">
        <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 mb-4">
          <svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Security Questions Setup</h2>
        <p className="text-gray-600">
          Set up 3 security questions to secure your account. These will be used as backup authentication.
        </p>
      </div>

      {/* Progress Indicator */}
      <div className="mb-6">
        <div className="flex items-center justify-center space-x-2 mb-2">
          {[0, 1, 2].map((index) => (
            <React.Fragment key={index}>
              <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                index === currentQuestionIndex 
                  ? 'bg-blue-600 text-white' 
                  : index < currentQuestionIndex 
                    ? 'bg-green-500 text-white'
                    : 'bg-gray-300 text-gray-600'
              }`}>
                {index < currentQuestionIndex ? '✓' : index + 1}
              </div>
              {index < 2 && (
                <div className={`w-12 h-1 ${
                  index < currentQuestionIndex ? 'bg-green-500' : 'bg-gray-300'
                }`}></div>
              )}
            </React.Fragment>
          ))}
        </div>
        <p className="text-center text-sm text-gray-600">
          Question {currentQuestionIndex + 1} of 3
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Current Question */}
        <div className="border border-gray-200 rounded-lg p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">
            Security Question {currentQuestionIndex + 1}
          </h3>
          
          {/* Predefined Questions Dropdown */}
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Choose a security question:
            </label>
            <select
              value={currentQuestion.question}
              onChange={(e) => handlePredefinedQuestionSelect(currentQuestionIndex, e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="">Select a question...</option>
              {predefinedQuestions.map((q, index) => (
                <option key={index} value={q}>{q}</option>
              ))}
            </select>
          </div>

          {/* Answer Input */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Your Answer:
            </label>
            <input
              type="text"
              value={currentQuestion.answer}
              onChange={(e) => handleQuestionChange(currentQuestionIndex, 'answer', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="Enter your answer..."
              required
              autoComplete="off"
            />
            <p className="mt-1 text-xs text-gray-500">
              Remember this answer exactly as you type it. It's case-sensitive.
            </p>
          </div>
        </div>

        {/* Error Display */}
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

        {/* Navigation Buttons */}
        <div className="flex justify-between space-x-4">
          <div className="flex space-x-3">
            <button
              type="button"
              onClick={goBackStep}
              className="bg-gray-100 hover:bg-gray-200 text-gray-700 font-medium py-2 px-4 rounded-lg transition-colors duration-200"
            >
              Back to Previous Step
            </button>
            
            {!isFirstQuestion && (
              <button
                type="button"
                onClick={handlePrevious}
                className="bg-gray-100 hover:bg-gray-200 text-gray-700 font-medium py-2 px-4 rounded-lg transition-colors duration-200"
              >
                Previous Question
              </button>
            )}
          </div>

          <div>
            {!isLastQuestion ? (
              <button
                type="button"
                onClick={handleNext}
                disabled={!currentQuestion.question.trim() || !currentQuestion.answer.trim()}
                className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-medium py-2 px-6 rounded-lg transition-colors duration-200"
              >
                Next Question
              </button>
            ) : (
              <button
                type="submit"
                disabled={isSubmitting || isLoading}
                className="bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white font-medium py-2 px-6 rounded-lg transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2"
              >
                {isSubmitting || isLoading ? (
                  <div className="flex items-center">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Saving Questions...
                  </div>
                ) : (
                  'Complete Setup'
                )}
              </button>
            )}
          </div>
        </div>
      </form>

      {/* Questions Summary */}
      <div className="mt-8 pt-6 border-t border-gray-200">
        <h4 className="text-sm font-medium text-gray-900 mb-3">Questions Summary:</h4>
        <div className="space-y-2">
          {questions.map((q, index) => (
            <div key={index} className={`text-sm p-2 rounded ${
              index === currentQuestionIndex ? 'bg-blue-50 border border-blue-200' : 'bg-gray-50'
            }`}>
              <div className="flex items-center">
                <span className={`inline-flex items-center justify-center h-5 w-5 rounded-full text-xs font-medium mr-2 ${
                  q.question.trim() && q.answer.trim() 
                    ? 'bg-green-100 text-green-800' 
                    : 'bg-gray-200 text-gray-600'
                }`}>
                  {q.question.trim() && q.answer.trim() ? '✓' : index + 1}
                </span>
                <span className="text-gray-700">
                  {q.question.trim() || `Question ${index + 1} - Not set`}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Security Notice */}
      <div className="mt-6 bg-amber-50 border border-amber-200 rounded-lg p-4">
        <div className="flex">
          <svg className="h-5 w-5 text-amber-400 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
          <div>
            <h3 className="text-sm font-medium text-amber-800">Security Notice</h3>
            <div className="mt-1 text-xs text-amber-700">
              <ul className="list-disc list-inside space-y-1">
                <li>Your answers are case-sensitive and will be encrypted</li>
                <li>Choose questions only you would know the answer to</li>
                <li>Avoid questions with answers that might change over time</li>
                <li>These questions will be used if biometric authentication fails</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SecurityQuestionsSetup;
// import React, { useState } from 'react';
// import { useAuth } from '../contexts/AuthContext';
// //import { useAuth } from '../../contexts/AuthContext';

// const SecurityQuestionsSetup = () => {
//   const { saveSecurityQuestions, isLoading, error, goBackStep } = useAuth();

//   const [questions, setQuestions] = useState([
//     { question: '', answer: '' },
//     { question: '', answer: '' },
//     { question: '', answer: '' }
//   ]);

//   const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
//   const [isSubmitting, setIsSubmitting] = useState(false);

//   // Predefined security questions for user to choose from
//   const predefinedQuestions = [
//     "What was the name of your first pet?",
//     "What is your mother's maiden name?",
//     "What city were you born in?",
//     "What was the name of your first school?",
//     "What is your favorite movie?",
//     "What was your childhood nickname?",
//     "What street did you live on in third grade?",
//     "What is the name of your favorite teacher?",
//     "What was the make of your first car?",
//     "What is your favorite food?",
//     "What was the name of your first boss?",
//     "What is your favorite book?",
//     "What was your favorite subject in school?",
//     "What is the name of the hospital where you were born?",
//     "What is your favorite color?"
//   ];

//   const handleQuestionChange = (index, field, value) => {
//     const updatedQuestions = [...questions];
//     updatedQuestions[index][field] = value;
//     setQuestions(updatedQuestions);
//   };

//   const handlePredefinedQuestionSelect = (index, selectedQuestion) => {
//     const updatedQuestions = [...questions];
//     updatedQuestions[index].question = selectedQuestion;
//     setQuestions(updatedQuestions);
//   };

//   const validateCurrentQuestion = () => {
//     const current = questions[currentQuestionIndex];
//     if (!current.question.trim()) {
//       alert('Please select or enter a security question.');
//       return false;
//     }
//     if (!current.answer.trim()) {
//       alert('Please provide an answer to the security question.');
//       return false;
//     }
//     if (current.answer.trim().length < 2) {
//       alert('Answer must be at least 2 characters long.');
//       return false;
//     }
//     return true;
//   };

//   const handleNext = () => {
//     if (validateCurrentQuestion()) {
//       if (currentQuestionIndex < 2) {
//         setCurrentQuestionIndex(currentQuestionIndex + 1);
//       }
//     }
//   };

//   const handlePrevious = () => {
//     if (currentQuestionIndex > 0) {
//       setCurrentQuestionIndex(currentQuestionIndex - 1);
//     }
//   };

//   const handleSubmit = async (e) => {
//     e.preventDefault();
    
//     // Validate all questions
//     for (let i = 0; i < questions.length; i++) {
//       if (!questions[i].question.trim() || !questions[i].answer.trim()) {
//         setCurrentQuestionIndex(i);
//         alert(`Please complete question ${i + 1}.`);
//         return;
//       }
//     }

//     // Check for duplicate questions
//     const questionTexts = questions.map(q => q.question.trim().toLowerCase());
//     const uniqueQuestions = [...new Set(questionTexts)];
//     if (uniqueQuestions.length !== questions.length) {
//       alert('Please ensure all security questions are different.');
//       return;
//     }

//     setIsSubmitting(true);
    
//     try {
//       // Prepare questions and answers for API
//       const questionsAndAnswers = questions.map(q => ({
//         question: q.question.trim(),
//         answer: q.answer.trim()
//       }));

//       await saveSecurityQuestions(questionsAndAnswers);
//       // The completeAuthentication function will be called automatically after successful save
//     } catch (error) {
//       console.error('Failed to save security questions:', error);
//     } finally {
//       setIsSubmitting(false);
//     }
//   };

//   const currentQuestion = questions[currentQuestionIndex];
//   const isLastQuestion = currentQuestionIndex === 2;
//   const isFirstQuestion = currentQuestionIndex === 0;

//   return (
//     <div className="bg-white rounded-lg shadow-lg p-8">
//       <div className="text-center mb-6">
//         <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 mb-4">
//           <svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
//           </svg>
//         </div>
//         <h2 className="text-2xl font-bold text-gray-900 mb-2">Security Questions Setup</h2>
//         <p className="text-gray-600">
//           Set up 3 security questions to secure your account. These will be used as backup authentication.
//         </p>
//       </div>

//       {/* Progress Indicator */}
//       <div className="mb-6">
//         <div className="flex items-center justify-center space-x-2 mb-2">
//           {[0, 1, 2].map((index) => (
//             <React.Fragment key={index}>
//               <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
//                 index === currentQuestionIndex 
//                   ? 'bg-blue-600 text-white' 
//                   : index < currentQuestionIndex 
//                     ? 'bg-green-500 text-white'
//                     : 'bg-gray-300 text-gray-600'
//               }`}>
//                 {index < currentQuestionIndex ? '✓' : index + 1}
//               </div>
//               {index < 2 && (
//                 <div className={`w-12 h-1 ${
//                   index < currentQuestionIndex ? 'bg-green-500' : 'bg-gray-300'
//                 }`}></div>
//               )}
//             </React.Fragment>
//           ))}
//         </div>
//         <p className="text-center text-sm text-gray-600">
//           Question {currentQuestionIndex + 1} of 3
//         </p>
//       </div>

//       <form onSubmit={handleSubmit} className="space-y-6">
//         {/* Current Question */}
//         <div className="border border-gray-200 rounded-lg p-6">
//           <h3 className="text-lg font-medium text-gray-900 mb-4">
//             Security Question {currentQuestionIndex + 1}
//           </h3>
          
//           {/* Predefined Questions Dropdown */}
//           <div className="mb-4">
//             <label className="block text-sm font-medium text-gray-700 mb-2">
//               Choose from predefined questions:
//             </label>
//             <select
//               value={currentQuestion.question}
//               onChange={(e) => handlePredefinedQuestionSelect(currentQuestionIndex, e.target.value)}
//               className="w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
//             >
//               <option value="">Select a question...</option>
//               {predefinedQuestions.map((q, index) => (
//                 <option key={index} value={q}>{q}</option>
//               ))}
//             </select>
//           </div>

//           {/* Custom Question Input */}
//           <div className="mb-4">
//             <label className="block text-sm font-medium text-gray-700 mb-2">
//               Or write your own question:
//             </label>
//             <input
//               type="text"
//               value={currentQuestion.question}
//               onChange={(e) => handleQuestionChange(currentQuestionIndex, 'question', e.target.value)}
//               className="w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
//               placeholder="Enter your custom security question..."
//             />
//           </div>

//           {/* Answer Input */}
//           <div>
//             <label className="block text-sm font-medium text-gray-700 mb-2">
//               Your Answer:
//             </label>
//             <input
//               type="text"
//               value={currentQuestion.answer}
//               onChange={(e) => handleQuestionChange(currentQuestionIndex, 'answer', e.target.value)}
//               className="w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
//               placeholder="Enter your answer..."
//               required
//               autoComplete="off"
//             />
//             <p className="mt-1 text-xs text-gray-500">
//               Remember this answer exactly as you type it. It's case-sensitive.
//             </p>
//           </div>
//         </div>

//         {/* Error Display */}
//         {error && (
//           <div className="bg-red-50 border border-red-200 rounded-lg p-4">
//             <div className="flex items-center">
//               <svg className="h-5 w-5 text-red-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
//                 <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
//               </svg>
//               <p className="text-sm text-red-700">{error}</p>
//             </div>
//           </div>
//         )}

//         {/* Navigation Buttons */}
//         <div className="flex justify-between space-x-4">
//           <div className="flex space-x-3">
//             <button
//               type="button"
//               onClick={goBackStep}
//               className="bg-gray-100 hover:bg-gray-200 text-gray-700 font-medium py-2 px-4 rounded-lg transition-colors duration-200"
//             >
//               Back to Previous Step
//             </button>
            
//             {!isFirstQuestion && (
//               <button
//                 type="button"
//                 onClick={handlePrevious}
//                 className="bg-gray-100 hover:bg-gray-200 text-gray-700 font-medium py-2 px-4 rounded-lg transition-colors duration-200"
//               >
//                 Previous Question
//               </button>
//             )}
//           </div>

//           <div>
//             {!isLastQuestion ? (
//               <button
//                 type="button"
//                 onClick={handleNext}
//                 disabled={!currentQuestion.question.trim() || !currentQuestion.answer.trim()}
//                 className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-medium py-2 px-6 rounded-lg transition-colors duration-200"
//               >
//                 Next Question
//               </button>
//             ) : (
//               <button
//                 type="submit"
//                 disabled={isSubmitting || isLoading}
//                 className="bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white font-medium py-2 px-6 rounded-lg transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2"
//               >
//                 {isSubmitting || isLoading ? (
//                   <div className="flex items-center">
//                     <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
//                     Saving Questions...
//                   </div>
//                 ) : (
//                   'Complete Setup'
//                 )}
//               </button>
//             )}
//           </div>
//         </div>
//       </form>

//       {/* Questions Summary */}
//       <div className="mt-8 pt-6 border-t border-gray-200">
//         <h4 className="text-sm font-medium text-gray-900 mb-3">Questions Summary:</h4>
//         <div className="space-y-2">
//           {questions.map((q, index) => (
//             <div key={index} className={`text-sm p-2 rounded ${
//               index === currentQuestionIndex ? 'bg-blue-50 border border-blue-200' : 'bg-gray-50'
//             }`}>
//               <div className="flex items-center">
//                 <span className={`inline-flex items-center justify-center h-5 w-5 rounded-full text-xs font-medium mr-2 ${
//                   q.question.trim() && q.answer.trim() 
//                     ? 'bg-green-100 text-green-800' 
//                     : 'bg-gray-200 text-gray-600'
//                 }`}>
//                   {q.question.trim() && q.answer.trim() ? '✓' : index + 1}
//                 </span>
//                 <span className="text-gray-700">
//                   {q.question.trim() || `Question ${index + 1} - Not set`}
//                 </span>
//               </div>
//             </div>
//           ))}
//         </div>
//       </div>

//       {/* Security Notice */}
//       <div className="mt-6 bg-amber-50 border border-amber-200 rounded-lg p-4">
//         <div className="flex">
//           <svg className="h-5 w-5 text-amber-400 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z" />
//           </svg>
//           <div>
//             <h3 className="text-sm font-medium text-amber-800">Security Notice</h3>
//             <div className="mt-1 text-xs text-amber-700">
//               <ul className="list-disc list-inside space-y-1">
//                 <li>Your answers are case-sensitive and will be encrypted</li>
//                 <li>Choose questions only you would know the answer to</li>
//                 <li>Avoid questions with answers that might change over time</li>
//                 <li>These questions will be used if biometric authentication fails</li>
//               </ul>
//             </div>
//           </div>
//         </div>
//       </div>
//     </div>
//   );
// };

// export default SecurityQuestionsSetup;