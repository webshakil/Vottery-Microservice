




// //this is 5 steps code
import React from 'react';

const AccessDenied = ({ referrerInfo }) => {
  const handleRedirectToSngine = () => {
    // Redirect to SNGINE registration page
    window.location.href = 'https://sngine.com/register';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-red-50 to-red-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md mx-auto">
        <div className="bg-white rounded-lg shadow-lg p-8 text-center">
          {/* Warning Icon */}
          <div className="mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-red-100 mb-6">
            <svg 
              className="h-8 w-8 text-red-600" 
              fill="none" 
              viewBox="0 0 24 24" 
              stroke="currentColor"
            >
              <path 
                strokeLinecap="round" 
                strokeLinejoin="round" 
                strokeWidth={2} 
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" 
              />
            </svg>
          </div>

          {/* Title */}
          <h1 className="text-2xl font-bold text-gray-900 mb-4">
            Access Denied
          </h1>

          {/* Message */}
          <div className="text-gray-600 mb-6 space-y-3">
            <p className="text-lg">
              You must register and access Vottery through SNGINE platform.
            </p>
            
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <div className="flex items-start">
                <svg className="h-5 w-5 text-red-400 mt-0.5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
                <div className="text-left">
                  <p className="text-sm text-red-700 font-medium">
                    Security Restriction
                  </p>
                  <p className="text-sm text-red-600 mt-1">
                    For security reasons, Vottery can only be accessed through authorized SNGINE accounts.
                  </p>
                </div>
              </div>
            </div>

            {referrerInfo && (
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-3">
                <p className="text-xs text-gray-500">
                  Current referrer: {referrerInfo.referrer || 'Direct access'}
                </p>
                <p className="text-xs text-gray-500">
                  Source: {referrerInfo.source}
                </p>
              </div>
            )}
          </div>

          {/* Action Button */}
          <button
            onClick={handleRedirectToSngine}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
          >
            Register on SNGINE
          </button>

          {/* Additional Information */}
          <div className="mt-6 pt-6 border-t border-gray-200">
            <h3 className="text-sm font-medium text-gray-900 mb-3">
              How to access Vottery:
            </h3>
            <ol className="text-sm text-gray-600 text-left space-y-2">
              <li className="flex items-start">
                <span className="flex-shrink-0 w-5 h-5 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-xs font-medium mr-3 mt-0.5">
                  1
                </span>
                Register or login to your SNGINE account
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 w-5 h-5 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-xs font-medium mr-3 mt-0.5">
                  2
                </span>
                Navigate to Vottery section from your SNGINE dashboard
              </li>
              <li className="flex items-start">
                <span className="flex-shrink-0 w-5 h-5 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-xs font-medium mr-3 mt-0.5">
                  3
                </span>
                Complete the 5-step verification process
              </li>
            </ol>
          </div>

          {/* Security Badge */}
          <div className="mt-6 pt-4 border-t border-gray-200">
            <div className="flex items-center justify-center text-xs text-gray-500">
              <svg className="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Protected by Vottery Security System
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AccessDenied;
//this is 3 steps code
// import React from 'react';

// const AccessDenied = () => {
//   const handleRedirectToSNGine = () => {
//     window.location.href = 'https://www.sngine.com/register';
//   };

//   return (
//     <div className="min-h-screen bg-gradient-to-br from-red-50 to-red-100 flex items-center justify-center p-4">
//       <div className="max-w-md w-full bg-white rounded-lg shadow-xl p-8">
//         <div className="text-center">
//           <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100 mb-4">
//             <svg className="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
//             </svg>
//           </div>
          
//           <h1 className="text-2xl font-bold text-gray-900 mb-4">Access Restricted</h1>
          
//           <p className="text-gray-600 mb-6">
//             You must register and come from SNGine to access Vottery. This ensures secure access to our voting platform.
//           </p>
          
//           <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
//             <h3 className="text-sm font-medium text-red-800 mb-2">Security Notice:</h3>
//             <p className="text-sm text-red-700">
//               Direct access to Vottery is not allowed. Please register through SNGine first.
//             </p>
//           </div>
          
//           <button
//             onClick={handleRedirectToSNGine}
//             className="w-full bg-primary-600 hover:bg-primary-700 text-white font-medium py-3 px-4 rounded-lg transition-colors duration-200 flex items-center justify-center"
//           >
//             <svg className="w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
//             </svg>
//             Register with SNGine
//           </button>
          
//           <p className="text-xs text-gray-500 mt-4">
//             You'll be redirected to SNGine's registration page
//           </p>
//         </div>
//       </div>
//     </div>
//   );
// };

// export default AccessDenied;