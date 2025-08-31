//this is 5 steps code
// import React from 'react';

// const LoadingScreen = ({ message = "Loading..." }) => {
//   return (
//     <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
//       <div className="max-w-md w-full space-y-8 text-center">
//         {/* Vottery Logo */}
//         <div>
//           <h1 className="text-4xl font-bold text-gray-900 mb-2">
//             Vottery
//           </h1>
//           <p className="text-gray-600">
//             Secure Voting Platform
//           </p>
//         </div>

//         {/* Loading Animation */}
//         <div className="flex flex-col items-center space-y-4">
//           {/* Spinner */}
//           <div className="relative">
//             <div className="w-16 h-16 border-4 border-blue-200 border-solid rounded-full animate-spin">
//               <div className="absolute top-0 left-0 w-16 h-16 border-4 border-blue-600 border-solid rounded-full border-t-transparent animate-spin"></div>
//             </div>
            
//             {/* Inner pulse */}
//             <div className="absolute inset-0 flex items-center justify-center">
//               <div className="w-8 h-8 bg-blue-600 rounded-full animate-pulse"></div>
//             </div>
//           </div>

//           {/* Loading Message */}
//           <div className="space-y-2">
//             <p className="text-lg font-medium text-gray-900">
//               {message}
//             </p>
//             <div className="flex items-center justify-center space-x-1">
//               <div className="w-2 h-2 bg-blue-600 rounded-full animate-bounce"></div>
//               <div className="w-2 h-2 bg-blue-600 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
//               <div className="w-2 h-2 bg-blue-600 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
//             </div>
//           </div>
//         </div>

//         {/* Security Features */}
//         <div className="bg-white rounded-lg shadow-lg p-6">
//           <h3 className="text-sm font-medium text-gray-900 mb-3">
//             Initializing Security Features
//           </h3>
//           <div className="space-y-2">
//             <div className="flex items-center text-xs text-gray-600">
//               <div className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse"></div>
//               End-to-end encryption
//             </div>
//             <div className="flex items-center text-xs text-gray-600">
//               <div className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse" style={{ animationDelay: '0.5s' }}></div>
//               Device fingerprinting
//             </div>
//             <div className="flex items-center text-xs text-gray-600">
//               <div className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse" style={{ animationDelay: '1s' }}></div>
//               Biometric validation
//             </div>
//             <div className="flex items-center text-xs text-gray-600">
//               <div className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse" style={{ animationDelay: '1.5s' }}></div>
//               Referrer verification
//             </div>
//           </div>
//         </div>

//         {/* Progress Bar */}
//         <div className="w-full bg-gray-200 rounded-full h-2">
//           <div 
//             className="bg-blue-600 h-2 rounded-full animate-pulse"
//             style={{
//               width: '70%',
//               animation: 'loading-progress 3s ease-in-out infinite'
//             }}
//           ></div>
//         </div>

//         {/* Additional Info */}
//         <p className="text-xs text-gray-500">
//           Please wait while we verify your security credentials...
//         </p>
//       </div>

//       <style jsx>{`
//         @keyframes loading-progress {
//           0% { width: 10%; }
//           50% { width: 70%; }
//           100% { width: 90%; }
//         }
//       `}</style>
//     </div>
//   );
// };

// export default LoadingScreen;





//this is 3 steps code
import React from 'react';

const LoadingScreen = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-primary-100 flex items-center justify-center p-4">
      <div className="text-center">
        <div className="mb-4">
          <div className="animate-spin-slow inline-block w-12 h-12 border-4 border-primary-200 border-t-primary-600 rounded-full"></div>
        </div>
        
        <h2 className="text-xl font-semibold text-primary-900 mb-2">
          Initializing Vottery
        </h2>
        
        <p className="text-primary-700">
          Verifying secure access...
        </p>
      </div>
    </div>
  );
};

export default LoadingScreen;