//to mimic that i am from sngine with 5 steps
// import React from 'react';
// import { Routes, Route, Navigate } from 'react-router';
// import { useAuth } from './contexts/AuthContext';
// import { useSecurity } from './contexts/SecurityContext';
// import AccessDenied from './components/AccessDenied';
// import AuthenticationFlow from './components/AuthenticationFlow';
// import Dashboard from './components/Dashboard';
// import LoadingScreen from './components/LoadingScreen';

// function App() {
//   const { isAuthenticated, isLoading } = useAuth();
//   const { isValidReferrer, referrerCheckComplete } = useSecurity();

//   // DEBUG: Log the states to help troubleshoot
//   console.log('🔍 App States:', {
//     isAuthenticated,
//     isLoading,
//     isValidReferrer,
//     referrerCheckComplete
//   });

//   // Show loading while auth or referrer check is in progress
//   if (isLoading || !referrerCheckComplete) {
//     return <LoadingScreen />;
//   }

//   // Show access denied if referrer check fails
//   if (!isValidReferrer) {
//     return <AccessDenied />;
//   }

//   return (
//     <div className="min-h-screen bg-gray-50">
//       <Routes>
//         <Route 
//           path="/" 
//           element={
//             isAuthenticated ? 
//             <Navigate to="/dashboard" replace /> : 
//             <AuthenticationFlow />
//           } 
//         />
//         <Route 
//           path="/dashboard" 
//           element={
//             isAuthenticated ? 
//             <Dashboard /> : 
//             <Navigate to="/" replace />
//           } 
//         />
//         <Route path="*" element={<Navigate to="/" replace />} />
//       </Routes>
//     </div>
//   );
// }

// export default App;


//latest orginal code without mimic

import React, { useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router';
import { useAuth } from './contexts/AuthContext';
import { useSecurity } from './contexts/SecurityContext';
import AccessDenied from './components/AccessDenied';
import AuthenticationFlow from './components/AuthenticationFlow';
import Dashboard from './components/Dashboard';
import LoadingScreen from './components/LoadingScreen';
//import AdminManagement from './components/AdminManagement';

function App() {
  const { isAuthenticated, isLoading } = useAuth();
  const { isValidReferrer, checkReferrer } = useSecurity();

  useEffect(() => {
    checkReferrer();
  }, [checkReferrer]);

  if (isLoading) {
    return <LoadingScreen />;
  }

  if (!isValidReferrer) {
    return <AccessDenied />;
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <Routes>
        <Route 
          path="/" 
          element={
            isAuthenticated ? 
            <Navigate to="/dashboard" replace /> : 
            <AuthenticationFlow />
          } 
        />
        <Route 
          path="/dashboard" 
          element={
            isAuthenticated ? 
            <Dashboard /> : 
            <Navigate to="/" replace />
          } 
        />
        {/* <Route path="/admin/users" element={<AdminManagement />} /> */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  );
}

export default App;



