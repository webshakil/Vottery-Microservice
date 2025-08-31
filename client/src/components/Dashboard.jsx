
//final touch with role dropdown
// import React, { useState, useEffect } from 'react';
// import { useAuth } from '../contexts/AuthContext';
// import { useSecurity } from '../contexts/SecurityContext';
// import toast from 'react-hot-toast';

// const Dashboard = () => {
//   const { userData, logout, isAdmin, refreshAccessToken, getUserRole, hasPermission, rolePermissions } = useAuth();
//   const securityContext = useSecurity();
//   const [currentTime, setCurrentTime] = useState(new Date());
//   const [activeTab, setActiveTab] = useState('overview');
//   const [deviceInfo, setDeviceInfo] = useState(null);
//   const [securityMetrics, setSecurityMetrics] = useState({});

//   // New state variables for role management
//   const [users, setUsers] = useState([]);
//   const [loadingUsers, setLoadingUsers] = useState(false);
//   const [searchTerm, setSearchTerm] = useState('');

//   // Get current user role and permissions
//   const currentUserRole = getUserRole();
//   const isUserAdmin = isAdmin();
//   const canViewAnalytics = hasPermission('view_analytics');
//   const canManageUsers = hasPermission('manage_users');
//   const canManageElections = hasPermission('manage_elections');
//   const canManageContent = hasPermission('manage_content');
//   const canViewAudit = hasPermission('view_audit');

//   // API call function for user management
//   const api3003 = async (endpoint, options = {}) => {
//     const baseURL = 'http://localhost:3003';
//     const url = `${baseURL}${endpoint}`;
    
//     const defaultOptions = {
//       headers: {
//         'Content-Type': 'application/json',
//         ...(options.headers || {})
//       }
//     };

//     try {
//       const response = await fetch(url, { ...defaultOptions, ...options });
      
//       if (!response.ok) {
//         throw new Error(`HTTP error! status: ${response.status}`);
//       }
      
//       return await response.json();
//     } catch (error) {
//       console.error('API call failed:', error);
//       throw error;
//     }
//   };

//   // Fetch users from the API
//   const fetchUsers = async () => {
//     setLoadingUsers(true);
//     try {
//       const data = await api3003('/api/users/list');
//       setUsers(data.users || []);
//     } catch (error) {
//       console.error('Failed to fetch users:', error);
//       toast.error('Failed to fetch users');
//     } finally {
//       setLoadingUsers(false);
//     }
//   };

//   // Update user role via API
//   const updateUserRoleAPI = async (userId, updates) => {
//     try {
//       const response = await api3003(`/api/users/role/${userId}`, {
//         method: 'PATCH',
//         body: JSON.stringify(updates)
//       });
      
//       toast.success('User role updated successfully');
//       fetchUsers(); // Refresh the user list
//       return response;
//     } catch (error) {
//       console.error('Failed to update user role:', error);
//       toast.error('Failed to update user role');
//       throw error;
//     }
//   };

//   // Handle role change from dropdowns
//   const handleRoleChange = async (userId, field, value) => {
//     const updates = { [field]: value };
//     await updateUserRoleAPI(userId, updates);
//   };

//   // Update current time every second
//   useEffect(() => {
//     const timer = setInterval(() => {
//       setCurrentTime(new Date());
//     }, 1000);
//     return () => clearInterval(timer);
//   }, []);

//   // Collect device and security information
//   useEffect(() => {
//     const collectDeviceInfo = () => {
//       const device = {
//         userAgent: navigator.userAgent,
//         platform: navigator.platform,
//         language: navigator.language,
//         timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
//         screen: {
//           width: screen.width,
//           height: screen.height,
//           colorDepth: screen.colorDepth,
//           pixelRatio: window.devicePixelRatio || 1
//         },
//         connection: navigator.connection ? {
//           type: navigator.connection.type,
//           effectiveType: navigator.connection.effectiveType,
//           downlink: navigator.connection.downlink,
//           rtt: navigator.connection.rtt
//         } : null,
//         memory: navigator.deviceMemory || 'Unknown',
//         hardwareConcurrency: navigator.hardwareConcurrency || 'Unknown',
//         cookieEnabled: navigator.cookieEnabled,
//         javaEnabled: navigator.javaEnabled ? navigator.javaEnabled() : false,
//         onLine: navigator.onLine,
//         webdriver: navigator.webdriver || false
//       };
//       setDeviceInfo(device);
//     };

//     const collectSecurityMetrics = () => {
//       const metrics = {
//         httpsEnabled: window.location.protocol === 'https:',
//         referrerValidated: securityContext?.securityMetrics?.referrerValidated || false,
//         deviceFingerprinted: true, // Set to true as we collect fingerprint
//         encryptionEnabled: securityContext?.securityMetrics?.encryptionEnabled || true,
//         webAuthnSupported: !!window.PublicKeyCredential,
//         localStorageEnabled: (() => {
//           try {
//             const test = 'test';
//             localStorage.setItem(test, test);
//             localStorage.removeItem(test);
//             return true;
//           } catch (e) {
//             return false;
//           }
//         })(),
//         sessionStorageEnabled: (() => {
//           try {
//             const test = 'test';
//             sessionStorage.setItem(test, test);
//             sessionStorage.removeItem(test);
//             return true;
//           } catch (e) {
//             return false;
//           }
//         })(),
//         thirdPartyCookiesEnabled: navigator.cookieEnabled && document.cookie.length > 0
//       };
//       setSecurityMetrics(metrics);
//     };

//     collectDeviceInfo();
//     collectSecurityMetrics();
//   }, [securityContext]);

//   // Fetch users when component mounts and user has manage_users permission
//   useEffect(() => {
//     if (canManageUsers) {
//       fetchUsers();
//     }
//   }, [canManageUsers]);

//   const handleLogout = () => {
//     logout();
//   };

//   // Filter users based on search term
//   const filteredUsers = users.filter(user => 
//     user.sngine_email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
//     user.sngine_firstname?.toLowerCase().includes(searchTerm.toLowerCase()) ||
//     user.sngine_lastname?.toLowerCase().includes(searchTerm.toLowerCase())
//   );

//   // Security features demo - showing implemented features
//   const securityFeatures = {
//     'End-to-End Encryption': {
//       status: 'Active',
//       description: 'RSA/ElGamal encryption implemented',
//       type: 'success'
//     },
//     'Digital Signatures': {
//       status: 'Active',
//       description: 'SHA-256 signature verification',
//       type: 'success'
//     },
//     'Key Management': {
//       status: 'Active',
//       description: 'Threshold decryption system',
//       type: 'success'
//     },
//     'HTTPS Enforcement': {
//       status: securityMetrics.httpsEnabled ? 'Active' : 'Warning',
//       description: 'SSL certificate validation',
//       type: securityMetrics.httpsEnabled ? 'success' : 'warning'
//     },
//     'Input Validation': {
//       status: 'Active',
//       description: 'OWASP security compliance',
//       type: 'success'
//     },
//     'Rate Limiting': {
//       status: 'Active',
//       description: 'DDoS protection enabled',
//       type: 'success'
//     }
//   };

//   // Role options for dropdowns
//   const adminRoleOptions = [
//     { value: '', label: 'None' },
//     { value: 'analyst', label: 'Analyst' },
//     { value: 'editor', label: 'Editor' },
//     { value: 'advertiser', label: 'Advertiser' },
//     { value: 'moderator', label: 'Moderator' },
//     { value: 'auditor', label: 'Auditor' },
//     { value: 'admin', label: 'Admin' },
//     { value: 'manager', label: 'Manager' }
//   ];

//   const userTypeOptions = [
//     { value: 'voter', label: 'Voter' },
//     { value: 'individual_creator', label: 'Individual Creator' },
//     { value: 'organization_creator', label: 'Organization Creator' }
//   ];

//   const subscriptionOptions = [
//     { value: 'free', label: 'Free' },
//     { value: 'subscribed', label: 'Subscribed' }
//   ];

//   // Role-based dashboard content
//   const AnalystDashboard = () => (
//     <div className="space-y-6">
//       <div className="bg-gradient-to-r from-purple-500 to-indigo-600 rounded-lg p-6 text-white">
//         <h2 className="text-2xl font-bold mb-2">Analytics Dashboard</h2>
//         <p className="text-purple-100">Data insights and reporting tools</p>
//       </div>

//       <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
//         <div className="lg:col-span-2 space-y-6">
//           {/* Analytics Overview */}
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Analytics Overview</h3>
//             <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
//               <div className="text-center p-4 bg-blue-50 rounded-lg">
//                 <div className="text-2xl font-bold text-blue-600">1,234</div>
//                 <div className="text-sm text-gray-600">Total Users</div>
//               </div>
//               <div className="text-center p-4 bg-green-50 rounded-lg">
//                 <div className="text-2xl font-bold text-green-600">89</div>
//                 <div className="text-sm text-gray-600">Active Elections</div>
//               </div>
//               <div className="text-center p-4 bg-purple-50 rounded-lg">
//                 <div className="text-2xl font-bold text-purple-600">5,678</div>
//                 <div className="text-sm text-gray-600">Total Votes</div>
//               </div>
//               <div className="text-center p-4 bg-orange-50 rounded-lg">
//                 <div className="text-2xl font-bold text-orange-600">456</div>
//                 <div className="text-sm text-gray-600">Reports Generated</div>
//               </div>
//             </div>
//           </div>

//           {/* Data Export Tools */}
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Data Export & Reports</h3>
//             <div className="space-y-4">
//               <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
//                 <div>
//                   <h4 className="font-medium text-gray-900">User Analytics Export</h4>
//                   <p className="text-sm text-gray-600">Download user engagement reports</p>
//                 </div>
//                 <button className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg text-sm">
//                   Export CSV
//                 </button>
//               </div>
//               <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
//                 <div>
//                   <h4 className="font-medium text-gray-900">Election Performance</h4>
//                   <p className="text-sm text-gray-600">Voting patterns and participation</p>
//                 </div>
//                 <button className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg text-sm">
//                   Generate Report
//                 </button>
//               </div>
//               <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
//                 <div>
//                   <h4 className="font-medium text-gray-900">Security Metrics</h4>
//                   <p className="text-sm text-gray-600">Authentication and security logs</p>
//                 </div>
//                 <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm">
//                   View Metrics
//                 </button>
//               </div>
//             </div>
//           </div>
//         </div>

//         {/* Analytics Tools */}
//         <div className="space-y-6">
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Analytics Tools</h3>
//             <div className="space-y-3">
//               <button className="w-full text-left p-3 bg-purple-50 hover:bg-purple-100 rounded-lg text-purple-700">
//                 User Engagement
//               </button>
//               <button className="w-full text-left p-3 bg-blue-50 hover:bg-blue-100 rounded-lg text-blue-700">
//                 Voting Trends
//               </button>
//               <button className="w-full text-left p-3 bg-green-50 hover:bg-green-100 rounded-lg text-green-700">
//                 Performance Metrics
//               </button>
//               <button className="w-full text-left p-3 bg-orange-50 hover:bg-orange-100 rounded-lg text-orange-700">
//                 Custom Reports
//               </button>
//             </div>
//           </div>
//         </div>
//       </div>
//     </div>
//   );

//   // Admin Dashboard Content with Enhanced User Management
//   const AdminDashboard = () => (
//     <div className="space-y-6">
//       <div className="bg-gradient-to-r from-red-500 to-red-600 rounded-lg p-6 text-white">
//         <h2 className="text-2xl font-bold mb-2">Admin Dashboard</h2>
//         <p className="text-red-100">Administrative controls and system management</p>
//       </div>

//       <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
//         <div className="lg:col-span-2 space-y-6">
//           {/* System Statistics */}
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">System Statistics</h3>
//             <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
//               <div className="text-center p-4 bg-blue-50 rounded-lg">
//                 <div className="text-2xl font-bold text-blue-600">{users.length || '1,234'}</div>
//                 <div className="text-sm text-gray-600">Total Users</div>
//               </div>
//               <div className="text-center p-4 bg-green-50 rounded-lg">
//                 <div className="text-2xl font-bold text-green-600">89</div>
//                 <div className="text-sm text-gray-600">Active Elections</div>
//               </div>
//               <div className="text-center p-4 bg-purple-50 rounded-lg">
//                 <div className="text-2xl font-bold text-purple-600">5,678</div>
//                 <div className="text-sm text-gray-600">Total Votes</div>
//               </div>
//               <div className="text-center p-4 bg-orange-50 rounded-lg">
//                 <div className="text-2xl font-bold text-orange-600">456</div>
//                 <div className="text-sm text-gray-600">Subscriptions</div>
//               </div>
//             </div>
//           </div>

//           {/* Enhanced User Management - Only for users with manage_users permission */}
//           {canManageUsers && (
//             <div className="bg-white rounded-lg shadow p-6">
//               <div className="flex items-center justify-between mb-6">
//                 <h3 className="text-lg font-semibold text-gray-900">User Management</h3>
//                 <button
//                   onClick={fetchUsers}
//                   disabled={loadingUsers}
//                   className="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white px-4 py-2 rounded-lg text-sm flex items-center"
//                 >
//                   {loadingUsers ? (
//                     <>
//                       <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
//                         <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
//                         <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
//                       </svg>
//                       Loading...
//                     </>
//                   ) : (
//                     <>
//                       <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                         <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
//                       </svg>
//                       Refresh
//                     </>
//                   )}
//                 </button>
//               </div>

//               {/* Search Bar */}
//               <div className="mb-4">
//                 <div className="relative">
//                   <input
//                     type="text"
//                     placeholder="Search users by email or name..."
//                     value={searchTerm}
//                     onChange={(e) => setSearchTerm(e.target.value)}
//                     className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
//                   />
//                   <svg className="absolute left-3 top-2.5 h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                     <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
//                   </svg>
//                 </div>
//               </div>

//               {/* Users List */}
//               <div className="space-y-4 max-h-96 overflow-y-auto">
//                 {loadingUsers ? (
//                   <div className="text-center py-8">
//                     <svg className="animate-spin mx-auto h-8 w-8 text-blue-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
//                       <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
//                       <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
//                     </svg>
//                     <p className="text-gray-500 mt-2">Loading users...</p>
//                   </div>
//                 ) : filteredUsers.length === 0 ? (
//                   <div className="text-center py-8 text-gray-500">
//                     {searchTerm ? 'No users found matching your search.' : 'No users found.'}
//                   </div>
//                 ) : (
//                   filteredUsers.map((user) => (
//                     <div key={user.user_id} className="p-4 border border-gray-200 rounded-lg bg-gray-50">
//                       <div className="flex items-start justify-between mb-4">
//                         <div className="flex-1">
//                           <div className="flex items-center space-x-3">
//                             <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
//                               <span className="text-sm font-medium text-blue-600">
//                                 {user.sngine_email?.[0]?.toUpperCase() || 'U'}
//                               </span>
//                             </div>
//                             <div>
//                               <h4 className="font-medium text-gray-900">
//                                 {user.sngine_firstname} {user.sngine_lastname}
//                               </h4>
//                               <p className="text-sm text-gray-600">{user.sngine_email}</p>
//                               <p className="text-xs text-gray-500">ID: {user.user_id}</p>
//                             </div>
//                           </div>
//                         </div>
//                         <div className="flex space-x-2">
//                           <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
//                             user.admin_role && user.admin_role !== 'user' 
//                               ? 'bg-red-100 text-red-800' 
//                               : 'bg-gray-100 text-gray-800'
//                           }`}>
//                             {user.admin_role || 'User'}
//                           </span>
//                           <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
//                             user.subscription_status === 'subscribed' 
//                               ? 'bg-green-100 text-green-800' 
//                               : 'bg-gray-100 text-gray-800'
//                           }`}>
//                             {user.subscription_status || 'Free'}
//                           </span>
//                         </div>
//                       </div>

//                       <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
//                         {/* Admin Role Dropdown */}
//                         <div>
//                           <label className="block text-xs font-medium text-gray-700 mb-1">Admin Role</label>
//                           <select
//                             value={user.admin_role || ''}
//                             onChange={(e) => handleRoleChange(user.user_id, 'admin_role', e.target.value)}
//                             className="w-full text-sm border border-gray-300 rounded-md px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
//                           >
//                             {adminRoleOptions.map(option => (
//                               <option key={option.value} value={option.value}>
//                                 {option.label}
//                               </option>
//                             ))}
//                           </select>
//                         </div>

//                         {/* User Type Dropdown */}
//                         <div>
//                           <label className="block text-xs font-medium text-gray-700 mb-1">User Type</label>
//                           <select
//                             value={user.user_type || 'voter'}
//                             onChange={(e) => handleRoleChange(user.user_id, 'user_type', e.target.value)}
//                             className="w-full text-sm border border-gray-300 rounded-md px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
//                           >
//                             {userTypeOptions.map(option => (
//                               <option key={option.value} value={option.value}>
//                                 {option.label}
//                               </option>
//                             ))}
//                           </select>
//                         </div>

//                         {/* Subscription Dropdown */}
//                         <div>
//                           <label className="block text-xs font-medium text-gray-700 mb-1">Subscription</label>
//                           <select
//                             value={user.subscription_status || 'free'}
//                             onChange={(e) => handleRoleChange(user.user_id, 'subscription_status', e.target.value)}
//                             className="w-full text-sm border border-gray-300 rounded-md px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
//                           >
//                             {subscriptionOptions.map(option => (
//                               <option key={option.value} value={option.value}>
//                                 {option.label}
//                               </option>
//                             ))}
//                           </select>
//                         </div>
//                       </div>
//                     </div>
//                   ))
//                 )}
//               </div>

//               {/* Legacy Role Assignment Button */}
//               <div className="mt-6 pt-6 border-t border-gray-200">
//                 <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
//                   <div>
//                     <h4 className="font-medium text-gray-900">Legacy Role Assignment</h4>
//                     <p className="text-sm text-gray-600">Bulk role management tools</p>
//                   </div>
//                   <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm">
//                     Bulk Actions
//                   </button>
//                 </div>
//               </div>
//             </div>
//           )}
//         </div>

//         {/* Admin Actions */}
//         <div className="space-y-6">
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h3>
//             <div className="space-y-3">
//               {hasPermission('system_config') && (
//                 <button className="w-full text-left p-3 bg-red-50 hover:bg-red-100 rounded-lg text-red-700">
//                   System Maintenance
//                 </button>
//               )}
//               {canViewAudit && (
//                 <button className="w-full text-left p-3 bg-blue-50 hover:bg-blue-100 rounded-lg text-blue-700">
//                   Security Audit
//                 </button>
//               )}
//               {canViewAnalytics && (
//                 <button className="w-full text-left p-3 bg-green-50 hover:bg-green-100 rounded-lg text-green-700">
//                   Generate Reports
//                 </button>
//               )}
//               {canViewAnalytics && (
//                 <button className="w-full text-left p-3 bg-yellow-50 hover:bg-yellow-100 rounded-lg text-yellow-700">
//                   User Analytics
//                 </button>
//               )}
//             </div>
//           </div>

//           {/* User Statistics */}
//           {canManageUsers && (
//             <div className="bg-white rounded-lg shadow p-6">
//               <h3 className="text-lg font-semibold text-gray-900 mb-4">User Statistics</h3>
//               <div className="space-y-3">
//                 <div className="flex justify-between items-center p-3 bg-blue-50 rounded-lg">
//                   <span className="text-sm font-medium text-blue-700">Total Users</span>
//                   <span className="text-lg font-bold text-blue-600">{users.length}</span>
//                 </div>
//                 <div className="flex justify-between items-center p-3 bg-green-50 rounded-lg">
//                   <span className="text-sm font-medium text-green-700">Admin Users</span>
//                   <span className="text-lg font-bold text-green-600">
//                     {users.filter(u => u.admin_role && u.admin_role !== 'user').length}
//                   </span>
//                 </div>
//                 <div className="flex justify-between items-center p-3 bg-purple-50 rounded-lg">
//                   <span className="text-sm font-medium text-purple-700">Subscribed Users</span>
//                   <span className="text-lg font-bold text-purple-600">
//                     {users.filter(u => u.subscription_status === 'subscribed').length}
//                   </span>
//                 </div>
//               </div>
//             </div>
//           )}
//         </div>
//       </div>
//     </div>
//   );

//   // Moderator Dashboard Content
//   const ModeratorDashboard = () => (
//     <div className="space-y-6">
//       <div className="bg-gradient-to-r from-green-500 to-teal-600 rounded-lg p-6 text-white">
//         <h2 className="text-2xl font-bold mb-2">Moderator Dashboard</h2>
//         <p className="text-green-100">Content and election management tools</p>
//       </div>

//       <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
//         {canManageContent && (
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Content Management</h3>
//             <div className="space-y-3">
//               <button className="w-full text-left p-3 bg-green-50 hover:bg-green-100 rounded-lg text-green-700">
//                 Review Reported Content
//               </button>
//               <button className="w-full text-left p-3 bg-blue-50 hover:bg-blue-100 rounded-lg text-blue-700">
//                 Moderate Comments
//               </button>
//               <button className="w-full text-left p-3 bg-yellow-50 hover:bg-yellow-100 rounded-lg text-yellow-700">
//                 Content Guidelines
//               </button>
//             </div>
//           </div>
//         )}
        
//         {canManageElections && (
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Election Oversight</h3>
//             <div className="space-y-3">
//               <button className="w-full text-left p-3 bg-teal-50 hover:bg-teal-100 rounded-lg text-teal-700">
//                 Review Elections
//               </button>
//               <button className="w-full text-left p-3 bg-purple-50 hover:bg-purple-100 rounded-lg text-purple-700">
//                 Monitor Voting
//               </button>
//             </div>
//           </div>
//         )}
//       </div>
//     </div>
//   );

//   // Auditor Dashboard Content
//   const AuditorDashboard = () => (
//     <div className="space-y-6">
//       <div className="bg-gradient-to-r from-orange-500 to-yellow-600 rounded-lg p-6 text-white">
//         <h2 className="text-2xl font-bold mb-2">Auditor Dashboard</h2>
//         <p className="text-orange-100">Audit and verification tools</p>
//       </div>

//       <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
//         {canViewAudit && (
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Audit Tools</h3>
//             <div className="space-y-3">
//               <button className="w-full text-left p-3 bg-orange-50 hover:bg-orange-100 rounded-lg text-orange-700">
//                 Election Audit Trail
//               </button>
//               <button className="w-full text-left p-3 bg-yellow-50 hover:bg-yellow-100 rounded-lg text-yellow-700">
//                 Security Logs
//               </button>
//               <button className="w-full text-left p-3 bg-red-50 hover:bg-red-100 rounded-lg text-red-700">
//                 Compliance Check
//               </button>
//             </div>
//           </div>
//         )}
        
//         {hasPermission('audit_elections') && (
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Verification</h3>
//             <div className="space-y-3">
//               <button className="w-full text-left p-3 bg-blue-50 hover:bg-blue-100 rounded-lg text-blue-700">
//                 Vote Verification
//               </button>
//               <button className="w-full text-left p-3 bg-green-50 hover:bg-green-100 rounded-lg text-green-700">
//                 Integrity Reports
//               </button>
//             </div>
//           </div>
//         )}
//       </div>
//     </div>
//   );

//   // Regular User Dashboard Content
//   const UserDashboard = () => (
//     <div className="space-y-6">
//       <div className="bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg p-6 text-white">
//         <h2 className="text-2xl font-bold mb-2">Welcome to Vottery</h2>
//         <p className="text-blue-100">Your secure voting platform dashboard</p>
//       </div>

//       <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
//         <div className="lg:col-span-2 space-y-6">
//           {/* Personal Information */}
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Personal Information</h3>
//             <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">Email</div>
//                 <div className="font-medium">{userData?.sngine_email}</div>
//               </div>
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">Phone</div>
//                 <div className="font-medium">{userData?.sngine_phone}</div>
//               </div>
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">User Type</div>
//                 <div className="font-medium capitalize">{userData?.user_type}</div>
//               </div>
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">Subscription</div>
//                 <div className="font-medium capitalize">{userData?.subscription_status}</div>
//               </div>
//             </div>
//           </div>

//           {/* Demographic Information */}
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Demographic Information</h3>
//             <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">Age</div>
//                 <div className="font-medium">{userData?.user_age || 'Not specified'}</div>
//               </div>
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">Gender</div>
//                 <div className="font-medium">{userData?.user_gender || 'Not specified'}</div>
//               </div>
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">Country</div>
//                 <div className="font-medium">{userData?.user_country || 'Not specified'}</div>
//               </div>
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">City</div>
//                 <div className="font-medium">{userData?.city || 'Not specified'}</div>
//               </div>
//             </div>
//           </div>

//           {/* Available Features */}
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Available Features (Milestone 1)</h3>
//             <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//               <div className="p-4 border border-green-200 bg-green-50 rounded-lg">
//                 <div className="flex items-center mb-2">
//                   <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
//                   <h4 className="font-medium text-gray-900">Multi-Factor Authentication</h4>
//                 </div>
//                 <p className="text-sm text-gray-600">Email + SMS + Biometric verification</p>
//               </div>
//               <div className="p-4 border border-green-200 bg-green-50 rounded-lg">
//                 <div className="flex items-center mb-2">
//                   <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
//                   <h4 className="font-medium text-gray-900">User Management</h4>
//                 </div>
//                 <p className="text-sm text-gray-600">Role-based access control</p>
//               </div>
//               <div className="p-4 border border-green-200 bg-green-50 rounded-lg">
//                 <div className="flex items-center mb-2">
//                   <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
//                   <h4 className="font-medium text-gray-900">Security Framework</h4>
//                 </div>
//                 <p className="text-sm text-gray-600">End-to-end encryption</p>
//               </div>
//               <div className="p-4 border border-yellow-200 bg-yellow-50 rounded-lg">
//                 <div className="flex items-center mb-2">
//                   <div className="w-2 h-2 bg-yellow-500 rounded-full mr-2"></div>
//                   <h4 className="font-medium text-gray-900">Election Management</h4>
//                 </div>
//                 <p className="text-sm text-gray-600">Coming in Milestone 2</p>
//               </div>
//             </div>
//           </div>
//         </div>

//         {/* Account Status */}
//         <div className="space-y-6">
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Account Status</h3>
//             <div className="space-y-3">
//               <div className="flex items-center justify-between">
//                 <span className="text-sm text-gray-600">Email Verified</span>
//                 <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-800">Verified</span>
//               </div>
//               <div className="flex items-center justify-between">
//                 <span className="text-sm text-gray-600">Phone Verified</span>
//                 <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-800">Verified</span>
//               </div>
//               <div className="flex items-center justify-between">
//                 <span className="text-sm text-gray-600">Biometric Auth</span>
//                 <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-800">Active</span>
//               </div>
//               <div className="flex items-center justify-between">
//                 <span className="text-sm text-gray-600">Profile Complete</span>
//                 <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-800">Complete</span>
//               </div>
//             </div>
//           </div>
//         </div>
//       </div>
//     </div>
//   );

//   // Role-based dashboard selector
//   const getDashboardContent = () => {
//     const role = currentUserRole.toLowerCase();
    
//     switch (role) {
//       case 'manager':
//       case 'admin':
//         return <AdminDashboard />;
//       case 'moderator':
//         return <ModeratorDashboard />;
//       case 'auditor':
//         return <AuditorDashboard />;
//       case 'analyst':
//         return <AnalystDashboard />;
//       case 'editor':
//       case 'advertiser':
//         return <ModeratorDashboard />; // Similar functionality for now
//       default:
//         return <UserDashboard />;
//     }
//   };

//   // Role-based header badge
//   const getRoleBadge = () => {
//     const role = currentUserRole.toLowerCase();
    
//     if (isUserAdmin) {
//       return (
//         <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
//           {role === 'manager' ? 'Super Admin' : 'Admin'}
//         </span>
//       );
//     }
    
//     if (role !== 'user') {
//       const colors = {
//         analyst: 'bg-purple-100 text-purple-800',
//         moderator: 'bg-green-100 text-green-800',
//         auditor: 'bg-orange-100 text-orange-800',
//         editor: 'bg-blue-100 text-blue-800',
//         advertiser: 'bg-pink-100 text-pink-800'
//       };
      
//       return (
//         <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${colors[role] || 'bg-gray-100 text-gray-800'}`}>
//           {role.charAt(0).toUpperCase() + role.slice(1)}
//         </span>
//       );
//     }
    
//     return null;
//   };

//   return (
//     <div className="min-h-screen bg-gray-50">
//       {/* Header */}
//       <header className="bg-white shadow-sm border-b">
//         <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
//           <div className="flex justify-between items-center h-16">
//             <div className="flex items-center space-x-4">
//               <h1 className="text-2xl font-bold text-blue-600">Vottery</h1>
//               {getRoleBadge()}
//             </div>
            
//             <div className="flex items-center space-x-4">
//               <div className="text-sm text-gray-600">
//                 {currentTime.toLocaleString()}
//               </div>
              
//               <div className="flex items-center space-x-2">
//                 <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
//                   <span className="text-sm font-medium text-blue-600">
//                     {userData?.sngine_email?.[0]?.toUpperCase()}
//                   </span>
//                 </div>
//                 <span className="text-sm font-medium text-gray-700">{userData?.sngine_email}</span>
//               </div>

//               <button
//                 onClick={handleLogout}
//                 className="text-gray-500 hover:text-gray-700 p-2 rounded-lg hover:bg-gray-100"
//                 title="Logout"
//               >
//                 <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                   <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
//                 </svg>
//               </button>
//             </div>
//           </div>
//         </div>
//       </header>

//       {/* Navigation Tabs */}
//       <nav className="bg-white border-b">
//         <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
//           <div className="flex space-x-8">
//             {['overview', 'security', 'biometric', 'device'].map((tab) => (
//               <button
//                 key={tab}
//                 onClick={() => setActiveTab(tab)}
//                 className={`py-4 px-1 border-b-2 font-medium text-sm ${
//                   activeTab === tab
//                     ? 'border-blue-500 text-blue-600'
//                     : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
//                 }`}
//               >
//                 {tab.charAt(0).toUpperCase() + tab.slice(1)}
//               </button>
//             ))}
//           </div>
//         </div>
//       </nav>

//       {/* Main Content */}
//       <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
//         {activeTab === 'overview' && getDashboardContent()}

//         {activeTab === 'security' && (
//           <div className="space-y-6">
//             <div className="bg-white rounded-lg shadow p-6">
//               <h3 className="text-lg font-semibold text-gray-900 mb-6">Security Framework Status</h3>
//               <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
//                 {Object.entries(securityFeatures).map(([feature, details]) => (
//                   <div key={feature} className="p-4 border rounded-lg">
//                     <div className="flex items-center justify-between mb-2">
//                       <h4 className="font-medium text-gray-900">{feature}</h4>
//                       <span className={`text-xs px-2 py-1 rounded-full ${
//                         details.type === 'success' ? 'bg-green-100 text-green-800' :
//                         details.type === 'warning' ? 'bg-yellow-100 text-yellow-800' :
//                         'bg-red-100 text-red-800'
//                       }`}>
//                         {details.status}
//                       </span>
//                     </div>
//                     <p className="text-sm text-gray-600">{details.description}</p>
//                   </div>
//                 ))}
//               </div>
//             </div>

//             <div className="bg-white rounded-lg shadow p-6">
//               <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Metrics</h3>
//               <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//                 <div className="p-4 bg-gray-50 rounded-lg">
//                   <div className="text-sm text-gray-600 mb-1">HTTPS Status</div>
//                   <div className={`font-medium ${securityMetrics.httpsEnabled ? 'text-green-600' : 'text-red-600'}`}>
//                     {securityMetrics.httpsEnabled ? 'Secure Connection' : 'Insecure Connection'}
//                   </div>
//                 </div>
//                 <div className="p-4 bg-gray-50 rounded-lg">
//                   <div className="text-sm text-gray-600 mb-1">WebAuthn Support</div>
//                   <div className={`font-medium ${securityMetrics.webAuthnSupported ? 'text-green-600' : 'text-yellow-600'}`}>
//                     {securityMetrics.webAuthnSupported ? 'Supported' : 'Not Supported'}
//                   </div>
//                 </div>
//                 <div className="p-4 bg-gray-50 rounded-lg">
//                   <div className="text-sm text-gray-600 mb-1">Local Storage</div>
//                   <div className={`font-medium ${securityMetrics.localStorageEnabled ? 'text-green-600' : 'text-red-600'}`}>
//                     {securityMetrics.localStorageEnabled ? 'Enabled' : 'Disabled'}
//                   </div>
//                 </div>
//                 <div className="p-4 bg-gray-50 rounded-lg">
//                   <div className="text-sm text-gray-600 mb-1">Session Storage</div>
//                   <div className={`font-medium ${securityMetrics.sessionStorageEnabled ? 'text-green-600' : 'text-red-600'}`}>
//                     {securityMetrics.sessionStorageEnabled ? 'Enabled' : 'Disabled'}
//                   </div>
//                 </div>
//               </div>
//             </div>
//           </div>
//         )}

//         {activeTab === 'biometric' && (
//           <div className="space-y-6">
//             <div className="bg-white rounded-lg shadow p-6">
//               <h3 className="text-lg font-semibold text-gray-900 mb-4">Biometric Authentication Status</h3>
//               <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
//                 <div className="p-6 border border-green-200 bg-green-50 rounded-lg">
//                   <div className="flex items-center mb-4">
//                     <svg className="w-8 h-8 text-green-600 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                       <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
//                     </svg>
//                     <div>
//                       <h4 className="font-medium text-green-800">Device Fingerprint</h4>
//                       <p className="text-sm text-green-600">Registered & Active</p>
//                     </div>
//                   </div>
//                   <div className="text-sm text-green-700">
//                     <p>• Unique device identification</p>
//                     <p>• Hardware-based security</p>
//                     <p>• Anti-fraud protection</p>
//                   </div>
//                 </div>

//                 <div className="p-6 border border-blue-200 bg-blue-50 rounded-lg">
//                   <div className="flex items-center mb-4">
//                     <svg className="w-8 h-8 text-blue-600 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                       <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
//                     </svg>
//                     <div>
//                       <h4 className="font-medium text-blue-800">WebAuthn Status</h4>
//                       <p className="text-sm text-blue-600">
//                         {securityMetrics.webAuthnSupported ? 'Available' : 'Not Available'}
//                       </p>
//                     </div>
//                   </div>
//                   <div className="text-sm text-blue-700">
//                     <p>• Passwordless authentication</p>
//                     <p>• Hardware security keys</p>
//                     <p>• Biometric verification</p>
//                   </div>
//                 </div>
//               </div>

//               <div className="mt-6 p-4 bg-gray-50 rounded-lg">
//                 <h4 className="font-medium text-gray-900 mb-2">Biometric Capabilities</h4>
//                 <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
//                   <div className="flex items-center">
//                     <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
//                     Face ID Support: {/iPhone|iPad/.test(navigator.userAgent) ? 'Yes' : 'No'}
//                   </div>
//                   <div className="flex items-center">
//                     <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
//                     Fingerprint: {/Android/.test(navigator.userAgent) ? 'Yes' : 'No'}
//                   </div>
//                   <div className="flex items-center">
//                     <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
//                     WebAuthn: {securityMetrics.webAuthnSupported ? 'Yes' : 'No'}
//                   </div>
//                 </div>
//               </div>
//             </div>
//           </div>
//         )}

//         {activeTab === 'device' && deviceInfo && (
//           <div className="space-y-6">
//             <div className="bg-white rounded-lg shadow p-6">
//               <h3 className="text-lg font-semibold text-gray-900 mb-4">Device Information</h3>
//               <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
//                 <div className="space-y-4">
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">Platform</div>
//                     <div className="font-medium">{deviceInfo.platform}</div>
//                   </div>
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">Language</div>
//                     <div className="font-medium">{deviceInfo.language}</div>
//                   </div>
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">Timezone</div>
//                     <div className="font-medium">{deviceInfo.timezone}</div>
//                   </div>
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">Screen Resolution</div>
//                     <div className="font-medium">{deviceInfo.screen.width}x{deviceInfo.screen.height}</div>
//                   </div>
//                 </div>

//                 <div className="space-y-4">
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">Color Depth</div>
//                     <div className="font-medium">{deviceInfo.screen.colorDepth}-bit</div>
//                   </div>
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">Pixel Ratio</div>
//                     <div className="font-medium">{deviceInfo.screen.pixelRatio}</div>
//                   </div>
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">CPU Cores</div>
//                     <div className="font-medium">{deviceInfo.hardwareConcurrency}</div>
//                   </div>
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">Memory</div>
//                     <div className="font-medium">{deviceInfo.memory} GB</div>
//                   </div>
//                 </div>
//               </div>

//               <div className="mt-6 p-4 bg-blue-50 rounded-lg">
//                 <h4 className="font-medium text-gray-900 mb-3">Browser Capabilities</h4>
//                 <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
//                   <div className="flex items-center">
//                     <span className={`w-2 h-2 rounded-full mr-2 ${deviceInfo.cookieEnabled ? 'bg-green-500' : 'bg-red-500'}`}></span>
//                     Cookies: {deviceInfo.cookieEnabled ? 'Enabled' : 'Disabled'}
//                   </div>
//                   <div className="flex items-center">
//                     <span className={`w-2 h-2 rounded-full mr-2 ${deviceInfo.javaEnabled ? 'bg-green-500' : 'bg-red-500'}`}></span>
//                     Java: {deviceInfo.javaEnabled ? 'Enabled' : 'Disabled'}
//                   </div>
//                   <div className="flex items-center">
//                     <span className={`w-2 h-2 rounded-full mr-2 ${deviceInfo.onLine ? 'bg-green-500' : 'bg-red-500'}`}></span>
//                     Online: {deviceInfo.onLine ? 'Yes' : 'No'}
//                   </div>
//                   <div className="flex items-center">
//                     <span className={`w-2 h-2 rounded-full mr-2 ${!deviceInfo.webdriver ? 'bg-green-500' : 'bg-yellow-500'}`}></span>
//                     Automation: {deviceInfo.webdriver ? 'Detected' : 'None'}
//                   </div>
//                 </div>
//               </div>

//               {deviceInfo.connection && (
//                 <div className="mt-6 p-4 bg-green-50 rounded-lg">
//                   <h4 className="font-medium text-gray-900 mb-3">Network Information</h4>
//                   <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
//                     <div>Connection Type: {deviceInfo.connection.type}</div>
//                     <div>Effective Type: {deviceInfo.connection.effectiveType}</div>
//                     <div>Downlink: {deviceInfo.connection.downlink} Mbps</div>
//                     <div>RTT: {deviceInfo.connection.rtt} ms</div>
//                   </div>
//                 </div>
//               )}
//             </div>
//           </div>
//         )}

//         {/* Role-based permissions display */}
//         {activeTab === 'overview' && (
//           <div className="mt-8 bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Your Role & Permissions</h3>
//             <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">Current Role</div>
//                 <div className="font-medium text-lg capitalize">{currentUserRole}</div>
//                 <div className="text-sm text-gray-500 mt-1">
//                   {currentUserRole === 'analyst' && 'Data analysis and reporting'}
//                   {isUserAdmin && 'Full administrative access'}
//                   {currentUserRole === 'moderator' && 'Content and election management'}
//                   {currentUserRole === 'auditor' && 'Audit and verification tools'}
//                   {currentUserRole === 'editor' && 'Content editing capabilities'}
//                   {currentUserRole === 'advertiser' && 'Campaign management'}
//                   {currentUserRole === 'user' && 'Standard voting access'}
//                 </div>
//               </div>
              
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-2">Available Permissions</div>
//                 <div className="space-y-1">
//                   {rolePermissions?.permissions?.length > 0 ? (
//                     rolePermissions.permissions.map(permission => (
//                       <div key={permission} className="text-sm text-green-600 flex items-center">
//                         <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
//                         {permission.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
//                       </div>
//                     ))
//                   ) : (
//                     <div className="text-sm text-gray-500">Standard user permissions</div>
//                   )}
//                 </div>
//               </div>
//             </div>
//           </div>
//         )}

//         {/* Coming Soon Features */}
//         <div className="mt-8 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-lg p-6 text-white">
//           <h3 className="text-xl font-bold mb-4">Coming in Next Milestones</h3>
//           <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
//             <div className="bg-white bg-opacity-20 rounded-lg p-4">
//               <h4 className="font-semibold mb-2">Milestone 2 (Sep 5-16)</h4>
//               <ul className="text-sm space-y-1">
//                 <li>• Election Management</li>
//                 <li>• Multi-Method Voting</li>
//                 <li>• Cryptographic Security</li>
//                 <li>• Vote Verification</li>
//               </ul>
//             </div>
//             <div className="bg-white bg-opacity-20 rounded-lg p-4">
//               <h4 className="font-semibold mb-2">Milestone 3 (Sep 17-28)</h4>
//               <ul className="text-sm space-y-1">
//                 <li>• Payment Processing</li>
//                 <li>• 3D/4D Lottery System</li>
//                 <li>• Prize Management</li>
//                 <li>• Subscription Plans</li>
//               </ul>
//             </div>
//             <div className="bg-white bg-opacity-20 rounded-lg p-4">
//               <h4 className="font-semibold mb-2">Milestone 4-6</h4>
//               <ul className="text-sm space-y-1">
//                 <li>• Mobile Applications</li>
//                 <li>• AI Recommendations</li>
//                 <li>• 70+ Languages</li>
//                 <li>• Production Deployment</li>
//               </ul>
//             </div>
//           </div>
//         </div>
//       </main>
//     </div>
//   );
// };

// export default Dashboard;

//This is dashboard for final touch


//This is dashboard for final touch
import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useSecurity } from '../contexts/SecurityContext';

const Dashboard = () => {
  const { userData, logout, isAdmin, refreshAccessToken, getUserRole, hasPermission, rolePermissions } = useAuth();
  const securityContext = useSecurity();
  const [currentTime, setCurrentTime] = useState(new Date());
  const [activeTab, setActiveTab] = useState('overview');
  const [deviceInfo, setDeviceInfo] = useState(null);
  const [securityMetrics, setSecurityMetrics] = useState({});

  // Get current user role and permissions
  const currentUserRole = getUserRole();
  const isUserAdmin = isAdmin();
  const canViewAnalytics = hasPermission('view_analytics');
  const canManageUsers = hasPermission('manage_users');
  const canManageElections = hasPermission('manage_elections');
  const canManageContent = hasPermission('manage_content');
  const canViewAudit = hasPermission('view_audit');

  // Update current time every second
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Collect device and security information
  useEffect(() => {
    const collectDeviceInfo = () => {
      const device = {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        screen: {
          width: screen.width,
          height: screen.height,
          colorDepth: screen.colorDepth,
          pixelRatio: window.devicePixelRatio || 1
        },
        connection: navigator.connection ? {
          type: navigator.connection.type,
          effectiveType: navigator.connection.effectiveType,
          downlink: navigator.connection.downlink,
          rtt: navigator.connection.rtt
        } : null,
        memory: navigator.deviceMemory || 'Unknown',
        hardwareConcurrency: navigator.hardwareConcurrency || 'Unknown',
        cookieEnabled: navigator.cookieEnabled,
        javaEnabled: navigator.javaEnabled ? navigator.javaEnabled() : false,
        onLine: navigator.onLine,
        webdriver: navigator.webdriver || false
      };
      setDeviceInfo(device);
    };

    const collectSecurityMetrics = () => {
      const metrics = {
        httpsEnabled: window.location.protocol === 'https:',
        referrerValidated: securityContext?.securityMetrics?.referrerValidated || false,
        deviceFingerprinted: true, // Set to true as we collect fingerprint
        encryptionEnabled: securityContext?.securityMetrics?.encryptionEnabled || true,
        webAuthnSupported: !!window.PublicKeyCredential,
        localStorageEnabled: (() => {
          try {
            const test = 'test';
            localStorage.setItem(test, test);
            localStorage.removeItem(test);
            return true;
          } catch (e) {
            return false;
          }
        })(),
        sessionStorageEnabled: (() => {
          try {
            const test = 'test';
            sessionStorage.setItem(test, test);
            sessionStorage.removeItem(test);
            return true;
          } catch (e) {
            return false;
          }
        })(),
        thirdPartyCookiesEnabled: navigator.cookieEnabled && document.cookie.length > 0
      };
      setSecurityMetrics(metrics);
    };

    collectDeviceInfo();
    collectSecurityMetrics();
  }, [securityContext]);

  const handleLogout = () => {
    logout();
  };

  // Security features demo - showing implemented features
  const securityFeatures = {
    'End-to-End Encryption': {
      status: 'Active',
      description: 'RSA/ElGamal encryption implemented',
      type: 'success'
    },
    'Digital Signatures': {
      status: 'Active',
      description: 'SHA-256 signature verification',
      type: 'success'
    },
    'Key Management': {
      status: 'Active',
      description: 'Threshold decryption system',
      type: 'success'
    },
    'HTTPS Enforcement': {
      status: securityMetrics.httpsEnabled ? 'Active' : 'Warning',
      description: 'SSL certificate validation',
      type: securityMetrics.httpsEnabled ? 'success' : 'warning'
    },
    'Input Validation': {
      status: 'Active',
      description: 'OWASP security compliance',
      type: 'success'
    },
    'Rate Limiting': {
      status: 'Active',
      description: 'DDoS protection enabled',
      type: 'success'
    }
  };

  // Role-based dashboard content
  const AnalystDashboard = () => (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-purple-500 to-indigo-600 rounded-lg p-6 text-white">
        <h2 className="text-2xl font-bold mb-2">Analytics Dashboard</h2>
        <p className="text-purple-100">Data insights and reporting tools</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          {/* Analytics Overview */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Analytics Overview</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center p-4 bg-blue-50 rounded-lg">
                <div className="text-2xl font-bold text-blue-600">1,234</div>
                <div className="text-sm text-gray-600">Total Users</div>
              </div>
              <div className="text-center p-4 bg-green-50 rounded-lg">
                <div className="text-2xl font-bold text-green-600">89</div>
                <div className="text-sm text-gray-600">Active Elections</div>
              </div>
              <div className="text-center p-4 bg-purple-50 rounded-lg">
                <div className="text-2xl font-bold text-purple-600">5,678</div>
                <div className="text-sm text-gray-600">Total Votes</div>
              </div>
              <div className="text-center p-4 bg-orange-50 rounded-lg">
                <div className="text-2xl font-bold text-orange-600">456</div>
                <div className="text-sm text-gray-600">Reports Generated</div>
              </div>
            </div>
          </div>

          {/* Data Export Tools */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Data Export & Reports</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div>
                  <h4 className="font-medium text-gray-900">User Analytics Export</h4>
                  <p className="text-sm text-gray-600">Download user engagement reports</p>
                </div>
                <button className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg text-sm">
                  Export CSV
                </button>
              </div>
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div>
                  <h4 className="font-medium text-gray-900">Election Performance</h4>
                  <p className="text-sm text-gray-600">Voting patterns and participation</p>
                </div>
                <button className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg text-sm">
                  Generate Report
                </button>
              </div>
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div>
                  <h4 className="font-medium text-gray-900">Security Metrics</h4>
                  <p className="text-sm text-gray-600">Authentication and security logs</p>
                </div>
                <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm">
                  View Metrics
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Analytics Tools */}
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Analytics Tools</h3>
            <div className="space-y-3">
              <button className="w-full text-left p-3 bg-purple-50 hover:bg-purple-100 rounded-lg text-purple-700">
                User Engagement
              </button>
              <button className="w-full text-left p-3 bg-blue-50 hover:bg-blue-100 rounded-lg text-blue-700">
                Voting Trends
              </button>
              <button className="w-full text-left p-3 bg-green-50 hover:bg-green-100 rounded-lg text-green-700">
                Performance Metrics
              </button>
              <button className="w-full text-left p-3 bg-orange-50 hover:bg-orange-100 rounded-lg text-orange-700">
                Custom Reports
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  // Admin Dashboard Content
  const AdminDashboard = () => (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-red-500 to-red-600 rounded-lg p-6 text-white">
        <h2 className="text-2xl font-bold mb-2">Admin Dashboard</h2>
        <p className="text-red-100">Administrative controls and system management</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          {/* System Statistics */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">System Statistics</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center p-4 bg-blue-50 rounded-lg">
                <div className="text-2xl font-bold text-blue-600">1,234</div>
                <div className="text-sm text-gray-600">Total Users</div>
              </div>
              <div className="text-center p-4 bg-green-50 rounded-lg">
                <div className="text-2xl font-bold text-green-600">89</div>
                <div className="text-sm text-gray-600">Active Elections</div>
              </div>
              <div className="text-center p-4 bg-purple-50 rounded-lg">
                <div className="text-2xl font-bold text-purple-600">5,678</div>
                <div className="text-sm text-gray-600">Total Votes</div>
              </div>
              <div className="text-center p-4 bg-orange-50 rounded-lg">
                <div className="text-2xl font-bold text-orange-600">456</div>
                <div className="text-sm text-gray-600">Subscriptions</div>
              </div>
            </div>
          </div>

          {/* User Management - Only for users with manage_users permission */}
          {canManageUsers && (
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">User Management</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                  <div>
                    <h4 className="font-medium text-gray-900">Role Assignment</h4>
                    <p className="text-sm text-gray-600">Manage user roles and permissions</p>
                  </div>
                  <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm">
                    Manage Roles
                  </button>
                </div>
                <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                  <div>
                    <h4 className="font-medium text-gray-900">User Types</h4>
                    <p className="text-sm text-gray-600">Individual, Organization, Voters</p>
                  </div>
                  <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm">
                    Configure Types
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Admin Actions */}
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h3>
            <div className="space-y-3">
              {hasPermission('system_config') && (
                <button className="w-full text-left p-3 bg-red-50 hover:bg-red-100 rounded-lg text-red-700">
                  System Maintenance
                </button>
              )}
              {canViewAudit && (
                <button className="w-full text-left p-3 bg-blue-50 hover:bg-blue-100 rounded-lg text-blue-700">
                  Security Audit
                </button>
              )}
              {canViewAnalytics && (
                <button className="w-full text-left p-3 bg-green-50 hover:bg-green-100 rounded-lg text-green-700">
                  Generate Reports
                </button>
              )}
              {canViewAnalytics && (
                <button className="w-full text-left p-3 bg-yellow-50 hover:bg-yellow-100 rounded-lg text-yellow-700">
                  User Analytics
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  // Moderator Dashboard Content
  const ModeratorDashboard = () => (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-green-500 to-teal-600 rounded-lg p-6 text-white">
        <h2 className="text-2xl font-bold mb-2">Moderator Dashboard</h2>
        <p className="text-green-100">Content and election management tools</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {canManageContent && (
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Content Management</h3>
            <div className="space-y-3">
              <button className="w-full text-left p-3 bg-green-50 hover:bg-green-100 rounded-lg text-green-700">
                Review Reported Content
              </button>
              <button className="w-full text-left p-3 bg-blue-50 hover:bg-blue-100 rounded-lg text-blue-700">
                Moderate Comments
              </button>
              <button className="w-full text-left p-3 bg-yellow-50 hover:bg-yellow-100 rounded-lg text-yellow-700">
                Content Guidelines
              </button>
            </div>
          </div>
        )}
        
        {canManageElections && (
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Election Oversight</h3>
            <div className="space-y-3">
              <button className="w-full text-left p-3 bg-teal-50 hover:bg-teal-100 rounded-lg text-teal-700">
                Review Elections
              </button>
              <button className="w-full text-left p-3 bg-purple-50 hover:bg-purple-100 rounded-lg text-purple-700">
                Monitor Voting
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );

  // Auditor Dashboard Content
  const AuditorDashboard = () => (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-orange-500 to-yellow-600 rounded-lg p-6 text-white">
        <h2 className="text-2xl font-bold mb-2">Auditor Dashboard</h2>
        <p className="text-orange-100">Audit and verification tools</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {canViewAudit && (
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Audit Tools</h3>
            <div className="space-y-3">
              <button className="w-full text-left p-3 bg-orange-50 hover:bg-orange-100 rounded-lg text-orange-700">
                Election Audit Trail
              </button>
              <button className="w-full text-left p-3 bg-yellow-50 hover:bg-yellow-100 rounded-lg text-yellow-700">
                Security Logs
              </button>
              <button className="w-full text-left p-3 bg-red-50 hover:bg-red-100 rounded-lg text-red-700">
                Compliance Check
              </button>
            </div>
          </div>
        )}
        
        {hasPermission('audit_elections') && (
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Verification</h3>
            <div className="space-y-3">
              <button className="w-full text-left p-3 bg-blue-50 hover:bg-blue-100 rounded-lg text-blue-700">
                Vote Verification
              </button>
              <button className="w-full text-left p-3 bg-green-50 hover:bg-green-100 rounded-lg text-green-700">
                Integrity Reports
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );

  // Regular User Dashboard Content
  const UserDashboard = () => (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg p-6 text-white">
        <h2 className="text-2xl font-bold mb-2">Welcome to Vottery</h2>
        <p className="text-blue-100">Your secure voting platform dashboard</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          {/* Personal Information */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Personal Information</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="text-sm text-gray-600 mb-1">Email</div>
                <div className="font-medium">{userData?.sngine_email}</div>
              </div>
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="text-sm text-gray-600 mb-1">Phone</div>
                <div className="font-medium">{userData?.sngine_phone}</div>
              </div>
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="text-sm text-gray-600 mb-1">User Type</div>
                <div className="font-medium capitalize">{userData?.user_type}</div>
              </div>
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="text-sm text-gray-600 mb-1">Subscription</div>
                <div className="font-medium capitalize">{userData?.subscription_status}</div>
              </div>
            </div>
          </div>

          {/* Demographic Information */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Demographic Information</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="text-sm text-gray-600 mb-1">Age</div>
                <div className="font-medium">{userData?.user_age || 'Not specified'}</div>
              </div>
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="text-sm text-gray-600 mb-1">Gender</div>
                <div className="font-medium">{userData?.user_gender || 'Not specified'}</div>
              </div>
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="text-sm text-gray-600 mb-1">Country</div>
                <div className="font-medium">{userData?.user_country || 'Not specified'}</div>
              </div>
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="text-sm text-gray-600 mb-1">City</div>
                <div className="font-medium">{userData?.city || 'Not specified'}</div>
              </div>
            </div>
          </div>

          {/* Available Features */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Available Features (Milestone 1)</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 border border-green-200 bg-green-50 rounded-lg">
                <div className="flex items-center mb-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                  <h4 className="font-medium text-gray-900">Multi-Factor Authentication</h4>
                </div>
                <p className="text-sm text-gray-600">Email + SMS + Biometric verification</p>
              </div>
              <div className="p-4 border border-green-200 bg-green-50 rounded-lg">
                <div className="flex items-center mb-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                  <h4 className="font-medium text-gray-900">User Management</h4>
                </div>
                <p className="text-sm text-gray-600">Role-based access control</p>
              </div>
              <div className="p-4 border border-green-200 bg-green-50 rounded-lg">
                <div className="flex items-center mb-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                  <h4 className="font-medium text-gray-900">Security Framework</h4>
                </div>
                <p className="text-sm text-gray-600">End-to-end encryption</p>
              </div>
              <div className="p-4 border border-yellow-200 bg-yellow-50 rounded-lg">
                <div className="flex items-center mb-2">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full mr-2"></div>
                  <h4 className="font-medium text-gray-900">Election Management</h4>
                </div>
                <p className="text-sm text-gray-600">Coming in Milestone 2</p>
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          {/* Account Status */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Account Status</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Email Verified</span>
                <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-800">Verified</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Phone Verified</span>
                <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-800">Verified</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Biometric Auth</span>
                <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-800">Active</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Profile Complete</span>
                <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-800">Complete</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  // Role-based dashboard selector
  const getDashboardContent = () => {
    const role = currentUserRole.toLowerCase();
    
    switch (role) {
      case 'manager':
      case 'admin':
        return <AdminDashboard />;
      case 'moderator':
        return <ModeratorDashboard />;
      case 'auditor':
        return <AuditorDashboard />;
      case 'analyst':
        return <AnalystDashboard />;
      case 'editor':
      case 'advertiser':
        return <ModeratorDashboard />; // Similar functionality for now
      default:
        return <UserDashboard />;
    }
  };

  // Role-based header badge
  const getRoleBadge = () => {
    const role = currentUserRole.toLowerCase();
    
    if (isUserAdmin) {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
          {role === 'manager' ? 'Super Admin' : 'Admin'}
        </span>
      );
    }
    
    if (role !== 'user') {
      const colors = {
        analyst: 'bg-purple-100 text-purple-800',
        moderator: 'bg-green-100 text-green-800',
        auditor: 'bg-orange-100 text-orange-800',
        editor: 'bg-blue-100 text-blue-800',
        advertiser: 'bg-pink-100 text-pink-800'
      };
      
      return (
        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${colors[role] || 'bg-gray-100 text-gray-800'}`}>
          {role.charAt(0).toUpperCase() + role.slice(1)}
        </span>
      );
    }
    
    return null;
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4">
              <h1 className="text-2xl font-bold text-blue-600">Vottery</h1>
              {getRoleBadge()}
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="text-sm text-gray-600">
                {currentTime.toLocaleString()}
              </div>
              
              <div className="flex items-center space-x-2">
                <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                  <span className="text-sm font-medium text-blue-600">
                    {userData?.sngine_email?.[0]?.toUpperCase()}
                  </span>
                </div>
                <span className="text-sm font-medium text-gray-700">{userData?.sngine_email}</span>
              </div>

              <button
                onClick={handleLogout}
                className="text-gray-500 hover:text-gray-700 p-2 rounded-lg hover:bg-gray-100"
                title="Logout"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            {['overview', 'security', 'biometric', 'device'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'overview' && getDashboardContent()}

        {activeTab === 'security' && (
          <div className="space-y-6">
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-6">Security Framework Status</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.entries(securityFeatures).map(([feature, details]) => (
                  <div key={feature} className="p-4 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-medium text-gray-900">{feature}</h4>
                      <span className={`text-xs px-2 py-1 rounded-full ${
                        details.type === 'success' ? 'bg-green-100 text-green-800' :
                        details.type === 'warning' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-red-100 text-red-800'
                      }`}>
                        {details.status}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600">{details.description}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Metrics</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 bg-gray-50 rounded-lg">
                  <div className="text-sm text-gray-600 mb-1">HTTPS Status</div>
                  <div className={`font-medium ${securityMetrics.httpsEnabled ? 'text-green-600' : 'text-red-600'}`}>
                    {securityMetrics.httpsEnabled ? 'Secure Connection' : 'Insecure Connection'}
                  </div>
                </div>
                <div className="p-4 bg-gray-50 rounded-lg">
                  <div className="text-sm text-gray-600 mb-1">WebAuthn Support</div>
                  <div className={`font-medium ${securityMetrics.webAuthnSupported ? 'text-green-600' : 'text-yellow-600'}`}>
                    {securityMetrics.webAuthnSupported ? 'Supported' : 'Not Supported'}
                  </div>
                </div>
                <div className="p-4 bg-gray-50 rounded-lg">
                  <div className="text-sm text-gray-600 mb-1">Local Storage</div>
                  <div className={`font-medium ${securityMetrics.localStorageEnabled ? 'text-green-600' : 'text-red-600'}`}>
                    {securityMetrics.localStorageEnabled ? 'Enabled' : 'Disabled'}
                  </div>
                </div>
                <div className="p-4 bg-gray-50 rounded-lg">
                  <div className="text-sm text-gray-600 mb-1">Session Storage</div>
                  <div className={`font-medium ${securityMetrics.sessionStorageEnabled ? 'text-green-600' : 'text-red-600'}`}>
                    {securityMetrics.sessionStorageEnabled ? 'Enabled' : 'Disabled'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'biometric' && (
          <div className="space-y-6">
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Biometric Authentication Status</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="p-6 border border-green-200 bg-green-50 rounded-lg">
                  <div className="flex items-center mb-4">
                    <svg className="w-8 h-8 text-green-600 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                    <div>
                      <h4 className="font-medium text-green-800">Device Fingerprint</h4>
                      <p className="text-sm text-green-600">Registered & Active</p>
                    </div>
                  </div>
                  <div className="text-sm text-green-700">
                    <p>• Unique device identification</p>
                    <p>• Hardware-based security</p>
                    <p>• Anti-fraud protection</p>
                  </div>
                </div>

                <div className="p-6 border border-blue-200 bg-blue-50 rounded-lg">
                  <div className="flex items-center mb-4">
                    <svg className="w-8 h-8 text-blue-600 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                    <div>
                      <h4 className="font-medium text-blue-800">WebAuthn Status</h4>
                      <p className="text-sm text-blue-600">
                        {securityMetrics.webAuthnSupported ? 'Available' : 'Not Available'}
                      </p>
                    </div>
                  </div>
                  <div className="text-sm text-blue-700">
                    <p>• Passwordless authentication</p>
                    <p>• Hardware security keys</p>
                    <p>• Biometric verification</p>
                  </div>
                </div>
              </div>

              <div className="mt-6 p-4 bg-gray-50 rounded-lg">
                <h4 className="font-medium text-gray-900 mb-2">Biometric Capabilities</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div className="flex items-center">
                    <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                    Face ID Support: {/iPhone|iPad/.test(navigator.userAgent) ? 'Yes' : 'No'}
                  </div>
                  <div className="flex items-center">
                    <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                    Fingerprint: {/Android/.test(navigator.userAgent) ? 'Yes' : 'No'}
                  </div>
                  <div className="flex items-center">
                    <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                    WebAuthn: {securityMetrics.webAuthnSupported ? 'Yes' : 'No'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'device' && deviceInfo && (
          <div className="space-y-6">
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Device Information</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <div className="text-sm text-gray-600 mb-1">Platform</div>
                    <div className="font-medium">{deviceInfo.platform}</div>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <div className="text-sm text-gray-600 mb-1">Language</div>
                    <div className="font-medium">{deviceInfo.language}</div>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <div className="text-sm text-gray-600 mb-1">Timezone</div>
                    <div className="font-medium">{deviceInfo.timezone}</div>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <div className="text-sm text-gray-600 mb-1">Screen Resolution</div>
                    <div className="font-medium">{deviceInfo.screen.width}x{deviceInfo.screen.height}</div>
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <div className="text-sm text-gray-600 mb-1">Color Depth</div>
                    <div className="font-medium">{deviceInfo.screen.colorDepth}-bit</div>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <div className="text-sm text-gray-600 mb-1">Pixel Ratio</div>
                    <div className="font-medium">{deviceInfo.screen.pixelRatio}</div>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <div className="text-sm text-gray-600 mb-1">CPU Cores</div>
                    <div className="font-medium">{deviceInfo.hardwareConcurrency}</div>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <div className="text-sm text-gray-600 mb-1">Memory</div>
                    <div className="font-medium">{deviceInfo.memory} GB</div>
                  </div>
                </div>
              </div>

              <div className="mt-6 p-4 bg-blue-50 rounded-lg">
                <h4 className="font-medium text-gray-900 mb-3">Browser Capabilities</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div className="flex items-center">
                    <span className={`w-2 h-2 rounded-full mr-2 ${deviceInfo.cookieEnabled ? 'bg-green-500' : 'bg-red-500'}`}></span>
                    Cookies: {deviceInfo.cookieEnabled ? 'Enabled' : 'Disabled'}
                  </div>
                  <div className="flex items-center">
                    <span className={`w-2 h-2 rounded-full mr-2 ${deviceInfo.javaEnabled ? 'bg-green-500' : 'bg-red-500'}`}></span>
                    Java: {deviceInfo.javaEnabled ? 'Enabled' : 'Disabled'}
                  </div>
                  <div className="flex items-center">
                    <span className={`w-2 h-2 rounded-full mr-2 ${deviceInfo.onLine ? 'bg-green-500' : 'bg-red-500'}`}></span>
                    Online: {deviceInfo.onLine ? 'Yes' : 'No'}
                  </div>
                  <div className="flex items-center">
                    <span className={`w-2 h-2 rounded-full mr-2 ${!deviceInfo.webdriver ? 'bg-green-500' : 'bg-yellow-500'}`}></span>
                    Automation: {deviceInfo.webdriver ? 'Detected' : 'None'}
                  </div>
                </div>
              </div>

              {deviceInfo.connection && (
                <div className="mt-6 p-4 bg-green-50 rounded-lg">
                  <h4 className="font-medium text-gray-900 mb-3">Network Information</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>Connection Type: {deviceInfo.connection.type}</div>
                    <div>Effective Type: {deviceInfo.connection.effectiveType}</div>
                    <div>Downlink: {deviceInfo.connection.downlink} Mbps</div>
                    <div>RTT: {deviceInfo.connection.rtt} ms</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Role-based permissions display */}
        {activeTab === 'overview' && (
          <div className="mt-8 bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Your Role & Permissions</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="text-sm text-gray-600 mb-1">Current Role</div>
                <div className="font-medium text-lg capitalize">{currentUserRole}</div>
                <div className="text-sm text-gray-500 mt-1">
                  {currentUserRole === 'analyst' && 'Data analysis and reporting'}
                  {isUserAdmin && 'Full administrative access'}
                  {currentUserRole === 'moderator' && 'Content and election management'}
                  {currentUserRole === 'auditor' && 'Audit and verification tools'}
                  {currentUserRole === 'editor' && 'Content editing capabilities'}
                  {currentUserRole === 'advertiser' && 'Campaign management'}
                  {currentUserRole === 'user' && 'Standard voting access'}
                </div>
              </div>
              
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="text-sm text-gray-600 mb-2">Available Permissions</div>
                <div className="space-y-1">
                  {rolePermissions?.permissions?.length > 0 ? (
                    rolePermissions.permissions.map(permission => (
                      <div key={permission} className="text-sm text-green-600 flex items-center">
                        <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                        {permission.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                      </div>
                    ))
                  ) : (
                    <div className="text-sm text-gray-500">Standard user permissions</div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Coming Soon Features */}
        <div className="mt-8 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-lg p-6 text-white">
          <h3 className="text-xl font-bold mb-4">Coming in Next Milestones</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="bg-white bg-opacity-20 rounded-lg p-4">
              <h4 className="font-semibold mb-2">Milestone 2 (Sep 5-16)</h4>
              <ul className="text-sm space-y-1">
                <li>• Election Management</li>
                <li>• Multi-Method Voting</li>
                <li>• Cryptographic Security</li>
                <li>• Vote Verification</li>
              </ul>
            </div>
            <div className="bg-white bg-opacity-20 rounded-lg p-4">
              <h4 className="font-semibold mb-2">Milestone 3 (Sep 17-28)</h4>
              <ul className="text-sm space-y-1">
                <li>• Payment Processing</li>
                <li>• 3D/4D Lottery System</li>
                <li>• Prize Management</li>
                <li>• Subscription Plans</li>
              </ul>
            </div>
            <div className="bg-white bg-opacity-20 rounded-lg p-4">
              <h4 className="font-semibold mb-2">Milestone 4-6</h4>
              <ul className="text-sm space-y-1">
                <li>• Mobile Applications</li>
                <li>• AI Recommendations</li>
                <li>• 70+ Languages</li>
                <li>• Production Deployment</li>
              </ul>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
// //This is dashboard for final touch
// import React, { useState, useEffect } from 'react';
// import { useAuth } from '../contexts/AuthContext';

// import { useSecurity } from '../contexts/SecurityContext';

// const Dashboard = () => {
//   const { userData, logout, isAdmin, refreshAccessToken } = useAuth();
//   const securityContext = useSecurity();
//   const [currentTime, setCurrentTime] = useState(new Date());
//   const [activeTab, setActiveTab] = useState('overview');
//   const [deviceInfo, setDeviceInfo] = useState(null);
//   const [securityMetrics, setSecurityMetrics] = useState({});

//   // Update current time every second
//   useEffect(() => {
//     const timer = setInterval(() => {
//       setCurrentTime(new Date());
//     }, 1000);
//     return () => clearInterval(timer);
//   }, []);

//   // Collect device and security information
//   useEffect(() => {
//     const collectDeviceInfo = () => {
//       const device = {
//         userAgent: navigator.userAgent,
//         platform: navigator.platform,
//         language: navigator.language,
//         timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
//         screen: {
//           width: screen.width,
//           height: screen.height,
//           colorDepth: screen.colorDepth,
//           pixelRatio: window.devicePixelRatio || 1
//         },
//         connection: navigator.connection ? {
//           type: navigator.connection.type,
//           effectiveType: navigator.connection.effectiveType,
//           downlink: navigator.connection.downlink,
//           rtt: navigator.connection.rtt
//         } : null,
//         memory: navigator.deviceMemory || 'Unknown',
//         hardwareConcurrency: navigator.hardwareConcurrency || 'Unknown',
//         cookieEnabled: navigator.cookieEnabled,
//         javaEnabled: navigator.javaEnabled ? navigator.javaEnabled() : false,
//         onLine: navigator.onLine,
//         webdriver: navigator.webdriver || false
//       };
//       setDeviceInfo(device);
//     };

//     const collectSecurityMetrics = () => {
//       const metrics = {
//         httpsEnabled: window.location.protocol === 'https:',
//         referrerValidated: securityContext?.securityMetrics?.referrerValidated || false,
//         deviceFingerprinted: true, // Set to true as we collect fingerprint
//         encryptionEnabled: securityContext?.securityMetrics?.encryptionEnabled || true,
//         webAuthnSupported: !!window.PublicKeyCredential,
//         localStorageEnabled: (() => {
//           try {
//             const test = 'test';
//             localStorage.setItem(test, test);
//             localStorage.removeItem(test);
//             return true;
//           } catch (e) {
//             return false;
//           }
//         })(),
//         sessionStorageEnabled: (() => {
//           try {
//             const test = 'test';
//             sessionStorage.setItem(test, test);
//             sessionStorage.removeItem(test);
//             return true;
//           } catch (e) {
//             return false;
//           }
//         })(),
//         thirdPartyCookiesEnabled: navigator.cookieEnabled && document.cookie.length > 0
//       };
//       setSecurityMetrics(metrics);
//     };

//     collectDeviceInfo();
//     collectSecurityMetrics();
//   }, [securityContext]);

//   const handleLogout = () => {
//     logout();
//   };

//   // Security features demo - showing implemented features
//   const securityFeatures = {
//     'End-to-End Encryption': {
//       status: 'Active',
//       description: 'RSA/ElGamal encryption implemented',
//       type: 'success'
//     },
//     'Digital Signatures': {
//       status: 'Active',
//       description: 'SHA-256 signature verification',
//       type: 'success'
//     },
//     'Key Management': {
//       status: 'Active',
//       description: 'Threshold decryption system',
//       type: 'success'
//     },
//     'HTTPS Enforcement': {
//       status: securityMetrics.httpsEnabled ? 'Active' : 'Warning',
//       description: 'SSL certificate validation',
//       type: securityMetrics.httpsEnabled ? 'success' : 'warning'
//     },
//     'Input Validation': {
//       status: 'Active',
//       description: 'OWASP security compliance',
//       type: 'success'
//     },
//     'Rate Limiting': {
//       status: 'Active',
//       description: 'DDoS protection enabled',
//       type: 'success'
//     }
//   };

//   // Determine user's role and permissions
//   const userRole = userData?.admin_role || 'user';
//   const userType = userData?.user_type || 'voter';
//   const subscriptionStatus = userData?.subscription_status || 'free';

//   // Admin Dashboard Content
//   const AdminDashboard = () => (
//     <div className="space-y-6">
//       <div className="bg-gradient-to-r from-red-500 to-red-600 rounded-lg p-6 text-white">
//         <h2 className="text-2xl font-bold mb-2">Admin Dashboard</h2>
//         <p className="text-red-100">Administrative controls and system management</p>
//       </div>

//       <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
//         <div className="lg:col-span-2 space-y-6">
//           {/* System Statistics */}
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">System Statistics</h3>
//             <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
//               <div className="text-center p-4 bg-blue-50 rounded-lg">
//                 <div className="text-2xl font-bold text-blue-600">1,234</div>
//                 <div className="text-sm text-gray-600">Total Users</div>
//               </div>
//               <div className="text-center p-4 bg-green-50 rounded-lg">
//                 <div className="text-2xl font-bold text-green-600">89</div>
//                 <div className="text-sm text-gray-600">Active Elections</div>
//               </div>
//               <div className="text-center p-4 bg-purple-50 rounded-lg">
//                 <div className="text-2xl font-bold text-purple-600">5,678</div>
//                 <div className="text-sm text-gray-600">Total Votes</div>
//               </div>
//               <div className="text-center p-4 bg-orange-50 rounded-lg">
//                 <div className="text-2xl font-bold text-orange-600">456</div>
//                 <div className="text-sm text-gray-600">Subscriptions</div>
//               </div>
//             </div>
//           </div>

//           {/* User Management */}
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">User Management</h3>
//             <div className="space-y-4">
//               <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
//                 <div>
//                   <h4 className="font-medium text-gray-900">Role Assignment</h4>
//                   <p className="text-sm text-gray-600">Manage user roles and permissions</p>
//                 </div>
//                 <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm">
//                   Manage Roles
//                 </button>
//               </div>
//               <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
//                 <div>
//                   <h4 className="font-medium text-gray-900">User Types</h4>
//                   <p className="text-sm text-gray-600">Individual, Organization, Voters</p>
//                 </div>
//                 <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm">
//                   Configure Types
//                 </button>
//               </div>
//             </div>
//           </div>
//         </div>

//         {/* Admin Actions */}
//         <div className="space-y-6">
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h3>
//             <div className="space-y-3">
//               <button className="w-full text-left p-3 bg-red-50 hover:bg-red-100 rounded-lg text-red-700">
//                 System Maintenance
//               </button>
//               <button className="w-full text-left p-3 bg-blue-50 hover:bg-blue-100 rounded-lg text-blue-700">
//                 Security Audit
//               </button>
//               <button className="w-full text-left p-3 bg-green-50 hover:bg-green-100 rounded-lg text-green-700">
//                 Generate Reports
//               </button>
//               <button className="w-full text-left p-3 bg-yellow-50 hover:bg-yellow-100 rounded-lg text-yellow-700">
//                 User Analytics
//               </button>
//             </div>
//           </div>
//         </div>
//       </div>
//     </div>
//   );

//   // Regular User Dashboard Content
//   const UserDashboard = () => (
//     <div className="space-y-6">
//       <div className="bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg p-6 text-white">
//         <h2 className="text-2xl font-bold mb-2">Welcome to Vottery</h2>
//         <p className="text-blue-100">Your secure voting platform dashboard</p>
//       </div>

//       <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
//         <div className="lg:col-span-2 space-y-6">
//           {/* Personal Information */}
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Personal Information</h3>
//             <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">Email</div>
//                 <div className="font-medium">{userData?.sngine_email}</div>
//               </div>
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">Phone</div>
//                 <div className="font-medium">{userData?.sngine_phone}</div>
//               </div>
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">User Type</div>
//                 <div className="font-medium capitalize">{userData?.user_type}</div>
//               </div>
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">Subscription</div>
//                 <div className="font-medium capitalize">{userData?.subscription_status}</div>
//               </div>
//             </div>
//           </div>

//           {/* Demographic Information */}
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Demographic Information</h3>
//             <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">Age</div>
//                 <div className="font-medium">{userData?.user_age || 'Not specified'}</div>
//               </div>
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">Gender</div>
//                 <div className="font-medium">{userData?.user_gender || 'Not specified'}</div>
//               </div>
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">Country</div>
//                 <div className="font-medium">{userData?.user_country || 'Not specified'}</div>
//               </div>
//               <div className="p-4 bg-gray-50 rounded-lg">
//                 <div className="text-sm text-gray-600 mb-1">City</div>
//                 <div className="font-medium">{userData?.city || 'Not specified'}</div>
//               </div>
//             </div>
//           </div>

//           {/* Available Features */}
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Available Features (Milestone 1)</h3>
//             <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//               <div className="p-4 border border-green-200 bg-green-50 rounded-lg">
//                 <div className="flex items-center mb-2">
//                   <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
//                   <h4 className="font-medium text-gray-900">Multi-Factor Authentication</h4>
//                 </div>
//                 <p className="text-sm text-gray-600">Email + SMS + Biometric verification</p>
//               </div>
//               <div className="p-4 border border-green-200 bg-green-50 rounded-lg">
//                 <div className="flex items-center mb-2">
//                   <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
//                   <h4 className="font-medium text-gray-900">User Management</h4>
//                 </div>
//                 <p className="text-sm text-gray-600">Role-based access control</p>
//               </div>
//               <div className="p-4 border border-green-200 bg-green-50 rounded-lg">
//                 <div className="flex items-center mb-2">
//                   <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
//                   <h4 className="font-medium text-gray-900">Security Framework</h4>
//                 </div>
//                 <p className="text-sm text-gray-600">End-to-end encryption</p>
//               </div>
//               <div className="p-4 border border-yellow-200 bg-yellow-50 rounded-lg">
//                 <div className="flex items-center mb-2">
//                   <div className="w-2 h-2 bg-yellow-500 rounded-full mr-2"></div>
//                   <h4 className="font-medium text-gray-900">Election Management</h4>
//                 </div>
//                 <p className="text-sm text-gray-600">Coming in Milestone 2</p>
//               </div>
//             </div>
//           </div>
//         </div>

//         <div className="space-y-6">
//           {/* Account Status */}
//           <div className="bg-white rounded-lg shadow p-6">
//             <h3 className="text-lg font-semibold text-gray-900 mb-4">Account Status</h3>
//             <div className="space-y-3">
//               <div className="flex items-center justify-between">
//                 <span className="text-sm text-gray-600">Email Verified</span>
//                 <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-800">Verified</span>
//               </div>
//               <div className="flex items-center justify-between">
//                 <span className="text-sm text-gray-600">Phone Verified</span>
//                 <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-800">Verified</span>
//               </div>
//               <div className="flex items-center justify-between">
//                 <span className="text-sm text-gray-600">Biometric Auth</span>
//                 <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-800">Active</span>
//               </div>
//               <div className="flex items-center justify-between">
//                 <span className="text-sm text-gray-600">Profile Complete</span>
//                 <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-800">Complete</span>
//               </div>
//             </div>
//           </div>
//         </div>
//       </div>
//     </div>
//   );

//   return (
//     <div className="min-h-screen bg-gray-50">
//       {/* Header */}
//       <header className="bg-white shadow-sm border-b">
//         <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
//           <div className="flex justify-between items-center h-16">
//             <div className="flex items-center space-x-4">
//               <h1 className="text-2xl font-bold text-blue-600">Vottery</h1>
//               {isAdmin() && (
//                 <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
//                   Admin
//                 </span>
//               )}
//             </div>
            
//             <div className="flex items-center space-x-4">
//               <div className="text-sm text-gray-600">
//                 {currentTime.toLocaleString()}
//               </div>
              
//               <div className="flex items-center space-x-2">
//                 <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
//                   <span className="text-sm font-medium text-blue-600">
//                     {userData?.sngine_email?.[0]?.toUpperCase()}
//                   </span>
//                 </div>
//                 <span className="text-sm font-medium text-gray-700">{userData?.sngine_email}</span>
//               </div>

//               <button
//                 onClick={handleLogout}
//                 className="text-gray-500 hover:text-gray-700 p-2 rounded-lg hover:bg-gray-100"
//                 title="Logout"
//               >
//                 <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                   <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
//                 </svg>
//               </button>
//             </div>
//           </div>
//         </div>
//       </header>

//       {/* Navigation Tabs */}
//       <nav className="bg-white border-b">
//         <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
//           <div className="flex space-x-8">
//             {['overview', 'security', 'biometric', 'device'].map((tab) => (
//               <button
//                 key={tab}
//                 onClick={() => setActiveTab(tab)}
//                 className={`py-4 px-1 border-b-2 font-medium text-sm ${
//                   activeTab === tab
//                     ? 'border-blue-500 text-blue-600'
//                     : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
//                 }`}
//               >
//                 {tab.charAt(0).toUpperCase() + tab.slice(1)}
//               </button>
//             ))}
//           </div>
//         </div>
//       </nav>

//       {/* Main Content */}
//       <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
//         {activeTab === 'overview' && (
//           isAdmin() ? <AdminDashboard /> : <UserDashboard />
//         )}

//         {activeTab === 'security' && (
//           <div className="space-y-6">
//             <div className="bg-white rounded-lg shadow p-6">
//               <h3 className="text-lg font-semibold text-gray-900 mb-6">Security Framework Status</h3>
//               <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
//                 {Object.entries(securityFeatures).map(([feature, details]) => (
//                   <div key={feature} className="p-4 border rounded-lg">
//                     <div className="flex items-center justify-between mb-2">
//                       <h4 className="font-medium text-gray-900">{feature}</h4>
//                       <span className={`text-xs px-2 py-1 rounded-full ${
//                         details.type === 'success' ? 'bg-green-100 text-green-800' :
//                         details.type === 'warning' ? 'bg-yellow-100 text-yellow-800' :
//                         'bg-red-100 text-red-800'
//                       }`}>
//                         {details.status}
//                       </span>
//                     </div>
//                     <p className="text-sm text-gray-600">{details.description}</p>
//                   </div>
//                 ))}
//               </div>
//             </div>

//             <div className="bg-white rounded-lg shadow p-6">
//               <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Metrics</h3>
//               <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//                 <div className="p-4 bg-gray-50 rounded-lg">
//                   <div className="text-sm text-gray-600 mb-1">HTTPS Status</div>
//                   <div className={`font-medium ${securityMetrics.httpsEnabled ? 'text-green-600' : 'text-red-600'}`}>
//                     {securityMetrics.httpsEnabled ? 'Secure Connection' : 'Insecure Connection'}
//                   </div>
//                 </div>
//                 <div className="p-4 bg-gray-50 rounded-lg">
//                   <div className="text-sm text-gray-600 mb-1">WebAuthn Support</div>
//                   <div className={`font-medium ${securityMetrics.webAuthnSupported ? 'text-green-600' : 'text-yellow-600'}`}>
//                     {securityMetrics.webAuthnSupported ? 'Supported' : 'Not Supported'}
//                   </div>
//                 </div>
//                 <div className="p-4 bg-gray-50 rounded-lg">
//                   <div className="text-sm text-gray-600 mb-1">Local Storage</div>
//                   <div className={`font-medium ${securityMetrics.localStorageEnabled ? 'text-green-600' : 'text-red-600'}`}>
//                     {securityMetrics.localStorageEnabled ? 'Enabled' : 'Disabled'}
//                   </div>
//                 </div>
//                 <div className="p-4 bg-gray-50 rounded-lg">
//                   <div className="text-sm text-gray-600 mb-1">Session Storage</div>
//                   <div className={`font-medium ${securityMetrics.sessionStorageEnabled ? 'text-green-600' : 'text-red-600'}`}>
//                     {securityMetrics.sessionStorageEnabled ? 'Enabled' : 'Disabled'}
//                   </div>
//                 </div>
//               </div>
//             </div>
//           </div>
//         )}

//         {activeTab === 'biometric' && (
//           <div className="space-y-6">
//             <div className="bg-white rounded-lg shadow p-6">
//               <h3 className="text-lg font-semibold text-gray-900 mb-4">Biometric Authentication Status</h3>
//               <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
//                 <div className="p-6 border border-green-200 bg-green-50 rounded-lg">
//                   <div className="flex items-center mb-4">
//                     <svg className="w-8 h-8 text-green-600 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                       <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
//                     </svg>
//                     <div>
//                       <h4 className="font-medium text-green-800">Device Fingerprint</h4>
//                       <p className="text-sm text-green-600">Registered & Active</p>
//                     </div>
//                   </div>
//                   <div className="text-sm text-green-700">
//                     <p>• Unique device identification</p>
//                     <p>• Hardware-based security</p>
//                     <p>• Anti-fraud protection</p>
//                   </div>
//                 </div>

//                 <div className="p-6 border border-blue-200 bg-blue-50 rounded-lg">
//                   <div className="flex items-center mb-4">
//                     <svg className="w-8 h-8 text-blue-600 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                       <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
//                     </svg>
//                     <div>
//                       <h4 className="font-medium text-blue-800">WebAuthn Status</h4>
//                       <p className="text-sm text-blue-600">
//                         {securityMetrics.webAuthnSupported ? 'Available' : 'Not Available'}
//                       </p>
//                     </div>
//                   </div>
//                   <div className="text-sm text-blue-700">
//                     <p>• Passwordless authentication</p>
//                     <p>• Hardware security keys</p>
//                     <p>• Biometric verification</p>
//                   </div>
//                 </div>
//               </div>

//               <div className="mt-6 p-4 bg-gray-50 rounded-lg">
//                 <h4 className="font-medium text-gray-900 mb-2">Biometric Capabilities</h4>
//                 <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
//                   <div className="flex items-center">
//                     <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
//                     Face ID Support: {/iPhone|iPad/.test(navigator.userAgent) ? 'Yes' : 'No'}
//                   </div>
//                   <div className="flex items-center">
//                     <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
//                     Fingerprint: {/Android/.test(navigator.userAgent) ? 'Yes' : 'No'}
//                   </div>
//                   <div className="flex items-center">
//                     <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
//                     WebAuthn: {securityMetrics.webAuthnSupported ? 'Yes' : 'No'}
//                   </div>
//                 </div>
//               </div>
//             </div>
//           </div>
//         )}

//         {activeTab === 'device' && deviceInfo && (
//           <div className="space-y-6">
//             <div className="bg-white rounded-lg shadow p-6">
//               <h3 className="text-lg font-semibold text-gray-900 mb-4">Device Information</h3>
//               <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
//                 <div className="space-y-4">
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">Platform</div>
//                     <div className="font-medium">{deviceInfo.platform}</div>
//                   </div>
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">Language</div>
//                     <div className="font-medium">{deviceInfo.language}</div>
//                   </div>
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">Timezone</div>
//                     <div className="font-medium">{deviceInfo.timezone}</div>
//                   </div>
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">Screen Resolution</div>
//                     <div className="font-medium">{deviceInfo.screen.width}x{deviceInfo.screen.height}</div>
//                   </div>
//                 </div>

//                 <div className="space-y-4">
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">Color Depth</div>
//                     <div className="font-medium">{deviceInfo.screen.colorDepth}-bit</div>
//                   </div>
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">Pixel Ratio</div>
//                     <div className="font-medium">{deviceInfo.screen.pixelRatio}</div>
//                   </div>
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">CPU Cores</div>
//                     <div className="font-medium">{deviceInfo.hardwareConcurrency}</div>
//                   </div>
//                   <div className="p-4 bg-gray-50 rounded-lg">
//                     <div className="text-sm text-gray-600 mb-1">Memory</div>
//                     <div className="font-medium">{deviceInfo.memory} GB</div>
//                   </div>
//                 </div>
//               </div>

//               <div className="mt-6 p-4 bg-blue-50 rounded-lg">
//                 <h4 className="font-medium text-gray-900 mb-3">Browser Capabilities</h4>
//                 <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
//                   <div className="flex items-center">
//                     <span className={`w-2 h-2 rounded-full mr-2 ${deviceInfo.cookieEnabled ? 'bg-green-500' : 'bg-red-500'}`}></span>
//                     Cookies: {deviceInfo.cookieEnabled ? 'Enabled' : 'Disabled'}
//                   </div>
//                   <div className="flex items-center">
//                     <span className={`w-2 h-2 rounded-full mr-2 ${deviceInfo.javaEnabled ? 'bg-green-500' : 'bg-red-500'}`}></span>
//                     Java: {deviceInfo.javaEnabled ? 'Enabled' : 'Disabled'}
//                   </div>
//                   <div className="flex items-center">
//                     <span className={`w-2 h-2 rounded-full mr-2 ${deviceInfo.onLine ? 'bg-green-500' : 'bg-red-500'}`}></span>
//                     Online: {deviceInfo.onLine ? 'Yes' : 'No'}
//                   </div>
//                   <div className="flex items-center">
//                     <span className={`w-2 h-2 rounded-full mr-2 ${!deviceInfo.webdriver ? 'bg-green-500' : 'bg-yellow-500'}`}></span>
//                     Automation: {deviceInfo.webdriver ? 'Detected' : 'None'}
//                   </div>
//                 </div>
//               </div>

//               {deviceInfo.connection && (
//                 <div className="mt-6 p-4 bg-green-50 rounded-lg">
//                   <h4 className="font-medium text-gray-900 mb-3">Network Information</h4>
//                   <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
//                     <div>Connection Type: {deviceInfo.connection.type}</div>
//                     <div>Effective Type: {deviceInfo.connection.effectiveType}</div>
//                     <div>Downlink: {deviceInfo.connection.downlink} Mbps</div>
//                     <div>RTT: {deviceInfo.connection.rtt} ms</div>
//                   </div>
//                 </div>
//               )}
//             </div>
//           </div>
//         )}

//         {/* Coming Soon Features */}
//         <div className="mt-8 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-lg p-6 text-white">
//           <h3 className="text-xl font-bold mb-4">Coming in Next Milestones</h3>
//           <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
//             <div className="bg-white bg-opacity-20 rounded-lg p-4">
//               <h4 className="font-semibold mb-2">Milestone 2 (Sep 5-16)</h4>
//               <ul className="text-sm space-y-1">
//                 <li>• Election Management</li>
//                 <li>• Multi-Method Voting</li>
//                 <li>• Cryptographic Security</li>
//                 <li>• Vote Verification</li>
//               </ul>
//             </div>
//             <div className="bg-white bg-opacity-20 rounded-lg p-4">
//               <h4 className="font-semibold mb-2">Milestone 3 (Sep 17-28)</h4>
//               <ul className="text-sm space-y-1">
//                 <li>• Payment Processing</li>
//                 <li>• 3D/4D Lottery System</li>
//                 <li>• Prize Management</li>
//                 <li>• Subscription Plans</li>
//               </ul>
//             </div>
//             <div className="bg-white bg-opacity-20 rounded-lg p-4">
//               <h4 className="font-semibold mb-2">Milestone 4-6</h4>
//               <ul className="text-sm space-y-1">
//                 <li>• Mobile Applications</li>
//                 <li>• AI Recommendations</li>
//                 <li>• 70+ Languages</li>
//                 <li>• Production Deployment</li>
//               </ul>
//             </div>
//           </div>
//         </div>
//       </main>
//     </div>
//   );
// };

// export default Dashboard;
// import React, { useState, useEffect } from 'react';
// import { useAuth } from '../contexts/AuthContext';
// import { useSecurity } from '../contexts/SecurityContext';

// const Dashboard = () => {
//   const { email, phone, logout } = useAuth();
//   const securityContext = useSecurity();
//   const [currentTime, setCurrentTime] = useState(new Date());

//   useEffect(() => {
//     const timer = setInterval(() => {
//       setCurrentTime(new Date());
//     }, 1000);
//     return () => clearInterval(timer);
//   }, []);

//   const handleLogout = () => {
//     logout();
//   };

//   // Provide safe fallback for securityMetrics
//   const securityMetrics = securityContext?.securityMetrics || {
//     referrerValidated: false,
//     httpsEnabled: window.location.protocol === 'https:',
//     deviceFingerprinted: false,
//     encryptionEnabled: false
//   };

//   return (
//     <div className="min-h-screen bg-gray-50">
//       {/* Header */}
//       <header className="bg-white shadow-sm border-b">
//         <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
//           <div className="flex justify-between items-center h-16">
//             <div className="flex items-center">
//               <h1 className="text-2xl font-bold text-blue-600">Vottery</h1>
//             </div>
            
//             <div className="flex items-center space-x-4">
//               <div className="text-sm text-gray-600">
//                 {currentTime.toLocaleString()}
//               </div>
              
//               <div className="flex items-center space-x-2">
//                 <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
//                   <span className="text-sm font-medium text-blue-600">
//                     {email?.[0]?.toUpperCase()}
//                   </span>
//                 </div>
//                 <span className="text-sm font-medium text-gray-700">{email}</span>
//               </div>

//               <button
//                 onClick={handleLogout}
//                 className="text-gray-500 hover:text-gray-700 p-2 rounded-lg hover:bg-gray-100"
//                 title="Logout"
//               >
//                 <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                   <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
//                 </svg>
//               </button>
//             </div>
//           </div>
//         </div>
//       </header>

//       {/* Main Content */}
//       <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
//         {/* Welcome Section */}
//         <div className="bg-white rounded-lg shadow p-6 mb-8">
//           <div className="flex items-center justify-between mb-4">
//             <h2 className="text-2xl font-bold text-gray-900">Welcome to Vottery Dashboard</h2>
//             <div className="flex space-x-2">
//               <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
//                 <svg className="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                   <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
//                 </svg>
//                 Verified User
//               </span>
//             </div>
//           </div>
          
//           <p className="text-gray-600">
//             You have successfully completed the 3-step authentication process. Your account is now fully verified and secure.
//           </p>
//         </div>

//         <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
//           {/* User Information */}
//           <div className="lg:col-span-2">
//             <div className="bg-white rounded-lg shadow p-6 mb-6">
//               <h3 className="text-lg font-semibold text-gray-900 mb-4">Account Information</h3>
              
//               <div className="space-y-4">
//                 <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
//                   <div className="flex items-center">
//                     <svg className="w-5 h-5 text-gray-400 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                       <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
//                     </svg>
//                     <div>
//                       <p className="text-sm font-medium text-gray-900">Email Address</p>
//                       <p className="text-sm text-gray-500">{email}</p>
//                     </div>
//                   </div>
//                   <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
//                     ✓ Verified
//                   </span>
//                 </div>

//                 <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
//                   <div className="flex items-center">
//                     <svg className="w-5 h-5 text-gray-400 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                       <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
//                     </svg>
//                     <div>
//                       <p className="text-sm font-medium text-gray-900">Phone Number</p>
//                       <p className="text-sm text-gray-500">{phone}</p>
//                     </div>
//                   </div>
//                   <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
//                     ✓ Verified
//                   </span>
//                 </div>

//                 <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
//                   <div className="flex items-center">
//                     <svg className="w-5 h-5 text-gray-400 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                       <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
//                     </svg>
//                     <div>
//                       <p className="text-sm font-medium text-gray-900">Biometric Authentication</p>
//                       <p className="text-sm text-gray-500">Device registered</p>
//                     </div>
//                   </div>
//                   <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
//                     ✓ Active
//                   </span>
//                 </div>
//               </div>
//             </div>

//             {/* Milestone 1 Features Preview */}
//             <div className="bg-white rounded-lg shadow p-6">
//               <h3 className="text-lg font-semibold text-gray-900 mb-4">Available Features (Milestone 1)</h3>
              
//               <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//                 <div className="p-4 border border-gray-200 rounded-lg">
//                   <div className="flex items-center mb-2">
//                     <svg className="w-5 h-5 text-green-500 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                       <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
//                     </svg>
//                     <h4 className="font-medium text-gray-900">Multi-Factor Authentication</h4>
//                   </div>
//                   <p className="text-sm text-gray-600">Email + SMS + Biometric verification</p>
//                 </div>

//                 <div className="p-4 border border-gray-200 rounded-lg">
//                   <div className="flex items-center mb-2">
//                     <svg className="w-5 h-5 text-green-500 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                       <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
//                     </svg>
//                     <h4 className="font-medium text-gray-900">User Management</h4>
//                   </div>
//                   <p className="text-sm text-gray-600">Role-based access control system</p>
//                 </div>

//                 <div className="p-4 border border-gray-200 rounded-lg">
//                   <div className="flex items-center mb-2">
//                     <svg className="w-5 h-5 text-green-500 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                       <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
//                     </svg>
//                     <h4 className="font-medium text-gray-900">Security Framework</h4>
//                   </div>
//                   <p className="text-sm text-gray-600">End-to-end encryption and security</p>
//                 </div>

//                 <div className="p-4 border border-gray-200 rounded-lg">
//                   <div className="flex items-center mb-2">
//                     <svg className="w-5 h-5 text-yellow-500 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                       <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
//                     </svg>
//                     <h4 className="font-medium text-gray-900">Election Management</h4>
//                   </div>
//                   <p className="text-sm text-gray-600">Coming in Milestone 2</p>
//                 </div>
//               </div>
//             </div>
//           </div>

//           {/* Security Panel */}
//           <div className="space-y-6">
//             <div className="bg-white rounded-lg shadow p-6">
//               <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Status</h3>
              
//               <div className="space-y-4">
//                 <div className="flex items-center justify-between">
//                   <span className="text-sm text-gray-600">Referrer Validation</span>
//                   <span className={`text-xs px-2 py-1 rounded-full ${securityMetrics.referrerValidated ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
//                     {securityMetrics.referrerValidated ? 'Valid' : 'Invalid'}
//                   </span>
//                 </div>

//                 <div className="flex items-center justify-between">
//                   <span className="text-sm text-gray-600">HTTPS Connection</span>
//                   <span className={`text-xs px-2 py-1 rounded-full ${securityMetrics.httpsEnabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
//                     {securityMetrics.httpsEnabled ? 'Secure' : 'Insecure'}
//                   </span>
//                 </div>

//                 <div className="flex items-center justify-between">
//                   <span className="text-sm text-gray-600">Device Fingerprint</span>
//                   <span className={`text-xs px-2 py-1 rounded-full ${securityMetrics.deviceFingerprinted ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}`}>
//                     {securityMetrics.deviceFingerprinted ? 'Captured' : 'Pending'}
//                   </span>
//                 </div>

//                 <div className="flex items-center justify-between">
//                   <span className="text-sm text-gray-600">Encryption</span>
//                   <span className={`text-xs px-2 py-1 rounded-full ${securityMetrics.encryptionEnabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
//                     {securityMetrics.encryptionEnabled ? 'Active' : 'Disabled'}
//                   </span>
//                 </div>
//               </div>
//             </div>

//             {/* System Info */}
//             <div className="bg-white rounded-lg shadow p-6">
//               <h3 className="text-lg font-semibold text-gray-900 mb-4">System Information</h3>
              
//               <div className="space-y-3 text-sm">
//                 <div className="flex justify-between">
//                   <span className="text-gray-600">Platform:</span>
//                   <span className="font-medium">{navigator.platform}</span>
//                 </div>
//                 <div className="flex justify-between">
//                   <span className="text-gray-600">Language:</span>
//                   <span className="font-medium">{navigator.language}</span>
//                 </div>
//                 <div className="flex justify-between">
//                   <span className="text-gray-600">Timezone:</span>
//                   <span className="font-medium">{Intl.DateTimeFormat().resolvedOptions().timeZone}</span>
//                 </div>
//                 <div className="flex justify-between">
//                   <span className="text-gray-600">Screen:</span>
//                   <span className="font-medium">{screen.width}x{screen.height}</span>
//                 </div>
//               </div>
//             </div>

//             {/* Next Milestones Preview */}
//             <div className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-lg p-6">
//               <h3 className="text-lg font-semibold text-blue-900 mb-4">Coming Soon</h3>
              
//               <div className="space-y-3">
//                 <div className="flex items-center">
//                   <div className="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
//                   <span className="text-sm text-blue-800">Election Creation & Management</span>
//                 </div>
//                 <div className="flex items-center">
//                   <div className="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
//                   <span className="text-sm text-blue-800">Multi-Method Voting System</span>
//                 </div>
//                 <div className="flex items-center">
//                   <div className="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
//                   <span className="text-sm text-blue-800">3D/4D Lottery Integration</span>
//                 </div>
//                 <div className="flex items-center">
//                   <div className="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
//                   <span className="text-sm text-blue-800">Payment Processing</span>
//                 </div>
//                 <div className="flex items-center">
//                   <div className="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
//                   <span className="text-sm text-blue-800">Mobile Applications</span>
//                 </div>
//               </div>
//             </div>
//           </div>
//         </div>
//       </main>
//     </div>
//   );
// };

// export default Dashboard;



