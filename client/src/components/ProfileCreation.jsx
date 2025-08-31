//This is final for role based redirct
import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';

const ProfileCreation = () => {
  const { 
    completeProfileCreation, 
    isLoading, 
    error, 
    goBackStep,
    email,
    phone,
    userId
  } = useAuth();

  const [formData, setFormData] = useState({
    first_name: '',
    last_name: '',
    date_of_birth: '',
    gender: '',
    country: '',
    city: '',
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
  });

  const [step, setStep] = useState(1); // 1: Basic Info, 2: Demographics, 3: Preferences

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleNext = () => {
    if (step < 3) setStep(step + 1);
  };

  const handlePrev = () => {
    if (step > 1) setStep(step - 1);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      // Prepare data for API call
      const profileData = {
        ...formData,
        // Add any additional data processing here
        user_age: formData.date_of_birth ? calculateAge(formData.date_of_birth) : null,
        user_gender: formData.gender,
        user_country: formData.country
      };

      await completeProfileCreation(profileData);
    } catch (error) {
      console.error('Profile creation failed:', error);
    }
  };

  const calculateAge = (dateOfBirth) => {
    const today = new Date();
    const birthDate = new Date(dateOfBirth);
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
      age--;
    }
    
    return age;
  };

  const countries = [
    'Afghanistan', 'Albania', 'Algeria', 'Argentina', 'Australia', 'Austria',
    'Bangladesh', 'Belgium', 'Brazil', 'Canada', 'China', 'Denmark',
    'Egypt', 'Finland', 'France', 'Germany', 'India', 'Indonesia',
    'Italy', 'Japan', 'Malaysia', 'Mexico', 'Netherlands', 'Norway',
    'Pakistan', 'Philippines', 'Russia', 'Singapore', 'South Korea',
    'Spain', 'Sweden', 'Switzerland', 'Thailand', 'Turkey', 'Ukraine',
    'United Kingdom', 'United States', 'Vietnam'
  ];

  return (
    <div className="bg-white rounded-lg shadow-lg p-8 w-full max-w-md mx-auto">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Complete Your Profile</h2>
        <p className="text-sm text-gray-600 mb-4">
          Step {step} of 3 - Help us personalize your Vottery experience
        </p>
        
        {/* Progress Bar */}
        <div className="w-full bg-gray-200 rounded-full h-2 mb-4">
          <div 
            className="bg-blue-600 h-2 rounded-full transition-all duration-300"
            style={{ width: `${(step / 3) * 100}%` }}
          ></div>
        </div>

        {/* User Info Display */}
        <div className="bg-gray-50 rounded-lg p-3 mb-4 text-sm">
          <div className="font-medium text-gray-700 mb-1">Verified Account:</div>
          <div className="text-gray-600">{email}</div>
          <div className="text-gray-600">{phone}</div>
          
        </div>
      </div>

      {error && (
        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-sm text-red-700">{error}</p>
        </div>
      )}

      <form onSubmit={handleSubmit}>
        {/* Step 1: Basic Information */}
        {step === 1 && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-800 mb-4">Basic Information</h3>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                First Name *
              </label>
              <input
                type="text"
                name="first_name"
                value={formData.first_name}
                onChange={handleInputChange}
                required
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Enter your first name"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Last Name *
              </label>
              <input
                type="text"
                name="last_name"
                value={formData.last_name}
                onChange={handleInputChange}
                required
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Enter your last name"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Date of Birth
              </label>
              <input
                type="date"
                name="date_of_birth"
                value={formData.date_of_birth}
                onChange={handleInputChange}
                max={new Date().toISOString().split('T')[0]}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
        )}

        {/* Step 2: Demographics */}
        {step === 2 && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-800 mb-4">Demographics</h3>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Gender
              </label>
              <select
                name="gender"
                value={formData.gender}
                onChange={handleInputChange}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="">Select Gender</option>
                <option value="male">Male</option>
                <option value="female">Female</option>
                <option value="other">Other</option>
                <option value="prefer_not_to_say">Prefer not to say</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Country *
              </label>
              <select
                name="country"
                value={formData.country}
                onChange={handleInputChange}
                required
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="">Select Country</option>
                {countries.map(country => (
                  <option key={country} value={country}>{country}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                City
              </label>
              <input
                type="text"
                name="city"
                value={formData.city}
                onChange={handleInputChange}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Enter your city"
              />
            </div>
          </div>
        )}

        {/* Step 3: Preferences & Review */}
        {step === 3 && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-800 mb-4">Review & Complete</h3>
            
            <div className="bg-gray-50 rounded-lg p-4 space-y-3">
              <h4 className="font-medium text-gray-800">Profile Summary:</h4>
              
              <div className="grid grid-cols-1 gap-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600">Name:</span>
                  <span className="font-medium">{formData.first_name} {formData.last_name}</span>
                </div>
                
                {formData.date_of_birth && (
                  <div className="flex justify-between">
                    <span className="text-gray-600">Age:</span>
                    <span className="font-medium">{calculateAge(formData.date_of_birth)} years</span>
                  </div>
                )}
                
                {formData.gender && (
                  <div className="flex justify-between">
                    <span className="text-gray-600">Gender:</span>
                    <span className="font-medium capitalize">{formData.gender.replace('_', ' ')}</span>
                  </div>
                )}
                
                <div className="flex justify-between">
                  <span className="text-gray-600">Country:</span>
                  <span className="font-medium">{formData.country}</span>
                </div>
                
                {formData.city && (
                  <div className="flex justify-between">
                    <span className="text-gray-600">City:</span>
                    <span className="font-medium">{formData.city}</span>
                  </div>
                )}
                
                <div className="flex justify-between">
                  <span className="text-gray-600">Timezone:</span>
                  <span className="font-medium">{formData.timezone}</span>
                </div>
              </div>
            </div>

            <div className="bg-blue-50 rounded-lg p-4">
              <h4 className="font-medium text-blue-800 mb-2">Account Defaults:</h4>
              <div className="text-sm text-blue-700 space-y-1">
                <div>• User Type: Voter</div>
                <div>• Admin Role: Analyst (can be changed by admin)</div>
                <div>• Subscription: Free (can be upgraded)</div>
              </div>
            </div>
          </div>
        )}

        {/* Navigation Buttons */}
        <div className="flex justify-between items-center mt-6">
          <div className="flex space-x-2">
            {step > 1 && (
              <button
                type="button"
                onClick={handlePrev}
                className="px-4 py-2 text-gray-600 bg-gray-100 rounded-lg hover:bg-gray-200 transition duration-200"
              >
                Previous
              </button>
            )}
            
            <button
              type="button"
              onClick={goBackStep}
              className="px-4 py-2 text-blue-600 bg-blue-50 rounded-lg hover:bg-blue-100 transition duration-200"
            >
              Back to Biometric
            </button>
          </div>

          <div>
            {step < 3 ? (
              <button
                type="button"
                onClick={handleNext}
                disabled={step === 1 && (!formData.first_name || !formData.last_name)}
                className="px-6 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white rounded-lg transition duration-200"
              >
                Next
              </button>
            ) : (
              <button
                type="submit"
                disabled={isLoading || !formData.first_name || !formData.last_name || !formData.country}
                className="px-6 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white rounded-lg transition duration-200 flex items-center"
              >
                {isLoading ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Creating Profile...
                  </>
                ) : (
                  'Complete Registration'
                )}
              </button>
            )}
          </div>
        </div>

        {/* Step indicators */}
        <div className="flex justify-center mt-4 space-x-2">
          {[1, 2, 3].map((stepNumber) => (
            <div
              key={stepNumber}
              className={`w-2 h-2 rounded-full transition-colors duration-200 ${
                stepNumber <= step ? 'bg-blue-600' : 'bg-gray-300'
              }`}
            />
          ))}
        </div>
      </form>

      {/* API Integration Info */}
      <div className="mt-6 p-3 bg-green-50 border border-green-200 rounded-lg text-xs text-green-700">
        <div className="font-medium mb-1">API Integration Ready:</div>
        <div>This form will send data to api3003 (/api/users/create) with:</div>
        <div className="mt-1 font-mono text-green-600">
          • user_id: {userId}<br/>
          • sngine_email: {email}<br/>
          • sngine_phone: {phone}<br/>
          • Profile data & demographics
        </div>
      </div>
    </div>
  );
};

export default ProfileCreation;
// import React, { useState } from 'react';
// import { useAuth } from '../contexts/AuthContext';

// const ProfileCreation = () => {
//   const { email, phone, completeProfileCreation, isLoading, error } = useAuth();
  
//   const [formData, setFormData] = useState({
//     first_name: '',
//     last_name: '',
//     date_of_birth: '',
//     gender: '',
//     country: '',
//     city: '',
//     timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
//     user_type: 'voter', // Default to voter
//     admin_role: 'analyst', // Default admin role
//     subscription_status: 'free'
//   });

//   const [step, setStep] = useState(1);
//   const [formErrors, setFormErrors] = useState({});

//   // Country options (simplified list)
//   const countries = [
//     'Afghanistan', 'Albania', 'Algeria', 'Argentina', 'Australia', 'Austria',
//     'Bangladesh', 'Belgium', 'Brazil', 'Canada', 'China', 'Denmark',
//     'Egypt', 'Finland', 'France', 'Germany', 'India', 'Indonesia',
//     'Italy', 'Japan', 'Malaysia', 'Netherlands', 'Norway', 'Pakistan',
//     'Philippines', 'Singapore', 'South Korea', 'Spain', 'Sweden',
//     'Switzerland', 'Thailand', 'Turkey', 'United Kingdom', 'United States',
//     'Vietnam'
//   ];

//   const userTypes = [
//     { value: 'voter', label: 'Voter', description: 'Participate in elections and voting' },
//     { value: 'individual_creator', label: 'Individual Election Creator', description: 'Create personal elections' },
//     { value: 'organization_creator', label: 'Organization Election Creator', description: 'Create elections for organizations' }
//   ];

//   const adminRoles = [
//     { value: 'analyst', label: 'Analyst', description: 'Data analysis and reporting' },
//     { value: 'editor', label: 'Editor', description: 'Content management' },
//     { value: 'moderator', label: 'Moderator', description: 'Content moderation' },
//     { value: 'auditor', label: 'Auditor', description: 'System auditing' },
//     { value: 'advertiser', label: 'Advertiser', description: 'Advertisement management' },
//     { value: 'admin', label: 'Admin', description: 'System administration' },
//     { value: 'manager', label: 'Manager', description: 'User and system management' }
//   ];

//   const validateStep = (stepNumber) => {
//     const errors = {};
    
//     if (stepNumber === 1) {
//       if (!formData.first_name?.trim()) errors.first_name = 'First name is required';
//       if (!formData.last_name?.trim()) errors.last_name = 'Last name is required';
//       if (!formData.date_of_birth) errors.date_of_birth = 'Date of birth is required';
//       if (!formData.gender) errors.gender = 'Gender is required';
//     }
    
//     if (stepNumber === 2) {
//       if (!formData.country) errors.country = 'Country is required';
//       if (!formData.city?.trim()) errors.city = 'City is required';
//     }
    
//     setFormErrors(errors);
//     return Object.keys(errors).length === 0;
//   };

//   const handleInputChange = (e) => {
//     const { name, value } = e.target;
//     setFormData(prev => ({ ...prev, [name]: value }));
    
//     // Clear error for this field
//     if (formErrors[name]) {
//       setFormErrors(prev => ({ ...prev, [name]: '' }));
//     }
//   };

//   const handleNextStep = () => {
//     if (validateStep(step)) {
//       setStep(step + 1);
//     }
//   };

//   const handlePrevStep = () => {
//     setStep(step - 1);
//   };

//   const handleSubmit = async (e) => {
//     e.preventDefault();
    
//     if (!validateStep(2)) return;

//     try {
//       // Calculate age from date of birth
//       const birthDate = new Date(formData.date_of_birth);
//       const today = new Date();
//       const age = today.getFullYear() - birthDate.getFullYear();
      
//       const profileData = {
//         ...formData,
//         sngine_email: email,
//         sngine_phone: phone,
//         user_age: age,
//         user_gender: formData.gender,
//         user_country: formData.country
//       };

//       await completeProfileCreation(profileData);
//     } catch (error) {
//       console.error('Profile creation failed:', error);
//     }
//   };

//   const renderStep1 = () => (
//     <div className="space-y-6">
//       <div className="text-center mb-6">
//         <h3 className="text-xl font-semibold text-gray-900 mb-2">Personal Information</h3>
//         <p className="text-gray-600">Tell us about yourself</p>
//       </div>

//       <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
//         <div>
//           <label className="block text-sm font-medium text-gray-700 mb-2">
//             First Name *
//           </label>
//           <input
//             type="text"
//             name="first_name"
//             value={formData.first_name}
//             onChange={handleInputChange}
//             className={`w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
//               formErrors.first_name ? 'border-red-500' : 'border-gray-300'
//             }`}
//             placeholder="Enter your first name"
//           />
//           {formErrors.first_name && (
//             <p className="text-red-500 text-xs mt-1">{formErrors.first_name}</p>
//           )}
//         </div>

//         <div>
//           <label className="block text-sm font-medium text-gray-700 mb-2">
//             Last Name *
//           </label>
//           <input
//             type="text"
//             name="last_name"
//             value={formData.last_name}
//             onChange={handleInputChange}
//             className={`w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
//               formErrors.last_name ? 'border-red-500' : 'border-gray-300'
//             }`}
//             placeholder="Enter your last name"
//           />
//           {formErrors.last_name && (
//             <p className="text-red-500 text-xs mt-1">{formErrors.last_name}</p>
//           )}
//         </div>
//       </div>

//       <div>
//         <label className="block text-sm font-medium text-gray-700 mb-2">
//           Date of Birth *
//         </label>
//         <input
//           type="date"
//           name="date_of_birth"
//           value={formData.date_of_birth}
//           onChange={handleInputChange}
//           max={new Date().toISOString().split('T')[0]}
//           className={`w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
//             formErrors.date_of_birth ? 'border-red-500' : 'border-gray-300'
//           }`}
//         />
//         {formErrors.date_of_birth && (
//           <p className="text-red-500 text-xs mt-1">{formErrors.date_of_birth}</p>
//         )}
//       </div>

//       <div>
//         <label className="block text-sm font-medium text-gray-700 mb-2">
//           Gender *
//         </label>
//         <select
//           name="gender"
//           value={formData.gender}
//           onChange={handleInputChange}
//           className={`w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
//             formErrors.gender ? 'border-red-500' : 'border-gray-300'
//           }`}
//         >
//           <option value="">Select gender</option>
//           <option value="male">Male</option>
//           <option value="female">Female</option>
//           <option value="other">Other</option>
//           <option value="prefer_not_to_say">Prefer not to say</option>
//         </select>
//         {formErrors.gender && (
//           <p className="text-red-500 text-xs mt-1">{formErrors.gender}</p>
//         )}
//       </div>
//     </div>
//   );

//   const renderStep2 = () => (
//     <div className="space-y-6">
//       <div className="text-center mb-6">
//         <h3 className="text-xl font-semibold text-gray-900 mb-2">Location & Preferences</h3>
//         <p className="text-gray-600">Complete your profile setup</p>
//       </div>

//       <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
//         <div>
//           <label className="block text-sm font-medium text-gray-700 mb-2">
//             Country *
//           </label>
//           <select
//             name="country"
//             value={formData.country}
//             onChange={handleInputChange}
//             className={`w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
//               formErrors.country ? 'border-red-500' : 'border-gray-300'
//             }`}
//           >
//             <option value="">Select country</option>
//             {countries.map(country => (
//               <option key={country} value={country}>{country}</option>
//             ))}
//           </select>
//           {formErrors.country && (
//             <p className="text-red-500 text-xs mt-1">{formErrors.country}</p>
//           )}
//         </div>

//         <div>
//           <label className="block text-sm font-medium text-gray-700 mb-2">
//             City *
//           </label>
//           <input
//             type="text"
//             name="city"
//             value={formData.city}
//             onChange={handleInputChange}
//             className={`w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
//               formErrors.city ? 'border-red-500' : 'border-gray-300'
//             }`}
//             placeholder="Enter your city"
//           />
//           {formErrors.city && (
//             <p className="text-red-500 text-xs mt-1">{formErrors.city}</p>
//           )}
//         </div>
//       </div>

//       <div>
//         <label className="block text-sm font-medium text-gray-700 mb-2">
//           User Type
//         </label>
//         <div className="space-y-3">
//           {userTypes.map(type => (
//             <div key={type.value} className="flex items-start">
//               <input
//                 type="radio"
//                 name="user_type"
//                 value={type.value}
//                 checked={formData.user_type === type.value}
//                 onChange={handleInputChange}
//                 className="mt-1 mr-3"
//               />
//               <div>
//                 <div className="font-medium text-gray-900">{type.label}</div>
//                 <div className="text-sm text-gray-600">{type.description}</div>
//               </div>
//             </div>
//           ))}
//         </div>
//       </div>

//       <div>
//         <label className="block text-sm font-medium text-gray-700 mb-2">
//           Admin Role
//         </label>
//         <select
//           name="admin_role"
//           value={formData.admin_role}
//           onChange={handleInputChange}
//           className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
//         >
//           {adminRoles.map(role => (
//             <option key={role.value} value={role.value}>{role.label} - {role.description}</option>
//           ))}
//         </select>
//       </div>

//       <div>
//         <label className="block text-sm font-medium text-gray-700 mb-2">
//           Subscription Preference
//         </label>
//         <div className="space-y-2">
//           <div className="flex items-center">
//             <input
//               type="radio"
//               name="subscription_status"
//               value="free"
//               checked={formData.subscription_status === 'free'}
//               onChange={handleInputChange}
//               className="mr-3"
//             />
//             <div>
//               <div className="font-medium text-gray-900">Free Account</div>
//               <div className="text-sm text-gray-600">Limited features</div>
//             </div>
//           </div>
//           <div className="flex items-center">
//             <input
//               type="radio"
//               name="subscription_status"
//               value="subscribed"
//               checked={formData.subscription_status === 'subscribed'}
//               onChange={handleInputChange}
//               className="mr-3"
//             />
//             <div>
//               <div className="font-medium text-gray-900">Premium Account</div>
//               <div className="text-sm text-gray-600">Unlimited features</div>
//             </div>
//           </div>
//         </div>
//       </div>
//     </div>
//   );

//   return (
//     <div className="bg-white rounded-lg shadow-lg p-6 max-w-2xl mx-auto">
//       {/* Progress Indicator */}
//       <div className="mb-6">
//         <div className="flex items-center justify-center space-x-4">
//           <div className={`flex items-center ${step >= 1 ? 'text-blue-600' : 'text-gray-400'}`}>
//             <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
//               step >= 1 ? 'bg-blue-600 text-white' : 'bg-gray-300 text-gray-600'
//             }`}>
//               1
//             </div>
//             <span className="ml-2 text-sm font-medium">Personal</span>
//           </div>
          
//           <div className={`h-px w-12 ${step >= 2 ? 'bg-blue-600' : 'bg-gray-300'}`}></div>
          
//           <div className={`flex items-center ${step >= 2 ? 'text-blue-600' : 'text-gray-400'}`}>
//             <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
//               step >= 2 ? 'bg-blue-600 text-white' : 'bg-gray-300 text-gray-600'
//             }`}>
//               2
//             </div>
//             <span className="ml-2 text-sm font-medium">Complete</span>
//           </div>
//         </div>
//       </div>

//       {/* Current Account Info */}
//       <div className="bg-gray-50 rounded-lg p-4 mb-6">
//         <h4 className="font-medium text-gray-900 mb-2">Creating profile for:</h4>
//         <div className="text-sm text-gray-600">
//           <div>Email: {email}</div>
//           <div>Phone: {phone}</div>
//         </div>
//       </div>

//       {/* Form Content */}
//       <form onSubmit={handleSubmit}>
//         {step === 1 && renderStep1()}
//         {step === 2 && renderStep2()}

//         {/* Error Display */}
//         {error && (
//           <div className="mt-4 bg-red-50 border border-red-200 rounded-lg p-4">
//             <div className="flex">
//               <svg className="h-5 w-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
//               </svg>
//               <div className="ml-3">
//                 <p className="text-sm text-red-700">{error}</p>
//               </div>
//             </div>
//           </div>
//         )}

//         {/* Navigation Buttons */}
//         <div className="flex justify-between mt-8">
//           {step > 1 ? (
//             <button
//               type="button"
//               onClick={handlePrevStep}
//               className="px-6 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition duration-200"
//             >
//               Previous
//             </button>
//           ) : (
//             <div></div>
//           )}

//           {step < 2 ? (
//             <button
//               type="button"
//               onClick={handleNextStep}
//               className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition duration-200"
//             >
//               Next
//             </button>
//           ) : (
//             <button
//               type="submit"
//               disabled={isLoading}
//               className="px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 transition duration-200"
//             >
//               {isLoading ? 'Creating Profile...' : 'Complete Profile'}
//             </button>
//           )}
//         </div>
//       </form>
//     </div>
//   );
// };

// export default ProfileCreation;