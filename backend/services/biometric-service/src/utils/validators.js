export const validateInput = {
    isValidId(id) {
      return id && !isNaN(parseInt(id)) && parseInt(id) > 0;
    },
  
    isValidEmail(email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return emailRegex.test(email);
    },
  
    isValidPhone(phone) {
      const phoneRegex = /^\+[1-9]\d{7,14}$/;
      return phoneRegex.test(phone);
    },
  
    // isValidBiometricType(type) {
    //   const validTypes = ['fingerprint', 'face', 'voice', 'iris', 'webauthn'];
    //   return validTypes.includes(type);
    // },
    isValidBiometricType: (type) => {
      const validTypes = ['fingerprint', 'face', 'voice', 'iris', 'webauthn', 'device_fingerprint'];
      return validTypes.includes(type);
    },
  
    isValidDeviceType(type) {
      const validTypes = ['desktop', 'laptop', 'tablet', 'mobile', 'ios', 'android', 'windows', 'macos', 'linux'];
      return validTypes.includes(type);
    }
  };