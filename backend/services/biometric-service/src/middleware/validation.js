import { BiometricUtils } from '../utils/biometricUtils.js';
import { DeviceUtils } from '../utils/deviceUtils.js';
import { validateInput } from '../utils/validators.js';

export const validateDevice = (req, res, next) => {
  try {
    const { sngine_email, sngine_phone, deviceInfo, location, capabilities } = req.body;
    
    console.log("sngine_email===>", sngine_email);
    console.log("sngine_phone===>", sngine_phone);
    console.log("deviceInfo===>", deviceInfo);

    // Validate required fields - at least one identifier is required
    if (!sngine_email && !sngine_phone) {
      return res.status(400).json({
        success: false,
        message: 'Either sngine_email or sngine_phone is required'
      });
    }

    // Validate email format if provided
    if (sngine_email && !validateInput.isValidEmail(sngine_email)) {
      return res.status(400).json({
        success: false,
        message: 'Valid email is required'
      });
    }

    // Validate phone format if provided
    if (sngine_phone && !validateInput.isValidPhone(sngine_phone)) {
      return res.status(400).json({
        success: false,
        message: 'Valid phone number is required'
      });
    }

    if (!deviceInfo || typeof deviceInfo !== 'object') {
      return res.status(400).json({
        success: false,
        message: 'Device information is required'
      });
    }

    // Validate device data structure (no userId required in validation)
    try {
      DeviceUtils.validateDeviceData(req.body);
    } catch (deviceError) {
      return res.status(400).json({
        success: false,
        message: deviceError.message
      });
    }

    next();
  } catch (error) {
    res.status(400).json({
      success: false,
      message: error.message
    });
  }
};

export const validateBiometric = (req, res, next) => {
  try {
    const { sngine_email, sngine_phone, deviceId, biometricType, biometricData } = req.body;

    console.log("Biometric validation - sngine_email:", sngine_email);
    console.log("Biometric validation - sngine_phone:", sngine_phone);
    console.log("Biometric validation - deviceId:", deviceId);
    console.log("Biometric validation - biometricType:", biometricType);

    // Validate required fields - at least one identifier is required
    if (!sngine_email && !sngine_phone) {
      return res.status(400).json({
        success: false,
        message: 'Either sngine_email or sngine_phone is required'
      });
    }

    // Validate email format if provided
    if (sngine_email && !validateInput.isValidEmail(sngine_email)) {
      return res.status(400).json({
        success: false,
        message: 'Valid email is required'
      });
    }

    // Validate phone format if provided
    if (sngine_phone && !validateInput.isValidPhone(sngine_phone)) {
      return res.status(400).json({
        success: false,
        message: 'Valid phone number is required'
      });
    }

    if (!deviceId || !validateInput.isValidId(deviceId)) {
      return res.status(400).json({
        success: false,
        message: 'Valid device ID is required'
      });
    }

    if (!biometricType || !validateInput.isValidBiometricType(biometricType)) {
      return res.status(400).json({
        success: false,
        message: 'Valid biometric type is required (fingerprint, face, voice, iris, webauthn)'
      });
    }

    if (!biometricData) {
      return res.status(400).json({
        success: false,
        message: 'Biometric data is required'
      });
    }

    // Validate biometric data format
    if (!BiometricUtils.validateBiometricData(biometricData, biometricType)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid biometric data format'
      });
    }

    next();
  } catch (error) {
    res.status(400).json({
      success: false,
      message: error.message
    });
  }
};
// import { BiometricUtils } from '../utils/biometricUtils.js';
// import { DeviceUtils } from '../utils/deviceUtils.js';
// import { validateInput } from '../utils/validators.js';

// export const validateDevice = (req, res, next) => {
//   try {
//     //const { userId, deviceInfo } = req.body;
//     const {  deviceInfo } = req.body;
//     console.log("userId===>", userId)
//     console.log("deviceInfo===>", deviceInfo)
//     // Validate required fields
//     if (!userId || !validateInput.isValidId(userId)) {
//       return res.status(400).json({
//         success: false,
//         message: 'Valid user ID is required'
//       });
//     }

//     if (!deviceInfo || typeof deviceInfo !== 'object') {
//       return res.status(400).json({
//         success: false,
//         message: 'Device information is required'
//       });
//     }

//     // Validate device data structure
//     DeviceUtils.validateDeviceData(req.body);

//     next();
//   } catch (error) {
//     res.status(400).json({
//       success: false,
//       message: error.message
//     });
//   }
// };

// export const validateBiometric = (req, res, next) => {
//   try {
//     //const { userId, deviceId, biometricType, biometricData } = req.body;
//     const {  deviceId, biometricType, biometricData } = req.body;

//     // Validate required fields
//     if (!userId || !validateInput.isValidId(userId)) {
//       return res.status(400).json({
//         success: false,
//         message: 'Valid user ID is required'
//       });
//     }

//     if (!deviceId || !validateInput.isValidId(deviceId)) {
//       return res.status(400).json({
//         success: false,
//         message: 'Valid device ID is required'
//       });
//     }

//     if (!biometricType || !validateInput.isValidBiometricType(biometricType)) {
//       return res.status(400).json({
//         success: false,
//         message: 'Valid biometric type is required (fingerprint, face, voice, iris, webauthn)'
//       });
//     }

//     if (!biometricData) {
//       return res.status(400).json({
//         success: false,
//         message: 'Biometric data is required'
//       });
//     }

//     // Validate biometric data format
//     if (!BiometricUtils.validateBiometricData(biometricData, biometricType)) {
//       return res.status(400).json({
//         success: false,
//         message: 'Invalid biometric data format'
//       });
//     }

//     next();
//   } catch (error) {
//     res.status(400).json({
//       success: false,
//       message: error.message
//     });
//   }
// };