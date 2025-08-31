//FInal role management
//proper dashboard management from database
//Complete AuthContext with Database-Driven Role Management - FULL VERSION
import React, { createContext, useContext, useReducer, useCallback, useEffect, useState, useRef } from 'react';
import { useSecurity } from './SecurityContext';
import { SecurityUtils } from '../utils/security';
import { toast } from 'react-hot-toast';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

// Token Management Utility with Rotation Support
const TokenManager = {
  setTokens: (accessToken, refreshToken, expiryInfo) => {
    localStorage.setItem('vottery_access_token', accessToken);
    localStorage.setItem('vottery_refresh_token', refreshToken);
    localStorage.setItem('vottery_token_expiry', JSON.stringify(expiryInfo));
    localStorage.setItem('vottery_token_timestamp', Date.now().toString());
  },

  getAccessToken: () => localStorage.getItem('vottery_access_token'),
  
  getRefreshToken: () => localStorage.getItem('vottery_refresh_token'),
  
  clearTokens: () => {
    localStorage.removeItem('vottery_access_token');
    localStorage.removeItem('vottery_refresh_token');
    localStorage.removeItem('vottery_token_expiry');
    localStorage.removeItem('vottery_token_timestamp');
    localStorage.removeItem('vottery_user_data');
  },

  isTokenExpired: () => {
    const timestamp = localStorage.getItem('vottery_token_timestamp');
    if (!timestamp) return true;
    
    // Assuming 7 days expiry (7 * 24 * 60 * 60 * 1000)
    const tokenAge = Date.now() - parseInt(timestamp);
    const maxAge = 7 * 24 * 60 * 60 * 1000;
    
    return tokenAge >= maxAge;
  }
};

// Request deduplication cache
const requestCache = new Map();
const CACHE_DURATION = 30000; // 30 seconds

// Auth reducer
const authReducer = (state, action) => {
  switch (action.type) {
    case 'SET_LOADING':
      return { ...state, isLoading: action.payload };
    case 'SET_STEP':
      return { ...state, currentStep: action.payload };
    case 'SET_EMAIL':
      return { ...state, email: SecurityUtils.sanitizeInput(action.payload) };
    case 'SET_PHONE':
      return { ...state, phone: SecurityUtils.sanitizeInput(action.payload) };
    case 'SET_EMAIL_VERIFIED':
      return { ...state, emailVerified: action.payload };
    case 'SET_PHONE_VERIFIED':
      return { ...state, phoneVerified: action.payload };
    case 'SET_BIOMETRIC_VERIFIED':
      return { ...state, biometricVerified: action.payload };
    case 'SET_PROFILE_CREATED':
      return { ...state, profileCreated: action.payload };
    case 'SET_AUTHENTICATED':
      return { ...state, isAuthenticated: action.payload };
    case 'SET_USER_DATA':
      return { ...state, userData: action.payload };
    case 'SET_USER_ID':
      return { ...state, userId: action.payload };
    case 'SET_ERROR':
      return { ...state, error: action.payload };
    case 'SET_REFERRER_VALID':
      return { ...state, isValidReferrer: action.payload, referrerInfo: action.referrerInfo };
    case 'SET_FALLBACK_QUESTIONS':
      return { ...state, fallbackQuestions: action.payload };
    case 'SET_FALLBACK_SETUP_COMPLETE':
      return { ...state, fallbackSetupComplete: action.payload };
    case 'SET_BIOMETRIC_KEYS':
      return { ...state, biometricKeys: action.payload };
    case 'SET_SECURITY_QUESTIONS_SETUP':
      return { ...state, securityQuestionsSetup: action.payload };
    case 'SET_COLLECTED_QUESTIONS':
      return { ...state, collectedSecurityQuestions: action.payload };
    case 'SET_FALLBACK_STEP':
      return { ...state, fallbackStep: action.payload };
    case 'RESET_AUTH':
      return {
        ...state,
        currentStep: 1,
        email: '',
        phone: '',
        userId: null,
        emailVerified: false,
        phoneVerified: false,
        biometricVerified: false,
        profileCreated: false,
        error: null,
        isAuthenticated: false,
        userData: null,
        fallbackQuestions: [],
        fallbackSetupComplete: false,
        biometricKeys: null,
        securityQuestionsSetup: false,
        collectedSecurityQuestions: [],
        fallbackStep: null
      };
    case 'SET_OTP_SENT':
      return { ...state, otpSent: action.payload };
    case 'SET_RESEND_COOLDOWN':
      return { ...state, resendCooldown: action.payload };
    default:
      return state;
  }
};

const initialState = {
  isAuthenticated: false,
  isLoading: false,
  currentStep: 1,
  email: '',
  phone: '',
  userId: null,
  emailVerified: false,
  phoneVerified: false,
  biometricVerified: false,
  profileCreated: false,
  userData: null,
  error: null,
  isValidReferrer: false,
  referrerInfo: null,
  otpSent: false,
  resendCooldown: 0,
  fallbackQuestions: [],
  fallbackSetupComplete: false,
  biometricKeys: null,
  securityQuestionsSetup: false,
  collectedSecurityQuestions: [],
  fallbackStep: null
};

// Utilities
const b64ToBytes = (b64) => {
  const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 2 ? '==' : normalized.length % 4 === 3 ? '=' : '';
  const str = atob(normalized + pad);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes;
};

const createApiRequest = (BASE) => {
  return async (endpoint, options = {}) => {
    const isAbsolute = /^https?:\/\//i.test(endpoint);
    const url = isAbsolute ? endpoint : `${BASE}${endpoint}`;

    // Check cache for GET requests to prevent duplicate calls
    if (options.method === 'GET' || !options.method) {
      const cacheKey = `${url}_${JSON.stringify(options.body || {})}`;
      const cached = requestCache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
        console.log('Returning cached response for:', url);
        return cached.data;
      }
    }

    const config = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-Referrer': typeof document !== 'undefined' ? document.referrer : '',
        ...(options.headers || {})
      },
      ...options
    };

    // Add Authorization header if access token exists
    const accessToken = TokenManager.getAccessToken();
    if (accessToken && !config.headers.Authorization) {
      config.headers.Authorization = `Bearer ${accessToken}`;
    }

    if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
      config.body = JSON.stringify(config.body);
    }

    try {
      const response = await fetch(url, config);
      const data = await response.json().catch(() => null);

      if (!response.ok) {
        // Handle rate limiting with exponential backoff
        if (response.status === 429) {
          console.warn('Rate limited, using cached data if available');
          const cacheKey = `${url}_${JSON.stringify(options.body || {})}`;
          const cached = requestCache.get(cacheKey);
          if (cached) {
            return cached.data;
          }
          throw new Error('Rate limited and no cached data available');
        }
        
        const error = new Error((data && data.message) || `HTTP error! status: ${response.status}`);
        error.response = { data };
        throw error;
      }

      // Cache successful GET responses
      if (config.method === 'GET' || !config.method) {
        const cacheKey = `${url}_${JSON.stringify(options.body || {})}`;
        requestCache.set(cacheKey, { data, timestamp: Date.now() });
      }

      return data;
    } catch (error) {
      console.error(`API request failed for ${url}:`, error);
      if (error.response) throw error;
      throw new Error('Network error. Please check your connection and try again.');
    }
  };
};

export const AuthProvider = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState);
  const [rolePermissions, setRolePermissions] = useState(null);
  const securityContext = useSecurity();
  const hasInitialized = useRef(false);
  const roleCheckInProgress = useRef(false);

  // Safe access to security functions with fallbacks
  const {
    checkReferrer = () => ({ isValid: false, referrer: '', error: 'Security context unavailable' }),
    encryptData = (data) => JSON.stringify(data),
    decryptData = (data) => JSON.parse(data),
    generateDeviceFingerprint = () => Promise.resolve('fallback-fingerprint'),
    createSession = () => {},
    clearSession = () => {}
  } = securityContext || {};

  const API_BASE_3001 = import.meta.env?.VITE_API_BASE_URL || 'http://localhost:3001';
  const API_BASE_3002 = import.meta.env?.VITE_BIOMETRIC_API_BASE_URL || 'http://localhost:3002';
  const API_BASE_3003 = import.meta.env?.VITE_USER_MANAGEMENT_API_BASE_URL|| 'http://localhost:3003';

  const api3001 = useCallback(createApiRequest(API_BASE_3001), [API_BASE_3001]);
  const api3002 = useCallback(createApiRequest(API_BASE_3002), [API_BASE_3002]);
  const api3003 = useCallback(createApiRequest(API_BASE_3003), [API_BASE_3003]);

  // DATABASE-DRIVEN ROLE MANAGEMENT FUNCTIONS
  
  // Derive permissions from role based on milestone document
  const derivePermissionsFromRole = useCallback((adminRole) => {
    if (!adminRole || adminRole === 'user') return [];
    
    
    const rolePermissionMap = {
      // Super Admin Roles - Full privileges
      'manager': [
        'manage_users', 'manage_elections', 'view_analytics', 
        'manage_content', 'view_audit', 'manage_ads', 'super_admin',
        'manage_subscriptions', 'manage_payments', 'system_config'
      ],
      'admin': [
        'manage_users', 'manage_elections', 'view_analytics', 
        'manage_content', 'view_audit', 'manage_ads', 'super_admin',
        'manage_subscriptions', 'manage_payments'
      ],
      
      // Functional Admin Roles - Limited privileges
      'moderator': ['manage_elections', 'manage_content', 'view_analytics'],
      'auditor': ['view_audit', 'view_analytics', 'audit_elections'],
      'editor': ['manage_content', 'edit_elections'],
      'advertiser': ['manage_ads', 'view_analytics', 'campaign_management'],
      
      // Specialized Role - Data access only (NOT ADMIN)
      'analyst': ['view_analytics', 'export_data', 'generate_reports']
    };
    
    return rolePermissionMap[adminRole.toLowerCase()] || [];
  }, []);

  // Fetch fresh role permissions from database (FIXED - prevents infinite calls)
  const fetchRolePermissions = useCallback(async (userId = null, forceRefresh = false) => {
    const targetUserId = userId || state.userData?.id;
    if (!targetUserId || roleCheckInProgress.current) return null;

    // Use cached data unless force refresh is requested
    if (!forceRefresh && rolePermissions && rolePermissions.userData?.id === targetUserId) {
      return rolePermissions;
    }

    try {
      roleCheckInProgress.current = true;
      
      const response = await api3003(`/api/users/profile/${targetUserId}`, {
        method: 'GET'
      });
      console.log("userRoleResponse===>", response)

      if (response?.success && response?.data) {
        // Update user data if fetching current user
        if (!userId || userId === state.userData?.id) {
          dispatch({ type: 'SET_USER_DATA', payload: response.data });
          localStorage.setItem('vottery_user_data', JSON.stringify(response.data));
        }
        
        // Extract role permissions from database
        const permissions = derivePermissionsFromRole(response.data.admin_role);
        const roleData = {
          admin_role: response.data.admin_role,
          user_type: response.data.user_type,
          subscription_status: response.data.subscription_status,
          permissions: permissions,
          userData: response.data
        };
        
        if (!userId || userId === state.userData?.id) {
          setRolePermissions(roleData);
        }
        
        return roleData;
      }
      return null;
    } catch (error) {
      console.error('Failed to fetch role permissions:', error);
      return null;
    } finally {
      roleCheckInProgress.current = false;
    }
  }, [api3003, derivePermissionsFromRole]); // Removed state.userData?.id dependency

  // Database-driven role functions (FIXED - uses cached data)
  const isAdmin = useCallback(() => {
    const currentRole = rolePermissions?.admin_role || state.userData?.admin_role;
    if (!currentRole) return false;
    
    // Only Manager and Admin are true admins
    const superAdminRoles = ['manager', 'admin'];
    return superAdminRoles.includes(currentRole.toLowerCase());
  }, [rolePermissions, state.userData]);

  const isSuperAdmin = useCallback(() => {
    const permissions = rolePermissions?.permissions || derivePermissionsFromRole(state.userData?.admin_role);
    return permissions?.includes('super_admin') || false;
  }, [rolePermissions, state.userData, derivePermissionsFromRole]);

  const canManageUsers = useCallback(() => {
    const permissions = rolePermissions?.permissions || derivePermissionsFromRole(state.userData?.admin_role);
    return permissions?.includes('manage_users') || false;
  }, [rolePermissions, state.userData, derivePermissionsFromRole]);

  const hasPermission = useCallback((permission) => {
    const permissions = rolePermissions?.permissions || derivePermissionsFromRole(state.userData?.admin_role);
    return permissions?.includes(permission) || false;
  }, [rolePermissions, state.userData, derivePermissionsFromRole]);

  const getUserRole = useCallback(() => {
    return rolePermissions?.admin_role || state.userData?.admin_role || 'user';
  }, [rolePermissions, state.userData]);

  const getUserType = useCallback(() => {
    return rolePermissions?.user_type || state.userData?.user_type || 'voter';
  }, [rolePermissions, state.userData]);

  const getSubscriptionStatus = useCallback(() => {
    return rolePermissions?.subscription_status || state.userData?.subscription_status || 'free';
  }, [rolePermissions, state.userData]);

  // Dashboard redirect based on cached role data (FIXED - no API calls)
  const getDashboardRoute = useCallback(() => {
    const role = (rolePermissions?.admin_role || state.userData?.admin_role || 'user').toLowerCase();
    
    // Route based on milestone document hierarchy
    switch (role) {
      case 'manager':
        return '/admin/super-dashboard'; // Full system control
      case 'admin':
        return '/admin/dashboard'; // Admin dashboard
      case 'moderator':
        return '/admin/moderation'; // Content & election management
      case 'auditor':
        return '/admin/audit'; // Audit and verification tools
      case 'editor':
        return '/admin/content'; // Content editing dashboard
      case 'advertiser':
        return '/admin/campaigns'; // Campaign management
      case 'analyst':
        return '/analytics'; // Analytics dashboard (READ-ONLY)
      default:
        return '/dashboard'; // Regular user dashboard
    }
  }, [rolePermissions, state.userData]);

  // Enhanced user role update with database validation
  const updateUserRole = useCallback(async (userId, newRole, newType = null) => {
    try {
      // Check if current user can manage users
      const canManage = canManageUsers();
      if (!canManage) {
        throw new Error('Insufficient permissions to manage users');
      }

      // Validate the new role against milestone document roles
      const allowedAdminRoles = ['manager', 'admin', 'moderator', 'auditor', 'editor', 'advertiser', 'analyst', 'user'];
      const allowedUserTypes = ['Individual Election Creators', 'Organization Election Creators', 'Voters'];
      
      if (!allowedAdminRoles.includes(newRole.toLowerCase())) {
        throw new Error('Invalid admin role specified');
      }
      
      if (newType && !allowedUserTypes.includes(newType)) {
        throw new Error('Invalid user type specified');
      }

      const response = await api3003(`/api/users/role/${userId}`, {
        method: 'PATCH',
        body: {
          admin_role: newRole,
          ...(newType && { user_type: newType })
        }
      });

      if (response?.success) {
        toast.success('User role updated successfully');
        
        // Refresh role permissions if updating current user
        if (userId === state.userData?.id) {
          await fetchRolePermissions(null, true); // Force refresh
        }
        
        return response;
      }
      throw new Error(response?.message || 'Failed to update user role');
    } catch (error) {
      console.error('Update user role error:', error);
      toast.error(error.message);
      throw error;
    }
  }, [canManageUsers, api3003, state.userData?.id, fetchRolePermissions]);

  // NEW FUNCTION: Update user role and type with subscription (for dropdown functionality)
  const updateUserRoleAndType = useCallback(async (userId, adminRole, userType, subscriptionStatus) => {
    try {
      // Check if current user can manage users
      const canManage = canManageUsers();
      if (!canManage) {
        throw new Error('Insufficient permissions to manage users');
      }

      // Validate inputs
      const allowedAdminRoles = ['analyst', 'editor', 'advertiser', 'moderator', 'auditor', 'admin', 'manager'];
      const allowedUserTypes = ['voter', 'individual_creator', 'organization_creator'];
      const allowedSubscriptions = ['free', 'subscribed'];
      
      if (!allowedAdminRoles.includes(adminRole.toLowerCase())) {
        throw new Error('Invalid admin role specified');
      }
      
      if (!allowedUserTypes.includes(userType.toLowerCase())) {
        throw new Error('Invalid user type specified');
      }

      if (!allowedSubscriptions.includes(subscriptionStatus.toLowerCase())) {
        throw new Error('Invalid subscription status specified');
      }

      const response = await api3003(`/api/users/role/${userId}`, {
        method: 'PATCH',
        body: {
          user_type: userType,
          admin_role: adminRole,
          subscription_status: subscriptionStatus
        }
      });

      if (response?.success) {
        toast.success('User role and type updated successfully');
        
        // Refresh role permissions if updating current user
        if (userId === state.userData?.id) {
          await fetchRolePermissions(null, true); // Force refresh
        }
        
        return response;
      }
      throw new Error(response?.message || 'Failed to update user role and type');
    } catch (error) {
      console.error('Update user role and type error:', error);
      toast.error(error.message);
      throw error;
    }
  }, [canManageUsers, api3003, state.userData?.id, fetchRolePermissions]);

  // Fetch user profile with role validation (FIXED - with deduplication)
  const fetchUserProfile = useCallback(async (userId = null, forceRefresh = false) => {
    const targetUserId = userId || state.userData?.id;
    if (!targetUserId) throw new Error('No user ID available');

    // Use cached data unless force refresh
    if (!forceRefresh && rolePermissions && rolePermissions.userData?.id === targetUserId) {
      return rolePermissions.userData;
    }

    try {
      const response = await api3003(`/api/users/profile/${targetUserId}`, {
        method: 'GET'
      });

      if (response?.success && response?.data) {
        // If fetching current user's profile, update state and permissions
        if (!userId || userId === state.userData?.id) {
          dispatch({ type: 'SET_USER_DATA', payload: response.data });
          localStorage.setItem('vottery_user_data', JSON.stringify(response.data));
          
          // Update role permissions
          const permissions = derivePermissionsFromRole(response.data.admin_role);
          setRolePermissions({
            admin_role: response.data.admin_role,
            user_type: response.data.user_type,
            subscription_status: response.data.subscription_status,
            permissions: permissions,
            userData: response.data
          });
        }
        return response.data;
      }
      throw new Error(response?.message || 'Failed to fetch user profile');
    } catch (error) {
      console.error('Fetch user profile error:', error);
      throw error;
    }
  }, [api3003, derivePermissionsFromRole]); // Removed state.userData?.id and rolePermissions dependencies

  // Check existing authentication on load (FIXED - runs only once)
  useEffect(() => {
    if (hasInitialized.current) return;
    
    const checkExistingAuth = () => {
      const accessToken = TokenManager.getAccessToken();
      const userData = localStorage.getItem('vottery_user_data');
      
      if (accessToken && !TokenManager.isTokenExpired() && userData) {
        try {
          const parsedUserData = JSON.parse(userData);
          dispatch({ type: 'SET_USER_DATA', payload: parsedUserData });
          dispatch({ type: 'SET_USER_ID', payload: parsedUserData.id });
          dispatch({ type: 'SET_EMAIL', payload: parsedUserData.sngine_email });
          dispatch({ type: 'SET_PHONE', payload: parsedUserData.sngine_phone });
          dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
          dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
          dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
          dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
          dispatch({ type: 'SET_SECURITY_QUESTIONS_SETUP', payload: true });
          dispatch({ type: 'SET_AUTHENTICATED', payload: true });
          
          // Set role permissions from cached data
          const permissions = derivePermissionsFromRole(parsedUserData.admin_role);
          setRolePermissions({
            admin_role: parsedUserData.admin_role,
            user_type: parsedUserData.user_type,
            subscription_status: parsedUserData.subscription_status,
            permissions: permissions,
            userData: parsedUserData
          });
          
        } catch (error) {
          console.warn('Failed to parse user data, clearing tokens');
          TokenManager.clearTokens();
        }
      }
    };

    checkExistingAuth();
    hasInitialized.current = true;
  }, []); // Empty dependency array - runs only once

  // Referrer check (runs only once)
  useEffect(() => {
    if (hasInitialized.current) return;
    
    try {
      const referrerInfo = checkReferrer();
      dispatch({ type: 'SET_REFERRER_VALID', payload: referrerInfo.isValid, referrerInfo });

      if (referrerInfo.isValid) {
        const validationData = encryptData({
          referrer: referrerInfo.referrer,
          timestamp: Date.now(),
          validated: true
        });
        sessionStorage.setItem('vottery_referrer_validation', validationData);
      }
    } catch (error) {
      console.warn('Referrer check failed:', error);
      dispatch({ type: 'SET_REFERRER_VALID', payload: false, referrerInfo: { error: error.message } });
    }
  }, [checkReferrer, encryptData]);

  // Get User ID from check-user endpoint
  const getUserId = useCallback(async () => {
    try {
      const response = await api3001('/api/auth/check-user', {
        body: {
          email: state.email,
          phone: state.phone,
        }
      });

      if (response?.success && response?.userId) {
        dispatch({ type: 'SET_USER_ID', payload: response.userId });
        return response.userId;
      }
      throw new Error(response?.message || 'Failed to get user ID');
    } catch (error) {
      console.error('Get user ID error:', error);
      throw error;
    }
  }, [state.email, state.phone, api3001]);

  // STEP 1: Send email OTP
  const sendEmailOTP = useCallback(async (email) => {
    try {
      dispatch({ type: 'SET_LOADING', payload: true });
      dispatch({ type: 'SET_ERROR', payload: null });

      if (!SecurityUtils.isValidEmail(email)) {
        throw new Error('Invalid email format');
      }

      const response = await api3001('/api/auth/send-email-otp', {
        body: {
          email: SecurityUtils.sanitizeInput(email),
          referrer: document.referrer,
          timestamp: Date.now()
        }
      });

      if (response?.success) {
        dispatch({ type: 'SET_EMAIL', payload: email });
        dispatch({ type: 'SET_OTP_SENT', payload: true });
        dispatch({ type: 'SET_STEP', payload: 2 });
        toast.success('OTP sent to your email successfully');
        return response;
      }
      throw new Error(response?.message || 'Failed to send email OTP');
    } catch (error) {
      const errorMessage = error.message || 'Failed to send email OTP';
      dispatch({ type: 'SET_ERROR', payload: errorMessage });
      toast.error(errorMessage);
      throw error;
    } finally {
      dispatch({ type: 'SET_LOADING', payload: false });
    }
  }, [api3001]);

  // STEP 2: Verify email OTP
  const verifyEmailOTP = useCallback(async (otp) => {
    try {
      dispatch({ type: 'SET_LOADING', payload: true });
      dispatch({ type: 'SET_ERROR', payload: null });

      if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

      const response = await api3001('/api/auth/verify-email-otp', {
        body: {
          otp: SecurityUtils.sanitizeInput(otp),
          referrer: document.referrer,
          timestamp: Date.now()
        }
      });

      if (response?.success) {
        dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
        dispatch({ type: 'SET_STEP', payload: 3 });
        toast.success('Email verified successfully');
        return response;
      }
      throw new Error(response?.message || 'Invalid email OTP');
    } catch (error) {
      const errorMessage = error.message || 'Invalid email OTP';
      dispatch({ type: 'SET_ERROR', payload: errorMessage });
      toast.error(errorMessage);
      throw error;
    } finally {
      dispatch({ type: 'SET_LOADING', payload: false });
    }
  }, [api3001]);

  // STEP 3: Send phone OTP
  const sendPhoneOTP = useCallback(async (phone) => {
    try {
      dispatch({ type: 'SET_LOADING', payload: true });
      dispatch({ type: 'SET_ERROR', payload: null });

      let cleanPhone = phone.trim();
      if (!cleanPhone.startsWith('+') && /^\d/.test(cleanPhone)) cleanPhone = '+' + cleanPhone;
      if (cleanPhone.startsWith('+')) cleanPhone = '+' + cleanPhone.substring(1).replace(/\D/g, '');

      if (!SecurityUtils.isValidPhone(cleanPhone)) {
        throw new Error('Invalid phone number format');
      }

      const response = await api3001('/api/auth/send-sms-otp', {
        body: {
          phone: cleanPhone,
          referrer: document.referrer,
          timestamp: Date.now()
        }
      });

      if (response?.success) {
        dispatch({ type: 'SET_PHONE', payload: cleanPhone });
        dispatch({ type: 'SET_OTP_SENT', payload: true });
        dispatch({ type: 'SET_STEP', payload: 4 });
        toast.success('OTP sent to your phone successfully');
        return response;
      }
      throw new Error(response?.message || 'Failed to send SMS OTP');
    } catch (error) {
      const errorMessage = error.message || 'Failed to send SMS OTP';
      dispatch({ type: 'SET_ERROR', payload: errorMessage });
      toast.error(errorMessage);
      throw error;
    } finally {
      dispatch({ type: 'SET_LOADING', payload: false });
    }
  }, [api3001]);

  // STEP 4: Verify phone OTP
  const verifyPhoneOTP = useCallback(async (otp) => {
    try {
      dispatch({ type: 'SET_LOADING', payload: true });
      dispatch({ type: 'SET_ERROR', payload: null });

      if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

      const response = await api3001('/api/auth/verify-sms-otp', {
        body: {
          otp: SecurityUtils.sanitizeInput(otp),
          referrer: document.referrer,
          timestamp: Date.now()
        }
      });

      if (response?.success) {
        dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
        dispatch({ type: 'SET_STEP', payload: 'security-questions' });
        toast.success('Phone verified successfully');
        return response;
      }
      throw new Error(response?.message || 'Invalid SMS OTP');
    } catch (error) {
      const errorMessage = error.message || 'Invalid SMS OTP';
      dispatch({ type: 'SET_ERROR', payload: errorMessage });
      toast.error(errorMessage);
      throw error;
    } finally {
      dispatch({ type: 'SET_LOADING', payload: false });
    }
  }, [api3001]);

  // STEP 5: Save security questions
  const saveSecurityQuestions = useCallback(async (questionsAndAnswers) => {
    try {
      dispatch({ type: 'SET_LOADING', payload: true });
      dispatch({ type: 'SET_ERROR', payload: null });

      if (!questionsAndAnswers || !Array.isArray(questionsAndAnswers) || questionsAndAnswers.length < 3) {
        throw new Error('Please provide exactly 3 security questions and answers');
      }

      for (const qa of questionsAndAnswers) {
        if (!qa.question || !qa.answer || qa.question.trim() === '' || qa.answer.trim() === '') {
          throw new Error('All questions and answers must be filled');
        }
        if (qa.answer.trim().length < 2) {
          throw new Error('All answers must be at least 2 characters long');
        }
      }

      const questionTexts = questionsAndAnswers.map(q => q.question.trim().toLowerCase());
      const uniqueQuestions = [...new Set(questionTexts)];
      if (uniqueQuestions.length !== questionsAndAnswers.length) {
        throw new Error('Please ensure all security questions are different');
      }

      let userId = state.userId;
      if (!userId) {
        userId = await getUserId();
        if (!userId) throw new Error('Failed to get user ID');
      }

      for (const qa of questionsAndAnswers) {
        const questionResponse = await api3003(`/api/biometric/add-question/${userId}`, {
          method: 'POST',
          body: {
            question: qa.question.trim(),
            answer: qa.answer.trim()
          }
        });

        if (!questionResponse?.success) {
          throw new Error(questionResponse?.message || `Failed to add security question: ${qa.question}`);
        }
      }

      dispatch({ type: 'SET_COLLECTED_QUESTIONS', payload: questionsAndAnswers });
      dispatch({ type: 'SET_SECURITY_QUESTIONS_SETUP', payload: true });
      
      toast.success('Security questions saved successfully!');
      return { success: true };

    } catch (error) {
      console.error('Save security questions error:', error);
      const errorMessage = error?.message || 'Failed to save security questions';
      dispatch({ type: 'SET_ERROR', payload: errorMessage });
      toast.error(errorMessage);
      throw new Error(errorMessage);
    } finally {
      dispatch({ type: 'SET_LOADING', payload: false });
    }
  }, [state.userId, getUserId, api3003]);

  // STEP 6: Complete Authentication
  const completeAuthentication = useCallback(async () => {
    try {
      dispatch({ type: 'SET_LOADING', payload: true });
      dispatch({ type: 'SET_ERROR', payload: null });

      if (!state.emailVerified || !state.phoneVerified) {
        throw new Error('Email and phone verification must be completed first');
      }

      if (!state.securityQuestionsSetup) {
        throw new Error('Security questions must be setup first');
      }

      let userId = state.userId;
      if (!userId) {
        userId = await getUserId();
        if (!userId) throw new Error('Failed to get user ID');
      }

      let biometricSuccess = false;

      const isBiometricSupported = window.PublicKeyCredential && 
        await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(() => false);

      if (isBiometricSupported) {
        try {
          console.log('Attempting biometric authentication...');
          const deviceFingerprint = await generateDeviceFingerprint();
          const deviceInfo = {
            type: /mobile/i.test(navigator.userAgent) ? 'mobile' :
                  /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop',
            browser: { name: navigator.userAgent, version: navigator.appVersion },
            os: { name: navigator.platform, version: navigator.platform },
            screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1 }
          };

          const capabilities = { hasWebAuthn: !!window.PublicKeyCredential, platform: navigator.platform, userAgent: navigator.userAgent };
          const location = { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, language: navigator.language };

          const deviceResponse = await api3002('/api/biometric/device/register', {
            body: { 
              sngine_email: state.email, 
              sngine_phone: state.phone, 
              deviceInfo, 
              location, 
              capabilities, 
              referrer: document.referrer, 
                              timestamp: Date.now() 
            }
          });

          if (deviceResponse?.success && deviceResponse?.device?.id) {
            const deviceId = deviceResponse.device.id;
            const biometricData = { deviceFingerprint, userAgent: navigator.userAgent, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, timestamp: Date.now(), capabilities };

            const biometricResponse = await api3002('/api/biometric/register', {
              body: { 
                sngine_email: state.email, 
                sngine_phone: state.phone, 
                deviceId, 
                biometricType: 'device_fingerprint', 
                biometricData, 
                referrer: document.referrer, 
                timestamp: Date.now() 
              }
            });

            if (biometricResponse?.success) {
              const begin = await api3002('/api/biometric/webauthn/register/begin', {
                body: { 
                  sngine_email: state.email, 
                  sngine_phone: state.phone, 
                  deviceId, 
                  referrer: document.referrer, 
                  timestamp: Date.now() 
                }
              });

              if (begin?.success && begin?.options) {
                const publicKey = { 
                  ...begin.options, 
                  challenge: b64ToBytes(begin.options.challenge), 
                  user: { ...begin.options.user, id: b64ToBytes(begin.options.user.id) } 
                };
                const credential = await navigator.credentials.create({ publicKey });

                if (credential) {
                  const attestationObject = new Uint8Array(credential.response.attestationObject || []);
                  const clientDataJSON = new Uint8Array(credential.response.clientDataJSON || []);

                  const finish = await api3002('/api/biometric/webauthn/register/finish', {
                    body: { 
                      sngine_email: state.email, 
                      sngine_phone: state.phone, 
                      deviceId, 
                      credential: { 
                        id: credential.id, 
                        rawId: Array.from(new Uint8Array(credential.rawId)), 
                        response: { 
                          attestationObject: Array.from(attestationObject), 
                          clientDataJSON: Array.from(clientDataJSON) 
                        }, 
                        type: credential.type 
                      }, 
                      referrer: document.referrer, 
                      timestamp: Date.now() 
                    }
                  });

                  if (finish?.success) {
                    biometricSuccess = true;
                    console.log('Biometric authentication completed successfully');
                  }
                }
              }
            }
          }
        } catch (biometricError) {
          console.warn('Biometric authentication failed, continuing with fallback setup:', biometricError);
        }
      } else {
        console.log('Biometric not supported on this device');
      }

      console.log('Setting up mandatory fallback security...');
      
      const keysResponse = await api3003(`/api/biometric/register-keys/${userId}`, {
        method: 'POST'
      });

      if (!keysResponse?.success) {
        throw new Error(keysResponse?.message || 'Failed to register cryptographic keys');
      }

      dispatch({ type: 'SET_BIOMETRIC_KEYS', payload: keysResponse.keys });

      const questionsResponse = await api3003(`/api/biometric/questions/${userId}`, {
        method: 'GET'
      });

      if (questionsResponse?.success && questionsResponse?.questions) {
        const questions = questionsResponse.questions.map(q => q.question);
        dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: questions });
      }

      dispatch({ type: 'SET_FALLBACK_SETUP_COMPLETE', payload: true });
      dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
      dispatch({ type: 'SET_STEP', payload: 6 });

      const successMessage = biometricSuccess 
        ? 'Biometric authentication and fallback security setup completed successfully!'
        : 'Fallback security setup completed successfully!';
      
      toast.success(successMessage);

      return { 
        success: true, 
        biometricSuccess, 
        fallbackSetup: true, 
        message: successMessage 
      };

    } catch (error) {
      console.error('Complete authentication error:', error);
      const errorMessage = error?.message || 'Authentication failed';
      dispatch({ type: 'SET_ERROR', payload: errorMessage });
      toast.error(errorMessage);
      throw new Error(errorMessage);
    } finally {
      dispatch({ type: 'SET_LOADING', payload: false });
    }
  }, [state.email, state.phone, state.emailVerified, state.phoneVerified, state.userId, state.securityQuestionsSetup, generateDeviceFingerprint, getUserId, api3002, api3003]);

  // Get fallback questions
  const getFallbackQuestions = useCallback(async () => {
    try {
      let userId = state.userId;
      if (!userId) {
        userId = await getUserId();
        if (!userId) throw new Error('Failed to get user ID');
      }

      const questionsResponse = await api3003(`/api/biometric/questions/${userId}`, {
        method: 'GET'
      });

      if (questionsResponse?.success && questionsResponse?.questions) {
        const questions = questionsResponse.questions.map(q => q.question);
        dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: questions });
        return questions;
      }

      return [];
    } catch (error) {
      console.error('Get fallback questions error:', error);
      return [];
    }
  }, [state.userId, getUserId, api3003]);

  // STEP 7: Complete Profile Creation
  const completeProfileCreation = useCallback(async (profileData) => {
    try {
      dispatch({ type: 'SET_LOADING', payload: true });
      dispatch({ type: 'SET_ERROR', payload: null });

      if (!state.biometricVerified || !state.fallbackSetupComplete) {
        throw new Error('Authentication and fallback security setup must be completed first');
      }

      let userId = state.userId;
      if (!userId) {
        userId = await getUserId();
        if (!userId) throw new Error('Failed to get user ID');
      }

      const response = await api3003('/api/users/create', {
        method: 'POST',
        body: {
          user_id: userId,
          sngine_email: state.email,
          sngine_phone: state.phone,
          ...profileData,
          referrer: document.referrer,
          timestamp: Date.now()
        }
      });

      if (response?.success && response?.accessToken && response?.refreshToken) {
        TokenManager.setTokens(
          response.accessToken,
          response.refreshToken,
          response.tokenExpiry
        );

        localStorage.setItem('vottery_user_data', JSON.stringify(response.data));

        dispatch({ type: 'SET_USER_DATA', payload: response.data });
        dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
        dispatch({ type: 'SET_AUTHENTICATED', payload: true });

        const sessionData = {
          userId: response.data.id,
          email: response.data.sngine_email,
          phone: response.data.sngine_phone,
          userType: response.data.user_type,
          adminRole: response.data.admin_role,
          subscriptionStatus: response.data.subscription_status,
          authenticated: true,
          profileCreated: true,
          timestamp: Date.now()
        };

        createSession(sessionData);
        
        // Set role permissions from response data
        const permissions = derivePermissionsFromRole(response.data.admin_role);
        setRolePermissions({
          admin_role: response.data.admin_role,
          user_type: response.data.user_type,
          subscription_status: response.data.subscription_status,
          permissions: permissions,
          userData: response.data
        });
        
        toast.success('Profile created successfully! Welcome to Vottery!');
        return response;
      }

      throw new Error(response?.message || 'Profile creation failed');
    } catch (error) {
      console.error('Profile creation error:', error);
      const errorMessage = error?.message || 'Profile creation failed';
      dispatch({ type: 'SET_ERROR', payload: errorMessage });
      toast.error(errorMessage);
      throw new Error(errorMessage);
    } finally {
      dispatch({ type: 'SET_LOADING', payload: false });
    }
  }, [state.biometricVerified, state.fallbackSetupComplete, state.userId, state.email, state.phone, getUserId, api3003, createSession, derivePermissionsFromRole]);

  // Token refresh utility with rotation
  const refreshAccessToken = useCallback(async () => {
    try {
      const refreshToken = TokenManager.getRefreshToken();
      if (!refreshToken) throw new Error('No refresh token available');

      const response = await api3003('/api/auth/refresh', {
        method: 'POST',
        body: { refreshToken }
      });

      if (response?.success && response?.accessToken && response?.refreshToken) {
        TokenManager.setTokens(
          response.accessToken,
          response.refreshToken,
          response.tokenExpiry
        );
        return response.accessToken;
      }

      throw new Error('Token refresh failed');
    } catch (error) {
      console.error('Token refresh failed:', error);
      logout();
      throw error;
    }
  }, [api3003]);

  // Navigation helpers
  const goBackStep = useCallback(() => {
    if (state.currentStep === 2) dispatch({ type: 'SET_STEP', payload: 1 });
    else if (state.currentStep === 4) dispatch({ type: 'SET_STEP', payload: 3 });
    else if (state.currentStep === 5) dispatch({ type: 'SET_STEP', payload: 4 });
    else if (state.currentStep === 6) dispatch({ type: 'SET_STEP', payload: 5 });
    else if (state.currentStep === 'security-questions') dispatch({ type: 'SET_STEP', payload: 4 });
  }, [state.currentStep]);

  const logout = useCallback(() => {
    TokenManager.clearTokens();
    clearSession();
    sessionStorage.removeItem('vottery_referrer_validation');
    setRolePermissions(null);
    hasInitialized.current = false;
    roleCheckInProgress.current = false;
    requestCache.clear(); // Clear API cache
    dispatch({ type: 'RESET_AUTH' });
    toast.success('Logged out successfully');
  }, [clearSession]);

  const resetAuth = useCallback(() => {
    TokenManager.clearTokens();
    setRolePermissions(null);
    hasInitialized.current = false;
    roleCheckInProgress.current = false;
    requestCache.clear(); // Clear API cache
    dispatch({ type: 'RESET_AUTH' });
  }, []);

  // Auto refresh token before expiry
  useEffect(() => {
    const accessToken = TokenManager.getAccessToken();
    const tokenExpiry = localStorage.getItem('vottery_token_expiry');
    
    if (accessToken && tokenExpiry && !TokenManager.isTokenExpired()) {
      try {
        const expiryData = JSON.parse(tokenExpiry);
        const expiryTime = new Date().getTime() + (7 * 24 * 60 * 60 * 1000);
        const refreshTime = expiryTime - Date.now() - 60000;

        if (refreshTime > 0) {
          const timeout = setTimeout(() => {
            refreshAccessToken().catch(console.error);
          }, refreshTime);

          return () => clearTimeout(timeout);
        }
      } catch (error) {
        console.warn('Failed to parse token expiry, clearing tokens');
        TokenManager.clearTokens();
      }
    }
  }, [refreshAccessToken]);

  // Context value with database-driven role functions
  const value = {
    ...state,
    dispatch,
    sendEmailOTP,
    verifyEmailOTP,
    sendPhoneOTP,
    verifyPhoneOTP,
    saveSecurityQuestions,
    completeAuthentication,
    completeProfileCreation,
    getFallbackQuestions,
    getUserId,
    refreshAccessToken,
    goBackStep,
    logout,
    resetAuth,
    // Token utilities
    getAccessToken: TokenManager.getAccessToken,
    getRefreshToken: TokenManager.getRefreshToken,
    isTokenExpired: TokenManager.isTokenExpired,
    // Database-driven role functions (FIXED)
    isAdmin,
    isSuperAdmin,
    canManageUsers,
    getUserRole,
    getUserType,
    getSubscriptionStatus,
    hasPermission,
    fetchUserProfile,
    updateUserRole,
    updateUserRoleAndType, // NEW FUNCTION ADDED
    fetchRolePermissions,
    getDashboardRoute,
    rolePermissions
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
};
// //proper dashboard management from database
// //Complete AuthContext with Database-Driven Role Management - FULL VERSION
// import React, { createContext, useContext, useReducer, useCallback, useEffect, useState, useRef } from 'react';
// import { useSecurity } from './SecurityContext';
// import { SecurityUtils } from '../utils/security';
// import { toast } from 'react-hot-toast';

// const AuthContext = createContext();

// export const useAuth = () => {
//   const context = useContext(AuthContext);
//   if (!context) {
//     throw new Error('useAuth must be used within AuthProvider');
//   }
//   return context;
// };

// // Token Management Utility with Rotation Support
// const TokenManager = {
//   setTokens: (accessToken, refreshToken, expiryInfo) => {
//     localStorage.setItem('vottery_access_token', accessToken);
//     localStorage.setItem('vottery_refresh_token', refreshToken);
//     localStorage.setItem('vottery_token_expiry', JSON.stringify(expiryInfo));
//     localStorage.setItem('vottery_token_timestamp', Date.now().toString());
//   },

//   getAccessToken: () => localStorage.getItem('vottery_access_token'),
  
//   getRefreshToken: () => localStorage.getItem('vottery_refresh_token'),
  
//   clearTokens: () => {
//     localStorage.removeItem('vottery_access_token');
//     localStorage.removeItem('vottery_refresh_token');
//     localStorage.removeItem('vottery_token_expiry');
//     localStorage.removeItem('vottery_token_timestamp');
//     localStorage.removeItem('vottery_user_data');
//   },

//   isTokenExpired: () => {
//     const timestamp = localStorage.getItem('vottery_token_timestamp');
//     if (!timestamp) return true;
    
//     // Assuming 7 days expiry (7 * 24 * 60 * 60 * 1000)
//     const tokenAge = Date.now() - parseInt(timestamp);
//     const maxAge = 7 * 24 * 60 * 60 * 1000;
    
//     return tokenAge >= maxAge;
//   }
// };

// // Request deduplication cache
// const requestCache = new Map();
// const CACHE_DURATION = 30000; // 30 seconds

// // Auth reducer
// const authReducer = (state, action) => {
//   switch (action.type) {
//     case 'SET_LOADING':
//       return { ...state, isLoading: action.payload };
//     case 'SET_STEP':
//       return { ...state, currentStep: action.payload };
//     case 'SET_EMAIL':
//       return { ...state, email: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_PHONE':
//       return { ...state, phone: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_EMAIL_VERIFIED':
//       return { ...state, emailVerified: action.payload };
//     case 'SET_PHONE_VERIFIED':
//       return { ...state, phoneVerified: action.payload };
//     case 'SET_BIOMETRIC_VERIFIED':
//       return { ...state, biometricVerified: action.payload };
//     case 'SET_PROFILE_CREATED':
//       return { ...state, profileCreated: action.payload };
//     case 'SET_AUTHENTICATED':
//       return { ...state, isAuthenticated: action.payload };
//     case 'SET_USER_DATA':
//       return { ...state, userData: action.payload };
//     case 'SET_USER_ID':
//       return { ...state, userId: action.payload };
//     case 'SET_ERROR':
//       return { ...state, error: action.payload };
//     case 'SET_REFERRER_VALID':
//       return { ...state, isValidReferrer: action.payload, referrerInfo: action.referrerInfo };
//     case 'SET_FALLBACK_QUESTIONS':
//       return { ...state, fallbackQuestions: action.payload };
//     case 'SET_FALLBACK_SETUP_COMPLETE':
//       return { ...state, fallbackSetupComplete: action.payload };
//     case 'SET_BIOMETRIC_KEYS':
//       return { ...state, biometricKeys: action.payload };
//     case 'SET_SECURITY_QUESTIONS_SETUP':
//       return { ...state, securityQuestionsSetup: action.payload };
//     case 'SET_COLLECTED_QUESTIONS':
//       return { ...state, collectedSecurityQuestions: action.payload };
//     case 'SET_FALLBACK_STEP':
//       return { ...state, fallbackStep: action.payload };
//     case 'RESET_AUTH':
//       return {
//         ...state,
//         currentStep: 1,
//         email: '',
//         phone: '',
//         userId: null,
//         emailVerified: false,
//         phoneVerified: false,
//         biometricVerified: false,
//         profileCreated: false,
//         error: null,
//         isAuthenticated: false,
//         userData: null,
//         fallbackQuestions: [],
//         fallbackSetupComplete: false,
//         biometricKeys: null,
//         securityQuestionsSetup: false,
//         collectedSecurityQuestions: [],
//         fallbackStep: null
//       };
//     case 'SET_OTP_SENT':
//       return { ...state, otpSent: action.payload };
//     case 'SET_RESEND_COOLDOWN':
//       return { ...state, resendCooldown: action.payload };
//     default:
//       return state;
//   }
// };

// const initialState = {
//   isAuthenticated: false,
//   isLoading: false,
//   currentStep: 1,
//   email: '',
//   phone: '',
//   userId: null,
//   emailVerified: false,
//   phoneVerified: false,
//   biometricVerified: false,
//   profileCreated: false,
//   userData: null,
//   error: null,
//   isValidReferrer: false,
//   referrerInfo: null,
//   otpSent: false,
//   resendCooldown: 0,
//   fallbackQuestions: [],
//   fallbackSetupComplete: false,
//   biometricKeys: null,
//   securityQuestionsSetup: false,
//   collectedSecurityQuestions: [],
//   fallbackStep: null
// };

// // Utilities
// const b64ToBytes = (b64) => {
//   const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
//   const pad = normalized.length % 4 === 2 ? '==' : normalized.length % 4 === 3 ? '=' : '';
//   const str = atob(normalized + pad);
//   const bytes = new Uint8Array(str.length);
//   for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
//   return bytes;
// };

// const createApiRequest = (BASE) => {
//   return async (endpoint, options = {}) => {
//     const isAbsolute = /^https?:\/\//i.test(endpoint);
//     const url = isAbsolute ? endpoint : `${BASE}${endpoint}`;

//     // Check cache for GET requests to prevent duplicate calls
//     if (options.method === 'GET' || !options.method) {
//       const cacheKey = `${url}_${JSON.stringify(options.body || {})}`;
//       const cached = requestCache.get(cacheKey);
//       if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
//         console.log('Returning cached response for:', url);
//         return cached.data;
//       }
//     }

//     const config = {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//         'X-Requested-With': 'XMLHttpRequest',
//         'X-Referrer': typeof document !== 'undefined' ? document.referrer : '',
//         ...(options.headers || {})
//       },
//       ...options
//     };

//     // Add Authorization header if access token exists
//     const accessToken = TokenManager.getAccessToken();
//     if (accessToken && !config.headers.Authorization) {
//       config.headers.Authorization = `Bearer ${accessToken}`;
//     }

//     if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
//       config.body = JSON.stringify(config.body);
//     }

//     try {
//       const response = await fetch(url, config);
//       const data = await response.json().catch(() => null);

//       if (!response.ok) {
//         // Handle rate limiting with exponential backoff
//         if (response.status === 429) {
//           console.warn('Rate limited, using cached data if available');
//           const cacheKey = `${url}_${JSON.stringify(options.body || {})}`;
//           const cached = requestCache.get(cacheKey);
//           if (cached) {
//             return cached.data;
//           }
//           throw new Error('Rate limited and no cached data available');
//         }
        
//         const error = new Error((data && data.message) || `HTTP error! status: ${response.status}`);
//         error.response = { data };
//         throw error;
//       }

//       // Cache successful GET responses
//       if (config.method === 'GET' || !config.method) {
//         const cacheKey = `${url}_${JSON.stringify(options.body || {})}`;
//         requestCache.set(cacheKey, { data, timestamp: Date.now() });
//       }

//       return data;
//     } catch (error) {
//       console.error(`API request failed for ${url}:`, error);
//       if (error.response) throw error;
//       throw new Error('Network error. Please check your connection and try again.');
//     }
//   };
// };

// export const AuthProvider = ({ children }) => {
//   const [state, dispatch] = useReducer(authReducer, initialState);
//   const [rolePermissions, setRolePermissions] = useState(null);
//   const securityContext = useSecurity();
//   const hasInitialized = useRef(false);
//   const roleCheckInProgress = useRef(false);

//   // Safe access to security functions with fallbacks
//   const {
//     checkReferrer = () => ({ isValid: false, referrer: '', error: 'Security context unavailable' }),
//     encryptData = (data) => JSON.stringify(data),
//     decryptData = (data) => JSON.parse(data),
//     generateDeviceFingerprint = () => Promise.resolve('fallback-fingerprint'),
//     createSession = () => {},
//     clearSession = () => {}
//   } = securityContext || {};

//   const API_BASE_3001 = import.meta.env?.VITE_API_BASE_URL || 'http://localhost:3001';
//   const API_BASE_3002 = import.meta.env?.VITE_BIOMETRIC_API_BASE_URL || 'http://localhost:3002';
//   const API_BASE_3003 = import.meta.env?.VITE_USER_MANAGEMENT_API_BASE_URL|| 'http://localhost:3003';

//   const api3001 = useCallback(createApiRequest(API_BASE_3001), [API_BASE_3001]);
//   const api3002 = useCallback(createApiRequest(API_BASE_3002), [API_BASE_3002]);
//   const api3003 = useCallback(createApiRequest(API_BASE_3003), [API_BASE_3003]);

//   // DATABASE-DRIVEN ROLE MANAGEMENT FUNCTIONS
  
//   // Derive permissions from role based on milestone document
//   const derivePermissionsFromRole = useCallback((adminRole) => {
//     if (!adminRole || adminRole === 'user') return [];
    
    
//     const rolePermissionMap = {
//       // Super Admin Roles - Full privileges
//       'manager': [
//         'manage_users', 'manage_elections', 'view_analytics', 
//         'manage_content', 'view_audit', 'manage_ads', 'super_admin',
//         'manage_subscriptions', 'manage_payments', 'system_config'
//       ],
//       'admin': [
//         'manage_users', 'manage_elections', 'view_analytics', 
//         'manage_content', 'view_audit', 'manage_ads', 'super_admin',
//         'manage_subscriptions', 'manage_payments'
//       ],
      
//       // Functional Admin Roles - Limited privileges
//       'moderator': ['manage_elections', 'manage_content', 'view_analytics'],
//       'auditor': ['view_audit', 'view_analytics', 'audit_elections'],
//       'editor': ['manage_content', 'edit_elections'],
//       'advertiser': ['manage_ads', 'view_analytics', 'campaign_management'],
      
//       // Specialized Role - Data access only (NOT ADMIN)
//       'analyst': ['view_analytics', 'export_data', 'generate_reports']
//     };
    
//     return rolePermissionMap[adminRole.toLowerCase()] || [];
//   }, []);

//   // Fetch fresh role permissions from database (FIXED - prevents infinite calls)
//   const fetchRolePermissions = useCallback(async (userId = null, forceRefresh = false) => {
//     const targetUserId = userId || state.userData?.id;
//     if (!targetUserId || roleCheckInProgress.current) return null;

//     // Use cached data unless force refresh is requested
//     if (!forceRefresh && rolePermissions && rolePermissions.userData?.id === targetUserId) {
//       return rolePermissions;
//     }

//     try {
//       roleCheckInProgress.current = true;
      
//       const response = await api3003(`/api/users/profile/${targetUserId}`, {
//         method: 'GET'
//       });
//       console.log("userRoleResponse===>", response)

//       if (response?.success && response?.data) {
//         // Update user data if fetching current user
//         if (!userId || userId === state.userData?.id) {
//           dispatch({ type: 'SET_USER_DATA', payload: response.data });
//           localStorage.setItem('vottery_user_data', JSON.stringify(response.data));
//         }
        
//         // Extract role permissions from database
//         const permissions = derivePermissionsFromRole(response.data.admin_role);
//         const roleData = {
//           admin_role: response.data.admin_role,
//           user_type: response.data.user_type,
//           subscription_status: response.data.subscription_status,
//           permissions: permissions,
//           userData: response.data
//         };
        
//         if (!userId || userId === state.userData?.id) {
//           setRolePermissions(roleData);
//         }
        
//         return roleData;
//       }
//       return null;
//     } catch (error) {
//       console.error('Failed to fetch role permissions:', error);
//       return null;
//     } finally {
//       roleCheckInProgress.current = false;
//     }
//   }, [api3003, derivePermissionsFromRole]); // Removed state.userData?.id dependency

//   // Database-driven role functions (FIXED - uses cached data)
//   const isAdmin = useCallback(() => {
//     const currentRole = rolePermissions?.admin_role || state.userData?.admin_role;
//     if (!currentRole) return false;
    
//     // Only Manager and Admin are true admins
//     const superAdminRoles = ['manager', 'admin'];
//     return superAdminRoles.includes(currentRole.toLowerCase());
//   }, [rolePermissions, state.userData]);

//   const isSuperAdmin = useCallback(() => {
//     const permissions = rolePermissions?.permissions || derivePermissionsFromRole(state.userData?.admin_role);
//     return permissions?.includes('super_admin') || false;
//   }, [rolePermissions, state.userData, derivePermissionsFromRole]);

//   const canManageUsers = useCallback(() => {
//     const permissions = rolePermissions?.permissions || derivePermissionsFromRole(state.userData?.admin_role);
//     return permissions?.includes('manage_users') || false;
//   }, [rolePermissions, state.userData, derivePermissionsFromRole]);

//   const hasPermission = useCallback((permission) => {
//     const permissions = rolePermissions?.permissions || derivePermissionsFromRole(state.userData?.admin_role);
//     return permissions?.includes(permission) || false;
//   }, [rolePermissions, state.userData, derivePermissionsFromRole]);

//   const getUserRole = useCallback(() => {
//     return rolePermissions?.admin_role || state.userData?.admin_role || 'user';
//   }, [rolePermissions, state.userData]);

//   const getUserType = useCallback(() => {
//     return rolePermissions?.user_type || state.userData?.user_type || 'voter';
//   }, [rolePermissions, state.userData]);

//   const getSubscriptionStatus = useCallback(() => {
//     return rolePermissions?.subscription_status || state.userData?.subscription_status || 'free';
//   }, [rolePermissions, state.userData]);

//   // Dashboard redirect based on cached role data (FIXED - no API calls)
//   const getDashboardRoute = useCallback(() => {
//     const role = (rolePermissions?.admin_role || state.userData?.admin_role || 'user').toLowerCase();
    
//     // Route based on milestone document hierarchy
//     switch (role) {
//       case 'manager':
//         return '/admin/super-dashboard'; // Full system control
//       case 'admin':
//         return '/admin/dashboard'; // Admin dashboard
//       case 'moderator':
//         return '/admin/moderation'; // Content & election management
//       case 'auditor':
//         return '/admin/audit'; // Audit and verification tools
//       case 'editor':
//         return '/admin/content'; // Content editing dashboard
//       case 'advertiser':
//         return '/admin/campaigns'; // Campaign management
//       case 'analyst':
//         return '/analytics'; // Analytics dashboard (READ-ONLY)
//       default:
//         return '/dashboard'; // Regular user dashboard
//     }
//   }, [rolePermissions, state.userData]);

//   // Enhanced user role update with database validation
//   const updateUserRole = useCallback(async (userId, newRole, newType = null) => {
//     try {
//       // Check if current user can manage users
//       const canManage = canManageUsers();
//       if (!canManage) {
//         throw new Error('Insufficient permissions to manage users');
//       }

//       // Validate the new role against milestone document roles
//       const allowedAdminRoles = ['manager', 'admin', 'moderator', 'auditor', 'editor', 'advertiser', 'analyst', 'user'];
//       const allowedUserTypes = ['Individual Election Creators', 'Organization Election Creators', 'Voters'];
      
//       if (!allowedAdminRoles.includes(newRole.toLowerCase())) {
//         throw new Error('Invalid admin role specified');
//       }
      
//       if (newType && !allowedUserTypes.includes(newType)) {
//         throw new Error('Invalid user type specified');
//       }

//       const response = await api3003(`/api/users/update-role/${userId}`, {
//         method: 'PUT',
//         body: {
//           admin_role: newRole,
//           ...(newType && { user_type: newType })
//         }
//       });

//       if (response?.success) {
//         toast.success('User role updated successfully');
        
//         // Refresh role permissions if updating current user
//         if (userId === state.userData?.id) {
//           await fetchRolePermissions(null, true); // Force refresh
//         }
        
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to update user role');
//     } catch (error) {
//       console.error('Update user role error:', error);
//       toast.error(error.message);
//       throw error;
//     }
//   }, [canManageUsers, api3003, state.userData?.id, fetchRolePermissions]);

//   // Fetch user profile with role validation (FIXED - with deduplication)
//   const fetchUserProfile = useCallback(async (userId = null, forceRefresh = false) => {
//     const targetUserId = userId || state.userData?.id;
//     if (!targetUserId) throw new Error('No user ID available');

//     // Use cached data unless force refresh
//     if (!forceRefresh && rolePermissions && rolePermissions.userData?.id === targetUserId) {
//       return rolePermissions.userData;
//     }

//     try {
//       const response = await api3003(`/api/users/profile/${targetUserId}`, {
//         method: 'GET'
//       });

//       if (response?.success && response?.data) {
//         // If fetching current user's profile, update state and permissions
//         if (!userId || userId === state.userData?.id) {
//           dispatch({ type: 'SET_USER_DATA', payload: response.data });
//           localStorage.setItem('vottery_user_data', JSON.stringify(response.data));
          
//           // Update role permissions
//           const permissions = derivePermissionsFromRole(response.data.admin_role);
//           setRolePermissions({
//             admin_role: response.data.admin_role,
//             user_type: response.data.user_type,
//             subscription_status: response.data.subscription_status,
//             permissions: permissions,
//             userData: response.data
//           });
//         }
//         return response.data;
//       }
//       throw new Error(response?.message || 'Failed to fetch user profile');
//     } catch (error) {
//       console.error('Fetch user profile error:', error);
//       throw error;
//     }
//   }, [api3003, derivePermissionsFromRole]); // Removed state.userData?.id and rolePermissions dependencies

//   // Check existing authentication on load (FIXED - runs only once)
//   useEffect(() => {
//     if (hasInitialized.current) return;
    
//     const checkExistingAuth = () => {
//       const accessToken = TokenManager.getAccessToken();
//       const userData = localStorage.getItem('vottery_user_data');
      
//       if (accessToken && !TokenManager.isTokenExpired() && userData) {
//         try {
//           const parsedUserData = JSON.parse(userData);
//           dispatch({ type: 'SET_USER_DATA', payload: parsedUserData });
//           dispatch({ type: 'SET_USER_ID', payload: parsedUserData.id });
//           dispatch({ type: 'SET_EMAIL', payload: parsedUserData.sngine_email });
//           dispatch({ type: 'SET_PHONE', payload: parsedUserData.sngine_phone });
//           dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
//           dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//           dispatch({ type: 'SET_SECURITY_QUESTIONS_SETUP', payload: true });
//           dispatch({ type: 'SET_AUTHENTICATED', payload: true });
          
//           // Set role permissions from cached data
//           const permissions = derivePermissionsFromRole(parsedUserData.admin_role);
//           setRolePermissions({
//             admin_role: parsedUserData.admin_role,
//             user_type: parsedUserData.user_type,
//             subscription_status: parsedUserData.subscription_status,
//             permissions: permissions,
//             userData: parsedUserData
//           });
          
//         } catch (error) {
//           console.warn('Failed to parse user data, clearing tokens');
//           TokenManager.clearTokens();
//         }
//       }
//     };

//     checkExistingAuth();
//     hasInitialized.current = true;
//   }, []); // Empty dependency array - runs only once

//   // Referrer check (runs only once)
//   useEffect(() => {
//     if (hasInitialized.current) return;
    
//     try {
//       const referrerInfo = checkReferrer();
//       dispatch({ type: 'SET_REFERRER_VALID', payload: referrerInfo.isValid, referrerInfo });

//       if (referrerInfo.isValid) {
//         const validationData = encryptData({
//           referrer: referrerInfo.referrer,
//           timestamp: Date.now(),
//           validated: true
//         });
//         sessionStorage.setItem('vottery_referrer_validation', validationData);
//       }
//     } catch (error) {
//       console.warn('Referrer check failed:', error);
//       dispatch({ type: 'SET_REFERRER_VALID', payload: false, referrerInfo: { error: error.message } });
//     }
//   }, [checkReferrer, encryptData]);

//   // Get User ID from check-user endpoint
//   const getUserId = useCallback(async () => {
//     try {
//       const response = await api3001('/api/auth/check-user', {
//         body: {
//           email: state.email,
//           phone: state.phone,
//         }
//       });

//       if (response?.success && response?.userId) {
//         dispatch({ type: 'SET_USER_ID', payload: response.userId });
//         return response.userId;
//       }
//       throw new Error(response?.message || 'Failed to get user ID');
//     } catch (error) {
//       console.error('Get user ID error:', error);
//       throw error;
//     }
//   }, [state.email, state.phone, api3001]);

//   // STEP 1: Send email OTP
//   const sendEmailOTP = useCallback(async (email) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!SecurityUtils.isValidEmail(email)) {
//         throw new Error('Invalid email format');
//       }

//       const response = await api3001('/api/auth/send-email-otp', {
//         body: {
//           email: SecurityUtils.sanitizeInput(email),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL', payload: email });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 2 });
//         toast.success('OTP sent to your email successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 2: Verify email OTP
//   const verifyEmailOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-email-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 3 });
//         toast.success('Email verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 3: Send phone OTP
//   const sendPhoneOTP = useCallback(async (phone) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       let cleanPhone = phone.trim();
//       if (!cleanPhone.startsWith('+') && /^\d/.test(cleanPhone)) cleanPhone = '+' + cleanPhone;
//       if (cleanPhone.startsWith('+')) cleanPhone = '+' + cleanPhone.substring(1).replace(/\D/g, '');

//       if (!SecurityUtils.isValidPhone(cleanPhone)) {
//         throw new Error('Invalid phone number format');
//       }

//       const response = await api3001('/api/auth/send-sms-otp', {
//         body: {
//           phone: cleanPhone,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE', payload: cleanPhone });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 4 });
//         toast.success('OTP sent to your phone successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 4: Verify phone OTP
//   const verifyPhoneOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-sms-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 'security-questions' });
//         toast.success('Phone verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 5: Save security questions
//   const saveSecurityQuestions = useCallback(async (questionsAndAnswers) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!questionsAndAnswers || !Array.isArray(questionsAndAnswers) || questionsAndAnswers.length < 3) {
//         throw new Error('Please provide exactly 3 security questions and answers');
//       }

//       for (const qa of questionsAndAnswers) {
//         if (!qa.question || !qa.answer || qa.question.trim() === '' || qa.answer.trim() === '') {
//           throw new Error('All questions and answers must be filled');
//         }
//         if (qa.answer.trim().length < 2) {
//           throw new Error('All answers must be at least 2 characters long');
//         }
//       }

//       const questionTexts = questionsAndAnswers.map(q => q.question.trim().toLowerCase());
//       const uniqueQuestions = [...new Set(questionTexts)];
//       if (uniqueQuestions.length !== questionsAndAnswers.length) {
//         throw new Error('Please ensure all security questions are different');
//       }

//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       for (const qa of questionsAndAnswers) {
//         const questionResponse = await api3003(`/api/biometric/add-question/${userId}`, {
//           method: 'POST',
//           body: {
//             question: qa.question.trim(),
//             answer: qa.answer.trim()
//           }
//         });

//         if (!questionResponse?.success) {
//           throw new Error(questionResponse?.message || `Failed to add security question: ${qa.question}`);
//         }
//       }

//       dispatch({ type: 'SET_COLLECTED_QUESTIONS', payload: questionsAndAnswers });
//       dispatch({ type: 'SET_SECURITY_QUESTIONS_SETUP', payload: true });
      
//       toast.success('Security questions saved successfully!');
//       return { success: true };

//     } catch (error) {
//       console.error('Save security questions error:', error);
//       const errorMessage = error?.message || 'Failed to save security questions';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.userId, getUserId, api3003]);

//   // STEP 6: Complete Authentication
//   const completeAuthentication = useCallback(async () => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.emailVerified || !state.phoneVerified) {
//         throw new Error('Email and phone verification must be completed first');
//       }

//       if (!state.securityQuestionsSetup) {
//         throw new Error('Security questions must be setup first');
//       }

//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       let biometricSuccess = false;

//       const isBiometricSupported = window.PublicKeyCredential && 
//         await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(() => false);

//       if (isBiometricSupported) {
//         try {
//           console.log('Attempting biometric authentication...');
//           const deviceFingerprint = await generateDeviceFingerprint();
//           const deviceInfo = {
//             type: /mobile/i.test(navigator.userAgent) ? 'mobile' :
//                   /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop',
//             browser: { name: navigator.userAgent, version: navigator.appVersion },
//             os: { name: navigator.platform, version: navigator.platform },
//             screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1 }
//           };

//           const capabilities = { hasWebAuthn: !!window.PublicKeyCredential, platform: navigator.platform, userAgent: navigator.userAgent };
//           const location = { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, language: navigator.language };

//           const deviceResponse = await api3002('/api/biometric/device/register', {
//             body: { 
//               sngine_email: state.email, 
//               sngine_phone: state.phone, 
//               deviceInfo, 
//               location, 
//               capabilities, 
//               referrer: document.referrer, 
//               timestamp: Date.now() 
//             }
//           });

//           if (deviceResponse?.success && deviceResponse?.device?.id) {
//             const deviceId = deviceResponse.device.id;
//             const biometricData = { deviceFingerprint, userAgent: navigator.userAgent, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, timestamp: Date.now(), capabilities };

//             const biometricResponse = await api3002('/api/biometric/register', {
//               body: { 
//                 sngine_email: state.email, 
//                 sngine_phone: state.phone, 
//                 deviceId, 
//                 biometricType: 'device_fingerprint', 
//                 biometricData, 
//                 referrer: document.referrer, 
//                 timestamp: Date.now() 
//               }
//             });

//             if (biometricResponse?.success) {
//               const begin = await api3002('/api/biometric/webauthn/register/begin', {
//                 body: { 
//                   sngine_email: state.email, 
//                   sngine_phone: state.phone, 
//                   deviceId, 
//                   referrer: document.referrer, 
//                   timestamp: Date.now() 
//                 }
//               });

//               if (begin?.success && begin?.options) {
//                 const publicKey = { 
//                   ...begin.options, 
//                   challenge: b64ToBytes(begin.options.challenge), 
//                   user: { ...begin.options.user, id: b64ToBytes(begin.options.user.id) } 
//                 };
//                 const credential = await navigator.credentials.create({ publicKey });

//                 if (credential) {
//                   const attestationObject = new Uint8Array(credential.response.attestationObject || []);
//                   const clientDataJSON = new Uint8Array(credential.response.clientDataJSON || []);

//                   const finish = await api3002('/api/biometric/webauthn/register/finish', {
//                     body: { 
//                       sngine_email: state.email, 
//                       sngine_phone: state.phone, 
//                       deviceId, 
//                       credential: { 
//                         id: credential.id, 
//                         rawId: Array.from(new Uint8Array(credential.rawId)), 
//                         response: { 
//                           attestationObject: Array.from(attestationObject), 
//                           clientDataJSON: Array.from(clientDataJSON) 
//                         }, 
//                         type: credential.type 
//                       }, 
//                       referrer: document.referrer, 
//                       timestamp: Date.now() 
//                     }
//                   });

//                   if (finish?.success) {
//                     biometricSuccess = true;
//                     console.log('Biometric authentication completed successfully');
//                   }
//                 }
//               }
//             }
//           }
//         } catch (biometricError) {
//           console.warn('Biometric authentication failed, continuing with fallback setup:', biometricError);
//         }
//       } else {
//         console.log('Biometric not supported on this device');
//       }

//       console.log('Setting up mandatory fallback security...');
      
//       const keysResponse = await api3003(`/api/biometric/register-keys/${userId}`, {
//         method: 'POST'
//       });

//       if (!keysResponse?.success) {
//         throw new Error(keysResponse?.message || 'Failed to register cryptographic keys');
//       }

//       dispatch({ type: 'SET_BIOMETRIC_KEYS', payload: keysResponse.keys });

//       const questionsResponse = await api3003(`/api/biometric/questions/${userId}`, {
//         method: 'GET'
//       });

//       if (questionsResponse?.success && questionsResponse?.questions) {
//         const questions = questionsResponse.questions.map(q => q.question);
//         dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: questions });
//       }

//       dispatch({ type: 'SET_FALLBACK_SETUP_COMPLETE', payload: true });
//       dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//       dispatch({ type: 'SET_STEP', payload: 6 });

//       const successMessage = biometricSuccess 
//         ? 'Biometric authentication and fallback security setup completed successfully!'
//         : 'Fallback security setup completed successfully!';
      
//       toast.success(successMessage);

//       return { 
//         success: true, 
//         biometricSuccess, 
//         fallbackSetup: true, 
//         message: successMessage 
//       };

//     } catch (error) {
//       console.error('Complete authentication error:', error);
//       const errorMessage = error?.message || 'Authentication failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.email, state.phone, state.emailVerified, state.phoneVerified, state.userId, state.securityQuestionsSetup, generateDeviceFingerprint, getUserId, api3002, api3003]);

//   // Get fallback questions
//   const getFallbackQuestions = useCallback(async () => {
//     try {
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       const questionsResponse = await api3003(`/api/biometric/questions/${userId}`, {
//         method: 'GET'
//       });

//       if (questionsResponse?.success && questionsResponse?.questions) {
//         const questions = questionsResponse.questions.map(q => q.question);
//         dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: questions });
//         return questions;
//       }

//       return [];
//     } catch (error) {
//       console.error('Get fallback questions error:', error);
//       return [];
//     }
//   }, [state.userId, getUserId, api3003]);

//   // STEP 7: Complete Profile Creation
//   const completeProfileCreation = useCallback(async (profileData) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.biometricVerified || !state.fallbackSetupComplete) {
//         throw new Error('Authentication and fallback security setup must be completed first');
//       }

//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       const response = await api3003('/api/users/create', {
//         method: 'POST',
//         body: {
//           user_id: userId,
//           sngine_email: state.email,
//           sngine_phone: state.phone,
//           ...profileData,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken,
//           response.tokenExpiry
//         );

//         localStorage.setItem('vottery_user_data', JSON.stringify(response.data));

//         dispatch({ type: 'SET_USER_DATA', payload: response.data });
//         dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//         dispatch({ type: 'SET_AUTHENTICATED', payload: true });

//         const sessionData = {
//           userId: response.data.id,
//           email: response.data.sngine_email,
//           phone: response.data.sngine_phone,
//           userType: response.data.user_type,
//           adminRole: response.data.admin_role,
//           subscriptionStatus: response.data.subscription_status,
//           authenticated: true,
//           profileCreated: true,
//           timestamp: Date.now()
//         };

//         createSession(sessionData);
        
//         // Set role permissions from response data
//         const permissions = derivePermissionsFromRole(response.data.admin_role);
//         setRolePermissions({
//           admin_role: response.data.admin_role,
//           user_type: response.data.user_type,
//           subscription_status: response.data.subscription_status,
//           permissions: permissions,
//           userData: response.data
//         });
        
//         toast.success('Profile created successfully! Welcome to Vottery!');
//         return response;
//       }

//       throw new Error(response?.message || 'Profile creation failed');
//     } catch (error) {
//       console.error('Profile creation error:', error);
//       const errorMessage = error?.message || 'Profile creation failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.biometricVerified, state.fallbackSetupComplete, state.userId, state.email, state.phone, getUserId, api3003, createSession, derivePermissionsFromRole]);

//   // Token refresh utility with rotation
//   const refreshAccessToken = useCallback(async () => {
//     try {
//       const refreshToken = TokenManager.getRefreshToken();
//       if (!refreshToken) throw new Error('No refresh token available');

//       const response = await api3003('/api/auth/refresh', {
//         method: 'POST',
//         body: { refreshToken }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken,
//           response.tokenExpiry
//         );
//         return response.accessToken;
//       }

//       throw new Error('Token refresh failed');
//     } catch (error) {
//       console.error('Token refresh failed:', error);
//       logout();
//       throw error;
//     }
//   }, [api3003]);

//   // Navigation helpers
//   const goBackStep = useCallback(() => {
//     if (state.currentStep === 2) dispatch({ type: 'SET_STEP', payload: 1 });
//     else if (state.currentStep === 4) dispatch({ type: 'SET_STEP', payload: 3 });
//     else if (state.currentStep === 5) dispatch({ type: 'SET_STEP', payload: 4 });
//     else if (state.currentStep === 6) dispatch({ type: 'SET_STEP', payload: 5 });
//     else if (state.currentStep === 'security-questions') dispatch({ type: 'SET_STEP', payload: 4 });
//   }, [state.currentStep]);

//   const logout = useCallback(() => {
//     TokenManager.clearTokens();
//     clearSession();
//     sessionStorage.removeItem('vottery_referrer_validation');
//     setRolePermissions(null);
//     hasInitialized.current = false;
//     roleCheckInProgress.current = false;
//     requestCache.clear(); // Clear API cache
//     dispatch({ type: 'RESET_AUTH' });
//     toast.success('Logged out successfully');
//   }, [clearSession]);

//   const resetAuth = useCallback(() => {
//     TokenManager.clearTokens();
//     setRolePermissions(null);
//     hasInitialized.current = false;
//     roleCheckInProgress.current = false;
//     requestCache.clear(); // Clear API cache
//     dispatch({ type: 'RESET_AUTH' });
//   }, []);

//   // Auto refresh token before expiry
//   useEffect(() => {
//     const accessToken = TokenManager.getAccessToken();
//     const tokenExpiry = localStorage.getItem('vottery_token_expiry');
    
//     if (accessToken && tokenExpiry && !TokenManager.isTokenExpired()) {
//       try {
//         const expiryData = JSON.parse(tokenExpiry);
//         const expiryTime = new Date().getTime() + (7 * 24 * 60 * 60 * 1000);
//         const refreshTime = expiryTime - Date.now() - 60000;

//         if (refreshTime > 0) {
//           const timeout = setTimeout(() => {
//             refreshAccessToken().catch(console.error);
//           }, refreshTime);

//           return () => clearTimeout(timeout);
//         }
//       } catch (error) {
//         console.warn('Failed to parse token expiry, clearing tokens');
//         TokenManager.clearTokens();
//       }
//     }
//   }, [refreshAccessToken]);

//   // Context value with database-driven role functions
//   const value = {
//     ...state,
//     dispatch,
//     sendEmailOTP,
//     verifyEmailOTP,
//     sendPhoneOTP,
//     verifyPhoneOTP,
//     saveSecurityQuestions,
//     completeAuthentication,
//     completeProfileCreation,
//     getFallbackQuestions,
//     getUserId,
//     refreshAccessToken,
//     goBackStep,
//     logout,
//     resetAuth,
//     // Token utilities
//     getAccessToken: TokenManager.getAccessToken,
//     getRefreshToken: TokenManager.getRefreshToken,
//     isTokenExpired: TokenManager.isTokenExpired,
//     // Database-driven role functions (FIXED)
//     isAdmin,
//     isSuperAdmin,
//     canManageUsers,
//     getUserRole,
//     getUserType,
//     getSubscriptionStatus,
//     hasPermission,
//     fetchUserProfile,
//     updateUserRole,
//     fetchRolePermissions,
//     getDashboardRoute,
//     rolePermissions
//   };

//   return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
// };



// //to solve security problem
// import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react';
// import { useSecurity } from './SecurityContext';
// import { SecurityUtils } from '../utils/security';
// import { toast } from 'react-hot-toast';

// const AuthContext = createContext();

// export const useAuth = () => {
//   const context = useContext(AuthContext);
//   if (!context) {
//     throw new Error('useAuth must be used within AuthProvider');
//   }
//   return context;
// };

// // Token Management Utility with Rotation Support
// const TokenManager = {
//   setTokens: (accessToken, refreshToken, expiryInfo) => {
//     localStorage.setItem('vottery_access_token', accessToken);
//     localStorage.setItem('vottery_refresh_token', refreshToken);
//     localStorage.setItem('vottery_token_expiry', JSON.stringify(expiryInfo));
//     localStorage.setItem('vottery_token_timestamp', Date.now().toString());
//   },

//   getAccessToken: () => localStorage.getItem('vottery_access_token'),
  
//   getRefreshToken: () => localStorage.getItem('vottery_refresh_token'),
  
//   clearTokens: () => {
//     localStorage.removeItem('vottery_access_token');
//     localStorage.removeItem('vottery_refresh_token');
//     localStorage.removeItem('vottery_token_expiry');
//     localStorage.removeItem('vottery_token_timestamp');
//     localStorage.removeItem('vottery_user_data');
//   },

//   isTokenExpired: () => {
//     const timestamp = localStorage.getItem('vottery_token_timestamp');
//     if (!timestamp) return true;
    
//     // Assuming 7 days expiry (7 * 24 * 60 * 60 * 1000)
//     const tokenAge = Date.now() - parseInt(timestamp);
//     const maxAge = 7 * 24 * 60 * 60 * 1000;
    
//     return tokenAge >= maxAge;
//   }
// };

// // Auth reducer
// const authReducer = (state, action) => {
//   switch (action.type) {
//     case 'SET_LOADING':
//       return { ...state, isLoading: action.payload };
//     case 'SET_STEP':
//       return { ...state, currentStep: action.payload };
//     case 'SET_EMAIL':
//       return { ...state, email: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_PHONE':
//       return { ...state, phone: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_EMAIL_VERIFIED':
//       return { ...state, emailVerified: action.payload };
//     case 'SET_PHONE_VERIFIED':
//       return { ...state, phoneVerified: action.payload };
//     case 'SET_BIOMETRIC_VERIFIED':
//       return { ...state, biometricVerified: action.payload };
//     case 'SET_PROFILE_CREATED':
//       return { ...state, profileCreated: action.payload };
//     case 'SET_AUTHENTICATED':
//       return { ...state, isAuthenticated: action.payload };
//     case 'SET_USER_DATA':
//       return { ...state, userData: action.payload };
//     case 'SET_USER_ID':
//       return { ...state, userId: action.payload };
//     case 'SET_ERROR':
//       return { ...state, error: action.payload };
//     case 'SET_REFERRER_VALID':
//       return { ...state, isValidReferrer: action.payload, referrerInfo: action.referrerInfo };
//     case 'SET_FALLBACK_QUESTIONS':
//       return { ...state, fallbackQuestions: action.payload };
//     case 'SET_FALLBACK_SETUP_COMPLETE':
//       return { ...state, fallbackSetupComplete: action.payload };
//     case 'SET_BIOMETRIC_KEYS':
//       return { ...state, biometricKeys: action.payload };
//     case 'SET_SECURITY_QUESTIONS_SETUP':
//       return { ...state, securityQuestionsSetup: action.payload };
//     case 'SET_COLLECTED_QUESTIONS':
//       return { ...state, collectedSecurityQuestions: action.payload };
//     case 'SET_FALLBACK_STEP':
//       return { ...state, fallbackStep: action.payload };
//     case 'RESET_AUTH':
//       return {
//         ...state,
//         currentStep: 1,
//         email: '',
//         phone: '',
//         userId: null,
//         emailVerified: false,
//         phoneVerified: false,
//         biometricVerified: false,
//         profileCreated: false,
//         error: null,
//         isAuthenticated: false,
//         userData: null,
//         fallbackQuestions: [],
//         fallbackSetupComplete: false,
//         biometricKeys: null,
//         securityQuestionsSetup: false,
//         collectedSecurityQuestions: [],
//         fallbackStep: null
//       };
//     case 'SET_OTP_SENT':
//       return { ...state, otpSent: action.payload };
//     case 'SET_RESEND_COOLDOWN':
//       return { ...state, resendCooldown: action.payload };
//     default:
//       return state;
//   }
// };

// const initialState = {
//   isAuthenticated: false,
//   isLoading: false,
//   currentStep: 1,
//   email: '',
//   phone: '',
//   userId: null,
//   emailVerified: false,
//   phoneVerified: false,
//   biometricVerified: false,
//   profileCreated: false,
//   userData: null,
//   error: null,
//   isValidReferrer: false,
//   referrerInfo: null,
//   otpSent: false,
//   resendCooldown: 0,
//   fallbackQuestions: [],
//   fallbackSetupComplete: false,
//   biometricKeys: null,
//   securityQuestionsSetup: false,
//   collectedSecurityQuestions: [],
//   fallbackStep: null
// };

// // Utilities
// const b64ToBytes = (b64) => {
//   const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
//   const pad = normalized.length % 4 === 2 ? '==' : normalized.length % 4 === 3 ? '=' : '';
//   const str = atob(normalized + pad);
//   const bytes = new Uint8Array(str.length);
//   for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
//   return bytes;
// };

// const createApiRequest = (BASE) => {
//   return async (endpoint, options = {}) => {
//     const isAbsolute = /^https?:\/\//i.test(endpoint);
//     const url = isAbsolute ? endpoint : `${BASE}${endpoint}`;

//     const config = {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//         'X-Requested-With': 'XMLHttpRequest',
//         'X-Referrer': typeof document !== 'undefined' ? document.referrer : '',
//         ...(options.headers || {})
//       },
//       ...options
//     };

//     // Add Authorization header if access token exists
//     const accessToken = TokenManager.getAccessToken();
//     if (accessToken && !config.headers.Authorization) {
//       config.headers.Authorization = `Bearer ${accessToken}`;
//     }

//     if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
//       config.body = JSON.stringify(config.body);
//     }

//     try {
//       const response = await fetch(url, config);
//       const data = await response.json().catch(() => null);

//       if (!response.ok) {
//         const error = new Error((data && data.message) || `HTTP error! status: ${response.status}`);
//         error.response = { data };
//         throw error;
//       }

//       return data;
//     } catch (error) {
//       console.error(`API request failed for ${url}:`, error);
//       if (error.response) throw error;
//       throw new Error('Network error. Please check your connection and try again.');
//     }
//   };
// };

// export const AuthProvider = ({ children }) => {
//   const [state, dispatch] = useReducer(authReducer, initialState);
//   const securityContext = useSecurity();

//   // Safe access to security functions with fallbacks
//   const {
//     checkReferrer = () => ({ isValid: false, referrer: '', error: 'Security context unavailable' }),
//     encryptData = (data) => JSON.stringify(data),
//     decryptData = (data) => JSON.parse(data),
//     generateDeviceFingerprint = () => Promise.resolve('fallback-fingerprint'),
//     createSession = () => {},
//     clearSession = () => {}
//   } = securityContext || {};

//   const API_BASE_3001 = import.meta.env?.VITE_API_BASE_URL || 'http://localhost:3001';
//   const API_BASE_3002 = import.meta.env?.VITE_BIOMETRIC_API_BASE_URL || 'http://localhost:3002';
//   const API_BASE_3003 = import.meta.env?.VITE_USER_MANAGEMENT_API_BASE_URL|| 'http://localhost:3003'; // Fixed URL as required

//   const api3001 = useCallback(createApiRequest(API_BASE_3001), [API_BASE_3001]);
//   const api3002 = useCallback(createApiRequest(API_BASE_3002), [API_BASE_3002]);
//   const api3003 = useCallback(createApiRequest(API_BASE_3003), [API_BASE_3003]);

//   // Role-based functions (NEW - fixes the isAdmin error)
//   const isAdmin = useCallback(() => {
//     if (!state.userData || !state.userData.admin_role) return false;
//     const adminRoles = ['manager', 'admin', 'moderator', 'auditor', 'editor', 'advertiser', 'analyst'];
//     return adminRoles.includes(state.userData.admin_role.toLowerCase());
//   }, [state.userData]);

//   const isSuperAdmin = useCallback(() => {
//     if (!state.userData || !state.userData.admin_role) return false;
//     const superAdminRoles = ['manager', 'admin'];
//     return superAdminRoles.includes(state.userData.admin_role.toLowerCase());
//   }, [state.userData]);

//   const canManageUsers = useCallback(() => {
//     return isSuperAdmin();
//   }, [isSuperAdmin]);

//   const getUserRole = useCallback(() => {
//     return state.userData?.admin_role || 'user';
//   }, [state.userData]);

//   const getUserType = useCallback(() => {
//     return state.userData?.user_type || 'voter';
//   }, [state.userData]);

//   const getSubscriptionStatus = useCallback(() => {
//     return state.userData?.subscription_status || 'free';
//   }, [state.userData]);

//   const hasPermission = useCallback((permission) => {
//     const userRole = getUserRole().toLowerCase();
//     const permissions = {
//       'manage_users': ['manager', 'admin'],
//       'manage_elections': ['manager', 'admin', 'moderator'],
//       'view_analytics': ['manager', 'admin', 'analyst'],
//       'manage_content': ['manager', 'admin', 'moderator', 'editor'],
//       'view_audit': ['manager', 'admin', 'auditor'],
//       'manage_ads': ['manager', 'admin', 'advertiser']
//     };
//     return permissions[permission]?.includes(userRole) || false;
//   }, [getUserRole]);

//   const fetchUserProfile = useCallback(async (userId = null) => {
//     try {
//       const targetUserId = userId || state.userData?.id;
//       if (!targetUserId) throw new Error('No user ID available');

//       const response = await api3003(`/api/users/profile/${targetUserId}`, {
//         method: 'GET'
//       });

//       if (response?.success && response?.data) {
//         // If fetching current user's profile, update state
//         if (!userId || userId === state.userData?.id) {
//           dispatch({ type: 'SET_USER_DATA', payload: response.data });
//           localStorage.setItem('vottery_user_data', JSON.stringify(response.data));
//         }
//         return response.data;
//       }
//       throw new Error(response?.message || 'Failed to fetch user profile');
//     } catch (error) {
//       console.error('Fetch user profile error:', error);
//       throw error;
//     }
//   }, [state.userData?.id, api3003]);

//   const updateUserRole = useCallback(async (userId, newRole, newType = null) => {
//     try {
//       if (!canManageUsers()) {
//         throw new Error('Insufficient permissions to manage users');
//       }

//       const response = await api3003(`/api/users/update-role/${userId}`, {
//         method: 'PUT',
//         body: {
//           admin_role: newRole,
//           ...(newType && { user_type: newType })
//         }
//       });

//       if (response?.success) {
//         toast.success('User role updated successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to update user role');
//     } catch (error) {
//       console.error('Update user role error:', error);
//       toast.error(error.message);
//       throw error;
//     }
//   }, [canManageUsers, api3003]);

//   // Check existing authentication on load
//   useEffect(() => {
//     const checkExistingAuth = () => {
//       const accessToken = TokenManager.getAccessToken();
//       const userData = localStorage.getItem('vottery_user_data');
      
//       if (accessToken && !TokenManager.isTokenExpired() && userData) {
//         try {
//           const parsedUserData = JSON.parse(userData);
//           dispatch({ type: 'SET_USER_DATA', payload: parsedUserData });
//           dispatch({ type: 'SET_USER_ID', payload: parsedUserData.id });
//           dispatch({ type: 'SET_EMAIL', payload: parsedUserData.sngine_email });
//           dispatch({ type: 'SET_PHONE', payload: parsedUserData.sngine_phone });
//           dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
//           dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//           dispatch({ type: 'SET_SECURITY_QUESTIONS_SETUP', payload: true });
//           dispatch({ type: 'SET_AUTHENTICATED', payload: true });
//         } catch (error) {
//           console.warn('Failed to parse user data, clearing tokens');
//           TokenManager.clearTokens();
//         }
//       }
//     };

//     checkExistingAuth();
//   }, []);

//   // Referrer check
//   useEffect(() => {
//     try {
//       const referrerInfo = checkReferrer();
//       dispatch({ type: 'SET_REFERRER_VALID', payload: referrerInfo.isValid, referrerInfo });

//       if (referrerInfo.isValid) {
//         const validationData = encryptData({
//           referrer: referrerInfo.referrer,
//           timestamp: Date.now(),
//           validated: true
//         });
//         sessionStorage.setItem('vottery_referrer_validation', validationData);
//       }
//     } catch (error) {
//       console.warn('Referrer check failed:', error);
//       dispatch({ type: 'SET_REFERRER_VALID', payload: false, referrerInfo: { error: error.message } });
//     }
//   }, [checkReferrer, encryptData]);

//   // Get User ID from check-user endpoint
//   const getUserId = useCallback(async () => {
//     try {
//       const response = await api3001('/api/auth/check-user', {
//         body: {
//           email: state.email,
//           phone: state.phone,
//         }
//       });

//       if (response?.success && response?.userId) {
//         dispatch({ type: 'SET_USER_ID', payload: response.userId });
//         return response.userId;
//       }
//       throw new Error(response?.message || 'Failed to get user ID');
//     } catch (error) {
//       console.error('Get user ID error:', error);
//       throw error;
//     }
//   }, [state.email, state.phone, api3001]);

//   // STEP 1: Send email OTP
//   const sendEmailOTP = useCallback(async (email) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!SecurityUtils.isValidEmail(email)) {
//         throw new Error('Invalid email format');
//       }

//       const response = await api3001('/api/auth/send-email-otp', {
//         body: {
//           email: SecurityUtils.sanitizeInput(email),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL', payload: email });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 2 });
//         toast.success('OTP sent to your email successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 2: Verify email OTP
//   const verifyEmailOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-email-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 3 });
//         toast.success('Email verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 3: Send phone OTP
//   const sendPhoneOTP = useCallback(async (phone) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       let cleanPhone = phone.trim();
//       if (!cleanPhone.startsWith('+') && /^\d/.test(cleanPhone)) cleanPhone = '+' + cleanPhone;
//       if (cleanPhone.startsWith('+')) cleanPhone = '+' + cleanPhone.substring(1).replace(/\D/g, '');

//       if (!SecurityUtils.isValidPhone(cleanPhone)) {
//         throw new Error('Invalid phone number format');
//       }

//       const response = await api3001('/api/auth/send-sms-otp', {
//         body: {
//           phone: cleanPhone,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE', payload: cleanPhone });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 4 });
//         toast.success('OTP sent to your phone successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 4: Verify phone OTP
//   const verifyPhoneOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-sms-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
        
//         // After phone verification, proceed to security questions setup
//         dispatch({ type: 'SET_STEP', payload: 'security-questions' });
//         toast.success('Phone verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 5: Save security questions (called from SecurityQuestionsSetup component)
//   const saveSecurityQuestions = useCallback(async (questionsAndAnswers) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       // Validate input
//       if (!questionsAndAnswers || !Array.isArray(questionsAndAnswers) || questionsAndAnswers.length < 3) {
//         throw new Error('Please provide exactly 3 security questions and answers');
//       }

//       // Validate each question-answer pair
//       for (const qa of questionsAndAnswers) {
//         if (!qa.question || !qa.answer || qa.question.trim() === '' || qa.answer.trim() === '') {
//           throw new Error('All questions and answers must be filled');
//         }
//         if (qa.answer.trim().length < 2) {
//           throw new Error('All answers must be at least 2 characters long');
//         }
//       }

//       // Check for duplicate questions
//       const questionTexts = questionsAndAnswers.map(q => q.question.trim().toLowerCase());
//       const uniqueQuestions = [...new Set(questionTexts)];
//       if (uniqueQuestions.length !== questionsAndAnswers.length) {
//         throw new Error('Please ensure all security questions are different');
//       }

//       // Get user ID first
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       // Save each question-answer pair
//       for (const qa of questionsAndAnswers) {
//         const questionResponse = await api3003(`/api/biometric/add-question/${userId}`, {
//           method: 'POST',
//           body: {
//             question: qa.question.trim(),
//             answer: qa.answer.trim()
//           }
//         });

//         if (!questionResponse?.success) {
//           throw new Error(questionResponse?.message || `Failed to add security question: ${qa.question}`);
//         }
//       }

//       // Update state to mark security questions as setup
//       dispatch({ type: 'SET_COLLECTED_QUESTIONS', payload: questionsAndAnswers });
//       dispatch({ type: 'SET_SECURITY_QUESTIONS_SETUP', payload: true });
      
//       toast.success('Security questions saved successfully!');
      
//       return { success: true };

//     } catch (error) {
//       console.error('Save security questions error:', error);
//       const errorMessage = error?.message || 'Failed to save security questions';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.userId, getUserId, api3003]);

//   // STEP 6: Complete Authentication (Biometric + Fallback Setup)
//   const completeAuthentication = useCallback(async () => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.emailVerified || !state.phoneVerified) {
//         throw new Error('Email and phone verification must be completed first');
//       }

//       if (!state.securityQuestionsSetup) {
//         throw new Error('Security questions must be setup first');
//       }

//       // Get user ID first
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       let biometricSuccess = false;

//       // Try biometric authentication if supported
//       const isBiometricSupported = window.PublicKeyCredential && 
//         await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(() => false);

//       if (isBiometricSupported) {
//         try {
//           console.log('Attempting biometric authentication...');
//           const deviceFingerprint = await generateDeviceFingerprint();
//           const deviceInfo = {
//             type: /mobile/i.test(navigator.userAgent) ? 'mobile' :
//                   /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop',
//             browser: { name: navigator.userAgent, version: navigator.appVersion },
//             os: { name: navigator.platform, version: navigator.platform },
//             screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1 }
//           };

//           const capabilities = { hasWebAuthn: !!window.PublicKeyCredential, platform: navigator.platform, userAgent: navigator.userAgent };
//           const location = { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, language: navigator.language };

//           const deviceResponse = await api3002('/api/biometric/device/register', {
//             body: { 
//               sngine_email: state.email, 
//               sngine_phone: state.phone, 
//               deviceInfo, 
//               location, 
//               capabilities, 
//               referrer: document.referrer, 
//               timestamp: Date.now() 
//             }
//           });

//           if (deviceResponse?.success && deviceResponse?.device?.id) {
//             const deviceId = deviceResponse.device.id;
//             const biometricData = { deviceFingerprint, userAgent: navigator.userAgent, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, timestamp: Date.now(), capabilities };

//             const biometricResponse = await api3002('/api/biometric/register', {
//               body: { 
//                 sngine_email: state.email, 
//                 sngine_phone: state.phone, 
//                 deviceId, 
//                 biometricType: 'device_fingerprint', 
//                 biometricData, 
//                 referrer: document.referrer, 
//                 timestamp: Date.now() 
//               }
//             });

//             if (biometricResponse?.success) {
//               // Try WebAuthn registration
//               const begin = await api3002('/api/biometric/webauthn/register/begin', {
//                 body: { 
//                   sngine_email: state.email, 
//                   sngine_phone: state.phone, 
//                   deviceId, 
//                   referrer: document.referrer, 
//                   timestamp: Date.now() 
//                 }
//               });

//               if (begin?.success && begin?.options) {
//                 const publicKey = { 
//                   ...begin.options, 
//                   challenge: b64ToBytes(begin.options.challenge), 
//                   user: { ...begin.options.user, id: b64ToBytes(begin.options.user.id) } 
//                 };
//                 const credential = await navigator.credentials.create({ publicKey });

//                 if (credential) {
//                   const attestationObject = new Uint8Array(credential.response.attestationObject || []);
//                   const clientDataJSON = new Uint8Array(credential.response.clientDataJSON || []);

//                   const finish = await api3002('/api/biometric/webauthn/register/finish', {
//                     body: { 
//                       sngine_email: state.email, 
//                       sngine_phone: state.phone, 
//                       deviceId, 
//                       credential: { 
//                         id: credential.id, 
//                         rawId: Array.from(new Uint8Array(credential.rawId)), 
//                         response: { 
//                           attestationObject: Array.from(attestationObject), 
//                           clientDataJSON: Array.from(clientDataJSON) 
//                         }, 
//                         type: credential.type 
//                       }, 
//                       referrer: document.referrer, 
//                       timestamp: Date.now() 
//                     }
//                   });

//                   if (finish?.success) {
//                     biometricSuccess = true;
//                     console.log('Biometric authentication completed successfully');
//                   }
//                 }
//               }
//             }
//           }
//         } catch (biometricError) {
//           console.warn('Biometric authentication failed, continuing with fallback setup:', biometricError);
//         }
//       } else {
//         console.log('Biometric not supported on this device');
//       }

//       // MANDATORY FALLBACK SETUP - Always required regardless of biometric success
//       console.log('Setting up mandatory fallback security...');
      
//       // Step 1: Register cryptographic keys
//       const keysResponse = await api3003(`/api/biometric/register-keys/${userId}`, {
//         method: 'POST'
//       });

//       if (!keysResponse?.success) {
//         throw new Error(keysResponse?.message || 'Failed to register cryptographic keys');
//       }

//       dispatch({ type: 'SET_BIOMETRIC_KEYS', payload: keysResponse.keys });

//       // Step 2: Get all questions for storage
//       const questionsResponse = await api3003(`/api/biometric/questions/${userId}`, {
//         method: 'GET'
//       });

//       if (questionsResponse?.success && questionsResponse?.questions) {
//         const questions = questionsResponse.questions.map(q => q.question);
//         dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: questions });
//       }

//       // Mark fallback setup complete and proceed to profile creation
//       dispatch({ type: 'SET_FALLBACK_SETUP_COMPLETE', payload: true });
//       dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//       dispatch({ type: 'SET_STEP', payload: 6 });

//       const successMessage = biometricSuccess 
//         ? 'Biometric authentication and fallback security setup completed successfully!'
//         : 'Fallback security setup completed successfully!';
      
//       toast.success(successMessage);

//       return { 
//         success: true, 
//         biometricSuccess, 
//         fallbackSetup: true, 
//         message: successMessage 
//       };

//     } catch (error) {
//       console.error('Complete authentication error:', error);
//       const errorMessage = error?.message || 'Authentication failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.email, state.phone, state.emailVerified, state.phoneVerified, state.userId, state.securityQuestionsSetup, generateDeviceFingerprint, getUserId, api3002, api3003]);

//   // Get fallback questions
//   const getFallbackQuestions = useCallback(async () => {
//     try {
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       const questionsResponse = await api3003(`/api/biometric/questions/${userId}`, {
//         method: 'GET'
//       });

//       if (questionsResponse?.success && questionsResponse?.questions) {
//         const questions = questionsResponse.questions.map(q => q.question);
//         dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: questions });
//         return questions;
//       }

//       return [];
//     } catch (error) {
//       console.error('Get fallback questions error:', error);
//       return [];
//     }
//   }, [state.userId, getUserId, api3003]);

//   // STEP 7: Complete Profile Creation
//   const completeProfileCreation = useCallback(async (profileData) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.biometricVerified || !state.fallbackSetupComplete) {
//         throw new Error('Authentication and fallback security setup must be completed first');
//       }

//       // Get user ID if not already available
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       const response = await api3003('/api/users/create', {
//         method: 'POST',
//         body: {
//           user_id: userId,
//           sngine_email: state.email,
//           sngine_phone: state.phone,
//           ...profileData,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         // Store tokens
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken,
//           response.tokenExpiry
//         );

//         // Store user data
//         localStorage.setItem('vottery_user_data', JSON.stringify(response.data));

//         // Update state
//         dispatch({ type: 'SET_USER_DATA', payload: response.data });
//         dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//         dispatch({ type: 'SET_AUTHENTICATED', payload: true });

//         // Create session
//         const sessionData = {
//           userId: response.data.id,
//           email: response.data.sngine_email,
//           phone: response.data.sngine_phone,
//           userType: response.data.user_type,
//           adminRole: response.data.admin_role,
//           subscriptionStatus: response.data.subscription_status,
//           authenticated: true,
//           profileCreated: true,
//           timestamp: Date.now()
//         };

//         createSession(sessionData);
//         toast.success('Profile created successfully! Welcome to Vottery!');

//         return response;
//       }

//       throw new Error(response?.message || 'Profile creation failed');
//     } catch (error) {
//       console.error('Profile creation error:', error);
//       const errorMessage = error?.message || 'Profile creation failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.biometricVerified, state.fallbackSetupComplete, state.userId, state.email, state.phone, getUserId, api3003, createSession]);

//   // Token refresh utility with rotation
//   const refreshAccessToken = useCallback(async () => {
//     try {
//       const refreshToken = TokenManager.getRefreshToken();
//       if (!refreshToken) throw new Error('No refresh token available');

//       const response = await api3003('/api/auth/refresh', {
//         method: 'POST',
//         body: { refreshToken }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         // Store NEW tokens (rotation - both access and refresh tokens are new)
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken, // This is the NEW refresh token
//           response.tokenExpiry
//         );
//         return response.accessToken;
//       }

//       throw new Error('Token refresh failed');
//     } catch (error) {
//       console.error('Token refresh failed:', error);
//       logout();
//       throw error;
//     }
//   }, [api3003]);

//   // Navigation helpers
//   const goBackStep = useCallback(() => {
//     if (state.currentStep === 2) dispatch({ type: 'SET_STEP', payload: 1 });
//     else if (state.currentStep === 4) dispatch({ type: 'SET_STEP', payload: 3 });
//     else if (state.currentStep === 5) dispatch({ type: 'SET_STEP', payload: 4 });
//     else if (state.currentStep === 6) dispatch({ type: 'SET_STEP', payload: 5 });
//     else if (state.currentStep === 'security-questions') dispatch({ type: 'SET_STEP', payload: 4 });
//   }, [state.currentStep]);

//   const logout = useCallback(() => {
//     TokenManager.clearTokens();
//     clearSession();
//     sessionStorage.removeItem('vottery_referrer_validation');
//     dispatch({ type: 'RESET_AUTH' });
//     toast.success('Logged out successfully');
//   }, [clearSession]);

//   const resetAuth = useCallback(() => {
//     TokenManager.clearTokens();
//     dispatch({ type: 'RESET_AUTH' });
//   }, []);

//   // Auto refresh token before expiry
//   useEffect(() => {
//     const accessToken = TokenManager.getAccessToken();
//     const tokenExpiry = localStorage.getItem('vottery_token_expiry');
    
//     if (accessToken && tokenExpiry && !TokenManager.isTokenExpired()) {
//       try {
//         const expiryData = JSON.parse(tokenExpiry);
//         const expiryTime = new Date().getTime() + (7 * 24 * 60 * 60 * 1000); // 7 days from now
//         const refreshTime = expiryTime - Date.now() - 60000; // Refresh 1 minute before expiry

//         if (refreshTime > 0) {
//           const timeout = setTimeout(() => {
//             refreshAccessToken().catch(console.error);
//           }, refreshTime);

//           return () => clearTimeout(timeout);
//         }
//       } catch (error) {
//         console.warn('Failed to parse token expiry, clearing tokens');
//         TokenManager.clearTokens();
//       }
//     }
//   }, [refreshAccessToken]);

//   // Context value
//   const value = {
//     ...state,
//     dispatch,
//     sendEmailOTP,
//     verifyEmailOTP,
//     sendPhoneOTP,
//     verifyPhoneOTP,
//     saveSecurityQuestions,
//     completeAuthentication,
//     completeProfileCreation,
//     getFallbackQuestions,
//     getUserId,
//     refreshAccessToken,
//     goBackStep,
//     logout,
//     resetAuth,
//     // Token utilities
//     getAccessToken: TokenManager.getAccessToken,
//     getRefreshToken: TokenManager.getRefreshToken,
//     isTokenExpired: TokenManager.isTokenExpired,
//     // Role-based functions (NEW)
//     isAdmin,
//     isSuperAdmin,
//     canManageUsers,
//     getUserRole,
//     getUserType,
//     getSubscriptionStatus,
//     hasPermission,
//     fetchUserProfile,
//     updateUserRole
//   };

//   return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>

// //to solve security problem
// import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react';
// import { useSecurity } from './SecurityContext';
// import { SecurityUtils } from '../utils/security';
// import { toast } from 'react-hot-toast';

// const AuthContext = createContext();

// export const useAuth = () => {
//   const context = useContext(AuthContext);
//   if (!context) {
//     throw new Error('useAuth must be used within AuthProvider');
//   }
//   return context;
// };

// // Token Management Utility with Rotation Support
// const TokenManager = {
//   setTokens: (accessToken, refreshToken, expiryInfo) => {
//     localStorage.setItem('vottery_access_token', accessToken);
//     localStorage.setItem('vottery_refresh_token', refreshToken);
//     localStorage.setItem('vottery_token_expiry', JSON.stringify(expiryInfo));
//     localStorage.setItem('vottery_token_timestamp', Date.now().toString());
//   },

//   getAccessToken: () => localStorage.getItem('vottery_access_token'),
  
//   getRefreshToken: () => localStorage.getItem('vottery_refresh_token'),
  
//   clearTokens: () => {
//     localStorage.removeItem('vottery_access_token');
//     localStorage.removeItem('vottery_refresh_token');
//     localStorage.removeItem('vottery_token_expiry');
//     localStorage.removeItem('vottery_token_timestamp');
//     localStorage.removeItem('vottery_user_data');
//   },

//   isTokenExpired: () => {
//     const timestamp = localStorage.getItem('vottery_token_timestamp');
//     if (!timestamp) return true;
    
//     // Assuming 7 days expiry (7 * 24 * 60 * 60 * 1000)
//     const tokenAge = Date.now() - parseInt(timestamp);
//     const maxAge = 7 * 24 * 60 * 60 * 1000;
    
//     return tokenAge >= maxAge;
//   }
// };

// // Auth reducer
// const authReducer = (state, action) => {
//   switch (action.type) {
//     case 'SET_LOADING':
//       return { ...state, isLoading: action.payload };
//     case 'SET_STEP':
//       return { ...state, currentStep: action.payload };
//     case 'SET_EMAIL':
//       return { ...state, email: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_PHONE':
//       return { ...state, phone: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_EMAIL_VERIFIED':
//       return { ...state, emailVerified: action.payload };
//     case 'SET_PHONE_VERIFIED':
//       return { ...state, phoneVerified: action.payload };
//     case 'SET_BIOMETRIC_VERIFIED':
//       return { ...state, biometricVerified: action.payload };
//     case 'SET_PROFILE_CREATED':
//       return { ...state, profileCreated: action.payload };
//     case 'SET_AUTHENTICATED':
//       return { ...state, isAuthenticated: action.payload };
//     case 'SET_USER_DATA':
//       return { ...state, userData: action.payload };
//     case 'SET_USER_ID':
//       return { ...state, userId: action.payload };
//     case 'SET_ERROR':
//       return { ...state, error: action.payload };
//     case 'SET_REFERRER_VALID':
//       return { ...state, isValidReferrer: action.payload, referrerInfo: action.referrerInfo };
//     case 'SET_FALLBACK_QUESTIONS':
//       return { ...state, fallbackQuestions: action.payload };
//     case 'SET_FALLBACK_SETUP_COMPLETE':
//       return { ...state, fallbackSetupComplete: action.payload };
//     case 'SET_BIOMETRIC_KEYS':
//       return { ...state, biometricKeys: action.payload };
//     case 'SET_SECURITY_QUESTIONS_SETUP':
//       return { ...state, securityQuestionsSetup: action.payload };
//     case 'SET_COLLECTED_QUESTIONS':
//       return { ...state, collectedSecurityQuestions: action.payload };
//     case 'SET_FALLBACK_STEP':
//       return { ...state, fallbackStep: action.payload };
//     case 'RESET_AUTH':
//       return {
//         ...state,
//         currentStep: 1,
//         email: '',
//         phone: '',
//         userId: null,
//         emailVerified: false,
//         phoneVerified: false,
//         biometricVerified: false,
//         profileCreated: false,
//         error: null,
//         isAuthenticated: false,
//         userData: null,
//         fallbackQuestions: [],
//         fallbackSetupComplete: false,
//         biometricKeys: null,
//         securityQuestionsSetup: false,
//         collectedSecurityQuestions: [],
//         fallbackStep: null
//       };
//     case 'SET_OTP_SENT':
//       return { ...state, otpSent: action.payload };
//     case 'SET_RESEND_COOLDOWN':
//       return { ...state, resendCooldown: action.payload };
//     default:
//       return state;
//   }
// };

// const initialState = {
//   isAuthenticated: false,
//   isLoading: false,
//   currentStep: 1,
//   email: '',
//   phone: '',
//   userId: null,
//   emailVerified: false,
//   phoneVerified: false,
//   biometricVerified: false,
//   profileCreated: false,
//   userData: null,
//   error: null,
//   isValidReferrer: false,
//   referrerInfo: null,
//   otpSent: false,
//   resendCooldown: 0,
//   fallbackQuestions: [],
//   fallbackSetupComplete: false,
//   biometricKeys: null,
//   securityQuestionsSetup: false,
//   collectedSecurityQuestions: [],
//   fallbackStep: null
// };

// // Utilities
// const b64ToBytes = (b64) => {
//   const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
//   const pad = normalized.length % 4 === 2 ? '==' : normalized.length % 4 === 3 ? '=' : '';
//   const str = atob(normalized + pad);
//   const bytes = new Uint8Array(str.length);
//   for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
//   return bytes;
// };

// const createApiRequest = (BASE) => {
//   return async (endpoint, options = {}) => {
//     const isAbsolute = /^https?:\/\//i.test(endpoint);
//     const url = isAbsolute ? endpoint : `${BASE}${endpoint}`;

//     const config = {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//         'X-Requested-With': 'XMLHttpRequest',
//         'X-Referrer': typeof document !== 'undefined' ? document.referrer : '',
//         ...(options.headers || {})
//       },
//       ...options
//     };

//     // Add Authorization header if access token exists
//     const accessToken = TokenManager.getAccessToken();
//     if (accessToken && !config.headers.Authorization) {
//       config.headers.Authorization = `Bearer ${accessToken}`;
//     }

//     if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
//       config.body = JSON.stringify(config.body);
//     }

//     try {
//       const response = await fetch(url, config);
//       const data = await response.json().catch(() => null);

//       if (!response.ok) {
//         const error = new Error((data && data.message) || `HTTP error! status: ${response.status}`);
//         error.response = { data };
//         throw error;
//       }

//       return data;
//     } catch (error) {
//       console.error(`API request failed for ${url}:`, error);
//       if (error.response) throw error;
//       throw new Error('Network error. Please check your connection and try again.');
//     }
//   };
// };

// export const AuthProvider = ({ children }) => {
//   const [state, dispatch] = useReducer(authReducer, initialState);
//   const securityContext = useSecurity();

//   // Safe access to security functions with fallbacks
//   const {
//     checkReferrer = () => ({ isValid: false, referrer: '', error: 'Security context unavailable' }),
//     encryptData = (data) => JSON.stringify(data),
//     decryptData = (data) => JSON.parse(data),
//     generateDeviceFingerprint = () => Promise.resolve('fallback-fingerprint'),
//     createSession = () => {},
//     clearSession = () => {}
//   } = securityContext || {};

//   const API_BASE_3001 = import.meta.env?.VITE_API_BASE_URL || 'http://localhost:3001';
//   const API_BASE_3002 = import.meta.env?.VITE_BIOMETRIC_API_BASE_URL || 'http://localhost:3002';
//   const API_BASE_3003 = import.meta.env?.VITE_USER_MANAGEMENT_API_BASE_URL|| 'http://localhost:3003'; // Fixed URL as required

//   const api3001 = useCallback(createApiRequest(API_BASE_3001), [API_BASE_3001]);
//   const api3002 = useCallback(createApiRequest(API_BASE_3002), [API_BASE_3002]);
//   const api3003 = useCallback(createApiRequest(API_BASE_3003), [API_BASE_3003]);

//   // Check existing authentication on load
//   useEffect(() => {
//     const checkExistingAuth = () => {
//       const accessToken = TokenManager.getAccessToken();
//       const userData = localStorage.getItem('vottery_user_data');
      
//       if (accessToken && !TokenManager.isTokenExpired() && userData) {
//         try {
//           const parsedUserData = JSON.parse(userData);
//           dispatch({ type: 'SET_USER_DATA', payload: parsedUserData });
//           dispatch({ type: 'SET_USER_ID', payload: parsedUserData.id });
//           dispatch({ type: 'SET_EMAIL', payload: parsedUserData.sngine_email });
//           dispatch({ type: 'SET_PHONE', payload: parsedUserData.sngine_phone });
//           dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
//           dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//           dispatch({ type: 'SET_SECURITY_QUESTIONS_SETUP', payload: true });
//           dispatch({ type: 'SET_AUTHENTICATED', payload: true });
//         } catch (error) {
//           console.warn('Failed to parse user data, clearing tokens');
//           TokenManager.clearTokens();
//         }
//       }
//     };

//     checkExistingAuth();
//   }, []);

//   // Referrer check
//   useEffect(() => {
//     try {
//       const referrerInfo = checkReferrer();
//       dispatch({ type: 'SET_REFERRER_VALID', payload: referrerInfo.isValid, referrerInfo });

//       if (referrerInfo.isValid) {
//         const validationData = encryptData({
//           referrer: referrerInfo.referrer,
//           timestamp: Date.now(),
//           validated: true
//         });
//         sessionStorage.setItem('vottery_referrer_validation', validationData);
//       }
//     } catch (error) {
//       console.warn('Referrer check failed:', error);
//       dispatch({ type: 'SET_REFERRER_VALID', payload: false, referrerInfo: { error: error.message } });
//     }
//   }, [checkReferrer, encryptData]);

//   // Get User ID from check-user endpoint
//   const getUserId = useCallback(async () => {
//     try {
//       const response = await api3001('/api/auth/check-user', {
//         body: {
//           email: state.email,
//           phone: state.phone,
//         }
//       });

//       if (response?.success && response?.userId) {
//         dispatch({ type: 'SET_USER_ID', payload: response.userId });
//         return response.userId;
//       }
//       throw new Error(response?.message || 'Failed to get user ID');
//     } catch (error) {
//       console.error('Get user ID error:', error);
//       throw error;
//     }
//   }, [state.email, state.phone, api3001]);

//   // STEP 1: Send email OTP
//   const sendEmailOTP = useCallback(async (email) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!SecurityUtils.isValidEmail(email)) {
//         throw new Error('Invalid email format');
//       }

//       const response = await api3001('/api/auth/send-email-otp', {
//         body: {
//           email: SecurityUtils.sanitizeInput(email),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL', payload: email });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 2 });
//         toast.success('OTP sent to your email successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 2: Verify email OTP
//   const verifyEmailOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-email-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 3 });
//         toast.success('Email verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 3: Send phone OTP
//   const sendPhoneOTP = useCallback(async (phone) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       let cleanPhone = phone.trim();
//       if (!cleanPhone.startsWith('+') && /^\d/.test(cleanPhone)) cleanPhone = '+' + cleanPhone;
//       if (cleanPhone.startsWith('+')) cleanPhone = '+' + cleanPhone.substring(1).replace(/\D/g, '');

//       if (!SecurityUtils.isValidPhone(cleanPhone)) {
//         throw new Error('Invalid phone number format');
//       }

//       const response = await api3001('/api/auth/send-sms-otp', {
//         body: {
//           phone: cleanPhone,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE', payload: cleanPhone });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 4 });
//         toast.success('OTP sent to your phone successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 4: Verify phone OTP
//   const verifyPhoneOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-sms-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
        
//         // After phone verification, proceed to security questions setup
//         dispatch({ type: 'SET_STEP', payload: 'security-questions' });
//         toast.success('Phone verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 5: Save security questions (called from SecurityQuestionsSetup component)
//   const saveSecurityQuestions = useCallback(async (questionsAndAnswers) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       // Validate input
//       if (!questionsAndAnswers || !Array.isArray(questionsAndAnswers) || questionsAndAnswers.length < 3) {
//         throw new Error('Please provide exactly 3 security questions and answers');
//       }

//       // Validate each question-answer pair
//       for (const qa of questionsAndAnswers) {
//         if (!qa.question || !qa.answer || qa.question.trim() === '' || qa.answer.trim() === '') {
//           throw new Error('All questions and answers must be filled');
//         }
//         if (qa.answer.trim().length < 2) {
//           throw new Error('All answers must be at least 2 characters long');
//         }
//       }

//       // Check for duplicate questions
//       const questionTexts = questionsAndAnswers.map(q => q.question.trim().toLowerCase());
//       const uniqueQuestions = [...new Set(questionTexts)];
//       if (uniqueQuestions.length !== questionsAndAnswers.length) {
//         throw new Error('Please ensure all security questions are different');
//       }

//       // Get user ID first
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       // Save each question-answer pair
//       for (const qa of questionsAndAnswers) {
//         const questionResponse = await api3003(`/api/biometric/add-question/${userId}`, {
//           method: 'POST',
//           body: {
//             question: qa.question.trim(),
//             answer: qa.answer.trim()
//           }
//         });

//         if (!questionResponse?.success) {
//           throw new Error(questionResponse?.message || `Failed to add security question: ${qa.question}`);
//         }
//       }

//       // Update state to mark security questions as setup
//       dispatch({ type: 'SET_COLLECTED_QUESTIONS', payload: questionsAndAnswers });
//       dispatch({ type: 'SET_SECURITY_QUESTIONS_SETUP', payload: true });
      
//       toast.success('Security questions saved successfully!');
      
//       return { success: true };

//     } catch (error) {
//       console.error('Save security questions error:', error);
//       const errorMessage = error?.message || 'Failed to save security questions';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.userId, getUserId, api3003]);

//   // STEP 6: Complete Authentication (Biometric + Fallback Setup)
//   const completeAuthentication = useCallback(async () => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.emailVerified || !state.phoneVerified) {
//         throw new Error('Email and phone verification must be completed first');
//       }

//       if (!state.securityQuestionsSetup) {
//         throw new Error('Security questions must be setup first');
//       }

//       // Get user ID first
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       let biometricSuccess = false;

//       // Try biometric authentication if supported
//       const isBiometricSupported = window.PublicKeyCredential && 
//         await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(() => false);

//       if (isBiometricSupported) {
//         try {
//           console.log('Attempting biometric authentication...');
//           const deviceFingerprint = await generateDeviceFingerprint();
//           const deviceInfo = {
//             type: /mobile/i.test(navigator.userAgent) ? 'mobile' :
//                   /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop',
//             browser: { name: navigator.userAgent, version: navigator.appVersion },
//             os: { name: navigator.platform, version: navigator.platform },
//             screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1 }
//           };

//           const capabilities = { hasWebAuthn: !!window.PublicKeyCredential, platform: navigator.platform, userAgent: navigator.userAgent };
//           const location = { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, language: navigator.language };

//           const deviceResponse = await api3002('/api/biometric/device/register', {
//             body: { 
//               sngine_email: state.email, 
//               sngine_phone: state.phone, 
//               deviceInfo, 
//               location, 
//               capabilities, 
//               referrer: document.referrer, 
//               timestamp: Date.now() 
//             }
//           });

//           if (deviceResponse?.success && deviceResponse?.device?.id) {
//             const deviceId = deviceResponse.device.id;
//             const biometricData = { deviceFingerprint, userAgent: navigator.userAgent, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, timestamp: Date.now(), capabilities };

//             const biometricResponse = await api3002('/api/biometric/register', {
//               body: { 
//                 sngine_email: state.email, 
//                 sngine_phone: state.phone, 
//                 deviceId, 
//                 biometricType: 'device_fingerprint', 
//                 biometricData, 
//                 referrer: document.referrer, 
//                 timestamp: Date.now() 
//               }
//             });

//             if (biometricResponse?.success) {
//               // Try WebAuthn registration
//               const begin = await api3002('/api/biometric/webauthn/register/begin', {
//                 body: { 
//                   sngine_email: state.email, 
//                   sngine_phone: state.phone, 
//                   deviceId, 
//                   referrer: document.referrer, 
//                   timestamp: Date.now() 
//                 }
//               });

//               if (begin?.success && begin?.options) {
//                 const publicKey = { 
//                   ...begin.options, 
//                   challenge: b64ToBytes(begin.options.challenge), 
//                   user: { ...begin.options.user, id: b64ToBytes(begin.options.user.id) } 
//                 };
//                 const credential = await navigator.credentials.create({ publicKey });

//                 if (credential) {
//                   const attestationObject = new Uint8Array(credential.response.attestationObject || []);
//                   const clientDataJSON = new Uint8Array(credential.response.clientDataJSON || []);

//                   const finish = await api3002('/api/biometric/webauthn/register/finish', {
//                     body: { 
//                       sngine_email: state.email, 
//                       sngine_phone: state.phone, 
//                       deviceId, 
//                       credential: { 
//                         id: credential.id, 
//                         rawId: Array.from(new Uint8Array(credential.rawId)), 
//                         response: { 
//                           attestationObject: Array.from(attestationObject), 
//                           clientDataJSON: Array.from(clientDataJSON) 
//                         }, 
//                         type: credential.type 
//                       }, 
//                       referrer: document.referrer, 
//                       timestamp: Date.now() 
//                     }
//                   });

//                   if (finish?.success) {
//                     biometricSuccess = true;
//                     console.log('Biometric authentication completed successfully');
//                   }
//                 }
//               }
//             }
//           }
//         } catch (biometricError) {
//           console.warn('Biometric authentication failed, continuing with fallback setup:', biometricError);
//         }
//       } else {
//         console.log('Biometric not supported on this device');
//       }

//       // MANDATORY FALLBACK SETUP - Always required regardless of biometric success
//       console.log('Setting up mandatory fallback security...');
      
//       // Step 1: Register cryptographic keys
//       const keysResponse = await api3003(`/api/biometric/register-keys/${userId}`, {
//         method: 'POST'
//       });

//       if (!keysResponse?.success) {
//         throw new Error(keysResponse?.message || 'Failed to register cryptographic keys');
//       }

//       dispatch({ type: 'SET_BIOMETRIC_KEYS', payload: keysResponse.keys });

//       // Step 2: Get all questions for storage
//       const questionsResponse = await api3003(`/api/biometric/questions/${userId}`, {
//         method: 'GET'
//       });

//       if (questionsResponse?.success && questionsResponse?.questions) {
//         const questions = questionsResponse.questions.map(q => q.question);
//         dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: questions });
//       }

//       // Mark fallback setup complete and proceed to profile creation
//       dispatch({ type: 'SET_FALLBACK_SETUP_COMPLETE', payload: true });
//       dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//       dispatch({ type: 'SET_STEP', payload: 6 });

//       const successMessage = biometricSuccess 
//         ? 'Biometric authentication and fallback security setup completed successfully!'
//         : 'Fallback security setup completed successfully!';
      
//       toast.success(successMessage);

//       return { 
//         success: true, 
//         biometricSuccess, 
//         fallbackSetup: true, 
//         message: successMessage 
//       };

//     } catch (error) {
//       console.error('Complete authentication error:', error);
//       const errorMessage = error?.message || 'Authentication failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.email, state.phone, state.emailVerified, state.phoneVerified, state.userId, state.securityQuestionsSetup, generateDeviceFingerprint, getUserId, api3002, api3003]);

//   // Get fallback questions
//   const getFallbackQuestions = useCallback(async () => {
//     try {
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       const questionsResponse = await api3003(`/api/biometric/questions/${userId}`, {
//         method: 'GET'
//       });

//       if (questionsResponse?.success && questionsResponse?.questions) {
//         const questions = questionsResponse.questions.map(q => q.question);
//         dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: questions });
//         return questions;
//       }

//       return [];
//     } catch (error) {
//       console.error('Get fallback questions error:', error);
//       return [];
//     }
//   }, [state.userId, getUserId, api3003]);

//   // STEP 7: Complete Profile Creation
//   const completeProfileCreation = useCallback(async (profileData) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.biometricVerified || !state.fallbackSetupComplete) {
//         throw new Error('Authentication and fallback security setup must be completed first');
//       }

//       // Get user ID if not already available
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       const response = await api3003('/api/users/create', {
//         method: 'POST',
//         body: {
//           user_id: userId,
//           sngine_email: state.email,
//           sngine_phone: state.phone,
//           ...profileData,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         // Store tokens
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken,
//           response.tokenExpiry
//         );

//         // Store user data
//         localStorage.setItem('vottery_user_data', JSON.stringify(response.data));

//         // Update state
//         dispatch({ type: 'SET_USER_DATA', payload: response.data });
//         dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//         dispatch({ type: 'SET_AUTHENTICATED', payload: true });

//         // Create session
//         const sessionData = {
//           userId: response.data.id,
//           email: response.data.sngine_email,
//           phone: response.data.sngine_phone,
//           userType: response.data.user_type,
//           adminRole: response.data.admin_role,
//           subscriptionStatus: response.data.subscription_status,
//           authenticated: true,
//           profileCreated: true,
//           timestamp: Date.now()
//         };

//         createSession(sessionData);
//         toast.success('Profile created successfully! Welcome to Vottery!');

//         return response;
//       }

//       throw new Error(response?.message || 'Profile creation failed');
//     } catch (error) {
//       console.error('Profile creation error:', error);
//       const errorMessage = error?.message || 'Profile creation failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.biometricVerified, state.fallbackSetupComplete, state.userId, state.email, state.phone, getUserId, api3003, createSession]);

//   // Token refresh utility with rotation
//   const refreshAccessToken = useCallback(async () => {
//     try {
//       const refreshToken = TokenManager.getRefreshToken();
//       if (!refreshToken) throw new Error('No refresh token available');

//       const response = await api3003('/api/auth/refresh', {
//         method: 'POST',
//         body: { refreshToken }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         // Store NEW tokens (rotation - both access and refresh tokens are new)
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken, // This is the NEW refresh token
//           response.tokenExpiry
//         );
//         return response.accessToken;
//       }

//       throw new Error('Token refresh failed');
//     } catch (error) {
//       console.error('Token refresh failed:', error);
//       logout();
//       throw error;
//     }
//   }, [api3003]);

//   // Navigation helpers
//   const goBackStep = useCallback(() => {
//     if (state.currentStep === 2) dispatch({ type: 'SET_STEP', payload: 1 });
//     else if (state.currentStep === 4) dispatch({ type: 'SET_STEP', payload: 3 });
//     else if (state.currentStep === 5) dispatch({ type: 'SET_STEP', payload: 4 });
//     else if (state.currentStep === 6) dispatch({ type: 'SET_STEP', payload: 5 });
//     else if (state.currentStep === 'security-questions') dispatch({ type: 'SET_STEP', payload: 4 });
//   }, [state.currentStep]);

//   const logout = useCallback(() => {
//     TokenManager.clearTokens();
//     clearSession();
//     sessionStorage.removeItem('vottery_referrer_validation');
//     dispatch({ type: 'RESET_AUTH' });
//     toast.success('Logged out successfully');
//   }, [clearSession]);

//   const resetAuth = useCallback(() => {
//     TokenManager.clearTokens();
//     dispatch({ type: 'RESET_AUTH' });
//   }, []);

//   // Auto refresh token before expiry
//   useEffect(() => {
//     const accessToken = TokenManager.getAccessToken();
//     const tokenExpiry = localStorage.getItem('vottery_token_expiry');
    
//     if (accessToken && tokenExpiry && !TokenManager.isTokenExpired()) {
//       try {
//         const expiryData = JSON.parse(tokenExpiry);
//         const expiryTime = new Date().getTime() + (7 * 24 * 60 * 60 * 1000); // 7 days from now
//         const refreshTime = expiryTime - Date.now() - 60000; // Refresh 1 minute before expiry

//         if (refreshTime > 0) {
//           const timeout = setTimeout(() => {
//             refreshAccessToken().catch(console.error);
//           }, refreshTime);

//           return () => clearTimeout(timeout);
//         }
//       } catch (error) {
//         console.warn('Failed to parse token expiry, clearing tokens');
//         TokenManager.clearTokens();
//       }
//     }
//   }, [refreshAccessToken]);

//   // Context value
//   const value = {
//     ...state,
//     dispatch,
//     sendEmailOTP,
//     verifyEmailOTP,
//     sendPhoneOTP,
//     verifyPhoneOTP,
//     saveSecurityQuestions,
//     completeAuthentication,
//     completeProfileCreation,
//     getFallbackQuestions,
//     getUserId,
//     refreshAccessToken,
//     goBackStep,
//     logout,
//     resetAuth,
//     // Token utilities
//     getAccessToken: TokenManager.getAccessToken,
//     getRefreshToken: TokenManager.getRefreshToken,
//     isTokenExpired: TokenManager.isTokenExpired
//   };

//   return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
// };
// import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react';
// import { useSecurity } from './SecurityContext';
// import { SecurityUtils } from '../utils/security';
// import { toast } from 'react-hot-toast';

// const AuthContext = createContext();

// export const useAuth = () => {
//   const context = useContext(AuthContext);
//   if (!context) {
//     throw new Error('useAuth must be used within AuthProvider');
//   }
//   return context;
// };

// // Token Management Utility with Rotation Support
// const TokenManager = {
//   setTokens: (accessToken, refreshToken, expiryInfo) => {
//     localStorage.setItem('vottery_access_token', accessToken);
//     localStorage.setItem('vottery_refresh_token', refreshToken);
//     localStorage.setItem('vottery_token_expiry', JSON.stringify(expiryInfo));
//     localStorage.setItem('vottery_token_timestamp', Date.now().toString());
//   },

//   getAccessToken: () => localStorage.getItem('vottery_access_token'),
  
//   getRefreshToken: () => localStorage.getItem('vottery_refresh_token'),
  
//   clearTokens: () => {
//     localStorage.removeItem('vottery_access_token');
//     localStorage.removeItem('vottery_refresh_token');
//     localStorage.removeItem('vottery_token_expiry');
//     localStorage.removeItem('vottery_token_timestamp');
//     localStorage.removeItem('vottery_user_data');
//   },

//   isTokenExpired: () => {
//     const timestamp = localStorage.getItem('vottery_token_timestamp');
//     if (!timestamp) return true;
    
//     // Assuming 7 days expiry (7 * 24 * 60 * 60 * 1000)
//     const tokenAge = Date.now() - parseInt(timestamp);
//     const maxAge = 7 * 24 * 60 * 60 * 1000;
    
//     return tokenAge >= maxAge;
//   }
// };

// // Auth reducer
// const authReducer = (state, action) => {
//   switch (action.type) {
//     case 'SET_LOADING':
//       return { ...state, isLoading: action.payload };
//     case 'SET_STEP':
//       return { ...state, currentStep: action.payload };
//     case 'SET_EMAIL':
//       return { ...state, email: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_PHONE':
//       return { ...state, phone: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_EMAIL_VERIFIED':
//       return { ...state, emailVerified: action.payload };
//     case 'SET_PHONE_VERIFIED':
//       return { ...state, phoneVerified: action.payload };
//     case 'SET_BIOMETRIC_VERIFIED':
//       return { ...state, biometricVerified: action.payload };
//     case 'SET_PROFILE_CREATED':
//       return { ...state, profileCreated: action.payload };
//     case 'SET_AUTHENTICATED':
//       return { ...state, isAuthenticated: action.payload };
//     case 'SET_USER_DATA':
//       return { ...state, userData: action.payload };
//     case 'SET_USER_ID':
//       return { ...state, userId: action.payload };
//     case 'SET_ERROR':
//       return { ...state, error: action.payload };
//     case 'SET_REFERRER_VALID':
//       return { ...state, isValidReferrer: action.payload, referrerInfo: action.referrerInfo };
//     case 'SET_FALLBACK_QUESTIONS':
//       return { ...state, fallbackQuestions: action.payload };
//     case 'SET_FALLBACK_SETUP_COMPLETE':
//       return { ...state, fallbackSetupComplete: action.payload };
//     case 'SET_BIOMETRIC_KEYS':
//       return { ...state, biometricKeys: action.payload };
//     case 'SET_SECURITY_QUESTIONS_SETUP':
//       return { ...state, securityQuestionsSetup: action.payload };
//     case 'SET_COLLECTED_QUESTIONS':
//       return { ...state, collectedSecurityQuestions: action.payload };
//     case 'RESET_AUTH':
//       return {
//         ...state,
//         currentStep: 1,
//         email: '',
//         phone: '',
//         userId: null,
//         emailVerified: false,
//         phoneVerified: false,
//         biometricVerified: false,
//         profileCreated: false,
//         error: null,
//         isAuthenticated: false,
//         userData: null,
//         fallbackQuestions: [],
//         fallbackSetupComplete: false,
//         biometricKeys: null,
//         securityQuestionsSetup: false,
//         collectedSecurityQuestions: []
//       };
//     case 'SET_OTP_SENT':
//       return { ...state, otpSent: action.payload };
//     case 'SET_RESEND_COOLDOWN':
//       return { ...state, resendCooldown: action.payload };
//     default:
//       return state;
//   }
// };

// const initialState = {
//   isAuthenticated: false,
//   isLoading: false,
//   currentStep: 1,
//   email: '',
//   phone: '',
//   userId: null,
//   emailVerified: false,
//   phoneVerified: false,
//   biometricVerified: false,
//   profileCreated: false,
//   userData: null,
//   error: null,
//   isValidReferrer: false,
//   referrerInfo: null,
//   otpSent: false,
//   resendCooldown: 0,
//   fallbackQuestions: [],
//   fallbackSetupComplete: false,
//   biometricKeys: null,
//   securityQuestionsSetup: false,
//   collectedSecurityQuestions: []
// };

// // Utilities
// const b64ToBytes = (b64) => {
//   const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
//   const pad = normalized.length % 4 === 2 ? '==' : normalized.length % 4 === 3 ? '=' : '';
//   const str = atob(normalized + pad);
//   const bytes = new Uint8Array(str.length);
//   for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
//   return bytes;
// };

// const createApiRequest = (BASE) => {
//   return async (endpoint, options = {}) => {
//     const isAbsolute = /^https?:\/\//i.test(endpoint);
//     const url = isAbsolute ? endpoint : `${BASE}${endpoint}`;

//     const config = {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//         'X-Requested-With': 'XMLHttpRequest',
//         'X-Referrer': typeof document !== 'undefined' ? document.referrer : '',
//         ...(options.headers || {})
//       },
//       ...options
//     };

//     // Add Authorization header if access token exists
//     const accessToken = TokenManager.getAccessToken();
//     if (accessToken && !config.headers.Authorization) {
//       config.headers.Authorization = `Bearer ${accessToken}`;
//     }

//     if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
//       config.body = JSON.stringify(config.body);
//     }

//     try {
//       const response = await fetch(url, config);
//       const data = await response.json().catch(() => null);

//       if (!response.ok) {
//         const error = new Error((data && data.message) || `HTTP error! status: ${response.status}`);
//         error.response = { data };
//         throw error;
//       }

//       return data;
//     } catch (error) {
//       console.error(`API request failed for ${url}:`, error);
//       if (error.response) throw error;
//       throw new Error('Network error. Please check your connection and try again.');
//     }
//   };
// };

// export const AuthProvider = ({ children }) => {
//   const [state, dispatch] = useReducer(authReducer, initialState);
//   const securityContext = useSecurity();

//   // Safe access to security functions with fallbacks
//   const {
//     checkReferrer = () => ({ isValid: false, referrer: '', error: 'Security context unavailable' }),
//     encryptData = (data) => JSON.stringify(data),
//     decryptData = (data) => JSON.parse(data),
//     generateDeviceFingerprint = () => Promise.resolve('fallback-fingerprint'),
//     createSession = () => {},
//     clearSession = () => {}
//   } = securityContext || {};

//   const API_BASE_3001 = import.meta.env?.VITE_API_BASE_URL || 'http://localhost:3001';
//   const API_BASE_3002 = import.meta.env?.VITE_BIOMETRIC_API_BASE_URL || 'http://localhost:3002';
//   const API_BASE_3003 = 'http://localhost:3003'; // Fixed URL as required

//   const api3001 = useCallback(createApiRequest(API_BASE_3001), [API_BASE_3001]);
//   const api3002 = useCallback(createApiRequest(API_BASE_3002), [API_BASE_3002]);
//   const api3003 = useCallback(createApiRequest(API_BASE_3003), [API_BASE_3003]);

//   // Check existing authentication on load
//   useEffect(() => {
//     const checkExistingAuth = () => {
//       const accessToken = TokenManager.getAccessToken();
//       const userData = localStorage.getItem('vottery_user_data');
      
//       if (accessToken && !TokenManager.isTokenExpired() && userData) {
//         try {
//           const parsedUserData = JSON.parse(userData);
//           dispatch({ type: 'SET_USER_DATA', payload: parsedUserData });
//           dispatch({ type: 'SET_USER_ID', payload: parsedUserData.id });
//           dispatch({ type: 'SET_EMAIL', payload: parsedUserData.sngine_email });
//           dispatch({ type: 'SET_PHONE', payload: parsedUserData.sngine_phone });
//           dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
//           dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//           dispatch({ type: 'SET_AUTHENTICATED', payload: true });
//         } catch (error) {
//           console.warn('Failed to parse user data, clearing tokens');
//           TokenManager.clearTokens();
//         }
//       }
//     };

//     checkExistingAuth();
//   }, []);

//   // Referrer check
//   useEffect(() => {
//     try {
//       const referrerInfo = checkReferrer();
//       dispatch({ type: 'SET_REFERRER_VALID', payload: referrerInfo.isValid, referrerInfo });

//       if (referrerInfo.isValid) {
//         const validationData = encryptData({
//           referrer: referrerInfo.referrer,
//           timestamp: Date.now(),
//           validated: true
//         });
//         sessionStorage.setItem('vottery_referrer_validation', validationData);
//       }
//     } catch (error) {
//       console.warn('Referrer check failed:', error);
//       dispatch({ type: 'SET_REFERRER_VALID', payload: false, referrerInfo: { error: error.message } });
//     }
//   }, [checkReferrer, encryptData]);

//   // Get User ID from check-user endpoint
//   const getUserId = useCallback(async () => {
//     try {
//       const response = await api3001('/api/auth/check-user', {
//         body: {
//           email: state.email,
//           phone: state.phone,
//         }
//       });

//       if (response?.success && response?.userId) {
//         dispatch({ type: 'SET_USER_ID', payload: response.userId });
//         return response.userId;
//       }
//       throw new Error(response?.message || 'Failed to get user ID');
//     } catch (error) {
//       console.error('Get user ID error:', error);
//       throw error;
//     }
//   }, [state.email, state.phone, api3001]);

//   // STEP 1: Send email OTP
//   const sendEmailOTP = useCallback(async (email) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!SecurityUtils.isValidEmail(email)) {
//         throw new Error('Invalid email format');
//       }

//       const response = await api3001('/api/auth/send-email-otp', {
//         body: {
//           email: SecurityUtils.sanitizeInput(email),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL', payload: email });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 2 });
//         toast.success('OTP sent to your email successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 2: Verify email OTP
//   const verifyEmailOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-email-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 3 });
//         toast.success('Email verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 3: Send phone OTP
//   const sendPhoneOTP = useCallback(async (phone) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       let cleanPhone = phone.trim();
//       if (!cleanPhone.startsWith('+') && /^\d/.test(cleanPhone)) cleanPhone = '+' + cleanPhone;
//       if (cleanPhone.startsWith('+')) cleanPhone = '+' + cleanPhone.substring(1).replace(/\D/g, '');

//       if (!SecurityUtils.isValidPhone(cleanPhone)) {
//         throw new Error('Invalid phone number format');
//       }

//       const response = await api3001('/api/auth/send-sms-otp', {
//         body: {
//           phone: cleanPhone,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE', payload: cleanPhone });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 4 });
//         toast.success('OTP sent to your phone successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 4: Verify phone OTP
//   const verifyPhoneOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-sms-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 5 });
//         toast.success('Phone verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // NEW: Save security questions (called from SecurityQuestionsSetup component)
//   const saveSecurityQuestions = useCallback(async (questionsAndAnswers) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       // Validate input
//       if (!questionsAndAnswers || !Array.isArray(questionsAndAnswers) || questionsAndAnswers.length < 2) {
//         throw new Error('Please provide at least 2 security questions and answers');
//       }

//       // Validate each question-answer pair
//       for (const qa of questionsAndAnswers) {
//         if (!qa.question || !qa.answer || qa.question.trim() === '' || qa.answer.trim() === '') {
//           throw new Error('All questions and answers must be filled');
//         }
//       }

//       // Get user ID first
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       // Save each question-answer pair
//       for (const qa of questionsAndAnswers) {
//         const questionResponse = await api3003(`/api/biometric/add-question/${userId}`, {
//           method: 'POST',
//           body: {
//             question: qa.question.trim(),
//             answer: qa.answer.trim()
//           }
//         });

//         if (!questionResponse?.success) {
//           throw new Error(questionResponse?.message || `Failed to add security question: ${qa.question}`);
//         }
//       }

//       dispatch({ type: 'SET_COLLECTED_QUESTIONS', payload: questionsAndAnswers });
//       dispatch({ type: 'SET_SECURITY_QUESTIONS_SETUP', payload: true });
      
//       toast.success('Security questions saved successfully!');
//       return { success: true };

//     } catch (error) {
//       console.error('Save security questions error:', error);
//       const errorMessage = error?.message || 'Failed to save security questions';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.userId, getUserId, api3003]);

//   // STEP 5: Complete Authentication (Modified to include security questions setup)
//   const completeAuthentication = useCallback(async () => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.emailVerified || !state.phoneVerified) {
//         throw new Error('Email and phone verification must be completed first');
//       }

//       // If security questions haven't been set up yet, redirect to security questions setup
//       if (!state.securityQuestionsSetup) {
//         dispatch({ type: 'SET_STEP', payload: 'security-questions' });
//         return { success: true, requiresSecurityQuestions: true };
//       }

//       // Get user ID first
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       let biometricSuccess = false;

//       // Try biometric authentication if supported
//       const isBiometricSupported = window.PublicKeyCredential && 
//         await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(() => false);

//       if (isBiometricSupported) {
//         try {
//           console.log('Attempting biometric authentication...');
//           const deviceFingerprint = await generateDeviceFingerprint();
//           const deviceInfo = {
//             type: /mobile/i.test(navigator.userAgent) ? 'mobile' :
//                   /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop',
//             browser: { name: navigator.userAgent, version: navigator.appVersion },
//             os: { name: navigator.platform, version: navigator.platform },
//             screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1 }
//           };

//           const capabilities = { hasWebAuthn: !!window.PublicKeyCredential, platform: navigator.platform, userAgent: navigator.userAgent };
//           const location = { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, language: navigator.language };

//           const deviceResponse = await api3002('/api/biometric/device/register', {
//             body: { 
//               sngine_email: state.email, 
//               sngine_phone: state.phone, 
//               deviceInfo, 
//               location, 
//               capabilities, 
//               referrer: document.referrer, 
//               timestamp: Date.now() 
//             }
//           });

//           if (deviceResponse?.success && deviceResponse?.device?.id) {
//             const deviceId = deviceResponse.device.id;
//             const biometricData = { deviceFingerprint, userAgent: navigator.userAgent, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, timestamp: Date.now(), capabilities };

//             const biometricResponse = await api3002('/api/biometric/register', {
//               body: { 
//                 sngine_email: state.email, 
//                 sngine_phone: state.phone, 
//                 deviceId, 
//                 biometricType: 'device_fingerprint', 
//                 biometricData, 
//                 referrer: document.referrer, 
//                 timestamp: Date.now() 
//               }
//             });

//             if (biometricResponse?.success) {
//               // Try WebAuthn registration
//               const begin = await api3002('/api/biometric/webauthn/register/begin', {
//                 body: { 
//                   sngine_email: state.email, 
//                   sngine_phone: state.phone, 
//                   deviceId, 
//                   referrer: document.referrer, 
//                   timestamp: Date.now() 
//                 }
//               });

//               if (begin?.success && begin?.options) {
//                 const publicKey = { 
//                   ...begin.options, 
//                   challenge: b64ToBytes(begin.options.challenge), 
//                   user: { ...begin.options.user, id: b64ToBytes(begin.options.user.id) } 
//                 };
//                 const credential = await navigator.credentials.create({ publicKey });

//                 if (credential) {
//                   const attestationObject = new Uint8Array(credential.response.attestationObject || []);
//                   const clientDataJSON = new Uint8Array(credential.response.clientDataJSON || []);

//                   const finish = await api3002('/api/biometric/webauthn/register/finish', {
//                     body: { 
//                       sngine_email: state.email, 
//                       sngine_phone: state.phone, 
//                       deviceId, 
//                       credential: { 
//                         id: credential.id, 
//                         rawId: Array.from(new Uint8Array(credential.rawId)), 
//                         response: { 
//                           attestationObject: Array.from(attestationObject), 
//                           clientDataJSON: Array.from(clientDataJSON) 
//                         }, 
//                         type: credential.type 
//                       }, 
//                       referrer: document.referrer, 
//                       timestamp: Date.now() 
//                     }
//                   });

//                   if (finish?.success) {
//                     biometricSuccess = true;
//                     console.log('Biometric authentication completed successfully');
//                   }
//                 }
//               }
//             }
//           }
//         } catch (biometricError) {
//           console.warn('Biometric authentication failed, continuing with fallback setup:', biometricError);
//         }
//       } else {
//         console.log('Biometric not supported on this device');
//       }

//       // MANDATORY FALLBACK SETUP - Always required regardless of biometric success
//       console.log('Setting up mandatory fallback security...');
      
//       // Step 1: Register cryptographic keys
//       const keysResponse = await api3003(`/api/biometric/register-keys/${userId}`, {
//         method: 'POST'
//       });

//       if (!keysResponse?.success) {
//         throw new Error(keysResponse?.message || 'Failed to register cryptographic keys');
//       }

//       dispatch({ type: 'SET_BIOMETRIC_KEYS', payload: keysResponse.keys });

//       // Step 2: Security questions are already added by saveSecurityQuestions function
//       // So we just need to verify they exist

//       // Step 3: Get all questions for storage
//       const questionsResponse = await api3003(`/api/biometric/questions/${userId}`, {
//         method: 'GET'
//       });

//       if (questionsResponse?.success && questionsResponse?.questions) {
//         const questions = questionsResponse.questions.map(q => q.question);
//         dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: questions });
//       }

//       // Mark fallback setup complete
//       dispatch({ type: 'SET_FALLBACK_SETUP_COMPLETE', payload: true });
//       dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//       dispatch({ type: 'SET_STEP', payload: 6 });

//       const successMessage = biometricSuccess 
//         ? 'Biometric authentication and fallback security setup completed successfully!'
//         : 'Fallback security setup completed successfully!';
      
//       toast.success(successMessage);

//       return { 
//         success: true, 
//         biometricSuccess, 
//         fallbackSetup: true, 
//         message: successMessage 
//       };

//     } catch (error) {
//       console.error('Complete authentication error:', error);
//       const errorMessage = error?.message || 'Authentication failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.email, state.phone, state.emailVerified, state.phoneVerified, state.userId, state.securityQuestionsSetup, generateDeviceFingerprint, getUserId, api3002, api3003]);

//   // Get fallback questions
//   const getFallbackQuestions = useCallback(async () => {
//     try {
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       const questionsResponse = await api3003(`/api/biometric/questions/${userId}`, {
//         method: 'GET'
//       });

//       if (questionsResponse?.success && questionsResponse?.questions) {
//         const questions = questionsResponse.questions.map(q => q.question);
//         dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: questions });
//         return questions;
//       }

//       return [];
//     } catch (error) {
//       console.error('Get fallback questions error:', error);
//       return [];
//     }
//   }, [state.userId, getUserId, api3003]);

//   // STEP 6: Complete Profile Creation
//   const completeProfileCreation = useCallback(async (profileData) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.biometricVerified || !state.fallbackSetupComplete) {
//         throw new Error('Authentication and fallback security setup must be completed first');
//       }

//       // Get user ID if not already available
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       const response = await api3003('/api/auth/create', {
//         method: 'POST',
//         body: {
//           user_id: userId,
//           sngine_email: state.email,
//           sngine_phone: state.phone,
//           ...profileData,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         // Store tokens
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken,
//           response.tokenExpiry
//         );

//         // Store user data
//         localStorage.setItem('vottery_user_data', JSON.stringify(response.data));

//         // Update state
//         dispatch({ type: 'SET_USER_DATA', payload: response.data });
//         dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//         dispatch({ type: 'SET_AUTHENTICATED', payload: true });

//         // Create session
//         const sessionData = {
//           userId: response.data.id,
//           email: response.data.sngine_email,
//           phone: response.data.sngine_phone,
//           userType: response.data.user_type,
//           adminRole: response.data.admin_role,
//           subscriptionStatus: response.data.subscription_status,
//           authenticated: true,
//           profileCreated: true,
//           timestamp: Date.now()
//         };

//         createSession(sessionData);
//         toast.success('Profile created successfully! Welcome to Vottery!');

//         return response;
//       }

//       throw new Error(response?.message || 'Profile creation failed');
//     } catch (error) {
//       console.error('Profile creation error:', error);
//       const errorMessage = error?.message || 'Profile creation failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.biometricVerified, state.fallbackSetupComplete, state.userId, state.email, state.phone, getUserId, api3003, createSession]);

//   // Token refresh utility with rotation
//   const refreshAccessToken = useCallback(async () => {
//     try {
//       const refreshToken = TokenManager.getRefreshToken();
//       if (!refreshToken) throw new Error('No refresh token available');

//       const response = await api3003('/api/auth/refresh', {
//         method: 'POST',
//         body: { refreshToken }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         // Store NEW tokens (rotation - both access and refresh tokens are new)
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken, // This is the NEW refresh token
//           response.tokenExpiry
//         );
//         return response.accessToken;
//       }

//       throw new Error('Token refresh failed');
//     } catch (error) {
//       console.error('Token refresh failed:', error);
//       logout();
//       throw error;
//     }
//   }, [api3003]);

//   // Navigation helpers
//   const goBackStep = useCallback(() => {
//     if (state.currentStep === 2) dispatch({ type: 'SET_STEP', payload: 1 });
//     else if (state.currentStep === 4) dispatch({ type: 'SET_STEP', payload: 3 });
//     else if (state.currentStep === 5) dispatch({ type: 'SET_STEP', payload: 4 });
//     else if (state.currentStep === 6) dispatch({ type: 'SET_STEP', payload: 5 });
//     else if (state.currentStep === 'security-questions') dispatch({ type: 'SET_STEP', payload: 5 });
//   }, [state.currentStep]);

//   const logout = useCallback(() => {
//     TokenManager.clearTokens();
//     clearSession();
//     sessionStorage.removeItem('vottery_referrer_validation');
//     dispatch({ type: 'RESET_AUTH' });
//     toast.success('Logged out successfully');
//   }, [clearSession]);

//   const resetAuth = useCallback(() => {
//     TokenManager.clearTokens();
//     dispatch({ type: 'RESET_AUTH' });
//   }, []);

//   // Auto refresh token before expiry
//   useEffect(() => {
//     const accessToken = TokenManager.getAccessToken();
//     const tokenExpiry = localStorage.getItem('vottery_token_expiry');
    
//     if (accessToken && tokenExpiry && !TokenManager.isTokenExpired()) {
//       try {
//         const expiryData = JSON.parse(tokenExpiry);
//         const expiryTime = new Date().getTime() + (7 * 24 * 60 * 60 * 1000); // 7 days from now
//         const refreshTime = expiryTime - Date.now() - 60000; // Refresh 1 minute before expiry

//         if (refreshTime > 0) {
//           const timeout = setTimeout(() => {
//             refreshAccessToken().catch(console.error);
//           }, refreshTime);

//           return () => clearTimeout(timeout);
//         }
//       } catch (error) {
//         console.warn('Failed to parse token expiry, clearing tokens');
//         TokenManager.clearTokens();
//       }
//     }
//   }, [refreshAccessToken]);

//   // Context value
//   const value = {
//     ...state,
//     dispatch,
//     sendEmailOTP,
//     verifyEmailOTP,
//     sendPhoneOTP,
//     verifyPhoneOTP,
//     saveSecurityQuestions,
//     completeAuthentication,
//     completeProfileCreation,
//     getFallbackQuestions,
//     getUserId,
//     refreshAccessToken,
//     goBackStep,
//     logout,
//     resetAuth,
//     // Token utilities
//     getAccessToken: TokenManager.getAccessToken,
//     getRefreshToken: TokenManager.getRefreshToken,
//     isTokenExpired: TokenManager.isTokenExpired
//   };

//   return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
// };
// //7 steps with mandatory fallback latest version
// import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react';
// import { useSecurity } from './SecurityContext';
// import { SecurityUtils } from '../utils/security';
// import { toast } from 'react-hot-toast';

// const AuthContext = createContext();

// export const useAuth = () => {
//   const context = useContext(AuthContext);
//   if (!context) {
//     throw new Error('useAuth must be used within AuthProvider');
//   }
//   return context;
// };

// // Token Management Utility with Rotation Support
// const TokenManager = {
//   setTokens: (accessToken, refreshToken, expiryInfo) => {
//     localStorage.setItem('vottery_access_token', accessToken);
//     localStorage.setItem('vottery_refresh_token', refreshToken);
//     localStorage.setItem('vottery_token_expiry', JSON.stringify(expiryInfo));
//     localStorage.setItem('vottery_token_timestamp', Date.now().toString());
//   },

//   getAccessToken: () => localStorage.getItem('vottery_access_token'),
  
//   getRefreshToken: () => localStorage.getItem('vottery_refresh_token'),
  
//   clearTokens: () => {
//     localStorage.removeItem('vottery_access_token');
//     localStorage.removeItem('vottery_refresh_token');
//     localStorage.removeItem('vottery_token_expiry');
//     localStorage.removeItem('vottery_token_timestamp');
//     localStorage.removeItem('vottery_user_data');
//   },

//   isTokenExpired: () => {
//     const timestamp = localStorage.getItem('vottery_token_timestamp');
//     if (!timestamp) return true;
    
//     // Assuming 7 days expiry (7 * 24 * 60 * 60 * 1000)
//     const tokenAge = Date.now() - parseInt(timestamp);
//     const maxAge = 7 * 24 * 60 * 60 * 1000;
    
//     return tokenAge >= maxAge;
//   }
// };

// // Auth reducer
// const authReducer = (state, action) => {
//   switch (action.type) {
//     case 'SET_LOADING':
//       return { ...state, isLoading: action.payload };
//     case 'SET_STEP':
//       return { ...state, currentStep: action.payload };
//     case 'SET_EMAIL':
//       return { ...state, email: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_PHONE':
//       return { ...state, phone: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_EMAIL_VERIFIED':
//       return { ...state, emailVerified: action.payload };
//     case 'SET_PHONE_VERIFIED':
//       return { ...state, phoneVerified: action.payload };
//     case 'SET_BIOMETRIC_VERIFIED':
//       return { ...state, biometricVerified: action.payload };
//     case 'SET_PROFILE_CREATED':
//       return { ...state, profileCreated: action.payload };
//     case 'SET_AUTHENTICATED':
//       return { ...state, isAuthenticated: action.payload };
//     case 'SET_USER_DATA':
//       return { ...state, userData: action.payload };
//     case 'SET_USER_ID':
//       return { ...state, userId: action.payload };
//     case 'SET_ERROR':
//       return { ...state, error: action.payload };
//     case 'SET_REFERRER_VALID':
//       return { ...state, isValidReferrer: action.payload, referrerInfo: action.referrerInfo };
//     case 'SET_FALLBACK_QUESTIONS':
//       return { ...state, fallbackQuestions: action.payload };
//     case 'SET_FALLBACK_SETUP_COMPLETE':
//       return { ...state, fallbackSetupComplete: action.payload };
//     case 'SET_BIOMETRIC_KEYS':
//       return { ...state, biometricKeys: action.payload };
//     case 'RESET_AUTH':
//       return {
//         ...state,
//         currentStep: 1,
//         email: '',
//         phone: '',
//         userId: null,
//         emailVerified: false,
//         phoneVerified: false,
//         biometricVerified: false,
//         profileCreated: false,
//         error: null,
//         isAuthenticated: false,
//         userData: null,
//         fallbackQuestions: [],
//         fallbackSetupComplete: false,
//         biometricKeys: null
//       };
//     case 'SET_OTP_SENT':
//       return { ...state, otpSent: action.payload };
//     case 'SET_RESEND_COOLDOWN':
//       return { ...state, resendCooldown: action.payload };
//     default:
//       return state;
//   }
// };

// const initialState = {
//   isAuthenticated: false,
//   isLoading: false,
//   currentStep: 1,
//   email: '',
//   phone: '',
//   userId: null,
//   emailVerified: false,
//   phoneVerified: false,
//   biometricVerified: false,
//   profileCreated: false,
//   userData: null,
//   error: null,
//   isValidReferrer: false,
//   referrerInfo: null,
//   otpSent: false,
//   resendCooldown: 0,
//   fallbackQuestions: [],
//   fallbackSetupComplete: false,
//   biometricKeys: null
// };

// // Utilities
// const b64ToBytes = (b64) => {
//   const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
//   const pad = normalized.length % 4 === 2 ? '==' : normalized.length % 4 === 3 ? '=' : '';
//   const str = atob(normalized + pad);
//   const bytes = new Uint8Array(str.length);
//   for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
//   return bytes;
// };

// const createApiRequest = (BASE) => {
//   return async (endpoint, options = {}) => {
//     const isAbsolute = /^https?:\/\//i.test(endpoint);
//     const url = isAbsolute ? endpoint : `${BASE}${endpoint}`;

//     const config = {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//         'X-Requested-With': 'XMLHttpRequest',
//         'X-Referrer': typeof document !== 'undefined' ? document.referrer : '',
//         ...(options.headers || {})
//       },
//       ...options
//     };

//     // Add Authorization header if access token exists
//     const accessToken = TokenManager.getAccessToken();
//     if (accessToken && !config.headers.Authorization) {
//       config.headers.Authorization = `Bearer ${accessToken}`;
//     }

//     if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
//       config.body = JSON.stringify(config.body);
//     }

//     try {
//       const response = await fetch(url, config);
//       const data = await response.json().catch(() => null);

//       if (!response.ok) {
//         const error = new Error((data && data.message) || `HTTP error! status: ${response.status}`);
//         error.response = { data };
//         throw error;
//       }

//       return data;
//     } catch (error) {
//       console.error(`API request failed for ${url}:`, error);
//       if (error.response) throw error;
//       throw new Error('Network error. Please check your connection and try again.');
//     }
//   };
// };

// export const AuthProvider = ({ children }) => {
//   const [state, dispatch] = useReducer(authReducer, initialState);
//   const securityContext = useSecurity();

//   // Safe access to security functions with fallbacks
//   const {
//     checkReferrer = () => ({ isValid: false, referrer: '', error: 'Security context unavailable' }),
//     encryptData = (data) => JSON.stringify(data),
//     decryptData = (data) => JSON.parse(data),
//     generateDeviceFingerprint = () => Promise.resolve('fallback-fingerprint'),
//     createSession = () => {},
//     clearSession = () => {}
//   } = securityContext || {};

//   const API_BASE_3001 = import.meta.env?.VITE_API_BASE_URL || 'http://localhost:3001';
//   const API_BASE_3002 = import.meta.env?.VITE_BIOMETRIC_API_BASE_URL || 'http://localhost:3002';
//   const API_BASE_3003 = 'http://localhost:3003'; // Fixed URL as required

//   const api3001 = useCallback(createApiRequest(API_BASE_3001), [API_BASE_3001]);
//   const api3002 = useCallback(createApiRequest(API_BASE_3002), [API_BASE_3002]);
//   const api3003 = useCallback(createApiRequest(API_BASE_3003), [API_BASE_3003]);

//   // Check existing authentication on load
//   useEffect(() => {
//     const checkExistingAuth = () => {
//       const accessToken = TokenManager.getAccessToken();
//       const userData = localStorage.getItem('vottery_user_data');
      
//       if (accessToken && !TokenManager.isTokenExpired() && userData) {
//         try {
//           const parsedUserData = JSON.parse(userData);
//           dispatch({ type: 'SET_USER_DATA', payload: parsedUserData });
//           dispatch({ type: 'SET_USER_ID', payload: parsedUserData.id });
//           dispatch({ type: 'SET_EMAIL', payload: parsedUserData.sngine_email });
//           dispatch({ type: 'SET_PHONE', payload: parsedUserData.sngine_phone });
//           dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
//           dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//           dispatch({ type: 'SET_AUTHENTICATED', payload: true });
//         } catch (error) {
//           console.warn('Failed to parse user data, clearing tokens');
//           TokenManager.clearTokens();
//         }
//       }
//     };

//     checkExistingAuth();
//   }, []);

//   // Referrer check
//   useEffect(() => {
//     try {
//       const referrerInfo = checkReferrer();
//       dispatch({ type: 'SET_REFERRER_VALID', payload: referrerInfo.isValid, referrerInfo });

//       if (referrerInfo.isValid) {
//         const validationData = encryptData({
//           referrer: referrerInfo.referrer,
//           timestamp: Date.now(),
//           validated: true
//         });
//         sessionStorage.setItem('vottery_referrer_validation', validationData);
//       }
//     } catch (error) {
//       console.warn('Referrer check failed:', error);
//       dispatch({ type: 'SET_REFERRER_VALID', payload: false, referrerInfo: { error: error.message } });
//     }
//   }, [checkReferrer, encryptData]);

//   // Get User ID from check-user endpoint
//   const getUserId = useCallback(async () => {
//     try {
//       const response = await api3001('/api/auth/check-user', {
//         // body: {
//         //   sngine_email: state.email,
//         //   sngine_phone: state.phone,
//         //   referrer: document.referrer,
//         //   timestamp: Date.now()
//         // }
//         body: {
//           email: state.email,
//           phone: state.phone,
          
//         }
//       });

//       // if (response?.success && response?.user_id) {
//         if (response?.success && response?.userId) {
//         // dispatch({ type: 'SET_USER_ID', payload: response.user_id });
//         dispatch({ type: 'SET_USER_ID', payload: response.userId });
//         // return response.user_id;
//         return response.userId;
//       }
//       throw new Error(response?.message || 'Failed to get user ID');
//     } catch (error) {
//       console.error('Get user ID error:', error);
//       throw error;
//     }
//   }, [state.email, state.phone, api3001]);

//   // STEP 1: Send email OTP
//   const sendEmailOTP = useCallback(async (email) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!SecurityUtils.isValidEmail(email)) {
//         throw new Error('Invalid email format');
//       }

//       const response = await api3001('/api/auth/send-email-otp', {
//         body: {
//           email: SecurityUtils.sanitizeInput(email),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL', payload: email });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 2 });
//         toast.success('OTP sent to your email successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 2: Verify email OTP
//   const verifyEmailOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-email-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 3 });
//         toast.success('Email verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 3: Send phone OTP
//   const sendPhoneOTP = useCallback(async (phone) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       let cleanPhone = phone.trim();
//       if (!cleanPhone.startsWith('+') && /^\d/.test(cleanPhone)) cleanPhone = '+' + cleanPhone;
//       if (cleanPhone.startsWith('+')) cleanPhone = '+' + cleanPhone.substring(1).replace(/\D/g, '');

//       if (!SecurityUtils.isValidPhone(cleanPhone)) {
//         throw new Error('Invalid phone number format');
//       }

//       const response = await api3001('/api/auth/send-sms-otp', {
//         body: {
//           phone: cleanPhone,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE', payload: cleanPhone });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 4 });
//         toast.success('OTP sent to your phone successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 4: Verify phone OTP
//   const verifyPhoneOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-sms-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 5 });
//         toast.success('Phone verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 5: Complete Authentication (Biometric + Mandatory Fallback Setup)
//   const completeAuthentication = useCallback(async () => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.emailVerified || !state.phoneVerified) {
//         throw new Error('Email and phone verification must be completed first');
//       }

//       // Get user ID first
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       let biometricSuccess = false;

//       // Try biometric authentication if supported
//       const isBiometricSupported = window.PublicKeyCredential && 
//         await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(() => false);

//       if (isBiometricSupported) {
//         try {
//           console.log('Attempting biometric authentication...');
//           const deviceFingerprint = await generateDeviceFingerprint();
//           const deviceInfo = {
//             type: /mobile/i.test(navigator.userAgent) ? 'mobile' :
//                   /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop',
//             browser: { name: navigator.userAgent, version: navigator.appVersion },
//             os: { name: navigator.platform, version: navigator.platform },
//             screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1 }
//           };

//           const capabilities = { hasWebAuthn: !!window.PublicKeyCredential, platform: navigator.platform, userAgent: navigator.userAgent };
//           const location = { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, language: navigator.language };

//           const deviceResponse = await api3002('/api/biometric/device/register', {
//             body: { 
//               sngine_email: state.email, 
//               sngine_phone: state.phone, 
//               deviceInfo, 
//               location, 
//               capabilities, 
//               referrer: document.referrer, 
//               timestamp: Date.now() 
//             }
//           });

//           if (deviceResponse?.success && deviceResponse?.device?.id) {
//             const deviceId = deviceResponse.device.id;
//             const biometricData = { deviceFingerprint, userAgent: navigator.userAgent, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, timestamp: Date.now(), capabilities };

//             const biometricResponse = await api3002('/api/biometric/register', {
//               body: { 
//                 sngine_email: state.email, 
//                 sngine_phone: state.phone, 
//                 deviceId, 
//                 biometricType: 'device_fingerprint', 
//                 biometricData, 
//                 referrer: document.referrer, 
//                 timestamp: Date.now() 
//               }
//             });

//             if (biometricResponse?.success) {
//               // Try WebAuthn registration
//               const begin = await api3002('/api/biometric/webauthn/register/begin', {
//                 body: { 
//                   sngine_email: state.email, 
//                   sngine_phone: state.phone, 
//                   deviceId, 
//                   referrer: document.referrer, 
//                   timestamp: Date.now() 
//                 }
//               });

//               if (begin?.success && begin?.options) {
//                 const publicKey = { 
//                   ...begin.options, 
//                   challenge: b64ToBytes(begin.options.challenge), 
//                   user: { ...begin.options.user, id: b64ToBytes(begin.options.user.id) } 
//                 };
//                 const credential = await navigator.credentials.create({ publicKey });

//                 if (credential) {
//                   const attestationObject = new Uint8Array(credential.response.attestationObject || []);
//                   const clientDataJSON = new Uint8Array(credential.response.clientDataJSON || []);

//                   const finish = await api3002('/api/biometric/webauthn/register/finish', {
//                     body: { 
//                       sngine_email: state.email, 
//                       sngine_phone: state.phone, 
//                       deviceId, 
//                       credential: { 
//                         id: credential.id, 
//                         rawId: Array.from(new Uint8Array(credential.rawId)), 
//                         response: { 
//                           attestationObject: Array.from(attestationObject), 
//                           clientDataJSON: Array.from(clientDataJSON) 
//                         }, 
//                         type: credential.type 
//                       }, 
//                       referrer: document.referrer, 
//                       timestamp: Date.now() 
//                     }
//                   });

//                   if (finish?.success) {
//                     biometricSuccess = true;
//                     console.log('Biometric authentication completed successfully');
//                   }
//                 }
//               }
//             }
//           }
//         } catch (biometricError) {
//           console.warn('Biometric authentication failed, continuing with fallback setup:', biometricError);
//         }
//       } else {
//         console.log('Biometric not supported on this device');
//       }

//       // MANDATORY FALLBACK SETUP - Always required regardless of biometric success
//       console.log('Setting up mandatory fallback security...');
      
//       // Step 1: Register cryptographic keys
//       const keysResponse = await api3003(`/api/biometric/register-keys/${userId}`, {
//         method: 'POST'
//       });

//       if (!keysResponse?.success) {
//         throw new Error(keysResponse?.message || 'Failed to register cryptographic keys');
//       }

//       dispatch({ type: 'SET_BIOMETRIC_KEYS', payload: keysResponse.keys });

//       // Step 2: Add security question
//       const questionResponse = await api3003(`/api/biometric/add-question/${userId}`, {
//         method: 'POST'
//       });

//       if (!questionResponse?.success) {
//         throw new Error(questionResponse?.message || 'Failed to add security question');
//       }

//       // Step 3: Get all questions for storage
//       const questionsResponse = await api3003(`/api/biometric/questions/${userId}`, {
//         method: 'GET'
//       });

//       if (questionsResponse?.success && questionsResponse?.questions) {
//         const questions = questionsResponse.questions.map(q => q.question);
//         dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: questions });
//       }

//       // Mark fallback setup complete
//       dispatch({ type: 'SET_FALLBACK_SETUP_COMPLETE', payload: true });
//       dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true }); // Mark as verified since fallback is complete
//       dispatch({ type: 'SET_STEP', payload: 6 });

//       const successMessage = biometricSuccess 
//         ? 'Biometric authentication and fallback security setup completed successfully!'
//         : 'Fallback security setup completed successfully!';
      
//       toast.success(successMessage);

//       return { 
//         success: true, 
//         biometricSuccess, 
//         fallbackSetup: true, 
//         message: successMessage 
//       };

//     } catch (error) {
//       console.error('Complete authentication error:', error);
//       const errorMessage = error?.message || 'Authentication failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.email, state.phone, state.emailVerified, state.phoneVerified, state.userId, generateDeviceFingerprint, getUserId, api3002, api3003]);

//   // Get fallback questions
//   const getFallbackQuestions = useCallback(async () => {
//     try {
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       const questionsResponse = await api3003(`/api/biometric/questions/${userId}`, {
//         method: 'GET'
//       });

//       if (questionsResponse?.success && questionsResponse?.questions) {
//         const questions = questionsResponse.questions.map(q => q.question);
//         dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: questions });
//         return questions;
//       }

//       return [];
//     } catch (error) {
//       console.error('Get fallback questions error:', error);
//       return [];
//     }
//   }, [state.userId, getUserId, api3003]);

//   // STEP 6: Complete Profile Creation
//   const completeProfileCreation = useCallback(async (profileData) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.biometricVerified || !state.fallbackSetupComplete) {
//         throw new Error('Authentication and fallback security setup must be completed first');
//       }

//       // Get user ID if not already available
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       const response = await api3003('/api/auth/create', {
//         method: 'POST',
//         body: {
//           user_id: userId,
//           sngine_email: state.email,
//           sngine_phone: state.phone,
//           ...profileData,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         // Store tokens
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken,
//           response.tokenExpiry
//         );

//         // Store user data
//         localStorage.setItem('vottery_user_data', JSON.stringify(response.data));

//         // Update state
//         dispatch({ type: 'SET_USER_DATA', payload: response.data });
//         dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//         dispatch({ type: 'SET_AUTHENTICATED', payload: true });

//         // Create session
//         const sessionData = {
//           userId: response.data.id,
//           email: response.data.sngine_email,
//           phone: response.data.sngine_phone,
//           userType: response.data.user_type,
//           adminRole: response.data.admin_role,
//           subscriptionStatus: response.data.subscription_status,
//           authenticated: true,
//           profileCreated: true,
//           timestamp: Date.now()
//         };

//         createSession(sessionData);
//         toast.success('Profile created successfully! Welcome to Vottery!');

//         return response;
//       }

//       throw new Error(response?.message || 'Profile creation failed');
//     } catch (error) {
//       console.error('Profile creation error:', error);
//       const errorMessage = error?.message || 'Profile creation failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.biometricVerified, state.fallbackSetupComplete, state.userId, state.email, state.phone, getUserId, api3003, createSession]);

//   // Token refresh utility with rotation
//   const refreshAccessToken = useCallback(async () => {
//     try {
//       const refreshToken = TokenManager.getRefreshToken();
//       if (!refreshToken) throw new Error('No refresh token available');

//       const response = await api3003('/api/auth/refresh', {
//         method: 'POST',
//         body: { refreshToken }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         // Store NEW tokens (rotation - both access and refresh tokens are new)
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken, // This is the NEW refresh token
//           response.tokenExpiry
//         );
//         return response.accessToken;
//       }

//       throw new Error('Token refresh failed');
//     } catch (error) {
//       console.error('Token refresh failed:', error);
//       logout();
//       throw error;
//     }
//   }, [api3003]);

//   // Navigation helpers
//   const goBackStep = useCallback(() => {
//     if (state.currentStep === 2) dispatch({ type: 'SET_STEP', payload: 1 });
//     else if (state.currentStep === 4) dispatch({ type: 'SET_STEP', payload: 3 });
//     else if (state.currentStep === 5) dispatch({ type: 'SET_STEP', payload: 4 });
//     else if (state.currentStep === 6) dispatch({ type: 'SET_STEP', payload: 5 });
//   }, [state.currentStep]);

//   const logout = useCallback(() => {
//     TokenManager.clearTokens();
//     clearSession();
//     sessionStorage.removeItem('vottery_referrer_validation');
//     dispatch({ type: 'RESET_AUTH' });
//     toast.success('Logged out successfully');
//   }, [clearSession]);

//   const resetAuth = useCallback(() => {
//     TokenManager.clearTokens();
//     dispatch({ type: 'RESET_AUTH' });
//   }, []);

//   // Auto refresh token before expiry
//   useEffect(() => {
//     const accessToken = TokenManager.getAccessToken();
//     const tokenExpiry = localStorage.getItem('vottery_token_expiry');
    
//     if (accessToken && tokenExpiry && !TokenManager.isTokenExpired()) {
//       try {
//         const expiryData = JSON.parse(tokenExpiry);
//         const expiryTime = new Date().getTime() + (7 * 24 * 60 * 60 * 1000); // 7 days from now
//         const refreshTime = expiryTime - Date.now() - 60000; // Refresh 1 minute before expiry

//         if (refreshTime > 0) {
//           const timeout = setTimeout(() => {
//             refreshAccessToken().catch(console.error);
//           }, refreshTime);

//           return () => clearTimeout(timeout);
//         }
//       } catch (error) {
//         console.warn('Failed to parse token expiry, clearing tokens');
//         TokenManager.clearTokens();
//       }
//     }
//   }, [refreshAccessToken]);

//   // Context value
//   const value = {
//     ...state,
//     dispatch,
//     sendEmailOTP,
//     verifyEmailOTP,
//     sendPhoneOTP,
//     verifyPhoneOTP,
//     completeAuthentication,
//     completeProfileCreation,
//     getFallbackQuestions,
//     getUserId,
//     refreshAccessToken,
//     goBackStep,
//     logout,
//     resetAuth,
//     // Token utilities
//     getAccessToken: TokenManager.getAccessToken,
//     getRefreshToken: TokenManager.getRefreshToken,
//     isTokenExpired: TokenManager.isTokenExpired
//   };

//   return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
// };
//auth context total 7 steps, with non mandatory security question.
// import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react';
// import { useSecurity } from './SecurityContext';
// import { SecurityUtils } from '../utils/security';
// import { toast } from 'react-hot-toast';

// const AuthContext = createContext();

// export const useAuth = () => {
//   const context = useContext(AuthContext);
//   if (!context) {
//     throw new Error('useAuth must be used within AuthProvider');
//   }
//   return context;
// };

// // Token Management Utility
// const TokenManager = {
//   setTokens: (accessToken, refreshToken, expiryInfo) => {
//     localStorage.setItem('vottery_access_token', accessToken);
//     localStorage.setItem('vottery_refresh_token', refreshToken);
//     localStorage.setItem('vottery_token_expiry', JSON.stringify(expiryInfo));
//     localStorage.setItem('vottery_token_timestamp', Date.now().toString());
//   },

//   getAccessToken: () => localStorage.getItem('vottery_access_token'),
  
//   getRefreshToken: () => localStorage.getItem('vottery_refresh_token'),
  
//   clearTokens: () => {
//     localStorage.removeItem('vottery_access_token');
//     localStorage.removeItem('vottery_refresh_token');
//     localStorage.removeItem('vottery_token_expiry');
//     localStorage.removeItem('vottery_token_timestamp');
//     localStorage.removeItem('vottery_user_data');
//   },

//   isTokenExpired: () => {
//     const timestamp = localStorage.getItem('vottery_token_timestamp');
//     if (!timestamp) return true;
    
//     // Assuming 7 days expiry (7 * 24 * 60 * 60 * 1000)
//     const tokenAge = Date.now() - parseInt(timestamp);
//     const maxAge = 7 * 24 * 60 * 60 * 1000;
    
//     return tokenAge >= maxAge;
//   }
// };

// // Auth reducer
// const authReducer = (state, action) => {
//   switch (action.type) {
//     case 'SET_LOADING':
//       return { ...state, isLoading: action.payload };
//     case 'SET_STEP':
//       return { ...state, currentStep: action.payload };
//     case 'SET_EMAIL':
//       return { ...state, email: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_PHONE':
//       return { ...state, phone: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_EMAIL_VERIFIED':
//       return { ...state, emailVerified: action.payload };
//     case 'SET_PHONE_VERIFIED':
//       return { ...state, phoneVerified: action.payload };
//     case 'SET_BIOMETRIC_VERIFIED':
//       return { ...state, biometricVerified: action.payload };
//     case 'SET_PROFILE_CREATED':
//       return { ...state, profileCreated: action.payload };
//     case 'SET_AUTHENTICATED':
//       return { ...state, isAuthenticated: action.payload };
//     case 'SET_USER_DATA':
//       return { ...state, userData: action.payload };
//     case 'SET_USER_ID':
//       return { ...state, userId: action.payload };
//     case 'SET_ERROR':
//       return { ...state, error: action.payload };
//     case 'SET_REFERRER_VALID':
//       return { ...state, isValidReferrer: action.payload, referrerInfo: action.referrerInfo };
//     case 'SET_FALLBACK_QUESTIONS':
//       return { ...state, fallbackQuestions: action.payload };
//     case 'SET_FALLBACK_STEP':
//       return { ...state, fallbackStep: action.payload };
//     case 'SET_BIOMETRIC_KEYS':
//       return { ...state, biometricKeys: action.payload };
//     case 'RESET_AUTH':
//       return {
//         ...state,
//         currentStep: 1,
//         email: '',
//         phone: '',
//         userId: null,
//         emailVerified: false,
//         phoneVerified: false,
//         biometricVerified: false,
//         profileCreated: false,
//         error: null,
//         isAuthenticated: false,
//         userData: null,
//         fallbackQuestions: [],
//         fallbackStep: null,
//         biometricKeys: null
//       };
//     case 'SET_OTP_SENT':
//       return { ...state, otpSent: action.payload };
//     case 'SET_RESEND_COOLDOWN':
//       return { ...state, resendCooldown: action.payload };
//     default:
//       return state;
//   }
// };

// const initialState = {
//   isAuthenticated: false,
//   isLoading: false,
//   currentStep: 1,
//   email: '',
//   phone: '',
//   userId: null,
//   emailVerified: false,
//   phoneVerified: false,
//   biometricVerified: false,
//   profileCreated: false,
//   userData: null,
//   error: null,
//   isValidReferrer: false,
//   referrerInfo: null,
//   otpSent: false,
//   resendCooldown: 0,
//   fallbackQuestions: [],
//   fallbackStep: null,
//   biometricKeys: null
// };

// // Utilities
// const b64ToBytes = (b64) => {
//   const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
//   const pad = normalized.length % 4 === 2 ? '==' : normalized.length % 4 === 3 ? '=' : '';
//   const str = atob(normalized + pad);
//   const bytes = new Uint8Array(str.length);
//   for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
//   return bytes;
// };

// const createApiRequest = (BASE) => {
//   return async (endpoint, options = {}) => {
//     const isAbsolute = /^https?:\/\//i.test(endpoint);
//     const url = isAbsolute ? endpoint : `${BASE}${endpoint}`;

//     const config = {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//         'X-Requested-With': 'XMLHttpRequest',
//         'X-Referrer': typeof document !== 'undefined' ? document.referrer : '',
//         ...(options.headers || {})
//       },
//       ...options
//     };

//     // Add Authorization header if access token exists
//     const accessToken = TokenManager.getAccessToken();
//     if (accessToken && !config.headers.Authorization) {
//       config.headers.Authorization = `Bearer ${accessToken}`;
//     }

//     if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
//       config.body = JSON.stringify(config.body);
//     }

//     try {
//       const response = await fetch(url, config);
//       const data = await response.json().catch(() => null);

//       if (!response.ok) {
//         const error = new Error((data && data.message) || `HTTP error! status: ${response.status}`);
//         error.response = { data };
//         throw error;
//       }

//       return data;
//     } catch (error) {
//       console.error(`API request failed for ${url}:`, error);
//       if (error.response) throw error;
//       throw new Error('Network error. Please check your connection and try again.');
//     }
//   };
// };

// export const AuthProvider = ({ children }) => {
//   const [state, dispatch] = useReducer(authReducer, initialState);
//   const securityContext = useSecurity();

//   // Safe access to security functions with fallbacks
//   const {
//     checkReferrer = () => ({ isValid: false, referrer: '', error: 'Security context unavailable' }),
//     encryptData = (data) => JSON.stringify(data),
//     decryptData = (data) => JSON.parse(data),
//     generateDeviceFingerprint = () => Promise.resolve('fallback-fingerprint'),
//     createSession = () => {},
//     clearSession = () => {}
//   } = securityContext || {};

//   const API_BASE_3001 = import.meta.env?.VITE_API_BASE_URL || 'http://localhost:3001';
//   const API_BASE_3002 = import.meta.env?.VITE_BIOMETRIC_API_BASE_URL || 'http://localhost:3002';
//   const API_BASE_3003 = 'http://localhost:3003'; // Fixed URL as required

//   const api3001 = useCallback(createApiRequest(API_BASE_3001), [API_BASE_3001]);
//   const api3002 = useCallback(createApiRequest(API_BASE_3002), [API_BASE_3002]);
//   const api3003 = useCallback(createApiRequest(API_BASE_3003), [API_BASE_3003]);

//   // Check existing authentication on load
//   useEffect(() => {
//     const checkExistingAuth = () => {
//       const accessToken = TokenManager.getAccessToken();
//       const userData = localStorage.getItem('vottery_user_data');
      
//       if (accessToken && !TokenManager.isTokenExpired() && userData) {
//         try {
//           const parsedUserData = JSON.parse(userData);
//           dispatch({ type: 'SET_USER_DATA', payload: parsedUserData });
//           dispatch({ type: 'SET_USER_ID', payload: parsedUserData.id });
//           dispatch({ type: 'SET_EMAIL', payload: parsedUserData.sngine_email });
//           dispatch({ type: 'SET_PHONE', payload: parsedUserData.sngine_phone });
//           dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
//           dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//           dispatch({ type: 'SET_AUTHENTICATED', payload: true });
//         } catch (error) {
//           console.warn('Failed to parse user data, clearing tokens');
//           TokenManager.clearTokens();
//         }
//       }
//     };

//     checkExistingAuth();
//   }, []);

//   // Referrer check
//   useEffect(() => {
//     try {
//       const referrerInfo = checkReferrer();
//       dispatch({ type: 'SET_REFERRER_VALID', payload: referrerInfo.isValid, referrerInfo });

//       if (referrerInfo.isValid) {
//         const validationData = encryptData({
//           referrer: referrerInfo.referrer,
//           timestamp: Date.now(),
//           validated: true
//         });
//         sessionStorage.setItem('vottery_referrer_validation', validationData);
//       }
//     } catch (error) {
//       console.warn('Referrer check failed:', error);
//       dispatch({ type: 'SET_REFERRER_VALID', payload: false, referrerInfo: { error: error.message } });
//     }
//   }, [checkReferrer, encryptData]);

//   // Get User ID from check-user endpoint
//   const getUserId = useCallback(async () => {
//     try {
//       const response = await api3001('/api/auth/check-user', {
//         body: {
//           sngine_email: state.email,
//           sngine_phone: state.phone,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success && response?.user_id) {
//         dispatch({ type: 'SET_USER_ID', payload: response.user_id });
//         return response.user_id;
//       }
//       throw new Error(response?.message || 'Failed to get user ID');
//     } catch (error) {
//       console.error('Get user ID error:', error);
//       throw error;
//     }
//   }, [state.email, state.phone, api3001]);

//   // STEP 1: Send email OTP
//   const sendEmailOTP = useCallback(async (email) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!SecurityUtils.isValidEmail(email)) {
//         throw new Error('Invalid email format');
//       }

//       const response = await api3001('/api/auth/send-email-otp', {
//         body: {
//           email: SecurityUtils.sanitizeInput(email),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL', payload: email });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 2 });
//         toast.success('OTP sent to your email successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 2: Verify email OTP
//   const verifyEmailOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-email-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 3 });
//         toast.success('Email verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 3: Send phone OTP
//   const sendPhoneOTP = useCallback(async (phone) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       let cleanPhone = phone.trim();
//       if (!cleanPhone.startsWith('+') && /^\d/.test(cleanPhone)) cleanPhone = '+' + cleanPhone;
//       if (cleanPhone.startsWith('+')) cleanPhone = '+' + cleanPhone.substring(1).replace(/\D/g, '');

//       if (!SecurityUtils.isValidPhone(cleanPhone)) {
//         throw new Error('Invalid phone number format');
//       }

//       const response = await api3001('/api/auth/send-sms-otp', {
//         body: {
//           phone: cleanPhone,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE', payload: cleanPhone });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 4 });
//         toast.success('OTP sent to your phone successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 4: Verify phone OTP
//   const verifyPhoneOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-sms-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 5 });
//         toast.success('Phone verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // STEP 5: Complete Biometric Authentication
//   const completeAuthentication = useCallback(async () => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.emailVerified || !state.phoneVerified) {
//         throw new Error('Email and phone verification must be completed first');
//       }

//       // Check if biometric is supported
//       const isBiometricSupported = window.PublicKeyCredential && 
//         await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(() => false);

//       if (!isBiometricSupported) {
//         console.log('Biometric not supported, setting up fallback security');
//         dispatch({ type: 'SET_FALLBACK_STEP', payload: 'setup' });
//         return { success: true, message: 'Biometric not supported, please set up fallback security', requiresFallback: true };
//       }

//       // Try biometric authentication
//       const deviceFingerprint = await generateDeviceFingerprint();
//       const deviceInfo = {
//         type: /mobile/i.test(navigator.userAgent) ? 'mobile' :
//               /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop',
//         browser: { name: navigator.userAgent, version: navigator.appVersion },
//         os: { name: navigator.platform, version: navigator.platform },
//         screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1 }
//       };

//       const capabilities = { hasWebAuthn: !!window.PublicKeyCredential, platform: navigator.platform, userAgent: navigator.userAgent };
//       const location = { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, language: navigator.language };

//       const deviceResponse = await api3002('/api/biometric/device/register', {
//         body: { 
//           sngine_email: state.email, 
//           sngine_phone: state.phone, 
//           deviceInfo, 
//           location, 
//           capabilities, 
//           referrer: document.referrer, 
//           timestamp: Date.now() 
//         }
//       });

//       if (!deviceResponse?.success || !deviceResponse?.device?.id) {
//         throw new Error(deviceResponse?.message || 'Device registration failed');
//       }

//       const deviceId = deviceResponse.device.id;
//       const biometricData = { deviceFingerprint, userAgent: navigator.userAgent, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, timestamp: Date.now(), capabilities };

//       const biometricResponse = await api3002('/api/biometric/register', {
//         body: { 
//           sngine_email: state.email, 
//           sngine_phone: state.phone, 
//           deviceId, 
//           biometricType: 'device_fingerprint', 
//           biometricData, 
//           referrer: document.referrer, 
//           timestamp: Date.now() 
//         }
//       });

//       if (!biometricResponse?.success) {
//         throw new Error(biometricResponse?.message || 'Biometric registration failed');
//       }

//       // Try WebAuthn registration
//       try {
//         const begin = await api3002('/api/biometric/webauthn/register/begin', {
//           body: { 
//             sngine_email: state.email, 
//             sngine_phone: state.phone, 
//             deviceId, 
//             referrer: document.referrer, 
//             timestamp: Date.now() 
//           }
//         });

//         if (begin?.success && begin?.options) {
//           const publicKey = { 
//             ...begin.options, 
//             challenge: b64ToBytes(begin.options.challenge), 
//             user: { ...begin.options.user, id: b64ToBytes(begin.options.user.id) } 
//           };
//           const credential = await navigator.credentials.create({ publicKey });

//           if (credential) {
//             const attestationObject = new Uint8Array(credential.response.attestationObject || []);
//             const clientDataJSON = new Uint8Array(credential.response.clientDataJSON || []);

//             const finish = await api3002('/api/biometric/webauthn/register/finish', {
//               body: { 
//                 sngine_email: state.email, 
//                 sngine_phone: state.phone, 
//                 deviceId, 
//                 credential: { 
//                   id: credential.id, 
//                   rawId: Array.from(new Uint8Array(credential.rawId)), 
//                   response: { 
//                     attestationObject: Array.from(attestationObject), 
//                     clientDataJSON: Array.from(clientDataJSON) 
//                   }, 
//                   type: credential.type 
//                 }, 
//                 referrer: document.referrer, 
//                 timestamp: Date.now() 
//               }
//             });

//             if (finish?.success) {
//               dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//               dispatch({ type: 'SET_STEP', payload: 6 });
//               toast.success('Biometric authentication completed successfully!');
//               return { success: true, message: 'Biometric authentication completed', deviceId, webauthnRegistered: true };
//             } else {
//               throw new Error('WebAuthn finish failed');
//             }
//           }
//         } else {
//           throw new Error('WebAuthn begin failed');
//         }
//       } catch (webAuthnError) {
//         console.warn('WebAuthn failed, setting up fallback security:', webAuthnError);
//         dispatch({ type: 'SET_FALLBACK_STEP', payload: 'setup' });
//         return { success: true, message: 'Biometric authentication failed, please set up fallback security', requiresFallback: true };
//       }

//     } catch (error) {
//       console.error('Complete authentication error:', error);
//       const errorMessage = error?.message || 'Authentication failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.email, state.phone, state.emailVerified, state.phoneVerified, generateDeviceFingerprint, api3002]);

//   // Setup fallback security
//   const setupFallbackSecurity = useCallback(async () => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       // Get user ID first
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       // Register cryptographic keys
//       const keysResponse = await api3003(`/api/biometric/register-keys/${userId}`, {
//         method: 'POST'
//       });

//       if (!keysResponse?.success) {
//         throw new Error(keysResponse?.message || 'Failed to register cryptographic keys');
//       }

//       dispatch({ type: 'SET_BIOMETRIC_KEYS', payload: keysResponse.keys });

//       // Add security question
//       const questionResponse = await api3003(`/api/biometric/add-question/${userId}`, {
//         method: 'POST'
//       });

//       if (!questionResponse?.success) {
//         throw new Error(questionResponse?.message || 'Failed to add security question');
//       }

//       dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: [questionResponse.question.question] });
//       dispatch({ type: 'SET_FALLBACK_STEP', payload: 'answer' });
      
//       toast.success('Fallback security setup completed. Please answer the security question.');
//       return { success: true, question: questionResponse.question };

//     } catch (error) {
//       console.error('Fallback security setup error:', error);
//       const errorMessage = error?.message || 'Failed to setup fallback security';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.email, state.phone, state.userId, getUserId, api3003]);

//   // Verify fallback security answers
//   const verifyFallbackSecurity = useCallback(async (answers) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       const verifyResponse = await api3003(`/api/biometric/verify/${userId}`, {
//         method: 'POST',
//         body: { answers }
//       });

//       if (verifyResponse?.success) {
//         dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//         dispatch({ type: 'SET_FALLBACK_STEP', payload: 'complete' });
//         dispatch({ type: 'SET_STEP', payload: 6 }); // Move to profile creation
//         toast.success('Fallback security verification completed successfully!');
//         return verifyResponse;
//       }

//       throw new Error(verifyResponse?.message || 'Security verification failed');

//     } catch (error) {
//       console.error('Fallback security verification error:', error);
//       const errorMessage = error?.message || 'Security verification failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.userId, getUserId, api3003]);

//   // Get fallback questions
//   const getFallbackQuestions = useCallback(async () => {
//     try {
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       const questionsResponse = await api3003(`/api/biometric/questions/${userId}`, {
//         method: 'GET'
//       });

//       if (questionsResponse?.success && questionsResponse?.questions) {
//         const questions = questionsResponse.questions.map(q => q.question);
//         dispatch({ type: 'SET_FALLBACK_QUESTIONS', payload: questions });
//         return questions;
//       }

//       return [];
//     } catch (error) {
//       console.error('Get fallback questions error:', error);
//       return [];
//     }
//   }, [state.userId, getUserId, api3003]);

//   // STEP 6: Complete Profile Creation
//   const completeProfileCreation = useCallback(async (profileData) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.biometricVerified) {
//         throw new Error('Biometric verification must be completed first');
//       }

//       // Get user ID if not already available
//       let userId = state.userId;
//       if (!userId) {
//         userId = await getUserId();
//         if (!userId) throw new Error('Failed to get user ID');
//       }

//       const response = await api3003('/api/auth/create', {
//         method: 'POST',
//         body: {
//           user_id: userId,
//           sngine_email: state.email,
//           sngine_phone: state.phone,
//           ...profileData,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         // Store tokens
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken,
//           response.tokenExpiry
//         );

//         // Store user data
//         localStorage.setItem('vottery_user_data', JSON.stringify(response.data));

//         // Update state
//         dispatch({ type: 'SET_USER_DATA', payload: response.data });
//         dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//         dispatch({ type: 'SET_AUTHENTICATED', payload: true });

//         // Create session
//         const sessionData = {
//           userId: response.data.id,
//           email: response.data.sngine_email,
//           phone: response.data.sngine_phone,
//           userType: response.data.user_type,
//           adminRole: response.data.admin_role,
//           subscriptionStatus: response.data.subscription_status,
//           authenticated: true,
//           profileCreated: true,
//           timestamp: Date.now()
//         };

//         createSession(sessionData);
//         toast.success('Profile created successfully! Welcome to Vottery!');

//         return response;
//       }

//       throw new Error(response?.message || 'Profile creation failed');
//     } catch (error) {
//       console.error('Profile creation error:', error);
//       const errorMessage = error?.message || 'Profile creation failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.biometricVerified, state.userId, state.email, state.phone, getUserId, api3003, createSession]);

//   // Token refresh utility
//   const refreshAccessToken = useCallback(async () => {
//     try {
//       const refreshToken = TokenManager.getRefreshToken();
//       if (!refreshToken) throw new Error('No refresh token available');

//       const response = await api3003('/api/auth/refresh', {
//         method: 'POST',
//         body: { refreshToken }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken,
//           response.tokenExpiry
//         );
//         return response.accessToken;
//       }

//       throw new Error('Token refresh failed');
//     } catch (error) {
//       console.error('Token refresh failed:', error);
//       logout();
//       throw error;
//     }
//   }, [api3003]);

//   // Navigation helpers
//   const goBackStep = useCallback(() => {
//     if (state.currentStep === 2) dispatch({ type: 'SET_STEP', payload: 1 });
//     else if (state.currentStep === 4) dispatch({ type: 'SET_STEP', payload: 3 });
//     else if (state.currentStep === 5) dispatch({ type: 'SET_STEP', payload: 4 });
//     else if (state.currentStep === 6) dispatch({ type: 'SET_STEP', payload: 5 });
//   }, [state.currentStep]);

//   const logout = useCallback(() => {
//     TokenManager.clearTokens();
//     clearSession();
//     sessionStorage.removeItem('vottery_referrer_validation');
//     dispatch({ type: 'RESET_AUTH' });
//     toast.success('Logged out successfully');
//   }, [clearSession]);

//   const resetAuth = useCallback(() => {
//     TokenManager.clearTokens();
//     dispatch({ type: 'RESET_AUTH' });
//   }, []);

//   // Auto refresh token before expiry
//   useEffect(() => {
//     const accessToken = TokenManager.getAccessToken();
//     const tokenExpiry = localStorage.getItem('vottery_token_expiry');
    
//     if (accessToken && tokenExpiry && !TokenManager.isTokenExpired()) {
//       try {
//         const expiryData = JSON.parse(tokenExpiry);
//         const expiryTime = new Date().getTime() + (7 * 24 * 60 * 60 * 1000); // 7 days from now
//         const refreshTime = expiryTime - Date.now() - 60000; // Refresh 1 minute before expiry

//         if (refreshTime > 0) {
//           const timeout = setTimeout(() => {
//             refreshAccessToken().catch(console.error);
//           }, refreshTime);

//           return () => clearTimeout(timeout);
//         }
//       } catch (error) {
//         console.warn('Failed to parse token expiry, clearing tokens');
//         TokenManager.clearTokens();
//       }
//     }
//   }, [refreshAccessToken]);

//   // Context value
//   const value = {
//     ...state,
//     dispatch,
//     sendEmailOTP,
//     verifyEmailOTP,
//     sendPhoneOTP,
//     verifyPhoneOTP,
//     completeAuthentication,
//     completeProfileCreation,
//     setupFallbackSecurity,
//     verifyFallbackSecurity,
//     getFallbackQuestions,
//     getUserId,
//     refreshAccessToken,
//     goBackStep,
//     logout,
//     resetAuth,
//     // Token utilities
//     getAccessToken: TokenManager.getAccessToken,
//     getRefreshToken: TokenManager.getRefreshToken,
//     isTokenExpired: TokenManager.isTokenExpired
//   };

//   return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
// };
// //this is final touch with role based redirect
// //this is new and finishing touch
// // import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react';
// // import { useSecurity } from './SecurityContext';
// // import { SecurityUtils } from '../utils/security';
// // import { toast } from 'react-hot-toast';

// // const AuthContext = createContext();

// // export const useAuth = () => {
// //   const context = useContext(AuthContext);
// //   if (!context) {
// //     throw new Error('useAuth must be used within AuthProvider');
// //   }
// //   return context;
// // };

// // // Token Management Utility
// // const TokenManager = {
// //   setTokens: (accessToken, refreshToken, expiryInfo) => {
// //     localStorage.setItem('vottery_access_token', accessToken);
// //     localStorage.setItem('vottery_refresh_token', refreshToken);
// //     localStorage.setItem('vottery_token_expiry', JSON.stringify(expiryInfo));
// //     localStorage.setItem('vottery_token_timestamp', Date.now().toString());
// //   },

// //   getAccessToken: () => localStorage.getItem('vottery_access_token'),
  
// //   getRefreshToken: () => localStorage.getItem('vottery_refresh_token'),
  
// //   clearTokens: () => {
// //     localStorage.removeItem('vottery_access_token');
// //     localStorage.removeItem('vottery_refresh_token');
// //     localStorage.removeItem('vottery_token_expiry');
// //     localStorage.removeItem('vottery_token_timestamp');
// //     localStorage.removeItem('vottery_user_data');
// //   },

// //   isTokenExpired: () => {
// //     const timestamp = localStorage.getItem('vottery_token_timestamp');
// //     if (!timestamp) return true;
    
// //     // Assuming 7 days expiry (7 * 24 * 60 * 60 * 1000)
// //     const tokenAge = Date.now() - parseInt(timestamp);
// //     const maxAge = 7 * 24 * 60 * 60 * 1000;
    
// //     return tokenAge >= maxAge;
// //   }
// // };

// // // ----------------------------------------------------
// // // Reducer & initial state
// // // ----------------------------------------------------
// // const authReducer = (state, action) => {
// //   switch (action.type) {
// //     case 'SET_LOADING':
// //       return { ...state, isLoading: action.payload };
// //     case 'SET_STEP':
// //       return { ...state, currentStep: action.payload };
// //     case 'SET_EMAIL':
// //       return { ...state, email: SecurityUtils.sanitizeInput(action.payload) };
// //     case 'SET_PHONE':
// //       return { ...state, phone: SecurityUtils.sanitizeInput(action.payload) };
// //     case 'SET_EMAIL_VERIFIED':
// //       return { ...state, emailVerified: action.payload };
// //     case 'SET_PHONE_VERIFIED':
// //       return { ...state, phoneVerified: action.payload };
// //     case 'SET_BIOMETRIC_VERIFIED':
// //       return { ...state, biometricVerified: action.payload };
// //     case 'SET_PROFILE_CREATED':
// //       return { ...state, profileCreated: action.payload };
// //     case 'SET_AUTHENTICATED':
// //       return { ...state, isAuthenticated: action.payload };
// //     case 'SET_USER_DATA':
// //       return { ...state, userData: action.payload };
// //     case 'SET_ERROR':
// //       return { ...state, error: action.payload };
// //     case 'SET_REFERRER_VALID':
// //       return { ...state, isValidReferrer: action.payload, referrerInfo: action.referrerInfo };
// //     case 'SET_USER_ID':
// //       return { ...state, userId: action.payload };
// //     case 'RESET_AUTH':
// //       return {
// //         ...state,
// //         currentStep: 1,
// //         email: '',
// //         phone: '',
// //         emailVerified: false,
// //         phoneVerified: false,
// //         biometricVerified: false,
// //         profileCreated: false,
// //         error: null,
// //         isAuthenticated: false,
// //         userData: null,
// //         userId: null
// //       };
// //     case 'SET_OTP_SENT':
// //       return { ...state, otpSent: action.payload };
// //     case 'SET_RESEND_COOLDOWN':
// //       return { ...state, resendCooldown: action.payload };
// //     default:
// //       return state;
// //   }
// // };

// // const initialState = {
// //   isAuthenticated: false,
// //   isLoading: false,
// //   currentStep: 1,
// //   email: '',
// //   phone: '',
// //   emailVerified: false,
// //   phoneVerified: false,
// //   biometricVerified: false,
// //   profileCreated: false,
// //   userData: null,
// //   error: null,
// //   isValidReferrer: false,
// //   referrerInfo: null,
// //   otpSent: false,
// //   resendCooldown: 0,
// //   userId: null
// // };

// // // ----------------------------------------------------
// // // Utilities
// // // ----------------------------------------------------
// // const b64ToBytes = (b64) => {
// //   const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
// //   const pad = normalized.length % 4 === 2 ? '==' : normalized.length % 4 === 3 ? '=' : '';
// //   const str = atob(normalized + pad);
// //   const bytes = new Uint8Array(str.length);
// //   for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
// //   return bytes;
// // };

// // const createApiRequest = (BASE) => {
// //   return async (endpoint, options = {}) => {
// //     const isAbsolute = /^https?:\/\//i.test(endpoint);
// //     const url = isAbsolute ? endpoint : `${BASE}${endpoint}`;

// //     const config = {
// //       method: 'POST',
// //       headers: {
// //         'Content-Type': 'application/json',
// //         'X-Requested-With': 'XMLHttpRequest',
// //         'X-Referrer': typeof document !== 'undefined' ? document.referrer : '',
// //         ...(options.headers || {})
// //       },
// //       ...options
// //     };

// //     // Add Authorization header if access token exists
// //     const accessToken = TokenManager.getAccessToken();
// //     if (accessToken && !config.headers.Authorization) {
// //       config.headers.Authorization = `Bearer ${accessToken}`;
// //     }

// //     if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
// //       config.body = JSON.stringify(config.body);
// //     }

// //     try {
// //       const response = await fetch(url, config);
// //       const data = await response.json().catch(() => null);

// //       if (!response.ok) {
// //         const error = new Error((data && data.message) || `HTTP error! status: ${response.status}`);
// //         error.response = { data };
// //         throw error;
// //       }

// //       return data;
// //     } catch (error) {
// //       console.error(`API request failed for ${url}:`, error);
// //       if (error.response) throw error;
// //       throw new Error('Network error. Please check your connection and try again.');
// //     }
// //   };
// // };

// // export const AuthProvider = ({ children }) => {
// //   const [state, dispatch] = useReducer(authReducer, initialState);
// //   const securityContext = useSecurity();

// //   // Safe access to security functions with fallbacks
// //   const {
// //     checkReferrer = () => ({ isValid: false, referrer: '', error: 'Security context unavailable' }),
// //     encryptData = (data) => JSON.stringify(data),
// //     decryptData = (data) => JSON.parse(data),
// //     generateDeviceFingerprint = () => Promise.resolve('fallback-fingerprint'),
// //     createSession = () => {},
// //     clearSession = () => {}
// //   } = securityContext || {};

// //   const API_BASE_3001 = import.meta.env?.VITE_API_BASE_URL || 'http://localhost:3001';
// //   const API_BASE_3002 = import.meta.env?.VITE_BIOMETRIC_API_BASE_URL || 'http://localhost:3002';
// //   const API_BASE_3003 = import.meta.env?.VITE_USER_API_BASE_URL || 'http://localhost:3003';

// //   const api3001 = useCallback(createApiRequest(API_BASE_3001), [API_BASE_3001]);
// //   const api3002 = useCallback(createApiRequest(API_BASE_3002), [API_BASE_3002]);
// //   const api3003 = useCallback(createApiRequest(API_BASE_3003), [API_BASE_3003]);

// //   // ----------------------------------------------------
// //   // Check existing authentication on load
// //   // ----------------------------------------------------
// //   useEffect(() => {
// //     const checkExistingAuth = () => {
// //       const accessToken = TokenManager.getAccessToken();
// //       const userData = localStorage.getItem('vottery_user_data');
      
// //       if (accessToken && !TokenManager.isTokenExpired() && userData) {
// //         try {
// //           const parsedUserData = JSON.parse(userData);
// //           dispatch({ type: 'SET_USER_DATA', payload: parsedUserData });
// //           dispatch({ type: 'SET_EMAIL', payload: parsedUserData.sngine_email });
// //           dispatch({ type: 'SET_PHONE', payload: parsedUserData.sngine_phone });
// //           dispatch({ type: 'SET_USER_ID', payload: parsedUserData.id });
// //           dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
// //           dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
// //           dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
// //           dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
// //           dispatch({ type: 'SET_AUTHENTICATED', payload: true });
// //         } catch (error) {
// //           console.warn('Failed to parse user data, clearing tokens');
// //           TokenManager.clearTokens();
// //         }
// //       }
// //     };

// //     checkExistingAuth();
// //   }, []);

// //   // ----------------------------------------------------
// //   // Referrer check
// //   // ----------------------------------------------------
// //   useEffect(() => {
// //     try {
// //       const referrerInfo = checkReferrer();
// //       dispatch({ type: 'SET_REFERRER_VALID', payload: referrerInfo.isValid, referrerInfo });

// //       if (referrerInfo.isValid) {
// //         const validationData = encryptData({
// //           referrer: referrerInfo.referrer,
// //           timestamp: Date.now(),
// //           validated: true
// //         });
// //         sessionStorage.setItem('vottery_referrer_validation', validationData);
// //       }
// //     } catch (error) {
// //       console.warn('Referrer check failed:', error);
// //       dispatch({ type: 'SET_REFERRER_VALID', payload: false, referrerInfo: { error: error.message } });
// //     }
// //   }, [checkReferrer, encryptData]);

// //   // ----------------------------------------------------
// //   // STEP 1: Send email OTP
// //   // ----------------------------------------------------
// //   const sendEmailOTP = useCallback(async (email) => {
// //     try {
// //       dispatch({ type: 'SET_LOADING', payload: true });
// //       dispatch({ type: 'SET_ERROR', payload: null });

// //       if (!SecurityUtils.isValidEmail(email)) {
// //         throw new Error('Invalid email format');
// //       }

// //       const response = await api3001('/api/auth/send-email-otp', {
// //         body: {
// //           email: SecurityUtils.sanitizeInput(email),
// //           referrer: document.referrer,
// //           timestamp: Date.now()
// //         }
// //       });

// //       if (response?.success) {
// //         dispatch({ type: 'SET_EMAIL', payload: email });
// //         dispatch({ type: 'SET_OTP_SENT', payload: true });
// //         dispatch({ type: 'SET_STEP', payload: 2 });
// //         toast.success('OTP sent to your email successfully');
// //         return response;
// //       }
// //       throw new Error(response?.message || 'Failed to send email OTP');
// //     } catch (error) {
// //       const errorMessage = error.message || 'Failed to send email OTP';
// //       dispatch({ type: 'SET_ERROR', payload: errorMessage });
// //       toast.error(errorMessage);
// //       throw error;
// //     } finally {
// //       dispatch({ type: 'SET_LOADING', payload: false });
// //     }
// //   }, [api3001]);

// //   // ----------------------------------------------------
// //   // STEP 2: Verify email OTP
// //   // ----------------------------------------------------
// //   const verifyEmailOTP = useCallback(async (otp) => {
// //     try {
// //       dispatch({ type: 'SET_LOADING', payload: true });
// //       dispatch({ type: 'SET_ERROR', payload: null });

// //       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

// //       const response = await api3001('/api/auth/verify-email-otp', {
// //         body: {
// //           otp: SecurityUtils.sanitizeInput(otp),
// //           referrer: document.referrer,
// //           timestamp: Date.now()
// //         }
// //       });

// //       if (response?.success && response?.userId) {
// //         dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
// //         dispatch({ type: 'SET_USER_ID', payload: response.userId });
// //         dispatch({ type: 'SET_STEP', payload: 3 });
// //         toast.success('Email verified successfully');
// //         return response;
// //       }
// //       throw new Error(response?.message || 'Invalid email OTP');
// //     } catch (error) {
// //       const errorMessage = error.message || 'Invalid email OTP';
// //       dispatch({ type: 'SET_ERROR', payload: errorMessage });
// //       toast.error(errorMessage);
// //       throw error;
// //     } finally {
// //       dispatch({ type: 'SET_LOADING', payload: false });
// //     }
// //   }, [api3001]);

// //   // ----------------------------------------------------
// //   // STEP 3: Send phone OTP
// //   // ----------------------------------------------------
// //   const sendPhoneOTP = useCallback(async (phone) => {
// //     try {
// //       dispatch({ type: 'SET_LOADING', payload: true });
// //       dispatch({ type: 'SET_ERROR', payload: null });

// //       let cleanPhone = phone.trim();
// //       if (!cleanPhone.startsWith('+') && /^\d/.test(cleanPhone)) cleanPhone = '+' + cleanPhone;
// //       if (cleanPhone.startsWith('+')) cleanPhone = '+' + cleanPhone.substring(1).replace(/\D/g, '');

// //       if (!SecurityUtils.isValidPhone(cleanPhone)) {
// //         throw new Error('Invalid phone number format');
// //       }

// //       const response = await api3001('/api/auth/send-sms-otp', {
// //         body: {
// //           phone: cleanPhone,
// //           referrer: document.referrer,
// //           timestamp: Date.now()
// //         }
// //       });

// //       if (response?.success) {
// //         dispatch({ type: 'SET_PHONE', payload: cleanPhone });
// //         dispatch({ type: 'SET_OTP_SENT', payload: true });
// //         dispatch({ type: 'SET_STEP', payload: 4 });
// //         toast.success('OTP sent to your phone successfully');
// //         return response;
// //       }
// //       throw new Error(response?.message || 'Failed to send SMS OTP');
// //     } catch (error) {
// //       const errorMessage = error.message || 'Failed to send SMS OTP';
// //       dispatch({ type: 'SET_ERROR', payload: errorMessage });
// //       toast.error(errorMessage);
// //       throw error;
// //     } finally {
// //       dispatch({ type: 'SET_LOADING', payload: false });
// //     }
// //   }, [api3001]);

// //   // ----------------------------------------------------
// //   // STEP 4: Verify phone OTP
// //   // ----------------------------------------------------
// //   const verifyPhoneOTP = useCallback(async (otp) => {
// //     try {
// //       dispatch({ type: 'SET_LOADING', payload: true });
// //       dispatch({ type: 'SET_ERROR', payload: null });

// //       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

// //       const response = await api3001('/api/auth/verify-sms-otp', {
// //         body: {
// //           otp: SecurityUtils.sanitizeInput(otp),
// //           referrer: document.referrer,
// //           timestamp: Date.now()
// //         }
// //       });

// //       if (response?.success) {
// //         dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
// //         dispatch({ type: 'SET_STEP', payload: 5 });
// //         toast.success('Phone verified successfully');
// //         return response;
// //       }
// //       throw new Error(response?.message || 'Invalid SMS OTP');
// //     } catch (error) {
// //       const errorMessage = error.message || 'Invalid SMS OTP';
// //       dispatch({ type: 'SET_ERROR', payload: errorMessage });
// //       toast.error(errorMessage);
// //       throw error;
// //     } finally {
// //       dispatch({ type: 'SET_LOADING', payload: false });
// //     }
// //   }, [api3001]);

// //   // ----------------------------------------------------
// //   // STEP 5: Complete Biometric Authentication
// //   // ----------------------------------------------------
// //   const completeAuthentication = useCallback(async () => {
// //     try {
// //       dispatch({ type: 'SET_LOADING', payload: true });
// //       dispatch({ type: 'SET_ERROR', payload: null });

// //       if (!state.emailVerified || !state.phoneVerified || !state.userId) {
// //         throw new Error('Email and phone verification must be completed first');
// //       }

// //       const deviceFingerprint = await generateDeviceFingerprint();

// //       const deviceInfo = {
// //         type: /mobile/i.test(navigator.userAgent) ? 'mobile' :
// //               /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop',
// //         browser: { name: navigator.userAgent, version: navigator.appVersion },
// //         os: { name: navigator.platform, version: navigator.platform },
// //         screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1 },
// //         device: { type: /mobile/i.test(navigator.userAgent) ? 'mobile' : /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop' }
// //       };

// //       const capabilities = { hasWebAuthn: !!window.PublicKeyCredential, platform: navigator.platform, userAgent: navigator.userAgent };
// //       const location = { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, language: navigator.language };

// //       const deviceResponse = await api3002('/api/biometric/device/register', {
// //         body: { 
// //           user_id: state.userId,
// //           sngine_email: state.email, 
// //           sngine_phone: state.phone, 
// //           deviceInfo, 
// //           location, 
// //           capabilities, 
// //           referrer: document.referrer, 
// //           timestamp: Date.now() 
// //         }
// //       });

// //       if (!deviceResponse?.success || !deviceResponse?.device?.id) {
// //         throw new Error(deviceResponse?.message || 'Device registration failed');
// //       }

// //       const deviceId = deviceResponse.device.id;

// //       const biometricData = { deviceFingerprint, userAgent: navigator.userAgent, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, timestamp: Date.now(), capabilities };

// //       const biometricResponse = await api3002('/api/biometric/register', {
// //         body: { 
// //           user_id: state.userId,
// //           sngine_email: state.email, 
// //           sngine_phone: state.phone, 
// //           deviceId, 
// //           biometricType: 'device_fingerprint', 
// //           biometricData, 
// //           referrer: document.referrer, 
// //           timestamp: Date.now() 
// //         }
// //       });

// //       if (!biometricResponse?.success) throw new Error(biometricResponse?.message || 'Biometric registration failed');

// //       let webauthnRegistered = false;

// //       if (window.PublicKeyCredential && capabilities.hasWebAuthn) {
// //         try {
// //           console.log('Attempting WebAuthn registration...');
// //           const begin = await api3002('/api/biometric/webauthn/register/begin', {
// //             body: { 
// //               user_id: state.userId,
// //               sngine_email: state.email, 
// //               sngine_phone: state.phone, 
// //               deviceId, 
// //               referrer: document.referrer, 
// //               timestamp: Date.now() 
// //             }
// //           });

// //           if (begin?.success && begin?.options) {
// //             console.log('WebAuthn begin successful, creating credential...');
// //             const publicKey = { ...begin.options, challenge: b64ToBytes(begin.options.challenge), user: { ...begin.options.user, id: b64ToBytes(begin.options.user.id) } };
// //             const credential = await navigator.credentials.create({ publicKey });

// //             if (credential) {
// //               console.log('WebAuthn credential created, finishing registration...');
// //               const attestationObject = new Uint8Array(credential.response.attestationObject || []);
// //               const clientDataJSON = new Uint8Array(credential.response.clientDataJSON || []);

// //               const finish = await api3002('/api/biometric/webauthn/register/finish', {
// //                 body: { 
// //                   user_id: state.userId,
// //                   sngine_email: state.email, 
// //                   sngine_phone: state.phone, 
// //                   deviceId, 
// //                   credential: { 
// //                     id: credential.id, 
// //                     rawId: Array.from(new Uint8Array(credential.rawId)), 
// //                     response: { 
// //                       attestationObject: Array.from(attestationObject), 
// //                       clientDataJSON: Array.from(clientDataJSON) 
// //                     }, 
// //                     type: credential.type 
// //                   }, 
// //                   referrer: document.referrer, 
// //                   timestamp: Date.now() 
// //                 }
// //               });

// //               if (finish?.success) {
// //                 webauthnRegistered = true;
// //                 console.log('WebAuthn registration completed successfully');
// //               } else {
// //                 console.warn('WebAuthn finish failed:', finish?.message);
// //               }
// //             }
// //           } else {
// //             console.warn('WebAuthn begin failed:', begin?.message);
// //           }
// //         } catch (webAuthNError) {
// //           console.warn('WebAuthn registration failed, continuing without it:', webAuthNError);
// //         }
// //       } else {
// //         console.log('WebAuthn not supported on this device/browser');
// //       }

// //       dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
// //       dispatch({ type: 'SET_STEP', payload: 6 }); // Move to profile creation step
// //       toast.success('Biometric authentication completed successfully!');

// //       return { success: true, message: 'Biometric authentication completed', deviceId, webauthnRegistered };

// //     } catch (error) {
// //       console.error('Complete authentication error:', error);
// //       const errorMessage = error?.message || 'Authentication failed';
// //       dispatch({ type: 'SET_ERROR', payload: errorMessage });
// //       toast.error(errorMessage);
// //       throw new Error(errorMessage);
// //     } finally {
// //       dispatch({ type: 'SET_LOADING', payload: false });
// //     }
// //   }, [state.email, state.phone, state.emailVerified, state.phoneVerified, state.userId, generateDeviceFingerprint, api3002]);

// //   // ----------------------------------------------------
// //   // STEP 6: Complete Profile Creation
// //   // ----------------------------------------------------
// //   const completeProfileCreation = useCallback(async (profileData = {}) => {
// //     try {
// //       dispatch({ type: 'SET_LOADING', payload: true });
// //       dispatch({ type: 'SET_ERROR', payload: null });

// //       if (!state.biometricVerified || !state.userId) {
// //         throw new Error('Biometric verification must be completed first');
// //       }

// //       const response = await api3003('/api/users/create', {
// //         body: {
// //           user_id: state.userId,
// //           sngine_email: state.email,
// //           sngine_phone: state.phone,
// //           ...profileData,
// //           referrer: document.referrer,
// //           timestamp: Date.now()
// //         }
// //       });

// //       if (response?.success && response?.accessToken && response?.refreshToken) {
// //         // Store tokens
// //         TokenManager.setTokens(
// //           response.accessToken,
// //           response.refreshToken,
// //           response.tokenExpiry
// //         );

// //         // Store user data
// //         localStorage.setItem('vottery_user_data', JSON.stringify(response.data));

// //         // Update state
// //         dispatch({ type: 'SET_USER_DATA', payload: response.data });
// //         dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
// //         dispatch({ type: 'SET_AUTHENTICATED', payload: true });

// //         // Create session
// //         const sessionData = {
// //           userId: response.data.id,
// //           email: response.data.sngine_email,
// //           phone: response.data.sngine_phone,
// //           userType: response.data.user_type,
// //           adminRole: response.data.admin_role,
// //           subscriptionStatus: response.data.subscription_status,
// //           authenticated: true,
// //           profileCreated: true,
// //           timestamp: Date.now()
// //         };

// //         createSession(sessionData);
// //         toast.success('Profile created successfully! Welcome to Vottery!');

// //         return response;
// //       }

// //       throw new Error(response?.message || 'Profile creation failed');
// //     } catch (error) {
// //       console.error('Profile creation error:', error);
// //       const errorMessage = error?.message || 'Profile creation failed';
// //       dispatch({ type: 'SET_ERROR', payload: errorMessage });
// //       toast.error(errorMessage);
// //       throw new Error(errorMessage);
// //     } finally {
// //       dispatch({ type: 'SET_LOADING', payload: false });
// //     }
// //   }, [state.biometricVerified, state.userId, state.email, state.phone, api3003, createSession]);

// //   // ----------------------------------------------------
// //   // Token refresh utility
// //   // ----------------------------------------------------
// //   const refreshAccessToken = useCallback(async () => {
// //     try {
// //       const refreshToken = TokenManager.getRefreshToken();
// //       if (!refreshToken) throw new Error('No refresh token available');

// //       const response = await api3001('/api/auth/refresh', {
// //         body: { refreshToken }
// //       });

// //       if (response?.success && response?.accessToken && response?.refreshToken) {
// //         TokenManager.setTokens(
// //           response.accessToken,
// //           response.refreshToken,
// //           response.tokenExpiry
// //         );
// //         return response.accessToken;
// //       }

// //       throw new Error('Token refresh failed');
// //     } catch (error) {
// //       console.error('Token refresh failed:', error);
// //       logout();
// //       throw error;
// //     }
// //   }, [api3001]);

// //   // ----------------------------------------------------
// //   // Navigation helpers
// //   // ----------------------------------------------------
// //   const goBackStep = useCallback(() => {
// //     if (state.currentStep === 2) dispatch({ type: 'SET_STEP', payload: 1 });
// //     else if (state.currentStep === 4) dispatch({ type: 'SET_STEP', payload: 3 });
// //     else if (state.currentStep === 5) dispatch({ type: 'SET_STEP', payload: 4 });
// //     else if (state.currentStep === 6) dispatch({ type: 'SET_STEP', payload: 5 });
// //   }, [state.currentStep]);

// //   const logout = useCallback(() => {
// //     TokenManager.clearTokens();
// //     clearSession();
// //     sessionStorage.removeItem('vottery_referrer_validation');
// //     dispatch({ type: 'RESET_AUTH' });
// //     toast.success('Logged out successfully');
// //   }, [clearSession]);

// //   const resetAuth = useCallback(() => {
// //     TokenManager.clearTokens();
// //     dispatch({ type: 'RESET_AUTH' });
// //   }, []);

// //   // Role check helper
// //   const isAdmin = useCallback(() => {
// //     return state.userData?.admin_role === 'admin' || 
// //            state.userData?.admin_role === 'manager';
// //   }, [state.userData]);

// //   // ----------------------------------------------------
// //   // Context value
// //   // ----------------------------------------------------
// //   const value = {
// //     ...state,
// //     dispatch,
// //     sendEmailOTP,
// //     verifyEmailOTP,
// //     sendPhoneOTP,
// //     verifyPhoneOTP,
// //     completeAuthentication,
// //     completeProfileCreation,
// //     refreshAccessToken,
// //     goBackStep,
// //     logout,
// //     resetAuth,
// //     isAdmin,
// //     // Token utilities
// //     getAccessToken: TokenManager.getAccessToken,
// //     getRefreshToken: TokenManager.getRefreshToken,
// //     isTokenExpired: TokenManager.isTokenExpired
// //   };

// //   return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
// // };



// //this is new and finishing touch
// import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react';
// import { useSecurity } from './SecurityContext';
// import { SecurityUtils } from '../utils/security';
// import { toast } from 'react-hot-toast';

// const AuthContext = createContext();

// export const useAuth = () => {
//   const context = useContext(AuthContext);
//   if (!context) {
//     throw new Error('useAuth must be used within AuthProvider');
//   }
//   return context;
// };

// // Token Management Utility
// const TokenManager = {
//   setTokens: (accessToken, refreshToken, expiryInfo) => {
//     localStorage.setItem('vottery_access_token', accessToken);
//     localStorage.setItem('vottery_refresh_token', refreshToken);
//     localStorage.setItem('vottery_token_expiry', JSON.stringify(expiryInfo));
//     localStorage.setItem('vottery_token_timestamp', Date.now().toString());
//   },

//   getAccessToken: () => localStorage.getItem('vottery_access_token'),
  
//   getRefreshToken: () => localStorage.getItem('vottery_refresh_token'),
  
//   clearTokens: () => {
//     localStorage.removeItem('vottery_access_token');
//     localStorage.removeItem('vottery_refresh_token');
//     localStorage.removeItem('vottery_token_expiry');
//     localStorage.removeItem('vottery_token_timestamp');
//     localStorage.removeItem('vottery_user_data');
//   },

//   isTokenExpired: () => {
//     const timestamp = localStorage.getItem('vottery_token_timestamp');
//     if (!timestamp) return true;
    
//     // Assuming 7 days expiry (7 * 24 * 60 * 60 * 1000)
//     const tokenAge = Date.now() - parseInt(timestamp);
//     const maxAge = 7 * 24 * 60 * 60 * 1000;
    
//     return tokenAge >= maxAge;
//   }
// };

// // ----------------------------------------------------
// // Reducer & initial state
// // ----------------------------------------------------
// const authReducer = (state, action) => {
//   switch (action.type) {
//     case 'SET_LOADING':
//       return { ...state, isLoading: action.payload };
//     case 'SET_STEP':
//       return { ...state, currentStep: action.payload };
//     case 'SET_EMAIL':
//       return { ...state, email: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_PHONE':
//       return { ...state, phone: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_EMAIL_VERIFIED':
//       return { ...state, emailVerified: action.payload };
//     case 'SET_PHONE_VERIFIED':
//       return { ...state, phoneVerified: action.payload };
//     case 'SET_BIOMETRIC_VERIFIED':
//       return { ...state, biometricVerified: action.payload };
//     case 'SET_PROFILE_CREATED':
//       return { ...state, profileCreated: action.payload };
//     case 'SET_AUTHENTICATED':
//       return { ...state, isAuthenticated: action.payload };
//     case 'SET_USER_DATA':
//       return { ...state, userData: action.payload };
//     case 'SET_ERROR':
//       return { ...state, error: action.payload };
//     case 'SET_REFERRER_VALID':
//       return { ...state, isValidReferrer: action.payload, referrerInfo: action.referrerInfo };
//     case 'RESET_AUTH':
//       return {
//         ...state,
//         currentStep: 1,
//         email: '',
//         phone: '',
//         emailVerified: false,
//         phoneVerified: false,
//         biometricVerified: false,
//         profileCreated: false,
//         error: null,
//         isAuthenticated: false,
//         userData: null
//       };
//     case 'SET_OTP_SENT':
//       return { ...state, otpSent: action.payload };
//     case 'SET_RESEND_COOLDOWN':
//       return { ...state, resendCooldown: action.payload };
//     default:
//       return state;
//   }
// };

// const initialState = {
//   isAuthenticated: false,
//   isLoading: false,
//   currentStep: 1,
//   email: '',
//   phone: '',
//   emailVerified: false,
//   phoneVerified: false,
//   biometricVerified: false,
//   profileCreated: false,
//   userData: null,
//   error: null,
//   isValidReferrer: false,
//   referrerInfo: null,
//   otpSent: false,
//   resendCooldown: 0
// };

// // ----------------------------------------------------
// // Utilities
// // ----------------------------------------------------
// const b64ToBytes = (b64) => {
//   const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
//   const pad = normalized.length % 4 === 2 ? '==' : normalized.length % 4 === 3 ? '=' : '';
//   const str = atob(normalized + pad);
//   const bytes = new Uint8Array(str.length);
//   for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
//   return bytes;
// };

// const createApiRequest = (BASE) => {
//   return async (endpoint, options = {}) => {
//     const isAbsolute = /^https?:\/\//i.test(endpoint);
//     const url = isAbsolute ? endpoint : `${BASE}${endpoint}`;

//     const config = {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//         'X-Requested-With': 'XMLHttpRequest',
//         'X-Referrer': typeof document !== 'undefined' ? document.referrer : '',
//         ...(options.headers || {})
//       },
//       ...options
//     };

//     // Add Authorization header if access token exists
//     const accessToken = TokenManager.getAccessToken();
//     if (accessToken && !config.headers.Authorization) {
//       config.headers.Authorization = `Bearer ${accessToken}`;
//     }

//     if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
//       config.body = JSON.stringify(config.body);
//     }

//     try {
//       const response = await fetch(url, config);
//       const data = await response.json().catch(() => null);

//       if (!response.ok) {
//         const error = new Error((data && data.message) || `HTTP error! status: ${response.status}`);
//         error.response = { data };
//         throw error;
//       }

//       return data;
//     } catch (error) {
//       console.error(`API request failed for ${url}:`, error);
//       if (error.response) throw error;
//       throw new Error('Network error. Please check your connection and try again.');
//     }
//   };
// };

// export const AuthProvider = ({ children }) => {
//   const [state, dispatch] = useReducer(authReducer, initialState);
//   const securityContext = useSecurity();

//   // Safe access to security functions with fallbacks
//   const {
//     checkReferrer = () => ({ isValid: false, referrer: '', error: 'Security context unavailable' }),
//     encryptData = (data) => JSON.stringify(data),
//     decryptData = (data) => JSON.parse(data),
//     generateDeviceFingerprint = () => Promise.resolve('fallback-fingerprint'),
//     createSession = () => {},
//     clearSession = () => {}
//   } = securityContext || {};

//   const API_BASE_3001 = import.meta.env?.VITE_API_BASE_URL || 'http://localhost:3001';
//   const API_BASE_3002 = import.meta.env?.VITE_BIOMETRIC_API_BASE_URL || 'http://localhost:3002';
//   const API_BASE_3003 = import.meta.env?.VITE_USER_API_BASE_URL || 'http://localhost:3003';

//   const api3001 = useCallback(createApiRequest(API_BASE_3001), [API_BASE_3001]);
//   const api3002 = useCallback(createApiRequest(API_BASE_3002), [API_BASE_3002]);
//   const api3003 = useCallback(createApiRequest(API_BASE_3002), [API_BASE_3003]);

//   // ----------------------------------------------------
//   // Check existing authentication on load
//   // ----------------------------------------------------
//   useEffect(() => {
//     const checkExistingAuth = () => {
//       const accessToken = TokenManager.getAccessToken();
//       const userData = localStorage.getItem('vottery_user_data');
      
//       if (accessToken && !TokenManager.isTokenExpired() && userData) {
//         try {
//           const parsedUserData = JSON.parse(userData);
//           dispatch({ type: 'SET_USER_DATA', payload: parsedUserData });
//           dispatch({ type: 'SET_EMAIL', payload: parsedUserData.sngine_email });
//           dispatch({ type: 'SET_PHONE', payload: parsedUserData.sngine_phone });
//           dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
//           dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//           dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//           dispatch({ type: 'SET_AUTHENTICATED', payload: true });
//         } catch (error) {
//           console.warn('Failed to parse user data, clearing tokens');
//           TokenManager.clearTokens();
//         }
//       }
//     };

//     checkExistingAuth();
//   }, []);

//   // ----------------------------------------------------
//   // Referrer check
//   // ----------------------------------------------------
//   useEffect(() => {
//     try {
//       const referrerInfo = checkReferrer();
//       dispatch({ type: 'SET_REFERRER_VALID', payload: referrerInfo.isValid, referrerInfo });

//       if (referrerInfo.isValid) {
//         const validationData = encryptData({
//           referrer: referrerInfo.referrer,
//           timestamp: Date.now(),
//           validated: true
//         });
//         sessionStorage.setItem('vottery_referrer_validation', validationData);
//       }
//     } catch (error) {
//       console.warn('Referrer check failed:', error);
//       dispatch({ type: 'SET_REFERRER_VALID', payload: false, referrerInfo: { error: error.message } });
//     }
//   }, [checkReferrer, encryptData]);

//   // ----------------------------------------------------
//   // STEP 1: Send email OTP
//   // ----------------------------------------------------
//   const sendEmailOTP = useCallback(async (email) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!SecurityUtils.isValidEmail(email)) {
//         throw new Error('Invalid email format');
//       }

//       const response = await api3001('/api/auth/send-email-otp', {
//         body: {
//           email: SecurityUtils.sanitizeInput(email),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL', payload: email });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 2 });
//         toast.success('OTP sent to your email successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // ----------------------------------------------------
//   // STEP 2: Verify email OTP
//   // ----------------------------------------------------
//   const verifyEmailOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-email-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 3 });
//         toast.success('Email verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // ----------------------------------------------------
//   // STEP 3: Send phone OTP
//   // ----------------------------------------------------
//   const sendPhoneOTP = useCallback(async (phone) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       let cleanPhone = phone.trim();
//       if (!cleanPhone.startsWith('+') && /^\d/.test(cleanPhone)) cleanPhone = '+' + cleanPhone;
//       if (cleanPhone.startsWith('+')) cleanPhone = '+' + cleanPhone.substring(1).replace(/\D/g, '');

//       if (!SecurityUtils.isValidPhone(cleanPhone)) {
//         throw new Error('Invalid phone number format');
//       }

//       const response = await api3001('/api/auth/send-sms-otp', {
//         body: {
//           phone: cleanPhone,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE', payload: cleanPhone });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 4 });
//         toast.success('OTP sent to your phone successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // ----------------------------------------------------
//   // STEP 4: Verify phone OTP
//   // ----------------------------------------------------
//   const verifyPhoneOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-sms-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 5 });
//         toast.success('Phone verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // ----------------------------------------------------
//   // STEP 5: Complete Biometric Authentication
//   // ----------------------------------------------------
//   const completeAuthentication = useCallback(async () => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.emailVerified || !state.phoneVerified) {
//         throw new Error('Email and phone verification must be completed first');
//       }

//       const deviceFingerprint = await generateDeviceFingerprint();

//       const deviceInfo = {
//         type: /mobile/i.test(navigator.userAgent) ? 'mobile' :
//               /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop',
//         browser: { name: navigator.userAgent, version: navigator.appVersion },
//         os: { name: navigator.platform, version: navigator.platform },
//         screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1 },
//         device: { type: /mobile/i.test(navigator.userAgent) ? 'mobile' : /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop' }
//       };

//       const capabilities = { hasWebAuthn: !!window.PublicKeyCredential, platform: navigator.platform, userAgent: navigator.userAgent };
//       const location = { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, language: navigator.language };

//       const deviceResponse = await api3002('/api/biometric/device/register', {
//         body: { sngine_email: state.email, sngine_phone: state.phone, deviceInfo, location, capabilities, referrer: document.referrer, timestamp: Date.now() }
//       });

//       if (!deviceResponse?.success || !deviceResponse?.device?.id) {
//         throw new Error(deviceResponse?.message || 'Device registration failed');
//       }

//       const deviceId = deviceResponse.device.id;

//       const biometricData = { deviceFingerprint, userAgent: navigator.userAgent, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, timestamp: Date.now(), capabilities };

//       const biometricResponse = await api3002('/api/biometric/register', {
//         body: { sngine_email: state.email, sngine_phone: state.phone, deviceId, biometricType: 'device_fingerprint', biometricData, referrer: document.referrer, timestamp: Date.now() }
//       });

//       if (!biometricResponse?.success) throw new Error(biometricResponse?.message || 'Biometric registration failed');

//       let webauthnRegistered = false;

//       if (window.PublicKeyCredential && capabilities.hasWebAuthn) {
//         try {
//           console.log('Attempting WebAuthn registration...');
//           const begin = await api3002('/api/biometric/webauthn/register/begin', {
//             body: { 
//               sngine_email: state.email, 
//               sngine_phone: state.phone, 
//               deviceId, 
//               referrer: document.referrer, 
//               timestamp: Date.now() 
//             }
//           });

//           if (begin?.success && begin?.options) {
//             console.log('WebAuthn begin successful, creating credential...');
//             const publicKey = { ...begin.options, challenge: b64ToBytes(begin.options.challenge), user: { ...begin.options.user, id: b64ToBytes(begin.options.user.id) } };
//             const credential = await navigator.credentials.create({ publicKey });

//             if (credential) {
//               console.log('WebAuthn credential created, finishing registration...');
//               const attestationObject = new Uint8Array(credential.response.attestationObject || []);
//               const clientDataJSON = new Uint8Array(credential.response.clientDataJSON || []);

//               const finish = await api3002('/api/biometric/webauthn/register/finish', {
//                 body: { 
//                   sngine_email: state.email, 
//                   sngine_phone: state.phone, 
//                   deviceId, 
//                   credential: { 
//                     id: credential.id, 
//                     rawId: Array.from(new Uint8Array(credential.rawId)), 
//                     response: { 
//                       attestationObject: Array.from(attestationObject), 
//                       clientDataJSON: Array.from(clientDataJSON) 
//                     }, 
//                     type: credential.type 
//                   }, 
//                   referrer: document.referrer, 
//                   timestamp: Date.now() 
//                 }
//               });

//               if (finish?.success) {
//                 webauthnRegistered = true;
//                 console.log('WebAuthn registration completed successfully');
//               } else {
//                 console.warn('WebAuthn finish failed:', finish?.message);
//               }
//             }
//           } else {
//             console.warn('WebAuthn begin failed:', begin?.message);
//           }
//         } catch (webAuthNError) {
//           console.warn('WebAuthn registration failed, continuing without it:', webAuthNError);
//         }
//       } else {
//         console.log('WebAuthn not supported on this device/browser');
//       }

//       dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//       dispatch({ type: 'SET_STEP', payload: 6 }); // Move to profile creation step
//       toast.success('Biometric authentication completed successfully!');

//       return { success: true, message: 'Biometric authentication completed', deviceId, webauthnRegistered };

//     } catch (error) {
//       console.error('Complete authentication error:', error);
//       const errorMessage = error?.message || 'Authentication failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.email, state.phone, state.emailVerified, state.phoneVerified, generateDeviceFingerprint, api3002]);

//   // ----------------------------------------------------
//   // STEP 6: Complete Profile Creation
//   // ----------------------------------------------------
//   const completeProfileCreation = useCallback(async (profileData) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.biometricVerified) {
//         throw new Error('Biometric verification must be completed first');
//       }

//       const response = await api3003('/api/users/create', {
//         body: {
//           ...profileData,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         // Store tokens
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken,
//           response.tokenExpiry
//         );

//         // Store user data
//         localStorage.setItem('vottery_user_data', JSON.stringify(response.data));

//         // Update state
//         dispatch({ type: 'SET_USER_DATA', payload: response.data });
//         dispatch({ type: 'SET_PROFILE_CREATED', payload: true });
//         dispatch({ type: 'SET_AUTHENTICATED', payload: true });

//         // Create session
//         const sessionData = {
//           userId: response.data.id,
//           email: response.data.sngine_email,
//           phone: response.data.sngine_phone,
//           userType: response.data.user_type,
//           adminRole: response.data.admin_role,
//           subscriptionStatus: response.data.subscription_status,
//           authenticated: true,
//           profileCreated: true,
//           timestamp: Date.now()
//         };

//         createSession(sessionData);
//         toast.success('Profile created successfully! Welcome to Vottery!');

//         return response;
//       }

//       throw new Error(response?.message || 'Profile creation failed');
//     } catch (error) {
//       console.error('Profile creation error:', error);
//       const errorMessage = error?.message || 'Profile creation failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.biometricVerified, api3001, createSession]);

//   // ----------------------------------------------------
//   // Token refresh utility
//   // ----------------------------------------------------
//   const refreshAccessToken = useCallback(async () => {
//     try {
//       const refreshToken = TokenManager.getRefreshToken();
//       if (!refreshToken) throw new Error('No refresh token available');

//       const response = await api3001('/api/auth/refresh', {
//         body: { refreshToken }
//       });

//       if (response?.success && response?.accessToken && response?.refreshToken) {
//         TokenManager.setTokens(
//           response.accessToken,
//           response.refreshToken,
//           response.tokenExpiry
//         );
//         return response.accessToken;
//       }

//       throw new Error('Token refresh failed');
//     } catch (error) {
//       console.error('Token refresh failed:', error);
//       logout();
//       throw error;
//     }
//   }, [api3001]);

//   // ----------------------------------------------------
//   // Navigation helpers
//   // ----------------------------------------------------
//   const goBackStep = useCallback(() => {
//     if (state.currentStep === 2) dispatch({ type: 'SET_STEP', payload: 1 });
//     else if (state.currentStep === 4) dispatch({ type: 'SET_STEP', payload: 3 });
//     else if (state.currentStep === 5) dispatch({ type: 'SET_STEP', payload: 4 });
//     else if (state.currentStep === 6) dispatch({ type: 'SET_STEP', payload: 5 });
//   }, [state.currentStep]);

//   const logout = useCallback(() => {
//     TokenManager.clearTokens();
//     clearSession();
//     sessionStorage.removeItem('vottery_referrer_validation');
//     dispatch({ type: 'RESET_AUTH' });
//     toast.success('Logged out successfully');
//   }, [clearSession]);

//   const resetAuth = useCallback(() => {
//     TokenManager.clearTokens();
//     dispatch({ type: 'RESET_AUTH' });
//   }, []);

//   // ----------------------------------------------------
//   // Context value
//   // ----------------------------------------------------
//   const value = {
//     ...state,
//     dispatch,
//     sendEmailOTP,
//     verifyEmailOTP,
//     sendPhoneOTP,
//     verifyPhoneOTP,
//     completeAuthentication,
//     completeProfileCreation,
//     refreshAccessToken,
//     goBackStep,
//     logout,
//     resetAuth,
//     // Token utilities
//     getAccessToken: TokenManager.getAccessToken,
//     getRefreshToken: TokenManager.getRefreshToken,
//     isTokenExpired: TokenManager.isTokenExpired
//   };

//   return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
// };




//this is previous successful
// //to solve last problem webauthn
// import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react';
// import { useSecurity } from './SecurityContext';
// import { SecurityUtils } from '../utils/security';
// import { toast } from 'react-hot-toast';

// const AuthContext = createContext();

// export const useAuth = () => {
//   const context = useContext(AuthContext);
//   if (!context) {
//     throw new Error('useAuth must be used within AuthProvider');
//   }
//   return context;
// };

// // ----------------------------------------------------
// // Reducer & initial state
// // ----------------------------------------------------
// const authReducer = (state, action) => {
//   switch (action.type) {
//     case 'SET_LOADING':
//       return { ...state, isLoading: action.payload };
//     case 'SET_STEP':
//       return { ...state, currentStep: action.payload };
//     case 'SET_EMAIL':
//       return { ...state, email: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_PHONE':
//       return { ...state, phone: SecurityUtils.sanitizeInput(action.payload) };
//     case 'SET_EMAIL_VERIFIED':
//       return { ...state, emailVerified: action.payload };
//     case 'SET_PHONE_VERIFIED':
//       return { ...state, phoneVerified: action.payload };
//     case 'SET_BIOMETRIC_VERIFIED':
//       return { ...state, biometricVerified: action.payload };
//     case 'SET_AUTHENTICATED':
//       return { ...state, isAuthenticated: action.payload };
//     case 'SET_ERROR':
//       return { ...state, error: action.payload };
//     case 'SET_REFERRER_VALID':
//       return { ...state, isValidReferrer: action.payload, referrerInfo: action.referrerInfo };
//     case 'RESET_AUTH':
//       return {
//         ...state,
//         currentStep: 1,
//         email: '',
//         phone: '',
//         emailVerified: false,
//         phoneVerified: false,
//         biometricVerified: false,
//         error: null,
//         isAuthenticated: false
//       };
//     case 'SET_OTP_SENT':
//       return { ...state, otpSent: action.payload };
//     case 'SET_RESEND_COOLDOWN':
//       return { ...state, resendCooldown: action.payload };
//     default:
//       return state;
//   }
// };

// const initialState = {
//   isAuthenticated: false,
//   isLoading: false,
//   currentStep: 1,
//   email: '',
//   phone: '',
//   emailVerified: false,
//   phoneVerified: false,
//   biometricVerified: false,
//   error: null,
//   isValidReferrer: false,
//   referrerInfo: null,
//   otpSent: false,
//   resendCooldown: 0
// };

// // ----------------------------------------------------
// // Utilities
// // ----------------------------------------------------
// const b64ToBytes = (b64) => {
//   const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
//   const pad = normalized.length % 4 === 2 ? '==' : normalized.length % 4 === 3 ? '=' : '';
//   const str = atob(normalized + pad);
//   const bytes = new Uint8Array(str.length);
//   for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
//   return bytes;
// };

// const createApiRequest = (BASE) => {
//   return async (endpoint, options = {}) => {
//     const isAbsolute = /^https?:\/\//i.test(endpoint);
//     const url = isAbsolute ? endpoint : `${BASE}${endpoint}`;

//     const config = {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//         'X-Requested-With': 'XMLHttpRequest',
//         'X-Referrer': typeof document !== 'undefined' ? document.referrer : '',
//         ...(options.headers || {})
//       },
//       ...options
//     };

//     if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
//       config.body = JSON.stringify(config.body);
//     }

//     try {
//       const response = await fetch(url, config);
//       const data = await response.json().catch(() => null);

//       if (!response.ok) {
//         const error = new Error((data && data.message) || `HTTP error! status: ${response.status}`);
//         error.response = { data };
//         throw error;
//       }

//       return data;
//     } catch (error) {
//       console.error(`API request failed for ${url}:`, error);
//       if (error.response) throw error;
//       throw new Error('Network error. Please check your connection and try again.');
//     }
//   };
// };

// export const AuthProvider = ({ children }) => {
//   const [state, dispatch] = useReducer(authReducer, initialState);
//   const securityContext = useSecurity();

//   // Safe access to security functions with fallbacks
//   const {
//     checkReferrer = () => ({ isValid: false, referrer: '', error: 'Security context unavailable' }),
//     encryptData = (data) => JSON.stringify(data),
//     decryptData = (data) => JSON.parse(data),
//     generateDeviceFingerprint = () => Promise.resolve('fallback-fingerprint'),
//     createSession = () => {},
//     clearSession = () => {}
//   } = securityContext || {};

//   const API_BASE_3001 = import.meta.env?.VITE_API_BASE_URL || 'http://localhost:3001';
//   const API_BASE_3002 = import.meta.env?.VITE_BIOMETRIC_API_BASE_URL || 'http://localhost:3002';

//   const api3001 = useCallback(createApiRequest(API_BASE_3001), [API_BASE_3001]);
//   const api3002 = useCallback(createApiRequest(API_BASE_3002), [API_BASE_3002]);

//   // ----------------------------------------------------
//   // Referrer check
//   // ----------------------------------------------------
//   useEffect(() => {
//     try {
//       const referrerInfo = checkReferrer();
//       dispatch({ type: 'SET_REFERRER_VALID', payload: referrerInfo.isValid, referrerInfo });

//       if (referrerInfo.isValid) {
//         const validationData = encryptData({
//           referrer: referrerInfo.referrer,
//           timestamp: Date.now(),
//           validated: true
//         });
//         sessionStorage.setItem('vottery_referrer_validation', validationData);
//       }
//     } catch (error) {
//       console.warn('Referrer check failed:', error);
//       dispatch({ type: 'SET_REFERRER_VALID', payload: false, referrerInfo: { error: error.message } });
//     }
//   }, [checkReferrer, encryptData]);

//   // ----------------------------------------------------
//   // STEP 1: Send email OTP
//   // ----------------------------------------------------
//   const sendEmailOTP = useCallback(async (email) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!SecurityUtils.isValidEmail(email)) {
//         throw new Error('Invalid email format');
//       }

//       const response = await api3001('/api/auth/send-email-otp', {
//         body: {
//           email: SecurityUtils.sanitizeInput(email),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL', payload: email });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 2 });
//         toast.success('OTP sent to your email successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // ----------------------------------------------------
//   // STEP 2: Verify email OTP
//   // ----------------------------------------------------
//   const verifyEmailOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-email-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 3 });
//         toast.success('Email verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid email OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid email OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // ----------------------------------------------------
//   // STEP 3: Send phone OTP
//   // ----------------------------------------------------
//   const sendPhoneOTP = useCallback(async (phone) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       let cleanPhone = phone.trim();
//       if (!cleanPhone.startsWith('+') && /^\d/.test(cleanPhone)) cleanPhone = '+' + cleanPhone;
//       if (cleanPhone.startsWith('+')) cleanPhone = '+' + cleanPhone.substring(1).replace(/\D/g, '');

//       if (!SecurityUtils.isValidPhone(cleanPhone)) {
//         throw new Error('Invalid phone number format');
//       }

//       const response = await api3001('/api/auth/send-sms-otp', {
//         body: {
//           phone: cleanPhone,
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE', payload: cleanPhone });
//         dispatch({ type: 'SET_OTP_SENT', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 4 });
//         toast.success('OTP sent to your phone successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Failed to send SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Failed to send SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // ----------------------------------------------------
//   // STEP 4: Verify phone OTP
//   // ----------------------------------------------------
//   const verifyPhoneOTP = useCallback(async (otp) => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

//       const response = await api3001('/api/auth/verify-sms-otp', {
//         body: {
//           otp: SecurityUtils.sanitizeInput(otp),
//           referrer: document.referrer,
//           timestamp: Date.now()
//         }
//       });

//       if (response?.success) {
//         dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
//         dispatch({ type: 'SET_STEP', payload: 5 });
//         toast.success('Phone verified successfully');
//         return response;
//       }
//       throw new Error(response?.message || 'Invalid SMS OTP');
//     } catch (error) {
//       const errorMessage = error.message || 'Invalid SMS OTP';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw error;
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [api3001]);

//   // ----------------------------------------------------
//   // STEP 5: Complete Authentication (Device/Biometric/WebAuthn)
//   // ----------------------------------------------------
//   const completeAuthentication = useCallback(async () => {
//     try {
//       dispatch({ type: 'SET_LOADING', payload: true });
//       dispatch({ type: 'SET_ERROR', payload: null });

//       if (!state.emailVerified || !state.phoneVerified) {
//         throw new Error('Email and phone verification must be completed first');
//       }

//       const deviceFingerprint = await generateDeviceFingerprint();

//       const deviceInfo = {
//         type: /mobile/i.test(navigator.userAgent) ? 'mobile' :
//               /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop',
//         browser: { name: navigator.userAgent, version: navigator.appVersion },
//         os: { name: navigator.platform, version: navigator.platform },
//         screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1 },
//         device: { type: /mobile/i.test(navigator.userAgent) ? 'mobile' : /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop' }
//       };

//       const capabilities = { hasWebAuthn: !!window.PublicKeyCredential, platform: navigator.platform, userAgent: navigator.userAgent };
//       const location = { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, language: navigator.language };

//       const deviceResponse = await api3002('/api/biometric/device/register', {
//         body: { sngine_email: state.email, sngine_phone: state.phone, deviceInfo, location, capabilities, referrer: document.referrer, timestamp: Date.now() }
//       });

//       if (!deviceResponse?.success || !deviceResponse?.device?.id) {
//         throw new Error(deviceResponse?.message || 'Device registration failed');
//       }

//       const deviceId = deviceResponse.device.id;

//       const biometricData = { deviceFingerprint, userAgent: navigator.userAgent, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, timestamp: Date.now(), capabilities };

//       const biometricResponse = await api3002('/api/biometric/register', {
//         body: { sngine_email: state.email, sngine_phone: state.phone, deviceId, biometricType: 'device_fingerprint', biometricData, referrer: document.referrer, timestamp: Date.now() }
//       });

//       if (!biometricResponse?.success) throw new Error(biometricResponse?.message || 'Biometric registration failed');

//       let webauthnRegistered = false;

//       if (window.PublicKeyCredential && capabilities.hasWebAuthn) {
//         try {
//           console.log('Attempting WebAuthn registration...');
//           // Sending correct field names that backend expects
//           const begin = await api3002('/api/biometric/webauthn/register/begin', {
//             body: { 
//               sngine_email: state.email, 
//               sngine_phone: state.phone, 
//               deviceId, 
//               referrer: document.referrer, 
//               timestamp: Date.now() 
//             }
//           });

//           if (begin?.success && begin?.options) {
//             console.log('WebAuthn begin successful, creating credential...');
//             const publicKey = { ...begin.options, challenge: b64ToBytes(begin.options.challenge), user: { ...begin.options.user, id: b64ToBytes(begin.options.user.id) } };
//             const credential = await navigator.credentials.create({ publicKey });

//             if (credential) {
//               console.log('WebAuthn credential created, finishing registration...');
//               const attestationObject = new Uint8Array(credential.response.attestationObject || []);
//               const clientDataJSON = new Uint8Array(credential.response.clientDataJSON || []);

//               // Sending correct field names that backend expects
//               const finish = await api3002('/api/biometric/webauthn/register/finish', {
//                 body: { 
//                   sngine_email: state.email, 
//                   sngine_phone: state.phone, 
//                   deviceId, 
//                   credential: { 
//                     id: credential.id, 
//                     rawId: Array.from(new Uint8Array(credential.rawId)), 
//                     response: { 
//                       attestationObject: Array.from(attestationObject), 
//                       clientDataJSON: Array.from(clientDataJSON) 
//                     }, 
//                     type: credential.type 
//                   }, 
//                   referrer: document.referrer, 
//                   timestamp: Date.now() 
//                 }
//               });

//               if (finish?.success) {
//                 webauthnRegistered = true;
//                 console.log('WebAuthn registration completed successfully');
//               } else {
//                 console.warn('WebAuthn finish failed:', finish?.message);
//               }
//             }
//           } else {
//             console.warn('WebAuthn begin failed:', begin?.message);
//           }
//         } catch (webAuthNError) {
//           console.warn('WebAuthn registration failed, continuing without it:', webAuthNError);
//         }
//       } else {
//         console.log('WebAuthn not supported on this device/browser');
//       }

//       dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
//       dispatch({ type: 'SET_AUTHENTICATED', payload: true });

//       const authData = { email: state.email, phone: state.phone, deviceId, authenticated: true, biometricVerified: true, webauthnRegistered, timestamp: Date.now() };
//       const encryptedAuthData = encryptData(authData);
//       sessionStorage.setItem('vottery_auth_data', encryptedAuthData);
//       createSession(authData);
//       toast.success('Authentication completed successfully!');

//       return { success: true, message: 'Authentication completed successfully', deviceId, webauthnRegistered };

//     } catch (error) {
//       console.error('Complete authentication error:', error);
//       const errorMessage = error?.message || 'Authentication failed';
//       dispatch({ type: 'SET_ERROR', payload: errorMessage });
//       toast.error(errorMessage);
//       throw new Error(errorMessage);
//     } finally {
//       dispatch({ type: 'SET_LOADING', payload: false });
//     }
//   }, [state.email, state.phone, state.emailVerified, state.phoneVerified, generateDeviceFingerprint, encryptData, createSession, api3002]);

//   // ----------------------------------------------------
//   // Navigation helpers
//   // ----------------------------------------------------
//   const goBackStep = useCallback(() => {
//     if (state.currentStep === 2) dispatch({ type: 'SET_STEP', payload: 1 });
//     else if (state.currentStep === 4) dispatch({ type: 'SET_STEP', payload: 3 });
//     else if (state.currentStep === 5) dispatch({ type: 'SET_STEP', payload: 4 });
//   }, [state.currentStep]);

//   const logout = useCallback(() => {
//     clearSession();
//     sessionStorage.removeItem('vottery_auth_data');
//     sessionStorage.removeItem('vottery_referrer_validation');
//     dispatch({ type: 'RESET_AUTH' });
//     toast.success('Logged out successfully');
//   }, [clearSession]);

//   const resetAuth = useCallback(() => dispatch({ type: 'RESET_AUTH' }), []);

//   // ----------------------------------------------------
//   // Context value
//   // ----------------------------------------------------
//   const value = {
//     ...state,
//     dispatch,
//     sendEmailOTP,
//     verifyEmailOTP,
//     sendPhoneOTP,
//     verifyPhoneOTP,
//     completeAuthentication,
//     goBackStep,
//     logout,
//     resetAuth
//   };

//   return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
// };


// //step 5 with 3001 and 3002
// // src/context/AuthContext.jsx
// // import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react';
// // import { useSecurity } from './SecurityContext';
// // import { SecurityUtils } from '../utils/security';
// // import { toast } from 'react-hot-toast';

// // const AuthContext = createContext();

// // export const useAuth = () => {
// //   const context = useContext(AuthContext);
// //   if (!context) {
// //     throw new Error('useAuth must be used within AuthProvider');
// //   }
// //   return context;
// // };

// // // ----------------------------------------------------
// // // Reducer & initial state
// // // ----------------------------------------------------
// // const authReducer = (state, action) => {
// //   switch (action.type) {
// //     case 'SET_LOADING':
// //       return { ...state, isLoading: action.payload };
// //     case 'SET_STEP':
// //       return { ...state, currentStep: action.payload };
// //     case 'SET_EMAIL':
// //       return { ...state, email: SecurityUtils.sanitizeInput(action.payload) };
// //     case 'SET_PHONE':
// //       return { ...state, phone: SecurityUtils.sanitizeInput(action.payload) };
// //     case 'SET_EMAIL_VERIFIED':
// //       return { ...state, emailVerified: action.payload };
// //     case 'SET_PHONE_VERIFIED':
// //       return { ...state, phoneVerified: action.payload };
// //     case 'SET_BIOMETRIC_VERIFIED':
// //       return { ...state, biometricVerified: action.payload };
// //     case 'SET_AUTHENTICATED':
// //       return { ...state, isAuthenticated: action.payload };
// //     case 'SET_ERROR':
// //       return { ...state, error: action.payload };
// //     case 'SET_REFERRER_VALID':
// //       return { ...state, isValidReferrer: action.payload, referrerInfo: action.referrerInfo };
// //     case 'RESET_AUTH':
// //       return {
// //         ...state,
// //         currentStep: 1,
// //         email: '',
// //         phone: '',
// //         emailVerified: false,
// //         phoneVerified: false,
// //         biometricVerified: false,
// //         error: null,
// //         isAuthenticated: false
// //       };
// //     case 'SET_OTP_SENT':
// //       return { ...state, otpSent: action.payload };
// //     case 'SET_RESEND_COOLDOWN':
// //       return { ...state, resendCooldown: action.payload };
// //     default:
// //       return state;
// //   }
// // };

// // const initialState = {
// //   isAuthenticated: false,
// //   isLoading: false,
// //   currentStep: 1,
// //   email: '',
// //   phone: '',
// //   emailVerified: false,
// //   phoneVerified: false,
// //   biometricVerified: false,
// //   error: null,
// //   isValidReferrer: false,
// //   referrerInfo: null,
// //   otpSent: false,
// //   resendCooldown: 0
// // };

// // // ----------------------------------------------------
// // // Utilities
// // // ----------------------------------------------------
// // const b64ToBytes = (b64) => {
// //   const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
// //   const pad = normalized.length % 4 === 2 ? '==' : normalized.length % 4 === 3 ? '=' : '';
// //   const str = atob(normalized + pad);
// //   const bytes = new Uint8Array(str.length);
// //   for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
// //   return bytes;
// // };

// // const createApiRequest = (BASE) => {
// //   return async (endpoint, options = {}) => {
// //     const isAbsolute = /^https?:\/\//i.test(endpoint);
// //     const url = isAbsolute ? endpoint : `${BASE}${endpoint}`;

// //     const config = {
// //       method: 'POST',
// //       headers: {
// //         'Content-Type': 'application/json',
// //         'X-Requested-With': 'XMLHttpRequest',
// //         'X-Referrer': typeof document !== 'undefined' ? document.referrer : '',
// //         ...(options.headers || {})
// //       },
// //       ...options
// //     };

// //     if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
// //       config.body = JSON.stringify(config.body);
// //     }

// //     try {
// //       const response = await fetch(url, config);
// //       const data = await response.json().catch(() => null);

// //       if (!response.ok) {
// //         const error = new Error((data && data.message) || `HTTP error! status: ${response.status}`);
// //         error.response = { data };
// //         throw error;
// //       }

// //       return data;
// //     } catch (error) {
// //       console.error(`API request failed for ${url}:`, error);
// //       if (error.response) throw error;
// //       throw new Error('Network error. Please check your connection and try again.');
// //     }
// //   };
// // };

// // export const AuthProvider = ({ children }) => {
// //   const [state, dispatch] = useReducer(authReducer, initialState);
// //   const { checkReferrer, encryptData, decryptData, generateDeviceFingerprint, createSession, clearSession } = useSecurity();

// //   const API_BASE_3001 = import.meta.env?.VITE_API_BASE_URL || 'http://localhost:3001';
// //   const API_BASE_3002 = import.meta.env?.VITE_BIOMETRIC_API_BASE_URL || 'http://localhost:3002';

// //   const api3001 = useCallback(createApiRequest(API_BASE_3001), [API_BASE_3001]);
// //   const api3002 = useCallback(createApiRequest(API_BASE_3002), [API_BASE_3002]);

// //   // ----------------------------------------------------
// //   // Referrer check
// //   // ----------------------------------------------------
// //   useEffect(() => {
// //     const referrerInfo = checkReferrer();
// //     dispatch({ type: 'SET_REFERRER_VALID', payload: referrerInfo.isValid, referrerInfo });

// //     if (referrerInfo.isValid) {
// //       const validationData = encryptData({
// //         referrer: referrerInfo.referrer,
// //         timestamp: Date.now(),
// //         validated: true
// //       });
// //       sessionStorage.setItem('vottery_referrer_validation', validationData);
// //     }
// //   }, [checkReferrer, encryptData]);

// //   // ----------------------------------------------------
// //   // STEP 1: Send email OTP
// //   // ----------------------------------------------------
// //   const sendEmailOTP = useCallback(async (email) => {
// //     try {
// //       dispatch({ type: 'SET_LOADING', payload: true });
// //       dispatch({ type: 'SET_ERROR', payload: null });

// //       if (!SecurityUtils.isValidEmail(email)) {
// //         throw new Error('Invalid email format');
// //       }

// //       const response = await api3001('/api/auth/send-email-otp', {
// //         body: {
// //           email: SecurityUtils.sanitizeInput(email),
// //           referrer: document.referrer,
// //           timestamp: Date.now()
// //         }
// //       });

// //       if (response?.success) {
// //         dispatch({ type: 'SET_EMAIL', payload: email });
// //         dispatch({ type: 'SET_OTP_SENT', payload: true });
// //         dispatch({ type: 'SET_STEP', payload: 2 });
// //         toast.success('OTP sent to your email successfully');
// //         return response;
// //       }
// //       throw new Error(response?.message || 'Failed to send email OTP');
// //     } catch (error) {
// //       const errorMessage = error.message || 'Failed to send email OTP';
// //       dispatch({ type: 'SET_ERROR', payload: errorMessage });
// //       toast.error(errorMessage);
// //       throw error;
// //     } finally {
// //       dispatch({ type: 'SET_LOADING', payload: false });
// //     }
// //   }, [api3001]);

// //   // ----------------------------------------------------
// //   // STEP 2: Verify email OTP
// //   // ----------------------------------------------------
// //   const verifyEmailOTP = useCallback(async (otp) => {
// //     try {
// //       dispatch({ type: 'SET_LOADING', payload: true });
// //       dispatch({ type: 'SET_ERROR', payload: null });

// //       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

// //       const response = await api3001('/api/auth/verify-email-otp', {
// //         body: {
// //           otp: SecurityUtils.sanitizeInput(otp),
// //           referrer: document.referrer,
// //           timestamp: Date.now()
// //         }
// //       });

// //       if (response?.success) {
// //         dispatch({ type: 'SET_EMAIL_VERIFIED', payload: true });
// //         dispatch({ type: 'SET_STEP', payload: 3 });
// //         toast.success('Email verified successfully');
// //         return response;
// //       }
// //       throw new Error(response?.message || 'Invalid email OTP');
// //     } catch (error) {
// //       const errorMessage = error.message || 'Invalid email OTP';
// //       dispatch({ type: 'SET_ERROR', payload: errorMessage });
// //       toast.error(errorMessage);
// //       throw error;
// //     } finally {
// //       dispatch({ type: 'SET_LOADING', payload: false });
// //     }
// //   }, [api3001]);

// //   // ----------------------------------------------------
// //   // STEP 3: Send phone OTP
// //   // ----------------------------------------------------
// //   const sendPhoneOTP = useCallback(async (phone) => {
// //     try {
// //       dispatch({ type: 'SET_LOADING', payload: true });
// //       dispatch({ type: 'SET_ERROR', payload: null });

// //       let cleanPhone = phone.trim();
// //       if (!cleanPhone.startsWith('+') && /^\d/.test(cleanPhone)) cleanPhone = '+' + cleanPhone;
// //       if (cleanPhone.startsWith('+')) cleanPhone = '+' + cleanPhone.substring(1).replace(/\D/g, '');

// //       if (!SecurityUtils.isValidPhone(cleanPhone)) {
// //         throw new Error('Invalid phone number format');
// //       }

// //       const response = await api3001('/api/auth/send-sms-otp', {
// //         body: {
// //           phone: cleanPhone,
// //           referrer: document.referrer,
// //           timestamp: Date.now()
// //         }
// //       });

// //       if (response?.success) {
// //         dispatch({ type: 'SET_PHONE', payload: cleanPhone });
// //         dispatch({ type: 'SET_OTP_SENT', payload: true });
// //         dispatch({ type: 'SET_STEP', payload: 4 });
// //         toast.success('OTP sent to your phone successfully');
// //         return response;
// //       }
// //       throw new Error(response?.message || 'Failed to send SMS OTP');
// //     } catch (error) {
// //       const errorMessage = error.message || 'Failed to send SMS OTP';
// //       dispatch({ type: 'SET_ERROR', payload: errorMessage });
// //       toast.error(errorMessage);
// //       throw error;
// //     } finally {
// //       dispatch({ type: 'SET_LOADING', payload: false });
// //     }
// //   }, [api3001]);

// //   // ----------------------------------------------------
// //   // STEP 4: Verify phone OTP
// //   // ----------------------------------------------------
// //   const verifyPhoneOTP = useCallback(async (otp) => {
// //     try {
// //       dispatch({ type: 'SET_LOADING', payload: true });
// //       dispatch({ type: 'SET_ERROR', payload: null });

// //       if (!otp || otp.length !== 6) throw new Error('Invalid OTP format');

// //       const response = await api3001('/api/auth/verify-sms-otp', {
// //         body: {
// //           otp: SecurityUtils.sanitizeInput(otp),
// //           referrer: document.referrer,
// //           timestamp: Date.now()
// //         }
// //       });

// //       if (response?.success) {
// //         dispatch({ type: 'SET_PHONE_VERIFIED', payload: true });
// //         dispatch({ type: 'SET_STEP', payload: 5 });
// //         toast.success('Phone verified successfully');
// //         return response;
// //       }
// //       throw new Error(response?.message || 'Invalid SMS OTP');
// //     } catch (error) {
// //       const errorMessage = error.message || 'Invalid SMS OTP';
// //       dispatch({ type: 'SET_ERROR', payload: errorMessage });
// //       toast.error(errorMessage);
// //       throw error;
// //     } finally {
// //       dispatch({ type: 'SET_LOADING', payload: false });
// //     }
// //   }, [api3001]);

// //   // ----------------------------------------------------
// //   // STEP 5: Complete Authentication (Device/Biometric/WebAuthn)
// //   // ----------------------------------------------------
// //   const completeAuthentication = useCallback(async () => {
// //     try {
// //       dispatch({ type: 'SET_LOADING', payload: true });
// //       dispatch({ type: 'SET_ERROR', payload: null });

// //       if (!state.emailVerified || !state.phoneVerified) {
// //         throw new Error('Email and phone verification must be completed first');
// //       }

// //       const deviceFingerprint = await generateDeviceFingerprint();

// //       const deviceInfo = {
// //         type: /mobile/i.test(navigator.userAgent) ? 'mobile' :
// //               /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop',
// //         browser: { name: navigator.userAgent, version: navigator.appVersion },
// //         os: { name: navigator.platform, version: navigator.platform },
// //         screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1 },
// //         device: { type: /mobile/i.test(navigator.userAgent) ? 'mobile' : /tablet/i.test(navigator.userAgent) ? 'tablet' : 'desktop' }
// //       };

// //       const capabilities = { hasWebAuthn: !!window.PublicKeyCredential, platform: navigator.platform, userAgent: navigator.userAgent };
// //       const location = { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, language: navigator.language };

// //       const deviceResponse = await api3002('/api/biometric/device/register', {
// //         body: { sngine_email: state.email, sngine_phone: state.phone, deviceInfo, location, capabilities, referrer: document.referrer, timestamp: Date.now() }
// //       });

// //       if (!deviceResponse?.success || !deviceResponse?.device?.id) {
// //         throw new Error(deviceResponse?.message || 'Device registration failed');
// //       }

// //       const deviceId = deviceResponse.device.id;

// //       const biometricData = { deviceFingerprint, userAgent: navigator.userAgent, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, timestamp: Date.now(), capabilities };

// //       const biometricResponse = await api3002('/api/biometric/register', {
// //         body: { sngine_email: state.email, sngine_phone: state.phone, deviceId, biometricType: 'device_fingerprint', biometricData, referrer: document.referrer, timestamp: Date.now() }
// //       });

// //       if (!biometricResponse?.success) throw new Error(biometricResponse?.message || 'Biometric registration failed');

// //       let webauthnRegistered = false;

// //       if (window.PublicKeyCredential && capabilities.hasWebAuthn) {
// //         try {
// //           const begin = await api3002('/api/biometric/webauthn/register/begin', {
// //             body: { sngine_email: state.email, sngine_phone: state.phone, deviceId, referrer: document.referrer, timestamp: Date.now() }
// //           });

// //           if (begin?.success && begin?.options) {
// //             const publicKey = { ...begin.options, challenge: b64ToBytes(begin.options.challenge), user: { ...begin.options.user, id: b64ToBytes(begin.options.user.id) } };
// //             const credential = await navigator.credentials.create({ publicKey });

// //             if (credential) {
// //               const attestationObject = new Uint8Array(credential.response.attestationObject || []);
// //               const clientDataJSON = new Uint8Array(credential.response.clientDataJSON || []);

// //               const finish = await api3002('/api/biometric/webauthn/register/finish', {
// //                 body: { sngine_email: state.email, sngine_phone: state.phone, deviceId, credential: { id: credential.id, rawId: Array.from(new Uint8Array(credential.rawId)), response: { attestationObject: Array.from(attestationObject), clientDataJSON: Array.from(clientDataJSON) }, type: credential.type }, referrer: document.referrer, timestamp: Date.now() }
// //               });

// //               if (finish?.success) webauthnRegistered = true;
// //             }
// //           }
// //         } catch (webAuthNError) {
// //           console.warn('WebAuthn registration failed, continuing without it:', webAuthNError);
// //         }
// //       }

// //       dispatch({ type: 'SET_BIOMETRIC_VERIFIED', payload: true });
// //       dispatch({ type: 'SET_AUTHENTICATED', payload: true });

// //       const authData = { email: state.email, phone: state.phone, deviceId, authenticated: true, biometricVerified: true, webauthnRegistered, timestamp: Date.now() };
// //       const encryptedAuthData = encryptData(authData);
// //       sessionStorage.setItem('vottery_auth_data', encryptedAuthData);
// //       createSession(authData);
// //       toast.success('Authentication completed successfully!');

// //       return { success: true, message: 'Authentication completed successfully', deviceId, webauthnRegistered };

// //     } catch (error) {
// //       console.error('Complete authentication error:', error);
// //       const errorMessage = error?.message || 'Authentication failed';
// //       dispatch({ type: 'SET_ERROR', payload: errorMessage });
// //       toast.error(errorMessage);
// //       throw new Error(errorMessage);
// //     } finally {
// //       dispatch({ type: 'SET_LOADING', payload: false });
// //     }
// //   }, [state.email, state.phone, state.emailVerified, state.phoneVerified, generateDeviceFingerprint, encryptData, createSession, api3002]);

// //   // ----------------------------------------------------
// //   // Navigation helpers
// //   // ----------------------------------------------------
// //   const goBackStep = useCallback(() => {
// //     if (state.currentStep === 2) dispatch({ type: 'SET_STEP', payload: 1 });
// //     else if (state.currentStep === 4) dispatch({ type: 'SET_STEP', payload: 3 });
// //     else if (state.currentStep === 5) dispatch({ type: 'SET_STEP', payload: 4 });
// //   }, [state.currentStep]);

// //   const logout = useCallback(() => {
// //     clearSession();
// //     dispatch({ type: 'RESET_AUTH' });
// //   }, [clearSession]);

// //   const resetAuth = useCallback(() => dispatch({ type: 'RESET_AUTH' }), []);

// //   // ----------------------------------------------------
// //   // Context value
// //   // ----------------------------------------------------
// //   const value = {
// //     ...state,
// //     dispatch,
// //     sendEmailOTP,
// //     verifyEmailOTP,
// //     sendPhoneOTP,
// //     verifyPhoneOTP,
// //     completeAuthentication,
// //     goBackStep,
// //     logout,
// //     resetAuth
// //   };

// //   return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
// // };


