// config/roles.js

export const PERMISSIONS = {
  // User Management Permissions
  USERS: {
    VIEW: 'users:view',
    EDIT: 'users:edit',
    DELETE: 'users:delete',
    SUSPEND: 'users:suspend',
    VERIFY: 'users:verify',
    AUDIT: 'users:audit'
  },

  // Election Management Permissions
  ELECTIONS: {
    CREATE: 'elections:create',
    VIEW: 'elections:view',
    EDIT: 'elections:edit',
    DELETE: 'elections:delete',
    MODERATE: 'elections:moderate',
    VERIFY: 'elections:verify',
    AUDIT: 'elections:audit'
  },

  // Analytics and Reporting Permissions
  ANALYTICS: {
    VIEW: 'analytics:view',
    EXPORT: 'analytics:export',
    ADVANCED: 'analytics:advanced',
    REAL_TIME: 'analytics:realtime'
  },

  // System Administration Permissions
  SYSTEM: {
    CONFIG: 'system:config',
    AUDIT: 'system:audit',
    SECURITY: 'system:security',
    BACKUP: 'system:backup',
    LOGS: 'system:logs'
  },

  // Financial Management Permissions
  FINANCE: {
    VIEW: 'finance:view',
    MANAGE: 'finance:manage',
    REFUND: 'finance:refund',
    AUDIT: 'finance:audit'
  },

  // Organization Management Permissions
  ORGANIZATION: {
    CREATE: 'organization:create',
    MANAGE: 'organization:manage',
    VERIFY: 'organization:verify',
    DELETE: 'organization:delete'
  },

  // Content Management Permissions
  CONTENT: {
    CREATE: 'content:create',
    EDIT: 'content:edit',
    DELETE: 'content:delete',
    MODERATE: 'content:moderate'
  }
};

// Role Definitions with Hierarchical Structure
export const ROLES = {
  // Admin Roles (Higher Level Access)
  ADMIN: {
    SUPER_ADMIN: {
      name: 'Super Admin',
      category: 'admin',
      level: 100,
      permissions: Object.values(PERMISSIONS).flatMap(group => Object.values(group)),
      description: 'Full system access with all permissions'
    },

    MANAGER: {
      name: 'Manager',
      category: 'admin',
      level: 90,
      permissions: [
        ...Object.values(PERMISSIONS.USERS),
        ...Object.values(PERMISSIONS.ELECTIONS),
        ...Object.values(PERMISSIONS.ANALYTICS),
        ...Object.values(PERMISSIONS.FINANCE),
        ...Object.values(PERMISSIONS.ORGANIZATION),
        PERMISSIONS.SYSTEM.AUDIT,
        PERMISSIONS.SYSTEM.LOGS
      ],
      description: 'Senior management with broad operational access'
    },

    ADMIN: {
      name: 'Admin',
      category: 'admin',
      level: 80,
      permissions: [
        PERMISSIONS.USERS.VIEW,
        PERMISSIONS.USERS.EDIT,
        PERMISSIONS.USERS.SUSPEND,
        ...Object.values(PERMISSIONS.ELECTIONS),
        PERMISSIONS.ANALYTICS.VIEW,
        PERMISSIONS.ANALYTICS.EXPORT,
        PERMISSIONS.FINANCE.VIEW,
        PERMISSIONS.ORGANIZATION.MANAGE,
        PERMISSIONS.SYSTEM.AUDIT
      ],
      description: 'General administrative access'
    },

    MODERATOR: {
      name: 'Moderator',
      category: 'admin',
      level: 70,
      permissions: [
        PERMISSIONS.USERS.VIEW,
        PERMISSIONS.USERS.SUSPEND,
        PERMISSIONS.ELECTIONS.VIEW,
        PERMISSIONS.ELECTIONS.MODERATE,
        PERMISSIONS.CONTENT.MODERATE,
        PERMISSIONS.ANALYTICS.VIEW
      ],
      description: 'Content moderation and user management'
    },

    AUDITOR: {
      name: 'Auditor',
      category: 'admin',
      level: 60,
      permissions: [
        PERMISSIONS.USERS.VIEW,
        PERMISSIONS.USERS.AUDIT,
        PERMISSIONS.ELECTIONS.VIEW,
        PERMISSIONS.ELECTIONS.AUDIT,
        PERMISSIONS.ELECTIONS.VERIFY,
        PERMISSIONS.ANALYTICS.VIEW,
        PERMISSIONS.ANALYTICS.EXPORT,
        PERMISSIONS.FINANCE.AUDIT,
        PERMISSIONS.SYSTEM.AUDIT,
        PERMISSIONS.SYSTEM.LOGS
      ],
      description: 'System auditing and compliance oversight'
    },

    EDITOR: {
      name: 'Editor',
      category: 'admin',
      level: 50,
      permissions: [
        PERMISSIONS.CONTENT.CREATE,
        PERMISSIONS.CONTENT.EDIT,
        PERMISSIONS.CONTENT.DELETE,
        PERMISSIONS.ELECTIONS.VIEW,
        PERMISSIONS.ANALYTICS.VIEW
      ],
      description: 'Content creation and editing'
    },

    ADVERTISER: {
      name: 'Advertiser',
      category: 'admin',
      level: 45,
      permissions: [
        PERMISSIONS.ANALYTICS.VIEW,
        PERMISSIONS.ANALYTICS.EXPORT,
        PERMISSIONS.CONTENT.CREATE,
        PERMISSIONS.ELECTIONS.VIEW
      ],
      description: 'Advertising and promotional content management'
    },

    ANALYST: {
      name: 'Analyst',
      category: 'admin',
      level: 40,
      permissions: [
        PERMISSIONS.ANALYTICS.VIEW,
        PERMISSIONS.ANALYTICS.EXPORT,
        PERMISSIONS.ANALYTICS.ADVANCED,
        PERMISSIONS.ANALYTICS.REAL_TIME,
        PERMISSIONS.ELECTIONS.VIEW,
        PERMISSIONS.USERS.VIEW
      ],
      description: 'Data analysis and reporting specialist'
    }
  },

  // User Roles (Standard Access)
  USER: {
    ORGANIZATION_CREATOR: {
      name: 'Organization Election Creator',
      category: 'user',
      level: 30,
      permissions: [
        PERMISSIONS.ELECTIONS.CREATE,
        PERMISSIONS.ELECTIONS.VIEW,
        PERMISSIONS.ELECTIONS.EDIT,
        PERMISSIONS.ELECTIONS.DELETE,
        PERMISSIONS.ORGANIZATION.CREATE,
        PERMISSIONS.ORGANIZATION.MANAGE,
        PERMISSIONS.ANALYTICS.VIEW,
        PERMISSIONS.FINANCE.VIEW
      ],
      description: 'Create and manage elections on behalf of organizations'
    },

    INDIVIDUAL_CREATOR: {
      name: 'Individual Election Creator',
      category: 'user',
      level: 20,
      permissions: [
        PERMISSIONS.ELECTIONS.CREATE,
        PERMISSIONS.ELECTIONS.VIEW,
        PERMISSIONS.ELECTIONS.EDIT,
        PERMISSIONS.ELECTIONS.DELETE,
        PERMISSIONS.ANALYTICS.VIEW,
        PERMISSIONS.FINANCE.VIEW
      ],
      description: 'Individual user who can create and manage elections'
    },

    PREMIUM_VOTER: {
      name: 'Premium Voter',
      category: 'user',
      level: 15,
      permissions: [
        PERMISSIONS.ELECTIONS.VIEW,
        PERMISSIONS.ANALYTICS.VIEW
      ],
      subscription: 'premium',
      description: 'Premium subscriber with unlimited voting access'
    },

    FREE_VOTER: {
      name: 'Free Voter',
      category: 'user',
      level: 10,
      permissions: [
        PERMISSIONS.ELECTIONS.VIEW
      ],
      subscription: 'free',
      limits: {
        votesPerDay: 10,
        electionsPerMonth: 5
      },
      description: 'Free user with limited voting access'
    },

    BASIC_USER: {
      name: 'Basic User',
      category: 'user',
      level: 5,
      permissions: [],
      description: 'Newly registered user with minimal access'
    }
  }
};

// Subscription Tiers
export const SUBSCRIPTION_TIERS = {
  FREE: {
    name: 'Free',
    level: 0,
    limits: {
      votesPerDay: 10,
      electionsPerMonth: 5,
      electionCreation: false,
      biometricAuth: false,
      advancedAnalytics: false
    }
  },
  
  PAY_AS_YOU_GO: {
    name: 'Pay as You Go',
    level: 1,
    limits: {
      votesPerDay: -1, // unlimited
      electionsPerMonth: -1, // unlimited
      electionCreation: true,
      biometricAuth: true,
      advancedAnalytics: false
    }
  },
  
  MONTHLY: {
    name: 'Monthly',
    level: 2,
    limits: {
      votesPerDay: -1,
      electionsPerMonth: -1,
      electionCreation: true,
      biometricAuth: true,
      advancedAnalytics: true
    }
  },
  
  QUARTERLY: {
    name: '3 Month',
    level: 3,
    limits: {
      votesPerDay: -1,
      electionsPerMonth: -1,
      electionCreation: true,
      biometricAuth: true,
      advancedAnalytics: true,
      prioritySupport: true
    }
  },
  
  SEMI_ANNUAL: {
    name: '6 Month',
    level: 4,
    limits: {
      votesPerDay: -1,
      electionsPerMonth: -1,
      electionCreation: true,
      biometricAuth: true,
      advancedAnalytics: true,
      prioritySupport: true,
      customBranding: true
    }
  },
  
  YEARLY: {
    name: 'Yearly',
    level: 5,
    limits: {
      votesPerDay: -1,
      electionsPerMonth: -1,
      electionCreation: true,
      biometricAuth: true,
      advancedAnalytics: true,
      prioritySupport: true,
      customBranding: true,
      apiAccess: true
    }
  }
};

// Role categories
export const ROLE_CATEGORIES = {
  ADMIN: 'admin',
  USER: 'user'
};

// Admin roles that cannot be modified
export const ADMIN_ROLES = [
  'Super Admin',
  'System Admin',
  'Root'
];

// Helper Functions
export const hasPermission = (userRoles, requiredPermission) => {
  return userRoles.some(role => 
    role.permissions && role.permissions.includes(requiredPermission)
  );
};

export const hasAnyPermission = (userRoles, requiredPermissions) => {
  return requiredPermissions.some(permission => 
    hasPermission(userRoles, permission)
  );
};

export const hasAllPermissions = (userRoles, requiredPermissions) => {
  return requiredPermissions.every(permission => 
    hasPermission(userRoles, permission)
  );
};

export const getRoleByName = (roleName, category) => {
  const roleCategory = category === 'admin' ? ROLES.ADMIN : ROLES.USER;
  return Object.values(roleCategory).find(role => role.name === roleName);
};

export const getRolesByLevel = (minLevel) => {
  const allRoles = [...Object.values(ROLES.ADMIN), ...Object.values(ROLES.USER)];
  return allRoles.filter(role => role.level >= minLevel);
};

export const canAccessResource = (userRoles, resourcePermissions) => {
  return resourcePermissions.some(permission => 
    hasPermission(userRoles, permission)
  );
};

// Get all permissions as flat array
export const getAllPermissions = () => {
  return Object.values(PERMISSIONS).flatMap(group => Object.values(group));
};

// Helper function to check if permission exists
export const isValidPermission = (permission) => {
  return getAllPermissions().includes(permission);
};

// Helper function to get permissions by category
export const getPermissionsByCategory = (category) => {
  return PERMISSIONS[category] || {};
};

const rolesConfig = {
  PERMISSIONS,
  ROLES,
  SUBSCRIPTION_TIERS,
  ROLE_CATEGORIES,
  ADMIN_ROLES,
  // Helper functions
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  getRoleByName,
  getRolesByLevel,
  canAccessResource,
  getAllPermissions,
  isValidPermission,
  getPermissionsByCategory
};

export default rolesConfig;
// const PERMISSIONS = {
//     // User Management Permissions
//     USERS: {
//       VIEW: 'users:view',
//       EDIT: 'users:edit',
//       DELETE: 'users:delete',
//       SUSPEND: 'users:suspend',
//       VERIFY: 'users:verify',
//       AUDIT: 'users:audit'
//     },
  
//     // Election Management Permissions
//     ELECTIONS: {
//       CREATE: 'elections:create',
//       VIEW: 'elections:view',
//       EDIT: 'elections:edit',
//       DELETE: 'elections:delete',
//       MODERATE: 'elections:moderate',
//       VERIFY: 'elections:verify',
//       AUDIT: 'elections:audit'
//     },
  
//     // Analytics and Reporting Permissions
//     ANALYTICS: {
//       VIEW: 'analytics:view',
//       EXPORT: 'analytics:export',
//       ADVANCED: 'analytics:advanced',
//       REAL_TIME: 'analytics:realtime'
//     },
  
//     // System Administration Permissions
//     SYSTEM: {
//       CONFIG: 'system:config',
//       AUDIT: 'system:audit',
//       SECURITY: 'system:security',
//       BACKUP: 'system:backup',
//       LOGS: 'system:logs'
//     },
  
//     // Financial Management Permissions
//     FINANCE: {
//       VIEW: 'finance:view',
//       MANAGE: 'finance:manage',
//       REFUND: 'finance:refund',
//       AUDIT: 'finance:audit'
//     },
  
//     // Organization Management Permissions
//     ORGANIZATION: {
//       CREATE: 'organization:create',
//       MANAGE: 'organization:manage',
//       VERIFY: 'organization:verify',
//       DELETE: 'organization:delete'
//     },
  
//     // Content Management Permissions
//     CONTENT: {
//       CREATE: 'content:create',
//       EDIT: 'content:edit',
//       DELETE: 'content:delete',
//       MODERATE: 'content:moderate'
//     }
//   };
  
//   // Role Definitions with Hierarchical Structure
//   const ROLES = {
//     // Admin Roles (Higher Level Access)
//     ADMIN: {
//       SUPER_ADMIN: {
//         name: 'Super Admin',
//         category: 'admin',
//         level: 100,
//         permissions: Object.values(PERMISSIONS).flatMap(group => Object.values(group)),
//         description: 'Full system access with all permissions'
//       },
  
//       MANAGER: {
//         name: 'Manager',
//         category: 'admin',
//         level: 90,
//         permissions: [
//           ...Object.values(PERMISSIONS.USERS),
//           ...Object.values(PERMISSIONS.ELECTIONS),
//           ...Object.values(PERMISSIONS.ANALYTICS),
//           ...Object.values(PERMISSIONS.FINANCE),
//           ...Object.values(PERMISSIONS.ORGANIZATION),
//           PERMISSIONS.SYSTEM.AUDIT,
//           PERMISSIONS.SYSTEM.LOGS
//         ],
//         description: 'Senior management with broad operational access'
//       },
  
//       ADMIN: {
//         name: 'Admin',
//         category: 'admin',
//         level: 80,
//         permissions: [
//           PERMISSIONS.USERS.VIEW,
//           PERMISSIONS.USERS.EDIT,
//           PERMISSIONS.USERS.SUSPEND,
//           ...Object.values(PERMISSIONS.ELECTIONS),
//           PERMISSIONS.ANALYTICS.VIEW,
//           PERMISSIONS.ANALYTICS.EXPORT,
//           PERMISSIONS.FINANCE.VIEW,
//           PERMISSIONS.ORGANIZATION.MANAGE,
//           PERMISSIONS.SYSTEM.AUDIT
//         ],
//         description: 'General administrative access'
//       },
  
//       MODERATOR: {
//         name: 'Moderator',
//         category: 'admin',
//         level: 70,
//         permissions: [
//           PERMISSIONS.USERS.VIEW,
//           PERMISSIONS.USERS.SUSPEND,
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ELECTIONS.MODERATE,
//           PERMISSIONS.CONTENT.MODERATE,
//           PERMISSIONS.ANALYTICS.VIEW
//         ],
//         description: 'Content moderation and user management'
//       },
  
//       AUDITOR: {
//         name: 'Auditor',
//         category: 'admin',
//         level: 60,
//         permissions: [
//           PERMISSIONS.USERS.VIEW,
//           PERMISSIONS.USERS.AUDIT,
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ELECTIONS.AUDIT,
//           PERMISSIONS.ELECTIONS.VERIFY,
//           PERMISSIONS.ANALYTICS.VIEW,
//           PERMISSIONS.ANALYTICS.EXPORT,
//           PERMISSIONS.FINANCE.AUDIT,
//           PERMISSIONS.SYSTEM.AUDIT,
//           PERMISSIONS.SYSTEM.LOGS
//         ],
//         description: 'System auditing and compliance oversight'
//       },
  
//       EDITOR: {
//         name: 'Editor',
//         category: 'admin',
//         level: 50,
//         permissions: [
//           PERMISSIONS.CONTENT.CREATE,
//           PERMISSIONS.CONTENT.EDIT,
//           PERMISSIONS.CONTENT.DELETE,
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ANALYTICS.VIEW
//         ],
//         description: 'Content creation and editing'
//       },
  
//       ADVERTISER: {
//         name: 'Advertiser',
//         category: 'admin',
//         level: 45,
//         permissions: [
//           PERMISSIONS.ANALYTICS.VIEW,
//           PERMISSIONS.ANALYTICS.EXPORT,
//           PERMISSIONS.CONTENT.CREATE,
//           PERMISSIONS.ELECTIONS.VIEW
//         ],
//         description: 'Advertising and promotional content management'
//       },
  
//       ANALYST: {
//         name: 'Analyst',
//         category: 'admin',
//         level: 40,
//         permissions: [
//           PERMISSIONS.ANALYTICS.VIEW,
//           PERMISSIONS.ANALYTICS.EXPORT,
//           PERMISSIONS.ANALYTICS.ADVANCED,
//           PERMISSIONS.ANALYTICS.REAL_TIME,
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.USERS.VIEW
//         ],
//         description: 'Data analysis and reporting specialist'
//       }
//     },
  
//     // User Roles (Standard Access)
//     USER: {
//       ORGANIZATION_CREATOR: {
//         name: 'Organization Election Creator',
//         category: 'user',
//         level: 30,
//         permissions: [
//           PERMISSIONS.ELECTIONS.CREATE,
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ELECTIONS.EDIT,
//           PERMISSIONS.ELECTIONS.DELETE,
//           PERMISSIONS.ORGANIZATION.CREATE,
//           PERMISSIONS.ORGANIZATION.MANAGE,
//           PERMISSIONS.ANALYTICS.VIEW,
//           PERMISSIONS.FINANCE.VIEW
//         ],
//         description: 'Create and manage elections on behalf of organizations'
//       },
  
//       INDIVIDUAL_CREATOR: {
//         name: 'Individual Election Creator',
//         category: 'user',
//         level: 20,
//         permissions: [
//           PERMISSIONS.ELECTIONS.CREATE,
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ELECTIONS.EDIT,
//           PERMISSIONS.ELECTIONS.DELETE,
//           PERMISSIONS.ANALYTICS.VIEW,
//           PERMISSIONS.FINANCE.VIEW
//         ],
//         description: 'Individual user who can create and manage elections'
//       },
  
//       PREMIUM_VOTER: {
//         name: 'Premium Voter',
//         category: 'user',
//         level: 15,
//         permissions: [
//           PERMISSIONS.ELECTIONS.VIEW,
//           PERMISSIONS.ANALYTICS.VIEW
//         ],
//         subscription: 'premium',
//         description: 'Premium subscriber with unlimited voting access'
//       },
  
//       FREE_VOTER: {
//         name: 'Free Voter',
//         category: 'user',
//         level: 10,
//         permissions: [
//           PERMISSIONS.ELECTIONS.VIEW
//         ],
//         subscription: 'free',
//         limits: {
//           votesPerDay: 10,
//           electionsPerMonth: 5
//         },
//         description: 'Free user with limited voting access'
//       },
  
//       BASIC_USER: {
//         name: 'Basic User',
//         category: 'user',
//         level: 5,
//         permissions: [],
//         description: 'Newly registered user with minimal access'
//       }
//     }
//   };
  
//   // Subscription Tiers
//   const SUBSCRIPTION_TIERS = {
//     FREE: {
//       name: 'Free',
//       level: 0,
//       limits: {
//         votesPerDay: 10,
//         electionsPerMonth: 5,
//         electionCreation: false,
//         biometricAuth: false,
//         advancedAnalytics: false
//       }
//     },
    
//     PAY_AS_YOU_GO: {
//       name: 'Pay as You Go',
//       level: 1,
//       limits: {
//         votesPerDay: -1, // unlimited
//         electionsPerMonth: -1, // unlimited
//         electionCreation: true,
//         biometricAuth: true,
//         advancedAnalytics: false
//       }
//     },
    
//     MONTHLY: {
//       name: 'Monthly',
//       level: 2,
//       limits: {
//         votesPerDay: -1,
//         electionsPerMonth: -1,
//         electionCreation: true,
//         biometricAuth: true,
//         advancedAnalytics: true
//       }
//     },
    
//     QUARTERLY: {
//       name: '3 Month',
//       level: 3,
//       limits: {
//         votesPerDay: -1,
//         electionsPerMonth: -1,
//         electionCreation: true,
//         biometricAuth: true,
//         advancedAnalytics: true,
//         prioritySupport: true
//       }
//     },
    
//     SEMI_ANNUAL: {
//       name: '6 Month',
//       level: 4,
//       limits: {
//         votesPerDay: -1,
//         electionsPerMonth: -1,
//         electionCreation: true,
//         biometricAuth: true,
//         advancedAnalytics: true,
//         prioritySupport: true,
//         customBranding: true
//       }
//     },
    
//     YEARLY: {
//       name: 'Yearly',
//       level: 5,
//       limits: {
//         votesPerDay: -1,
//         electionsPerMonth: -1,
//         electionCreation: true,
//         biometricAuth: true,
//         advancedAnalytics: true,
//         prioritySupport: true,
//         customBranding: true,
//         apiAccess: true
//       }
//     }
//   };
  
//   // Helper Functions
//   export const hasPermission = (userRoles, requiredPermission) => {
//     return userRoles.some(role => 
//       role.permissions && role.permissions.includes(requiredPermission)
//     );
//   };
  
//   export const hasAnyPermission = (userRoles, requiredPermissions) => {
//     return requiredPermissions.some(permission => 
//       hasPermission(userRoles, permission)
//     );
//   };
  
//   export const hasAllPermissions = (userRoles, requiredPermissions) => {
//     return requiredPermissions.every(permission => 
//       hasPermission(userRoles, permission)
//     );
//   };
  
//   export const getRoleByName = (roleName, category) => {
//     const roleCategory = category === 'admin' ? ROLES.ADMIN : ROLES.USER;
//     return Object.values(roleCategory).find(role => role.name === roleName);
//   };
  
//   export const getRolesByLevel = (minLevel) => {
//     const allRoles = [...Object.values(ROLES.ADMIN), ...Object.values(ROLES.USER)];
//     return allRoles.filter(role => role.level >= minLevel);
//   };
  
//   export const canAccessResource = (userRoles, resourcePermissions) => {
//     return resourcePermissions.some(permission => 
//       hasPermission(userRoles, permission)
//     );
//   };
  
//   const rolesConfig = {
//     PERMISSIONS,
//     ROLES,
//     SUBSCRIPTION_TIERS,
//     // Helper functions
//     hasPermission,
//     hasAnyPermission,
//     hasAllPermissions,
//     getRoleByName,
//     getRolesByLevel,
//     canAccessResource
//   };
  
//   export default rolesConfig;
  