import { DataTypes, Model } from 'sequelize';
import bcrypt from 'bcrypt';

export default class VotteryUser extends Model {
  static init(sequelize) {
    return super.init({
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      email: {
        type: DataTypes.STRING(255),
        allowNull: false,
        unique: true,
        validate: {
          isEmail: true
        }
      },
      email_verified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      phone: {
        type: DataTypes.STRING(20),
        validate: {
          isPhoneNumber(value) {
            if (value && !/^\+?[\d\s\-\(\)]{8,20}$/.test(value)) {
              throw new Error('Invalid phone number format');
            }
          }
        }
      },
      phone_verified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      password_hash: {
        type: DataTypes.TEXT
      },
      status: {
        type: DataTypes.ENUM('active', 'inactive', 'suspended', 'deleted'),
        defaultValue: 'active'
      },
      last_login_at: {
        type: DataTypes.DATE
      },
      login_attempts: {
        type: DataTypes.INTEGER,
        defaultValue: 0
      },
      locked_until: {
        type: DataTypes.DATE
      },
      two_factor_enabled: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      two_factor_secret: {
        type: DataTypes.TEXT
      },
      recovery_codes: {
        type: DataTypes.JSON,
        defaultValue: []
      }
    }, {
      sequelize,
      modelName: 'VotteryUser',
      tableName: 'vottery_users',
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at',
      hooks: {
        beforeCreate: async (user) => {
          if (user.password_hash) {
            user.password_hash = await bcrypt.hash(user.password_hash, 12);
          }
        },
        beforeUpdate: async (user) => {
          if (user.changed('password_hash') && user.password_hash) {
            user.password_hash = await bcrypt.hash(user.password_hash, 12);
          }
        }
      }
    });
  }

  static associate(models) {
    // One-to-One with UserProfile
    this.hasOne(models.UserProfile, {
      foreignKey: 'user_id',
      as: 'profile'
    });

    // Many-to-Many with Roles through UserRoles
    this.belongsToMany(models.Role, {
      through: models.UserRole,
      foreignKey: 'user_id',
      otherKey: 'role_id',
      as: 'roles'
    });

    // One-to-Many with UserRoles
    this.hasMany(models.UserRole, {
      foreignKey: 'user_id',
      as: 'userRoles'
    });

    // One-to-Many with Organizations (created)
    this.hasMany(models.Organization, {
      foreignKey: 'created_by',
      as: 'createdOrganizations'
    });

    // Many-to-Many with Organizations through OrganizationMembers
    this.belongsToMany(models.Organization, {
      through: models.OrganizationMember,
      foreignKey: 'user_id',
      otherKey: 'organization_id',
      as: 'organizations'
    });

    // One-to-Many with Subscriptions
    this.hasMany(models.Subscription, {
      foreignKey: 'user_id',
      as: 'subscriptions'
    });

    // One-to-Many with UserActivityLogs
    this.hasMany(models.UserActivityLog, {
      foreignKey: 'user_id',
      as: 'activityLogs'
    });

    // One-to-Many with EncryptionKeys
    this.hasMany(models.EncryptionKey, {
      foreignKey: 'user_id',
      as: 'encryptionKeys'
    });

    // One-to-Many with DigitalSignatures
    this.hasMany(models.DigitalSignature, {
      foreignKey: 'user_id',
      as: 'digitalSignatures'
    });

    // One-to-Many with SecurityEvents
    this.hasMany(models.SecurityEvent, {
      foreignKey: 'user_id',
      as: 'securityEvents'
    });
  }

  // Instance methods
  async validatePassword(password) {
    if (!this.password_hash) return false;
    return await bcrypt.compare(password, this.password_hash);
  }

  isLocked() {
    return this.locked_until && new Date() < this.locked_until;
  }

  async incrementLoginAttempts() {
    this.login_attempts += 1;
    if (this.login_attempts >= 5) {
      this.locked_until = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
    }
    await this.save();
  }

  async resetLoginAttempts() {
    this.login_attempts = 0;
    this.locked_until = null;
    this.last_login_at = new Date();
    await this.save();
  }

  toJSON() {
    const values = { ...this.get() };
    delete values.password_hash;
    delete values.two_factor_secret;
    delete values.recovery_codes;
    return values;
  }




  // Add this to your VotteryUser.js model's associate method:

static associate(models) {
  // Existing associations...
  
  // Add this line to establish the reverse relationship with UserProfile
  VotteryUser.hasOne(models.UserProfile, {
    foreignKey: 'user_id',
    as: 'profile',
    onDelete: 'CASCADE'
  });

  // Add associations with other models
  VotteryUser.belongsToMany(models.Role, {
    through: models.UserRole,
    foreignKey: 'user_id',
    otherKey: 'role_id',
    as: 'roles'
  });

  VotteryUser.hasMany(models.UserActivityLog, {
    foreignKey: 'user_id',
    as: 'activityLogs',
    onDelete: 'CASCADE'
  });

  VotteryUser.hasMany(models.OrganizationMember, {
    foreignKey: 'user_id',
    as: 'organizationMemberships',
    onDelete: 'CASCADE'
  });

  VotteryUser.hasOne(models.Subscription, {
    foreignKey: 'user_id',
    as: 'subscription',
    onDelete: 'CASCADE'
  });

  VotteryUser.hasMany(models.DigitalSignature, {
    foreignKey: 'user_id',
    as: 'digitalSignatures',
    onDelete: 'CASCADE'
  });

  VotteryUser.hasMany(models.SecurityEvent, {
    foreignKey: 'user_id',
    as: 'securityEvents',
    onDelete: 'CASCADE'
  });
}
}




// const { DataTypes, Model } = require('sequelize');
// const bcrypt = require('bcrypt');

// class VotteryUser extends Model {
//   static init(sequelize) {
//     return super.init({
//       id: {
//         type: DataTypes.INTEGER,
//         primaryKey: true,
//         autoIncrement: true
//       },
//       email: {
//         type: DataTypes.STRING(255),
//         allowNull: false,
//         unique: true,
//         validate: {
//           isEmail: true
//         }
//       },
//       email_verified: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: false
//       },
//       phone: {
//         type: DataTypes.STRING(20),
//         validate: {
//           isPhoneNumber(value) {
//             if (value && !/^\+?[\d\s\-\(\)]{8,20}$/.test(value)) {
//               throw new Error('Invalid phone number format');
//             }
//           }
//         }
//       },
//       phone_verified: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: false
//       },
//       password_hash: {
//         type: DataTypes.TEXT
//       },
//       status: {
//         type: DataTypes.ENUM('active', 'inactive', 'suspended', 'deleted'),
//         defaultValue: 'active'
//       },
//       last_login_at: {
//         type: DataTypes.DATE
//       },
//       login_attempts: {
//         type: DataTypes.INTEGER,
//         defaultValue: 0
//       },
//       locked_until: {
//         type: DataTypes.DATE
//       },
//       two_factor_enabled: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: false
//       },
//       two_factor_secret: {
//         type: DataTypes.TEXT
//       },
//       recovery_codes: {
//         type: DataTypes.JSON,
//         defaultValue: []
//       }
//     }, {
//       sequelize,
//       modelName: 'VotteryUser',
//       tableName: 'vottery_users',
//       timestamps: true,
//       createdAt: 'created_at',
//       updatedAt: 'updated_at',
//       hooks: {
//         beforeCreate: async (user) => {
//           if (user.password_hash) {
//             user.password_hash = await bcrypt.hash(user.password_hash, 12);
//           }
//         },
//         beforeUpdate: async (user) => {
//           if (user.changed('password_hash') && user.password_hash) {
//             user.password_hash = await bcrypt.hash(user.password_hash, 12);
//           }
//         }
//       }
//     });
//   }

//   static associate(models) {
//     // One-to-One with UserProfile
//     this.hasOne(models.UserProfile, {
//       foreignKey: 'user_id',
//       as: 'profile'
//     });

//     // Many-to-Many with Roles through UserRoles
//     this.belongsToMany(models.Role, {
//       through: models.UserRole,
//       foreignKey: 'user_id',
//       otherKey: 'role_id',
//       as: 'roles'
//     });

//     // One-to-Many with UserRoles
//     this.hasMany(models.UserRole, {
//       foreignKey: 'user_id',
//       as: 'userRoles'
//     });

//     // One-to-Many with Organizations (created)
//     this.hasMany(models.Organization, {
//       foreignKey: 'created_by',
//       as: 'createdOrganizations'
//     });

//     // Many-to-Many with Organizations through OrganizationMembers
//     this.belongsToMany(models.Organization, {
//       through: models.OrganizationMember,
//       foreignKey: 'user_id',
//       otherKey: 'organization_id',
//       as: 'organizations'
//     });

//     // One-to-Many with Subscriptions
//     this.hasMany(models.Subscription, {
//       foreignKey: 'user_id',
//       as: 'subscriptions'
//     });

//     // One-to-Many with UserActivityLogs
//     this.hasMany(models.UserActivityLog, {
//       foreignKey: 'user_id',
//       as: 'activityLogs'
//     });

//     // One-to-Many with EncryptionKeys
//     this.hasMany(models.EncryptionKey, {
//       foreignKey: 'user_id',
//       as: 'encryptionKeys'
//     });

//     // One-to-Many with DigitalSignatures
//     this.hasMany(models.DigitalSignature, {
//       foreignKey: 'user_id',
//       as: 'digitalSignatures'
//     });

//     // One-to-Many with SecurityEvents
//     this.hasMany(models.SecurityEvent, {
//       foreignKey: 'user_id',
//       as: 'securityEvents'
//     });
//   }

//   // Instance methods
//   async validatePassword(password) {
//     if (!this.password_hash) return false;
//     return await bcrypt.compare(password, this.password_hash);
//   }

//   isLocked() {
//     return this.locked_until && new Date() < this.locked_until;
//   }

//   async incrementLoginAttempts() {
//     this.login_attempts += 1;
//     if (this.login_attempts >= 5) {
//       this.locked_until = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
//     }
//     await this.save();
//   }

//   async resetLoginAttempts() {
//     this.login_attempts = 0;
//     this.locked_until = null;
//     this.last_login_at = new Date();
//     await this.save();
//   }

//   toJSON() {
//     const values = { ...this.get() };
//     delete values.password_hash;
//     delete values.two_factor_secret;
//     delete values.recovery_codes;
//     return values;
//   }
// }

// module.exports = VotteryUser;