import { DataTypes, Model } from 'sequelize';
import  encrypt from '../utils/encryption.js';
import decrypt  from '../utils/encryption.js';

export default class Organization extends Model {
  static init(sequelize) {
    return super.init({
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      name_encrypted: {
        type: DataTypes.TEXT,
        allowNull: false
      },
      type_encrypted: {
        type: DataTypes.TEXT
      },
      registration_number_encrypted: {
        type: DataTypes.TEXT
      },
      website: {
        type: DataTypes.STRING(255)
      },
      verification_status: {
        type: DataTypes.ENUM('pending', 'verified', 'rejected'),
        defaultValue: 'pending'
      },
      verification_documents: {
        type: DataTypes.JSON
      },
      settings: {
        type: DataTypes.JSON,
        defaultValue: {}
      },
      created_by: {
        type: DataTypes.INTEGER
      }
    }, {
      sequelize,
      modelName: 'Organization',
      tableName: 'vottery_organizations',
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at'
    });
  }

  static associate(models) {
    // Belongs to VotteryUser (creator)
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'created_by',
      as: 'creator'
    });

    // Many-to-Many with VotteryUsers through OrganizationMembers
    this.belongsToMany(models.VotteryUser, {
      through: models.OrganizationMember,
      foreignKey: 'organization_id',
      otherKey: 'user_id',
      as: 'members'
    });

    // One-to-Many with OrganizationMembers
    this.hasMany(models.OrganizationMember, {
      foreignKey: 'organization_id',
      as: 'organizationMembers'
    });
  }

  // Virtual fields for encrypted data
  get name() {
    return this.name_encrypted ? decrypt(this.name_encrypted) : null;
  }

  set name(value) {
    this.name_encrypted = value ? encrypt(value) : null;
  }

  get type() {
    return this.type_encrypted ? decrypt(this.type_encrypted) : null;
  }

  set type(value) {
    this.type_encrypted = value ? encrypt(value) : null;
  }

  get registration_number() {
    return this.registration_number_encrypted ? decrypt(this.registration_number_encrypted) : null;
  }

  set registration_number(value) {
    this.registration_number_encrypted = value ? encrypt(value) : null;
  }

  toJSON() {
    const values = { ...this.get() };
    
    // Add decrypted fields
    values.name = this.name;
    values.type = this.type;
    values.registration_number = this.registration_number;

    // Remove encrypted fields from output
    delete values.name_encrypted;
    delete values.type_encrypted;
    delete values.registration_number_encrypted;

    return values;
  }
}

// const { DataTypes, Model } = require('sequelize');
// const { encrypt, decrypt } = require('../utils/encryption');

// class Organization extends Model {
//   static init(sequelize) {
//     return super.init({
//       id: {
//         type: DataTypes.INTEGER,
//         primaryKey: true,
//         autoIncrement: true
//       },
//       name_encrypted: {
//         type: DataTypes.TEXT,
//         allowNull: false
//       },
//       type_encrypted: {
//         type: DataTypes.TEXT
//       },
//       registration_number_encrypted: {
//         type: DataTypes.TEXT
//       },
//       website: {
//         type: DataTypes.STRING(255)
//       },
//       verification_status: {
//         type: DataTypes.ENUM('pending', 'verified', 'rejected'),
//         defaultValue: 'pending'
//       },
//       verification_documents: {
//         type: DataTypes.JSON
//       },
//       settings: {
//         type: DataTypes.JSON,
//         defaultValue: {}
//       },
//       created_by: {
//         type: DataTypes.INTEGER
//       }
//     }, {
//       sequelize,
//       modelName: 'Organization',
//       tableName: 'vottery_organizations',
//       timestamps: true,
//       createdAt: 'created_at',
//       updatedAt: 'updated_at'
//     });
//   }

//   static associate(models) {
//     // Belongs to VotteryUser (creator)
//     this.belongsTo(models.VotteryUser, {
//       foreignKey: 'created_by',
//       as: 'creator'
//     });

//     // Many-to-Many with VotteryUsers through OrganizationMembers
//     this.belongsToMany(models.VotteryUser, {
//       through: models.OrganizationMember,
//       foreignKey: 'organization_id',
//       otherKey: 'user_id',
//       as: 'members'
//     });

//     // One-to-Many with OrganizationMembers
//     this.hasMany(models.OrganizationMember, {
//       foreignKey: 'organization_id',
//       as: 'organizationMembers'
//     });
//   }

//   // Virtual fields for encrypted data
//   get name() {
//     return this.name_encrypted ? decrypt(this.name_encrypted) : null;
//   }

//   set name(value) {
//     this.name_encrypted = value ? encrypt(value) : null;
//   }

//   get type() {
//     return this.type_encrypted ? decrypt(this.type_encrypted) : null;
//   }

//   set type(value) {
//     this.type_encrypted = value ? encrypt(value) : null;
//   }

//   get registration_number() {
//     return this.registration_number_encrypted ? decrypt(this.registration_number_encrypted) : null;
//   }

//   set registration_number(value) {
//     this.registration_number_encrypted = value ? encrypt(value) : null;
//   }

//   toJSON() {
//     const values = { ...this.get() };
    
//     // Add decrypted fields
//     values.name = this.name;
//     values.type = this.type;
//     values.registration_number = this.registration_number;

//     // Remove encrypted fields from output
//     delete values.name_encrypted;
//     delete values.type_encrypted;
//     delete values.registration_number_encrypted;

//     return values;
//   }
// }

// module.exports = Organization;