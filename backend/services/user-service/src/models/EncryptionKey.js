import { DataTypes, Model, Op } from 'sequelize';

export default class EncryptionKey extends Model {
  static init(sequelize) {
    return super.init({
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      user_id: {
        type: DataTypes.INTEGER
      },
      key_type: {
        type: DataTypes.ENUM('rsa_public', 'rsa_private', 'elgamal_public', 'elgamal_private', 'threshold', 'aes'),
        allowNull: false
      },
      key_data_encrypted: {
        type: DataTypes.TEXT,
        allowNull: false
      },
      key_fingerprint: {
        type: DataTypes.STRING(128),
        allowNull: false,
        unique: true
      },
      algorithm: {
        type: DataTypes.STRING(50),
        defaultValue: 'RSA-2048'
      },
      key_size: {
        type: DataTypes.INTEGER,
        defaultValue: 2048
      },
      purpose: {
        type: DataTypes.ENUM('voting', 'profile', 'communication', 'signature'),
        defaultValue: 'voting'
      },
      is_active: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
      },
      created_at: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW
      },
      expires_at: {
        type: DataTypes.DATE
      },
      revoked_at: {
        type: DataTypes.DATE
      }
    }, {
      sequelize,
      modelName: 'EncryptionKey',
      tableName: 'vottery_encryption_keys',
      timestamps: false
    });
  }

  static associate(models) {
    // Belongs to VotteryUser
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'user_id',
      as: 'user'
    });
  }

  // Check if key is currently valid
  isValid() {
    if (!this.is_active) return false;
    if (this.revoked_at) return false;
    if (this.expires_at && new Date() > this.expires_at) return false;
    return true;
  }

  // Revoke key
  async revoke() {
    this.is_active = false;
    this.revoked_at = new Date();
    await this.save();
  }

  // Get active keys by user and type
  static async getActiveKeys(userId, keyType = null, purpose = null) {
    const where = {
      user_id: userId,
      is_active: true,
      revoked_at: null
    };

    if (keyType) where.key_type = keyType;
    if (purpose) where.purpose = purpose;

    // Exclude expired keys
    const now = new Date();
    where[Op.or] = [
      { expires_at: null },
      { expires_at: { [Op.gt]: now } }
    ];

    return await this.findAll({
      where,
      order: [['created_at', 'DESC']]
    });
  }
}
//common js
// const { DataTypes, Model } = require('sequelize');

// class EncryptionKey extends Model {
//   static init(sequelize) {
//     return super.init({
//       id: {
//         type: DataTypes.INTEGER,
//         primaryKey: true,
//         autoIncrement: true
//       },
//       user_id: {
//         type: DataTypes.INTEGER
//       },
//       key_type: {
//         type: DataTypes.ENUM('rsa_public', 'rsa_private', 'elgamal_public', 'elgamal_private', 'threshold', 'aes'),
//         allowNull: false
//       },
//       key_data_encrypted: {
//         type: DataTypes.TEXT,
//         allowNull: false
//       },
//       key_fingerprint: {
//         type: DataTypes.STRING(128),
//         allowNull: false,
//         unique: true
//       },
//       algorithm: {
//         type: DataTypes.STRING(50),
//         defaultValue: 'RSA-2048'
//       },
//       key_size: {
//         type: DataTypes.INTEGER,
//         defaultValue: 2048
//       },
//       purpose: {
//         type: DataTypes.ENUM('voting', 'profile', 'communication', 'signature'),
//         defaultValue: 'voting'
//       },
//       is_active: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: true
//       },
//       created_at: {
//         type: DataTypes.DATE,
//         defaultValue: DataTypes.NOW
//       },
//       expires_at: {
//         type: DataTypes.DATE
//       },
//       revoked_at: {
//         type: DataTypes.DATE
//       }
//     }, {
//       sequelize,
//       modelName: 'EncryptionKey',
//       tableName: 'vottery_encryption_keys',
//       timestamps: false
//     });
//   }

//   static associate(models) {
//     // Belongs to VotteryUser
//     this.belongsTo(models.VotteryUser, {
//       foreignKey: 'user_id',
//       as: 'user'
//     });
//   }

//   // Check if key is currently valid
//   isValid() {
//     if (!this.is_active) return false;
//     if (this.revoked_at) return false;
//     if (this.expires_at && new Date() > this.expires_at) return false;
//     return true;
//   }

//   // Revoke key
//   async revoke() {
//     this.is_active = false;
//     this.revoked_at = new Date();
//     await this.save();
//   }

//   // Get active keys by user and type
//   static async getActiveKeys(userId, keyType = null, purpose = null) {
//     const where = {
//       user_id: userId,
//       is_active: true,
//       revoked_at: null
//     };

//     if (keyType) where.key_type = keyType;
//     if (purpose) where.purpose = purpose;

//     // Exclude expired keys
//     const now = new Date();
//     where[Op.or] = [
//       { expires_at: null },
//       { expires_at: { [Op.gt]: now } }
//     ];

//     return await this.findAll({
//       where,
//       order: [['created_at', 'DESC']]
//     });
//   }
// }

// module.exports = EncryptionKey;