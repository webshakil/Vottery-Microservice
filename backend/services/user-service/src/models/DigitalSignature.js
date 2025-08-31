import { DataTypes, Model } from 'sequelize';

export default class DigitalSignature extends Model {
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
      data_hash: {
        type: DataTypes.STRING(64),
        allowNull: false,
        comment: 'SHA-256 hash of signed data'
      },
      signature_data: {
        type: DataTypes.TEXT,
        allowNull: false
      },
      algorithm: {
        type: DataTypes.STRING(20),
        defaultValue: 'RSA-SHA256'
      },
      key_fingerprint: {
        type: DataTypes.STRING(128),
        allowNull: false
      },
      document_type: {
        type: DataTypes.STRING(50)
      },
      document_id: {
        type: DataTypes.INTEGER
      },
      verified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      verification_timestamp: {
        type: DataTypes.DATE
      },
      created_at: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW
      }
    }, {
      sequelize,
      modelName: 'DigitalSignature',
      tableName: 'vottery_digital_signatures',
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

  // Verify signature
  async verify() {
    // Implementation would use cryptographic verification
    // This is a placeholder that would integrate with the security service
    this.verified = true;
    this.verification_timestamp = new Date();
    await this.save();
    return true;
  }

  // Get signatures by document
  static async getByDocument(documentType, documentId) {
    return await this.findAll({
      where: {
        document_type: documentType,
        document_id: documentId
      },
      include: ['user'],
      order: [['created_at', 'DESC']]
    });
  }
}
//common js
// const { DataTypes, Model } = require('sequelize');

// class DigitalSignature extends Model {
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
//       data_hash: {
//         type: DataTypes.STRING(64),
//         allowNull: false,
//         comment: 'SHA-256 hash of signed data'
//       },
//       signature_data: {
//         type: DataTypes.TEXT,
//         allowNull: false
//       },
//       algorithm: {
//         type: DataTypes.STRING(20),
//         defaultValue: 'RSA-SHA256'
//       },
//       key_fingerprint: {
//         type: DataTypes.STRING(128),
//         allowNull: false
//       },
//       document_type: {
//         type: DataTypes.STRING(50)
//       },
//       document_id: {
//         type: DataTypes.INTEGER
//       },
//       verified: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: false
//       },
//       verification_timestamp: {
//         type: DataTypes.DATE
//       },
//       created_at: {
//         type: DataTypes.DATE,
//         defaultValue: DataTypes.NOW
//       }
//     }, {
//       sequelize,
//       modelName: 'DigitalSignature',
//       tableName: 'vottery_digital_signatures',
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

//   // Verify signature
//   async verify() {
//     // Implementation would use cryptographic verification
//     // This is a placeholder that would integrate with the security service
//     this.verified = true;
//     this.verification_timestamp = new Date();
//     await this.save();
//     return true;
//   }

//   // Get signatures by document
//   static async getByDocument(documentType, documentId) {
//     return await this.findAll({
//       where: {
//         document_type: documentType,
//         document_id: documentId
//       },
//       include: ['user'],
//       order: [['created_at', 'DESC']]
//     });
//   }
// }

// module.exports = DigitalSignature;