import { DataTypes, Model } from 'sequelize';

export default class SecurityEvent extends Model {
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
      event_type: {
        type: DataTypes.ENUM('login_attempt', 'password_change', 'email_change', 'suspicious_activity', 'account_locked', 'key_generated', 'key_revoked'),
        allowNull: false
      },
      severity: {
        type: DataTypes.ENUM('info', 'warning', 'error', 'critical'),
        defaultValue: 'info'
      },
      description: {
        type: DataTypes.TEXT
      },
      metadata: {
        type: DataTypes.JSON
      },
      ip_address: {
        type: DataTypes.INET
      },
      user_agent: {
        type: DataTypes.TEXT
      },
      resolved: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      resolved_by: {
        type: DataTypes.INTEGER
      },
      resolved_at: {
        type: DataTypes.DATE
      },
      created_at: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW
      }
    }, {
      sequelize,
      modelName: 'SecurityEvent',
      tableName: 'vottery_security_events',
      timestamps: false
    });
  }

  static associate(models) {
    // Belongs to VotteryUser
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'user_id',
      as: 'user'
    });

    // Belongs to VotteryUser (resolved by)
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'resolved_by',
      as: 'resolvedBy'
    });
  }

  // Static method to log security event
  static async logEvent({
    userId = null,
    eventType,
    severity = 'info',
    description = '',
    metadata = {},
    ipAddress = null,
    userAgent = null
  }) {
    return await this.create({
      user_id: userId,
      event_type: eventType,
      severity,
      description,
      metadata,
      ip_address: ipAddress,
      user_agent: userAgent
    });
  }

  // Resolve security event
  async resolve(resolvedByUserId) {
    this.resolved = true;
    this.resolved_by = resolvedByUserId;
    this.resolved_at = new Date();
    await this.save();
  }

  // Get unresolved events
  static async getUnresolved(severity = null) {
    const where = { resolved: false };
    if (severity) where.severity = severity;

    return await this.findAll({
      where,
      include: ['user'],
      order: [['created_at', 'DESC']]
    });
  }
}

// const { DataTypes, Model } = require('sequelize');

// class SecurityEvent extends Model {
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
//       event_type: {
//         type: DataTypes.ENUM('login_attempt', 'password_change', 'email_change', 'suspicious_activity', 'account_locked', 'key_generated', 'key_revoked'),
//         allowNull: false
//       },
//       severity: {
//         type: DataTypes.ENUM('info', 'warning', 'error', 'critical'),
//         defaultValue: 'info'
//       },
//       description: {
//         type: DataTypes.TEXT
//       },
//       metadata: {
//         type: DataTypes.JSON
//       },
//       ip_address: {
//         type: DataTypes.INET
//       },
//       user_agent: {
//         type: DataTypes.TEXT
//       },
//       resolved: {
//         type: DataTypes.BOOLEAN,
//         defaultValue: false
//       },
//       resolved_by: {
//         type: DataTypes.INTEGER
//       },
//       resolved_at: {
//         type: DataTypes.DATE
//       },
//       created_at: {
//         type: DataTypes.DATE,
//         defaultValue: DataTypes.NOW
//       }
//     }, {
//       sequelize,
//       modelName: 'SecurityEvent',
//       tableName: 'vottery_security_events',
//       timestamps: false
//     });
//   }

//   static associate(models) {
//     // Belongs to VotteryUser
//     this.belongsTo(models.VotteryUser, {
//       foreignKey: 'user_id',
//       as: 'user'
//     });

//     // Belongs to VotteryUser (resolved by)
//     this.belongsTo(models.VotteryUser, {
//       foreignKey: 'resolved_by',
//       as: 'resolvedBy'
//     });
//   }

//   // Static method to log security event
//   static async logEvent({
//     userId = null,
//     eventType,
//     severity = 'info',
//     description = '',
//     metadata = {},
//     ipAddress = null,
//     userAgent = null
//   }) {
//     return await this.create({
//       user_id: userId,
//       event_type: eventType,
//       severity,
//       description,
//       metadata,
//       ip_address: ipAddress,
//       user_agent: userAgent
//     });
//   }

//   // Resolve security event
//   async resolve(resolvedByUserId) {
//     this.resolved = true;
//     this.resolved_by = resolvedByUserId;
//     this.resolved_at = new Date();
//     await this.save();
//   }

//   // Get unresolved events
//   static async getUnresolved(severity = null) {
//     const where = { resolved: false };
//     if (severity) where.severity = severity;

//     return await this.findAll({
//       where,
//       include: ['user'],
//       order: [['created_at', 'DESC']]
//     });
//   }
// }

// module.exports = SecurityEvent;