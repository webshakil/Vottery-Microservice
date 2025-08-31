import { DataTypes, Model, Op } from 'sequelize';

class UserActivityLog extends Model {
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
      action: {
        type: DataTypes.STRING(100),
        allowNull: false
      },
      resource_type: {
        type: DataTypes.STRING(50)
      },
      resource_id: {
        type: DataTypes.INTEGER
      },
      details: {
        type: DataTypes.JSON
      },
      ip_address: {
        type: DataTypes.INET
      },
      user_agent: {
        type: DataTypes.TEXT
      },
      service_name: {
        type: DataTypes.STRING(50),
        defaultValue: 'user-service'
      },
      session_id: {
        type: DataTypes.STRING(128)
      },
      severity: {
        type: DataTypes.ENUM('low', 'medium', 'high', 'critical'),
        defaultValue: 'low'
      },
      created_at: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW
      }
    }, {
      sequelize,
      modelName: 'UserActivityLog',
      tableName: 'vottery_user_activity_logs',
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

  // Static method to log activity
  static async logActivity({
    userId,
    action,
    resourceType = null,
    resourceId = null,
    details = {},
    ipAddress = null,
    userAgent = null,
    sessionId = null,
    severity = 'low'
  }) {
    return await this.create({
      user_id: userId,
      action,
      resource_type: resourceType,
      resource_id: resourceId,
      details,
      ip_address: ipAddress,
      user_agent: userAgent,
      session_id: sessionId,
      severity
    });
  }

  // Get activities by user
  static async getByUser(userId, options = {}) {
    const {
      limit = 50,
      offset = 0,
      action = null,
      severity = null,
      dateFrom = null,
      dateTo = null
    } = options;

    const where = { user_id: userId };
    
    if (action) where.action = action;
    if (severity) where.severity = severity;
    if (dateFrom) where.created_at = { [Op.gte]: dateFrom };
    if (dateTo) {
      where.created_at = where.created_at || {};
      where.created_at[Op.lte] = dateTo;
    }

    return await this.findAndCountAll({
      where,
      limit,
      offset,
      order: [['created_at', 'DESC']]
    });
  }
}

export default UserActivityLog;


// const { DataTypes, Model } = require('sequelize');

// class UserActivityLog extends Model {
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
//       action: {
//         type: DataTypes.STRING(100),
//         allowNull: false
//       },
//       resource_type: {
//         type: DataTypes.STRING(50)
//       },
//       resource_id: {
//         type: DataTypes.INTEGER
//       },
//       details: {
//         type: DataTypes.JSON
//       },
//       ip_address: {
//         type: DataTypes.INET
//       },
//       user_agent: {
//         type: DataTypes.TEXT
//       },
//       service_name: {
//         type: DataTypes.STRING(50),
//         defaultValue: 'user-service'
//       },
//       session_id: {
//         type: DataTypes.STRING(128)
//       },
//       severity: {
//         type: DataTypes.ENUM('low', 'medium', 'high', 'critical'),
//         defaultValue: 'low'
//       },
//       created_at: {
//         type: DataTypes.DATE,
//         defaultValue: DataTypes.NOW
//       }
//     }, {
//       sequelize,
//       modelName: 'UserActivityLog',
//       tableName: 'vottery_user_activity_logs',
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

//   // Static method to log activity
//   static async logActivity({
//     userId,
//     action,
//     resourceType = null,
//     resourceId = null,
//     details = {},
//     ipAddress = null,
//     userAgent = null,
//     sessionId = null,
//     severity = 'low'
//   }) {
//     return await this.create({
//       user_id: userId,
//       action,
//       resource_type: resourceType,
//       resource_id: resourceId,
//       details,
//       ip_address: ipAddress,
//       user_agent: userAgent,
//       session_id: sessionId,
//       severity
//     });
//   }

//   // Get activities by user
//   static async getByUser(userId, options = {}) {
//     const {
//       limit = 50,
//       offset = 0,
//       action = null,
//       severity = null,
//       dateFrom = null,
//       dateTo = null
//     } = options;

//     const where = { user_id: userId };
    
//     if (action) where.action = action;
//     if (severity) where.severity = severity;
//     if (dateFrom) where.created_at = { [Op.gte]: dateFrom };
//     if (dateTo) {
//       where.created_at = where.created_at || {};
//       where.created_at[Op.lte] = dateTo;
//     }

//     return await this.findAndCountAll({
//       where,
//       limit,
//       offset,
//       order: [['created_at', 'DESC']]
//     });
//   }
// }

// module.exports = UserActivityLog;