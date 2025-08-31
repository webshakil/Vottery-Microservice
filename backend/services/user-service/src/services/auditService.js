// // services/auditService.js
import { Op, Sequelize } from 'sequelize';
import UserActivityLog from '../models/UserActivityLog.js';
import SecurityEvent from '../models/SecurityEvent.js';
import { AppError } from '../utils/response.js';
import { AUDIT_ACTIONS, SECURITY_EVENT_TYPES } from '../utils/constants.js';

class AuditService {
  /**
   * Log user activity
   * @param {number} userId 
   * @param {string} action 
   * @param {string} resourceType 
   * @param {number} resourceId 
   * @param {object} details 
   * @param {string} ipAddress 
   * @param {string} userAgent 
   * @returns {Promise<object|null>}
   */
  async logActivity(userId, action, resourceType = null, resourceId = null, details = {}, ipAddress = null, userAgent = null) {
    try {
      const activityLog = await UserActivityLog.create({
        user_id: userId,
        action,
        resource_type: resourceType,
        resource_id: resourceId,
        details: JSON.stringify(details),
        ip_address: ipAddress,
        user_agent: userAgent,
        service_name: 'user-service'
      });

      return activityLog;
    } catch (error) {
      // Don't throw errors for audit logging to avoid breaking main functionality
      console.error('Audit logging failed:', error);
      return null;
    }
  }

  /**
   * Safe JSON parsing helper
   * @param {string} jsonString 
   * @returns {object}
   */
  safeParseJSON(jsonString) {
    try {
      return typeof jsonString === 'string' ? JSON.parse(jsonString) : jsonString;
    } catch (error) {
      return {};
    }
  }

  /**
   * Log security event
   * @param {number} userId 
   * @param {string} eventType 
   * @param {string} severity 
   * @param {string} description 
   * @param {object} metadata 
   * @param {string} ipAddress 
   * @returns {Promise<object|null>}
   */
  async logSecurityEvent(userId, eventType, severity = 'medium', description = '', metadata = {}, ipAddress = null) {
    try {
      const securityEvent = await SecurityEvent.create({
        user_id: userId,
        event_type: eventType,
        severity,
        description,
        metadata: JSON.stringify(metadata),
        ip_address: ipAddress,
        service_name: 'user-service'
      });

      if (severity === 'high' || severity === 'critical') {
        await this.handleHighSeverityEvent(securityEvent);
      }

      return securityEvent;
    } catch (error) {
      console.error('Security event logging failed:', error);
      return null;
    }
  }

  /**
   * Handle high severity security events
   * @param {object} securityEvent 
   * @returns {Promise<void>}
   */
  async handleHighSeverityEvent(securityEvent) {
    try {
      console.warn('High severity security event:', {
        id: securityEvent.id,
        type: securityEvent.event_type,
        severity: securityEvent.severity,
        userId: securityEvent.user_id,
        description: securityEvent.description
      });

      // Additional alerting logic can be added here
    } catch (error) {
      console.error('High severity event handling failed:', error);
    }
  }

  /**
   * Clean up old audit logs
   * @param {number} daysToKeep 
   * @returns {Promise<object>}
   */
  async cleanupOldLogs(daysToKeep = 90) {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

      const [deletedActivities, deletedSecurityEvents] = await Promise.all([
        UserActivityLog.destroy({
          where: {
            created_at: { [Op.lt]: cutoffDate }
          }
        }),
        SecurityEvent.destroy({
          where: {
            created_at: { [Op.lt]: cutoffDate },
            severity: { [Op.notIn]: ['high', 'critical'] } // Keep high/critical events longer
          }
        })
      ]);

      return {
        deletedActivities,
        deletedSecurityEvents,
        cutoffDate,
        daysKept: daysToKeep
      };
    } catch (error) {
      throw new AppError(`Audit log cleanup failed: ${error.message}`, 500);
    }
  }
}

export default new AuditService();



//this is by clude uncomplete, above is by chatgpt complete
// services/auditService.js
// import UserActivityLog from '../models/UserActivityLog.js';
// import SecurityEvent from '../models/SecurityEvent.js';
// import { AppError } from '../utils/response.js';
// import { AUDIT_ACTIONS, SECURITY_EVENT_TYPES } from '../utils/constants.js';

// class AuditService {
//   /**
//    * Log user activity
//    * @param {number} userId 
//    * @param {string} action 
//    * @param {string} resourceType 
//    * @param {number} resourceId 
//    * @param {object} details 
//    * @param {string} ipAddress 
//    * @param {string} userAgent 
//    * @returns {Promise<object>}
//    */
//   async logActivity(userId, action, resourceType = null, resourceId = null, details = {}, ipAddress = null, userAgent = null) {
//     try {
//       const activityLog = await UserActivityLog.create({
//         user_id: userId,
//         action,
//         resource_type: resourceType,
//         resource_id: resourceId,
//         details: JSON.stringify(details),
//         ip_address: ipAddress,
//         user_agent: userAgent,
//         service_name: 'user-service'
//       });

//       return {
//         deletedActivities,
//         deletedSecurityEvents,
//         cutoffDate,
//         daysKept: daysToKeep
//       };
//     } catch (error) {
//       throw new AppError(`Audit log cleanup failed: ${error.message}`, 500);
//     }
//   }

//   /**
//    * Safe JSON parsing helper
//    * @param {string} jsonString 
//    * @returns {object}
//    */
//   safeParseJSON(jsonString) {
//     try {
//       return typeof jsonString === 'string' ? JSON.parse(jsonString) : jsonString;
//     } catch (error) {
//       return {};
//     }
//   }

//   /**
//    * Export audit data for compliance
//    * @param {object} criteria 
//    * @returns {Promise<object>}
//    */
//   async exportAuditData(criteria = {}) {
//     try {
//       const whereClause = {};
      
//       if (criteria.userId) {
//         whereClause.user_id = criteria.userId;
//       }
      
//       if (criteria.dateFrom && criteria.dateTo) {
//         whereClause.created_at = {
//           [Op.between]: [new Date(criteria.dateFrom), new Date(criteria.dateTo)]
//         };
//       }

//       const [activities, securityEvents] = await Promise.all([
//         UserActivityLog.findAll({
//           where: whereClause,
//           order: [['created_at', 'DESC']]
//         }),
//         SecurityEvent.findAll({
//           where: whereClause,
//           order: [['created_at', 'DESC']]
//         })
//       ]);

//       return {
//         exportedAt: new Date(),
//         criteria,
//         data: {
//           activities: activities.map(activity => ({
//             id: activity.id,
//             userId: activity.user_id,
//             action: activity.action,
//             resourceType: activity.resource_type,
//             resourceId: activity.resource_id,
//             details: this.safeParseJSON(activity.details),
//             ipAddress: activity.ip_address,
//             userAgent: activity.user_agent,
//             serviceName: activity.service_name,
//             createdAt: activity.created_at
//           })),
//           securityEvents: securityEvents.map(event => ({
//             id: event.id,
//             userId: event.user_id,
//             eventType: event.event_type,
//             severity: event.severity,
//             description: event.description,
//             metadata: this.safeParseJSON(event.metadata),
//             ipAddress: event.ip_address,
//             serviceName: event.service_name,
//             createdAt: event.created_at
//           }))
//         },
//         summary: {
//           totalActivities: activities.length,
//           totalSecurityEvents: securityEvents.length
//         }
//       };
//     } catch (error) {
//       throw new AppError(`Audit data export failed: ${error.message}`, 500);
//     }
//   }
// }

// export default new AuditService(); activityLog;
//     } catch (error) {
//       // Don't throw errors for audit logging to avoid breaking main functionality
//       console.error('Audit logging failed:', error);
//       return null;
//     }
//   }

//   /**
//    * Log security event
//    * @param {number} userId 
//    * @param {string} eventType 
//    * @param {string} severity 
//    * @param {string} description 
//    * @param {object} metadata 
//    * @param {string} ipAddress 
//    * @returns {Promise<object>}
//    */
//   async logSecurityEvent(userId, eventType, severity = 'medium', description = '', metadata = {}, ipAddress = null) {
//     try {
//       const securityEvent = await SecurityEvent.create({
//         user_id: userId,
//         event_type: eventType,
//         severity,
//         description,
//         metadata: JSON.stringify(metadata),
//         ip_address: ipAddress,
//         service_name: 'user-service'
//       });

//       // If it's a high severity event, we might want to trigger alerts
//       if (severity === 'high' || severity === 'critical') {
//         await this.handleHighSeverityEvent(securityEvent);
//       }

//       return securityEvent;
//     } catch (error) {
//       console.error('Security event logging failed:', error);
//       return null;
//     }
//   }

//   /**
//    * Get user activity history
//    * @param {number} userId 
//    * @param {object} filters 
//    * @param {number} page 
//    * @param {number} limit 
//    * @returns {Promise<object>}
//    */
//   async getUserActivityHistory(userId, filters = {}, page = 1, limit = 50) {
//     try {
//       const offset = (page - 1) * limit;
//       const whereClause = { user_id: userId };

//       // Apply filters
//       if (filters.action) {
//         whereClause.action = filters.action;
//       }

//       if (filters.resourceType) {
//         whereClause.resource_type = filters.resourceType;
//       }

//       if (filters.dateFrom) {
//         whereClause.created_at = { [Op.gte]: new Date(filters.dateFrom) };
//       }

//       if (filters.dateTo) {
//         whereClause.created_at = {
//           ...whereClause.created_at,
//           [Op.lte]: new Date(filters.dateTo)
//         };
//       }

//       if (filters.ipAddress) {
//         whereClause.ip_address = filters.ipAddress;
//       }

//       const { count, rows } = await UserActivityLog.findAndCountAll({
//         where: whereClause,
//         limit,
//         offset,
//         order: [['created_at', 'DESC']]
//       });

//       return {
//         activities: rows.map(activity => ({
//           id: activity.id,
//           action: activity.action,
//           resourceType: activity.resource_type,
//           resourceId: activity.resource_id,
//           details: this.safeParseJSON(activity.details),
//           ipAddress: activity.ip_address,
//           userAgent: activity.user_agent,
//           serviceName: activity.service_name,
//           createdAt: activity.created_at
//         })),
//         pagination: {
//           currentPage: page,
//           totalPages: Math.ceil(count / limit),
//           totalCount: count,
//           limit
//         }
//       };
//     } catch (error) {
//       throw new AppError(error.message, 500);
//     }
//   }

//   /**
//    * Get security events for user
//    * @param {number} userId 
//    * @param {object} filters 
//    * @param {number} page 
//    * @param {number} limit 
//    * @returns {Promise<object>}
//    */
//   async getUserSecurityEvents(userId, filters = {}, page = 1, limit = 20) {
//     try {
//       const offset = (page - 1) * limit;
//       const whereClause = { user_id: userId };

//       // Apply filters
//       if (filters.eventType) {
//         whereClause.event_type = filters.eventType;
//       }

//       if (filters.severity) {
//         whereClause.severity = filters.severity;
//       }

//       if (filters.dateFrom) {
//         whereClause.created_at = { [Op.gte]: new Date(filters.dateFrom) };
//       }

//       if (filters.dateTo) {
//         whereClause.created_at = {
//           ...whereClause.created_at,
//           [Op.lte]: new Date(filters.dateTo)
//         };
//       }

//       const { count, rows } = await SecurityEvent.findAndCountAll({
//         where: whereClause,
//         limit,
//         offset,
//         order: [['created_at', 'DESC']]
//       });

//       return {
//         events: rows.map(event => ({
//           id: event.id,
//           eventType: event.event_type,
//           severity: event.severity,
//           description: event.description,
//           metadata: this.safeParseJSON(event.metadata),
//           ipAddress: event.ip_address,
//           serviceName: event.service_name,
//           createdAt: event.created_at
//         })),
//         pagination: {
//           currentPage: page,
//           totalPages: Math.ceil(count / limit),
//           totalCount: count,
//           limit
//         }
//       };
//     } catch (error) {
//       throw new AppError(error.message, 500);
//     }
//   }

//   /**
//    * Get system-wide activity statistics
//    * @param {object} filters 
//    * @returns {Promise<object>}
//    */
//   async getActivityStatistics(filters = {}) {
//     try {
//       const whereClause = {};

//       // Apply date filters
//       if (filters.dateFrom && filters.dateTo) {
//         whereClause.created_at = {
//           [Op.between]: [new Date(filters.dateFrom), new Date(filters.dateTo)]
//         };
//       } else if (filters.dateFrom) {
//         whereClause.created_at = { [Op.gte]: new Date(filters.dateFrom) };
//       } else if (filters.dateTo) {
//         whereClause.created_at = { [Op.lte]: new Date(filters.dateTo) };
//       }

//       const [
//         totalActivities,
//         activitiesByAction,
//         activitiesByResource,
//         activitiesByHour,
//         uniqueUsers,
//         topIPs
//       ] = await Promise.all([
//         // Total activities
//         UserActivityLog.count({ where: whereClause }),

//         // Activities by action
//         UserActivityLog.findAll({
//           attributes: [
//             'action',
//             [Sequelize.fn('COUNT', Sequelize.col('id')), 'count']
//           ],
//           where: whereClause,
//           group: ['action'],
//           order: [[Sequelize.fn('COUNT', Sequelize.col('id')), 'DESC']]
//         }),

//         // Activities by resource type
//         UserActivityLog.findAll({
//           attributes: [
//             'resource_type',
//             [Sequelize.fn('COUNT', Sequelize.col('id')), 'count']
//           ],
//           where: whereClause,
//           group: ['resource_type'],
//           order: [[Sequelize.fn('COUNT', Sequelize.col('id')), 'DESC']]
//         }),

//         // Activities by hour of day
//         UserActivityLog.findAll({
//           attributes: [
//             [Sequelize.fn('EXTRACT', Sequelize.literal('HOUR FROM created_at')), 'hour'],
//             [Sequelize.fn('COUNT', Sequelize.col('id')), 'count']
//           ],
//           where: whereClause,
//           group: [Sequelize.fn('EXTRACT', Sequelize.literal('HOUR FROM created_at'))],
//           order: [[Sequelize.fn('EXTRACT', Sequelize.literal('HOUR FROM created_at')), 'ASC']]
//         }),

//         // Unique active users
//         UserActivityLog.count({
//           distinct: true,
//           col: 'user_id',
//           where: whereClause
//         }),

//         // Top IP addresses
//         UserActivityLog.findAll({
//           attributes: [
//             'ip_address',
//             [Sequelize.fn('COUNT', Sequelize.col('id')), 'count']
//           ],
//           where: {
//             ...whereClause,
//             ip_address: { [Op.ne]: null }
//           },
//           group: ['ip_address'],
//           order: [[Sequelize.fn('COUNT', Sequelize.col('id')), 'DESC']],
//           limit: 10
//         })
//       ]);

//       return {
//         totalActivities,
//         uniqueUsers,
//         actionDistribution: activitiesByAction.map(item => ({
//           action: item.action,
//           count: parseInt(item.dataValues.count)
//         })),
//         resourceDistribution: activitiesByResource.map(item => ({
//           resourceType: item.resource_type,
//           count: parseInt(item.dataValues.count)
//         })),
//         hourlyDistribution: activitiesByHour.map(item => ({
//           hour: parseInt(item.dataValues.hour),
//           count: parseInt(item.dataValues.count)
//         })),
//         topIPs: topIPs.map(item => ({
//           ipAddress: item.ip_address,
//           count: parseInt(item.dataValues.count)
//         }))
//       };
//     } catch (error) {
//       throw new AppError(error.message, 500);
//     }
//   }

//   /**
//    * Get security event statistics
//    * @param {object} filters 
//    * @returns {Promise<object>}
//    */
//   async getSecurityStatistics(filters = {}) {
//     try {
//       const whereClause = {};

//       // Apply date filters
//       if (filters.dateFrom && filters.dateTo) {
//         whereClause.created_at = {
//           [Op.between]: [new Date(filters.dateFrom), new Date(filters.dateTo)]
//         };
//       }

//       const [
//         totalEvents,
//         eventsBySeverity,
//         eventsByType,
//         recentCritical
//       ] = await Promise.all([
//         SecurityEvent.count({ where: whereClause }),

//         SecurityEvent.findAll({
//           attributes: [
//             'severity',
//             [Sequelize.fn('COUNT', Sequelize.col('id')), 'count']
//           ],
//           where: whereClause,
//           group: ['severity']
//         }),

//         SecurityEvent.findAll({
//           attributes: [
//             'event_type',
//             [Sequelize.fn('COUNT', Sequelize.col('id')), 'count']
//           ],
//           where: whereClause,
//           group: ['event_type'],
//           order: [[Sequelize.fn('COUNT', Sequelize.col('id')), 'DESC']]
//         }),

//         SecurityEvent.findAll({
//           where: {
//             ...whereClause,
//             severity: { [Op.in]: ['high', 'critical'] }
//           },
//           order: [['created_at', 'DESC']],
//           limit: 10
//         })
//       ]);

//       return {
//         totalEvents,
//         severityDistribution: eventsBySeverity.map(item => ({
//           severity: item.severity,
//           count: parseInt(item.dataValues.count)
//         })),
//         typeDistribution: eventsByType.map(item => ({
//           eventType: item.event_type,
//           count: parseInt(item.dataValues.count)
//         })),
//         recentCriticalEvents: recentCritical.map(event => ({
//           id: event.id,
//           eventType: event.event_type,
//           severity: event.severity,
//           description: event.description,
//           userId: event.user_id,
//           createdAt: event.created_at
//         }))
//       };
//     } catch (error) {
//       throw new AppError(error.message, 500);
//     }
//   }

//   /**
//    * Track login attempts
//    * @param {string} identifier 
//    * @param {boolean} success 
//    * @param {string} ipAddress 
//    * @param {string} userAgent 
//    * @param {number} userId 
//    * @returns {Promise<void>}
//    */
//   async trackLoginAttempt(identifier, success, ipAddress, userAgent, userId = null) {
//     try {
//       const action = success ? 'LOGIN_SUCCESS' : 'LOGIN_FAILED';
//       const eventType = success ? 'AUTHENTICATION_SUCCESS' : 'AUTHENTICATION_FAILURE';
      
//       // Log activity
//       await this.logActivity(
//         userId,
//         action,
//         'authentication',
//         null,
//         { identifier, success },
//         ipAddress,
//         userAgent
//       );

//       // Log security event for failed attempts
//       if (!success) {
//         await this.logSecurityEvent(
//           userId,
//           eventType,
//           'medium',
//           `Failed login attempt for ${identifier}`,
//           { identifier, ip_address: ipAddress, user_agent: userAgent },
//           ipAddress
//         );

//         // Check for brute force attempts
//         await this.checkBruteForceAttempts(identifier, ipAddress);
//       }
//     } catch (error) {
//       console.error('Login attempt tracking failed:', error);
//     }
//   }

//   /**
//    * Check for brute force attempts
//    * @param {string} identifier 
//    * @param {string} ipAddress 
//    * @returns {Promise<void>}
//    */
//   async checkBruteForceAttempts(identifier, ipAddress) {
//     try {
//       const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);

//       // Count failed attempts from same IP in last 15 minutes
//       const ipAttempts = await UserActivityLog.count({
//         where: {
//           action: 'LOGIN_FAILED',
//           ip_address: ipAddress,
//           created_at: { [Op.gte]: fifteenMinutesAgo }
//         }
//       });

//       // Count failed attempts for same identifier in last 15 minutes
//       const identifierAttempts = await UserActivityLog.count({
//         where: {
//           action: 'LOGIN_FAILED',
//           details: { [Op.like]: `%${identifier}%` },
//           created_at: { [Op.gte]: fifteenMinutesAgo }
//         }
//       });

//       // Log high severity event if threshold exceeded
//       if (ipAttempts >= 5 || identifierAttempts >= 3) {
//         await this.logSecurityEvent(
//           null,
//           'BRUTE_FORCE_ATTEMPT',
//           'high',
//           `Potential brute force attack detected`,
//           {
//             identifier,
//             ip_address: ipAddress,
//             ip_attempts: ipAttempts,
//             identifier_attempts: identifierAttempts
//           },
//           ipAddress
//         );
//       }
//     } catch (error) {
//       console.error('Brute force check failed:', error);
//     }
//   }

//   /**
//    * Generate audit report
//    * @param {object} criteria 
//    * @returns {Promise<object>}
//    */
//   async generateAuditReport(criteria = {}) {
//     try {
//       const report = {
//         generatedAt: new Date(),
//         criteria,
//         summary: {},
//         details: {}
//       };

//       // Get activity statistics
//       report.summary.activities = await this.getActivityStatistics(criteria);

//       // Get security statistics
//       report.summary.security = await this.getSecurityStatistics(criteria);

//       // Get detailed breakdowns if requested
//       if (criteria.includeDetails) {
//         const whereClause = {};
//         if (criteria.dateFrom && criteria.dateTo) {
//           whereClause.created_at = {
//             [Op.between]: [new Date(criteria.dateFrom), new Date(criteria.dateTo)]
//           };
//         }

//         report.details.topUsers = await UserActivityLog.findAll({
//           attributes: [
//             'user_id',
//             [Sequelize.fn('COUNT', Sequelize.col('id')), 'activity_count']
//           ],
//           where: whereClause,
//           group: ['user_id'],
//           order: [[Sequelize.fn('COUNT', Sequelize.col('id')), 'DESC']],
//           limit: 10
//         });

//         report.details.suspiciousActivities = await this.getSuspiciousActivities(criteria);
//       }

//       return report;
//     } catch (error) {
//       throw new AppError(`Audit report generation failed: ${error.message}`, 500);
//     }
//   }

//   /**
//    * Get suspicious activities
//    * @param {object} criteria 
//    * @returns {Promise<array>}
//    */
//   async getSuspiciousActivities(criteria = {}) {
//     try {
//       const whereClause = {};
//       if (criteria.dateFrom && criteria.dateTo) {
//         whereClause.created_at = {
//           [Op.between]: [new Date(criteria.dateFrom), new Date(criteria.dateTo)]
//         };
//       }

//       // Find activities that might be suspicious
//       const suspiciousPatterns = [
//         'MULTIPLE_LOGIN_FAILURES',
//         'UNUSUAL_IP_ACCESS',
//         'RAPID_SUCCESSION_ACTIONS',
//         'PRIVILEGE_ESCALATION',
//         'SENSITIVE_DATA_ACCESS'
//       ];

//       const suspicious = await UserActivityLog.findAll({
//         where: {
//           ...whereClause,
//           [Op.or]: [
//             { action: { [Op.in]: ['LOGIN_FAILED', 'PERMISSION_DENIED', 'UNAUTHORIZED_ACCESS'] } },
//             { details: { [Op.like]: '%suspicious%' } },
//             { details: { [Op.like]: '%blocked%' } }
//           ]
//         },
//         order: [['created_at', 'DESC']],
//         limit: 50
//       });

//       return suspicious.map(activity => ({
//         id: activity.id,
//         userId: activity.user_id,
//         action: activity.action,
//         resourceType: activity.resource_type,
//         details: this.safeParseJSON(activity.details),
//         ipAddress: activity.ip_address,
//         createdAt: activity.created_at
//       }));
//     } catch (error) {
//       throw new AppError(`Suspicious activity detection failed: ${error.message}`, 500);
//     }
//   }

//   /**
//    * Handle high severity security events
//    * @param {object} securityEvent 
//    * @returns {Promise<void>}
//    */
//   async handleHighSeverityEvent(securityEvent) {
//     try {
//       // This could trigger notifications, alerts, etc.
//       console.warn('High severity security event:', {
//         id: securityEvent.id,
//         type: securityEvent.event_type,
//         severity: securityEvent.severity,
//         userId: securityEvent.user_id,
//         description: securityEvent.description
//       });

//       // Here you could integrate with alerting systems, send notifications, etc.
//       // For now, we'll just log it
//     } catch (error) {
//       console.error('High severity event handling failed:', error);
//     }
//   }

//   /**
//    * Clean up old audit logs
//    * @param {number} daysToKeep 
//    * @returns {Promise<object>}
//    */
//   async cleanupOldLogs(daysToKeep = 90) {
//     try {
//       const cutoffDate = new Date();
//       cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

//       const [deletedActivities, deletedSecurityEvents] = await Promise.all([
//         UserActivityLog.destroy({
//           where: {
//             created_at: { [Op.lt]: cutoffDate }
//           }
//         }),
//         SecurityEvent.destroy({
//           where: {
//             created_at: { [Op.lt]: cutoffDate },
//             severity: { [Op.notIn]: ['high', 'critical'] } // Keep high/critical events longer
//           }
//         })
//       ]);

//       return
