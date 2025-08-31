import { DataTypes, Model } from 'sequelize';
import crypto from 'node:crypto';

class SecurityEvent extends Model {
  static init(sequelize) {
    return super.init(
      {
        id: {
          type: DataTypes.UUID,
          defaultValue: DataTypes.UUIDV4,
          primaryKey: true,
          allowNull: false,
        },
        event_id: {
          type: DataTypes.STRING(64),
          allowNull: false,
          unique: true,
          comment: 'Unique identifier for tracking',
        },
        event_type: {
          type: DataTypes.ENUM,
          values: [
            'login_anomaly', 'multiple_failed_logins', 'account_lockout', 'password_brute_force',
            'suspicious_location', 'unusual_device', 'rate_limit_exceeded', 'api_abuse',
            'privilege_escalation', 'unauthorized_access', 'data_export_anomaly',
            'encryption_key_compromise', 'signature_verification_failure', 'token_theft',
            'session_hijacking', 'csrf_attack', 'sql_injection', 'xss_attempt',
            'malware_detected', 'phishing_attempt', 'social_engineering',
            'system_intrusion', 'data_breach', 'compliance_violation',
            'security_policy_violation', 'threat_detected', 'vulnerability_exploit',
            'ddos_attack', 'insider_threat', 'fraud_attempt', 'other'
          ],
          allowNull: false,
        },
        severity: {
          type: DataTypes.ENUM,
          values: ['critical', 'high', 'medium', 'low', 'info'],
          allowNull: false,
        },
        status: {
          type: DataTypes.ENUM,
          values: ['open', 'investigating', 'mitigated', 'resolved', 'false_positive', 'ignored'],
          allowNull: false,
          defaultValue: 'open',
        },
        title: {
          type: DataTypes.STRING(200),
          allowNull: false,
        },
        description: {
          type: DataTypes.TEXT,
          allowNull: false,
        },
        user_id: {
          type: DataTypes.UUID,
          allowNull: true,
        },
        organization_id: {
          type: DataTypes.UUID,
          allowNull: true,
        },
        source_ip: {
          type: DataTypes.INET,
          allowNull: true,
        },
        target_ip: {
          type: DataTypes.INET,
          allowNull: true,
        },
        user_agent: {
          type: DataTypes.TEXT,
          allowNull: true,
        },
        request_method: {
          type: DataTypes.STRING(10),
          allowNull: true,
        },
        request_path: {
          type: DataTypes.STRING(500),
          allowNull: true,
        },
        request_headers: {
          type: DataTypes.JSON,
          allowNull: true,
          comment: 'Sanitized request headers',
        },
        response_status: {
          type: DataTypes.INTEGER,
          allowNull: true,
        },
        session_id: {
          type: DataTypes.STRING(128),
          allowNull: true,
        },
        api_token_id: {
          type: DataTypes.UUID,
          allowNull: true,
        },
        geolocation: {
          type: DataTypes.JSON,
          allowNull: true,
          comment: 'Geographic location data',
        },
        device_fingerprint: {
          type: DataTypes.JSON,
          allowNull: true,
          comment: 'Device identification data',
        },
        threat_indicators: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Array of threat intelligence indicators',
        },
        attack_vector: {
          type: DataTypes.STRING(100),
          allowNull: true,
          comment: 'Method of attack or compromise',
        },
        payload_signature: {
          type: DataTypes.STRING(128),
          allowNull: true,
          comment: 'Hash of attack payload for correlation',
        },
        affected_resources: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Resources that were targeted or compromised',
        },
        detection_method: {
          type: DataTypes.ENUM,
          values: ['automated_rule', 'ml_anomaly', 'user_report', 'admin_discovery', 'external_alert', 'audit_finding'],
          allowNull: false,
        },
        detection_rule_id: {
          type: DataTypes.STRING(100),
          allowNull: true,
          comment: 'ID of the detection rule that triggered',
        },
        confidence_score: {
          type: DataTypes.DECIMAL(3, 2),
          allowNull: true,
          comment: 'Confidence level (0.00 to 1.00)',
        },
        risk_score: {
          type: DataTypes.INTEGER,
          allowNull: false,
          comment: 'Risk score (0-100)',
        },
        impact_assessment: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
          comment: 'Assessment of potential impact',
        },
        mitigation_actions: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Actions taken to mitigate the threat',
        },
        remediation_steps: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Steps taken or required for remediation',
        },
        automated_response: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
          comment: 'Automated response actions taken',
        },
        false_positive_reason: {
          type: DataTypes.TEXT,
          allowNull: true,
        },
        correlation_ids: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Related security events',
        },
        parent_event_id: {
          type: DataTypes.UUID,
          allowNull: true,
        },
        timeline: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Timeline of event progression',
        },
        evidence: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Evidence and forensic data',
        },
        investigation_notes: {
          type: DataTypes.TEXT,
          allowNull: true,
        },
        assigned_to: {
          type: DataTypes.UUID,
          allowNull: true,
        },
        escalated_to: {
          type: DataTypes.UUID,
          allowNull: true,
        },
        external_references: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'External threat intelligence references',
        },
        compliance_impact: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
          comment: 'Impact on compliance requirements',
        },
        notification_sent: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Record of notifications sent',
        },
        escalation_level: {
          type: DataTypes.INTEGER,
          defaultValue: 0,
          allowNull: false,
          comment: 'Current escalation level',
        },
        sla_deadline: {
          type: DataTypes.DATE,
          allowNull: true,
          comment: 'SLA response deadline',
        },
        resolution_time_minutes: {
          type: DataTypes.INTEGER,
          allowNull: true,
          comment: 'Time to resolution in minutes',
        },
        cost_impact: {
          type: DataTypes.DECIMAL(10, 2),
          allowNull: true,
          comment: 'Estimated cost impact',
        },
        lessons_learned: {
          type: DataTypes.TEXT,
          allowNull: true,
        },
        tags: {
          type: DataTypes.JSON,
          defaultValue: [],
          allowNull: false,
          comment: 'Searchable tags for categorization',
        },
        created_by: {
          type: DataTypes.UUID,
          allowNull: true,
          comment: 'System or user who created the event',
        },
        updated_by: {
          type: DataTypes.UUID,
          allowNull: true,
        },
        resolved_by: {
          type: DataTypes.UUID,
          allowNull: true,
        },
        resolved_at: {
          type: DataTypes.DATE,
          allowNull: true,
        },
        first_seen_at: {
          type: DataTypes.DATE,
          allowNull: false,
          defaultValue: DataTypes.NOW,
        },
        last_seen_at: {
          type: DataTypes.DATE,
          allowNull: false,
          defaultValue: DataTypes.NOW,
        },
        occurrence_count: {
          type: DataTypes.INTEGER,
          defaultValue: 1,
          allowNull: false,
          comment: 'Number of times this event has occurred',
        },
        metadata: {
          type: DataTypes.JSON,
          defaultValue: {},
          allowNull: false,
        },
      },
      {
        sequelize,
        modelName: 'SecurityEvent',
        tableName: 'vottery_security_events',
        paranoid: true,
        hooks: {
          beforeCreate: (event) => {
            if (!event.event_id) {
              event.event_id = crypto.randomBytes(16).toString('hex');
            }
            event.addTimelineEntry('created', 'Security event created');
          },
        },
      }
    );
  }

  // Instance methods
  isCritical() {
    return this.severity === 'critical';
  }

  isHigh() {
    return this.severity === 'high';
  }

  isOpen() {
    return this.status === 'open';
  }

  isResolved() {
    return this.status === 'resolved';
  }

  isFalsePositive() {
    return this.status === 'false_positive';
  }

  getAge() {
    const now = new Date();
    const created = new Date(this.first_seen_at);
    return Math.floor((now - created) / (1000 * 60 * 60 * 24)); // days
  }

  getResolutionTime() {
    if (!this.resolved_at) {
      return null;
    }
    
    const resolved = new Date(this.resolved_at);
    const created = new Date(this.first_seen_at);
    return Math.floor((resolved - created) / (1000 * 60)); // minutes
  }

  isOverdue() {
    if (!this.sla_deadline || this.isResolved()) {
      return false;
    }
    
    return new Date() > this.sla_deadline;
  }

  // Status management
  async assign(userId, assignedBy = null) {
    this.assigned_to = userId;
    this.updated_by = assignedBy;
    this.addTimelineEntry('assigned', `Event assigned to user ${userId}`, { assigned_by: assignedBy });
    return await this.save();
  }

  async escalate(userId, escalationLevel = null) {
    this.escalated_to = userId;
    this.escalation_level = escalationLevel || (this.escalation_level + 1);
    this.addTimelineEntry('escalated', `Event escalated to user ${userId} (level ${this.escalation_level})`);
    return await this.save();
  }

  async updateStatus(newStatus, userId = null, reason = null) {
    const oldStatus = this.status;
    this.status = newStatus;
    this.updated_by = userId;
    
    if (newStatus === 'resolved') {
      this.resolved_at = new Date();
      this.resolved_by = userId;
      this.resolution_time_minutes = this.getResolutionTime();
    }
    
    this.addTimelineEntry(
      'status_changed', 
      `Status changed from ${oldStatus} to ${newStatus}`,
      { reason, changed_by: userId }
    );
    
    return await this.save();
  }

  async markFalsePositive(reason, userId = null) {
    this.false_positive_reason = reason;
    return await this.updateStatus('false_positive', userId, reason);
  }

  async resolve(resolution, userId = null) {
    this.investigation_notes = resolution;
    return await this.updateStatus('resolved', userId, 'Investigation completed');
  }

  // Timeline management
  addTimelineEntry(action, description, metadata = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      action,
      description,
      metadata,
    };
    
    this.timeline.push(entry);
    return entry;
  }

  getTimeline(limit = 20) {
    return this.timeline
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, limit);
  }

  // Evidence management
  addEvidence(type, description, data = {}) {
    const evidence = {
      id: crypto.randomUUID(),
      type,
      description,
      data,
      timestamp: new Date().toISOString(),
      collected_by: data.collected_by || null,
    };
    
    this.evidence.push(evidence);
    this.addTimelineEntry('evidence_added', `Evidence added: ${type} - ${description}`);
    return evidence;
  }

  getEvidence(type = null) {
    if (!type) {
      return this.evidence;
    }
    
    return this.evidence.filter(e => e.type === type);
  }

  // Mitigation and remediation
  addMitigationAction(action, description, status = 'completed') {
    const mitigation = {
      id: crypto.randomUUID(),
      action,
      description,
      status,
      timestamp: new Date().toISOString(),
    };
    
    this.mitigation_actions.push(mitigation);
    this.addTimelineEntry('mitigation_added', `Mitigation action: ${action}`);
    return mitigation;
  }

  addRemediationStep(step, description, status = 'pending') {
    const remediation = {
      id: crypto.randomUUID(),
      step,
      description,
      status,
      timestamp: new Date().toISOString(),
    };
    
    this.remediation_steps.push(remediation);
    this.addTimelineEntry('remediation_added', `Remediation step: ${step}`);
    return remediation;
  }

  // Threat intelligence
  addThreatIndicator(type, value, confidence = 0.5) {
    const indicator = {
      type,
      value,
      confidence,
      timestamp: new Date().toISOString(),
    };
    
    this.threat_indicators.push(indicator);
    return indicator;
  }

  hasThreatIndicator(type, value) {
    return this.threat_indicators.some(
      indicator => indicator.type === type && indicator.value === value
    );
  }

  // Correlation
  addCorrelationId(eventId) {
    if (!this.correlation_ids.includes(eventId)) {
      this.correlation_ids.push(eventId);
      this.addTimelineEntry('correlated', `Event correlated with ${eventId}`);
    }
    return this;
  }

  removeCorrelationId(eventId) {
    this.correlation_ids = this.correlation_ids.filter(id => id !== eventId);
    return this;
  }

  // Risk assessment
  updateRiskScore(newScore, reason = null) {
    const oldScore = this.risk_score;
    this.risk_score = newScore;
    
    this.addTimelineEntry(
      'risk_score_updated',
      `Risk score changed from ${oldScore} to ${newScore}`,
      { reason }
    );
    
    return this;
  }

  isHighRisk() {
    return this.risk_score >= 70;
  }

  isMediumRisk() {
    return this.risk_score >= 40 && this.risk_score < 70;
  }

  isLowRisk() {
    return this.risk_score < 40;
  }

  // Tags management
  addTag(tag) {
    if (!this.tags.includes(tag)) {
      this.tags.push(tag);
    }
    return this;
  }

  removeTag(tag) {
    this.tags = this.tags.filter(t => t !== tag);
    return this;
  }

  hasTag(tag) {
    return this.tags.includes(tag);
  }

  // Notification management
  addNotificationRecord(type, recipient, status = 'sent') {
    const notification = {
      type,
      recipient,
      status,
      timestamp: new Date().toISOString(),
    };
    
    this.notification_sent.push(notification);
    return notification;
  }

  // Static methods
  static async createEvent(data) {
    const {
      eventType,
      severity,
      title,
      description,
      userId = null,
      organizationId = null,
      sourceIp = null,
      detectionMethod = 'automated_rule',
      riskScore = 50,
      ...otherData
    } = data;

    const event = await this.create({
      event_type: eventType,
      severity,
      title,
      description,
      user_id: userId,
      organization_id: organizationId,
      source_ip: sourceIp,
      detection_method: detectionMethod,
      risk_score: riskScore,
      ...otherData,
    });

    // Auto-assign SLA deadline based on severity
    event.setSLADeadline();
    await event.save();

    return event;
  }

  setSLADeadline() {
    const slaHours = {
      critical: 1,
      high: 4,
      medium: 24,
      low: 72,
      info: 168, // 1 week
    };

    const hours = slaHours[this.severity] || 24;
    this.sla_deadline = new Date();
    this.sla_deadline.setHours(this.sla_deadline.getHours() + hours);
  }

  static async findByUser(userId, options = {}) {
    const { limit = 50, severity = null, status = null } = options;
    
    const whereClause = { user_id: userId };
    if (severity) whereClause.severity = severity;
    if (status) whereClause.status = status;
    
    return await this.findAll({
      where: whereClause,
      limit,
      order: [['first_seen_at', 'DESC']],
    });
  }

  static async findByOrganization(organizationId, options = {}) {
    const { limit = 100, severity = null, status = null } = options;
    
    const whereClause = { organization_id: organizationId };
    if (severity) whereClause.severity = severity;
    if (status) whereClause.status = status;
    
    return await this.findAll({
      where: whereClause,
      limit,
      order: [['first_seen_at', 'DESC']],
    });
  }

  static async findCriticalEvents(timeframe = '24 hours') {
    const timeAgo = new Date();
    timeAgo.setHours(timeAgo.getHours() - 24);
    
    return await this.findAll({
      where: {
        severity: 'critical',
        first_seen_at: {
          [this.sequelize.Sequelize.Op.gte]: timeAgo,
        },
      },
      order: [['first_seen_at', 'DESC']],
    });
  }

  static async findOpenEvents(assigneeId = null) {
    const whereClause = {
      status: {
        [this.sequelize.Sequelize.Op.in]: ['open', 'investigating'],
      },
    };
    
    if (assigneeId) {
      whereClause.assigned_to = assigneeId;
    }
    
    return await this.findAll({
      where: whereClause,
      order: [['severity', 'DESC'], ['first_seen_at', 'ASC']],
    });
  }

  static async findOverdueEvents() {
    return await this.findAll({
      where: {
        sla_deadline: {
          [this.sequelize.Sequelize.Op.lt]: new Date(),
        },
        status: {
          [this.sequelize.Sequelize.Op.notIn]: ['resolved', 'false_positive'],
        },
      },
      order: [['sla_deadline', 'ASC']],
    });
  }

  static async findCorrelatedEvents(eventId) {
    const event = await this.findByPk(eventId);
    if (!event || event.correlation_ids.length === 0) {
      return [];
    }
    
    return await this.findAll({
      where: {
        id: {
          [this.sequelize.Sequelize.Op.in]: event.correlation_ids,
        },
      },
      order: [['first_seen_at', 'DESC']],
    });
  }

  static async findByThreatIndicator(type, value) {
    return await this.findAll({
      where: {
        threat_indicators: {
          [this.sequelize.Sequelize.Op.contains]: [{ type, value }],
        },
      },
    });
  }

  static async getSecurityDashboard(organizationId = null) {
    const whereClause = organizationId ? { organization_id: organizationId } : {};
    
    const [
      totalEvents,
      openEvents,
      criticalEvents,
      overdueEvents,
      recentEvents
    ] = await Promise.all([
      this.count({ where: whereClause }),
      this.count({ 
        where: { 
          ...whereClause, 
          status: { [this.sequelize.Sequelize.Op.in]: ['open', 'investigating'] }
        }
      }),
      this.count({ 
        where: { 
          ...whereClause, 
          severity: 'critical',
          status: { [this.sequelize.Sequelize.Op.ne]: 'resolved' }
        }
      }),
      this.count({
        where: {
          ...whereClause,
          sla_deadline: { [this.sequelize.Sequelize.Op.lt]: new Date() },
          status: { [this.sequelize.Sequelize.Op.notIn]: ['resolved', 'false_positive'] }
        }
      }),
      this.findAll({
        where: {
          ...whereClause,
          first_seen_at: {
            [this.sequelize.Sequelize.Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000)
          }
        },
        limit: 10,
        order: [['first_seen_at', 'DESC']]
      })
    ]);

    return {
      total_events: totalEvents,
      open_events: openEvents,
      critical_events: criticalEvents,
      overdue_events: overdueEvents,
      recent_events: recentEvents,
      generated_at: new Date(),
    };
  }

  static async getSecurityMetrics(organizationId = null, days = 30) {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);
    
    const whereClause = {
      first_seen_at: { [this.sequelize.Sequelize.Op.gte]: startDate }
    };
    
    if (organizationId) {
      whereClause.organization_id = organizationId;
    }

    const events = await this.findAll({
      where: whereClause,
      attributes: ['severity', 'event_type', 'status', 'first_seen_at', 'resolution_time_minutes'],
    });

    const metrics = {
      total_events: events.length,
      by_severity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      },
      by_status: {
        open: 0,
        investigating: 0,
        resolved: 0,
        false_positive: 0,
      },
      by_type: {},
      average_resolution_time: 0,
      daily_counts: {},
    };

    let totalResolutionTime = 0;
    let resolvedCount = 0;

    events.forEach(event => {
      // Count by severity
      metrics.by_severity[event.severity] = (metrics.by_severity[event.severity] || 0) + 1;
      
      // Count by status
      metrics.by_status[event.status] = (metrics.by_status[event.status] || 0) + 1;
      
      // Count by type
      metrics.by_type[event.event_type] = (metrics.by_type[event.event_type] || 0) + 1;
      
      // Calculate resolution time
      if (event.resolution_time_minutes) {
        totalResolutionTime += event.resolution_time_minutes;
        resolvedCount++;
      }
      
      // Daily counts
      const day = event.first_seen_at.toISOString().split('T')[0];
      metrics.daily_counts[day] = (metrics.daily_counts[day] || 0) + 1;
    });

    if (resolvedCount > 0) {
      metrics.average_resolution_time = Math.round(totalResolutionTime / resolvedCount);
    }

    return metrics;
  }

  static async cleanupResolvedEvents(retentionDays = 365) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    return await this.destroy({
      where: {
        status: 'resolved',
        resolved_at: {
          [this.sequelize.Sequelize.Op.lt]: cutoffDate,
        },
      },
    });
  }

  // Associations
  static associate(models) {
    // User involved in the event
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'user_id',
      as: 'user'
    });

    // Organization context
    this.belongsTo(models.VotteryOrganization, {
      foreignKey: 'organization_id',
      as: 'organization'
    });

    // API token involved
    this.belongsTo(models.ApiToken, {
      foreignKey: 'api_token_id',
      as: 'apiToken'
    });

    // Created by user/system
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'created_by',
      as: 'creator'
    });

    // Updated by user
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'updated_by',
      as: 'updater'
    });

    // Assigned to user
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'assigned_to',
      as: 'assignee'
    });

    // Escalated to user
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'escalated_to',
      as: 'escalatedTo'
    });

    // Resolved by user
    this.belongsTo(models.VotteryUser, {
      foreignKey: 'resolved_by',
      as: 'resolver'
    });

    // Parent event (self-referencing)
    this.belongsTo(models.SecurityEvent, {
      foreignKey: 'parent_event_id',
      as: 'parentEvent'
    });

    // Child events (self-referencing)
    this.hasMany(models.SecurityEvent, {
      foreignKey: 'parent_event_id',
      as: 'childEvents'
    });
  }
}

export default (sequelize) => {
  return SecurityEvent.init(sequelize);
};