import { DataTypes } from 'sequelize';

const up = async (queryInterface, Sequelize) => {
  await queryInterface.createTable('vottery_security_events', {
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
      references: {
        model: 'vottery_users',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE',
    },
    organization_id: {
      type: DataTypes.UUID,
      allowNull: true,
      references: {
        model: 'vottery_organizations',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'CASCADE',
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
      references: {
        model: 'vottery_api_tokens',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'SET NULL',
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
      references: {
        model: 'vottery_security_events',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'SET NULL',
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
      references: {
        model: 'vottery_users',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'SET NULL',
    },
    escalated_to: {
      type: DataTypes.UUID,
      allowNull: true,
      references: {
        model: 'vottery_users',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'SET NULL',
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
      references: {
        model: 'vottery_users',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'SET NULL',
      comment: 'System or user who created the event',
    },
    updated_by: {
      type: DataTypes.UUID,
      allowNull: true,
      references: {
        model: 'vottery_users',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'SET NULL',
    },
    resolved_by: {
      type: DataTypes.UUID,
      allowNull: true,
      references: {
        model: 'vottery_users',
        key: 'id',
      },
      onUpdate: 'CASCADE',
      onDelete: 'SET NULL',
    },
    resolved_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    first_seen_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
    },
    last_seen_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
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
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
    },
    updated_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
    },
    deleted_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
  });

  // Add indexes for performance and security monitoring
  await queryInterface.addIndex('vottery_security_events', ['event_id']);
  await queryInterface.addIndex('vottery_security_events', ['event_type']);
  await queryInterface.addIndex('vottery_security_events', ['severity']);
  await queryInterface.addIndex('vottery_security_events', ['status']);
  await queryInterface.addIndex('vottery_security_events', ['user_id']);
  await queryInterface.addIndex('vottery_security_events', ['organization_id']);
  await queryInterface.addIndex('vottery_security_events', ['source_ip']);
  await queryInterface.addIndex('vottery_security_events', ['api_token_id']);
  await queryInterface.addIndex('vottery_security_events', ['detection_method']);
  await queryInterface.addIndex('vottery_security_events', ['risk_score']);
  await queryInterface.addIndex('vottery_security_events', ['assigned_to']);
  await queryInterface.addIndex('vottery_security_events', ['parent_event_id']);
  await queryInterface.addIndex('vottery_security_events', ['first_seen_at']);
  await queryInterface.addIndex('vottery_security_events', ['last_seen_at']);
  await queryInterface.addIndex('vottery_security_events', ['resolved_at']);
  await queryInterface.addIndex('vottery_security_events', ['sla_deadline']);
  
  // Composite indexes for common security queries
  await queryInterface.addIndex('vottery_security_events', ['event_type', 'severity']);
  await queryInterface.addIndex('vottery_security_events', ['status', 'severity']);
  await queryInterface.addIndex('vottery_security_events', ['user_id', 'event_type']);
  await queryInterface.addIndex('vottery_security_events', ['organization_id', 'severity']);
  await queryInterface.addIndex('vottery_security_events', ['source_ip', 'event_type']);
  await queryInterface.addIndex('vottery_security_events', ['first_seen_at', 'severity']);
  await queryInterface.addIndex('vottery_security_events', ['status', 'assigned_to']);
  await queryInterface.addIndex('vottery_security_events', ['risk_score', 'status']);
};

const down = async (queryInterface, Sequelize) => {
  await queryInterface.dropTable('vottery_security_events');
};

export { up, down };