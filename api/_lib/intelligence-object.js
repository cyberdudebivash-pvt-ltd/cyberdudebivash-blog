/**
 * SENTINEL APEX — Canonical Intelligence Object
 * Single unified schema for all intelligence: detections, IOCs, threat reports, campaigns, etc.
 * Every intelligence object has: governance metadata, version history, confidence, audit trail.
 */
'use strict';

const crypto = require('crypto');

/**
 * Intelligence object types (extensible).
 */
const INTELLIGENCE_TYPES = {
  DETECTION_RULE:    'detection_rule',    // Sigma/YARA/Suricata/KQL rule
  IOC:               'ioc',               // IP/domain/hash/registry key
  THREAT_ACTOR:      'threat_actor',      // APT group or cybercriminal
  MALWARE:           'malware',           // Malware family or variant
  CAMPAIGN:          'campaign',          // Cyber campaign or operation
  VULNERABILITY:     'vulnerability',     // CVE or software vuln
  THREAT_REPORT:     'threat_report',     // Analysis report
  INCIDENT:          'incident',          // Security incident
  SUPPLY_CHAIN:      'supply_chain',      // Supply chain threat
  INFRASTRUCTURE:    'infrastructure',    // C2, hosting, domain infrastructure
  TECHNIQUE:         'technique',         // MITRE ATT&CK technique
  INDICATOR_SET:     'indicator_set',     // Curated IOC collection
};

/**
 * Intelligence lifecycle states.
 */
const LIFECYCLE_STATES = {
  DRAFT:      'draft',       // Initial creation — not yet reviewed
  REVIEW:     'review',      // Awaiting analyst review and approval
  APPROVED:   'approved',    // Approved for publication
  PUBLISHED:  'published',   // Active in production, customers see it
  ARCHIVED:   'archived',    // No longer active (superseded or incorrect)
  RETRACTED:  'retracted',   // Published then retracted (error discovered)
};

/**
 * Intelligence confidence levels.
 */
const CONFIDENCE_LEVELS = {
  HIGH:    'HIGH',      // 75%+: Multiple corroborating sources, verified evidence
  MEDIUM:  'MEDIUM',    // 40-75%: Some evidence, some corroboration
  LOW:     'LOW',       // <40%: Single source or unverified claims
};

/**
 * Intelligence severity levels.
 */
const SEVERITY_LEVELS = {
  CRITICAL: 'CRITICAL',  // Immediate exploitation risk, active campaigns
  HIGH:     'HIGH',      // Significant risk, targeted attacks
  MEDIUM:   'MEDIUM',    // Moderate risk, affects some organizations
  LOW:      'LOW',       // Low-impact vulnerabilities or threats
  INFO:     'INFO',      // Informational, no direct risk
};

/**
 * Canonical Intelligence Object.
 * Every intelligence piece in SENTINEL APEX conforms to this schema.
 */
class IntelligenceObject {
  constructor(type, sourceData = {}) {
    if (!INTELLIGENCE_TYPES[type]) {
      throw new Error(`Invalid intelligence type: ${type}`);
    }

    this.id = sourceData.id || generateIntelligenceId(type);
    this.type = type;
    this.version = sourceData.version || '1.0.0';

    // ─── Core Content ──────────────────────────────────────────
    this.title = sourceData.title || '';
    this.description = sourceData.description || '';
    this.content = sourceData.content || {};
    this.tags = sourceData.tags || [];

    // ─── Governance Metadata ──────────────────────────────────
    this.status = sourceData.status || LIFECYCLE_STATES.DRAFT;
    this.confidence = sourceData.confidence || CONFIDENCE_LEVELS.MEDIUM;
    this.severity = sourceData.severity || SEVERITY_LEVELS.MEDIUM;

    // ─── Versioning & History ────────────────────────────────
    this.createdAt = sourceData.createdAt || new Date().toISOString();
    this.createdBy = sourceData.createdBy || 'system';
    this.updatedAt = sourceData.updatedAt || this.createdAt;
    this.updatedBy = sourceData.updatedBy || this.createdBy;
    this.history = sourceData.history || [];

    // ─── Governance Chain ────────────────────────────────────
    this.reviewedAt = sourceData.reviewedAt || null;
    this.reviewedBy = sourceData.reviewedBy || null;
    this.approvedAt = sourceData.approvedAt || null;
    this.approvedBy = sourceData.approvedBy || null;
    this.publishedAt = sourceData.publishedAt || null;
    this.publishedBy = sourceData.publishedBy || null;

    // ─── Audit Trail ─────────────────────────────────────────
    this.auditLog = sourceData.auditLog || [];

    // ─── Relationships ───────────────────────────────────────
    this.relatedIntelligence = sourceData.relatedIntelligence || [];
    this.sources = sourceData.sources || [];
    this.references = sourceData.references || [];

    // ─── Production Metadata ─────────────────────────────────
    this.dataClassification = sourceData.dataClassification || 'PUBLIC';
    this.tlp = sourceData.tlp || 'WHITE';
    this.distribution = sourceData.distribution || ['customers', 'partners'];
    this.expiration = sourceData.expiration || null;
  }

  /**
   * Transition to a new lifecycle state.
   * Enforces valid state transitions and records governance changes.
   */
  transitionState(newState, actor = 'system', reason = '') {
    if (!LIFECYCLE_STATES[newState]) {
      throw new Error(`Invalid lifecycle state: ${newState}`);
    }

    // Validate state transitions
    const validTransitions = {
      [LIFECYCLE_STATES.DRAFT]:      [LIFECYCLE_STATES.REVIEW, LIFECYCLE_STATES.ARCHIVED],
      [LIFECYCLE_STATES.REVIEW]:     [LIFECYCLE_STATES.APPROVED, LIFECYCLE_STATES.DRAFT],
      [LIFECYCLE_STATES.APPROVED]:   [LIFECYCLE_STATES.PUBLISHED, LIFECYCLE_STATES.REVIEW],
      [LIFECYCLE_STATES.PUBLISHED]:  [LIFECYCLE_STATES.ARCHIVED, LIFECYCLE_STATES.RETRACTED],
      [LIFECYCLE_STATES.ARCHIVED]:   [LIFECYCLE_STATES.PUBLISHED],
      [LIFECYCLE_STATES.RETRACTED]:  [LIFECYCLE_STATES.ARCHIVED],
    };

    if (!validTransitions[this.status]?.includes(newState)) {
      throw new Error(`Cannot transition from ${this.status} to ${newState}`);
    }

    const now = new Date().toISOString();
    const oldStatus = this.status;
    this.status = newState;

    // Record governance milestone
    if (newState === LIFECYCLE_STATES.REVIEW) {
      this.reviewedAt = now;
      this.reviewedBy = actor;
    } else if (newState === LIFECYCLE_STATES.APPROVED) {
      this.approvedAt = now;
      this.approvedBy = actor;
    } else if (newState === LIFECYCLE_STATES.PUBLISHED) {
      this.publishedAt = now;
      this.publishedBy = actor;
    }

    // Log the state change
    this.auditLog.push({
      action: 'STATE_CHANGE',
      from: oldStatus,
      to: newState,
      actor,
      reason,
      timestamp: now,
    });

    return this;
  }

  /**
   * Create a new version with modified content.
   * Increments semantic version and preserves full history.
   */
  createVersion(newContent = {}, actor = 'system', reason = '') {
    const now = new Date().toISOString();

    // Increment semantic version
    const [major, minor, patch] = this.version.split('.');
    const newVersion = `${major}.${minor}.${parseInt(patch, 10) + 1}`;

    // Record previous version in history
    this.history.push({
      version: this.version,
      content: { ...this.content },
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      updatedBy: this.updatedBy,
    });

    // Update to new version
    this.version = newVersion;
    this.content = { ...this.content, ...newContent };
    this.updatedAt = now;
    this.updatedBy = actor;

    // Log the version change
    this.auditLog.push({
      action: 'VERSION_CHANGE',
      version: newVersion,
      actor,
      reason,
      timestamp: now,
      changedFields: Object.keys(newContent),
    });

    return this;
  }

  /**
   * Set confidence level with justification.
   * Confidence drives downstream processing (filtering, prioritization, etc.)
   */
  setConfidence(level, justification = '') {
    if (!CONFIDENCE_LEVELS[level]) {
      throw new Error(`Invalid confidence level: ${level}`);
    }

    const now = new Date().toISOString();
    const oldConfidence = this.confidence;
    this.confidence = level;

    this.auditLog.push({
      action: 'CONFIDENCE_UPDATE',
      from: oldConfidence,
      to: level,
      justification,
      timestamp: now,
    });

    return this;
  }

  /**
   * Add audit log entry for any significant event.
   */
  logAudit(action, data = {}) {
    this.auditLog.push({
      action,
      timestamp: new Date().toISOString(),
      ...data,
    });
    return this;
  }

  /**
   * Serialize for storage (Redis, database, etc.)
   */
  toJSON() {
    return {
      id: this.id,
      type: this.type,
      version: this.version,
      title: this.title,
      description: this.description,
      content: this.content,
      tags: this.tags,
      status: this.status,
      confidence: this.confidence,
      severity: this.severity,
      createdAt: this.createdAt,
      createdBy: this.createdBy,
      updatedAt: this.updatedAt,
      updatedBy: this.updatedBy,
      history: this.history,
      reviewedAt: this.reviewedAt,
      reviewedBy: this.reviewedBy,
      approvedAt: this.approvedAt,
      approvedBy: this.approvedBy,
      publishedAt: this.publishedAt,
      publishedBy: this.publishedBy,
      auditLog: this.auditLog,
      relatedIntelligence: this.relatedIntelligence,
      sources: this.sources,
      references: this.references,
      dataClassification: this.dataClassification,
      tlp: this.tlp,
      distribution: this.distribution,
      expiration: this.expiration,
    };
  }

  /**
   * Deserialize from storage.
   */
  static fromJSON(data) {
    return new IntelligenceObject(data.type, data);
  }
}

/**
 * Generate deterministic intelligence ID.
 * Type + content hash ensures same intelligence object always has same ID.
 */
function generateIntelligenceId(type, contentSeed = '') {
  const hash = crypto
    .createHash('sha256')
    .update(`${type}|${contentSeed}|${Date.now()}`)
    .digest('hex');
  return `intel_${type.toLowerCase()}_${hash.slice(0, 16)}`;
}

/**
 * Validate intelligence object against schema.
 */
function validateIntelligenceObject(obj) {
  const errors = [];

  if (!INTELLIGENCE_TYPES[obj.type]) {
    errors.push(`Invalid type: ${obj.type}`);
  }
  if (!LIFECYCLE_STATES[obj.status]) {
    errors.push(`Invalid status: ${obj.status}`);
  }
  if (!CONFIDENCE_LEVELS[obj.confidence]) {
    errors.push(`Invalid confidence: ${obj.confidence}`);
  }
  if (!SEVERITY_LEVELS[obj.severity]) {
    errors.push(`Invalid severity: ${obj.severity}`);
  }
  if (!obj.id) {
    errors.push('Missing id');
  }
  if (!obj.title) {
    errors.push('Missing title');
  }

  return { valid: errors.length === 0, errors };
}

module.exports = {
  IntelligenceObject,
  INTELLIGENCE_TYPES,
  LIFECYCLE_STATES,
  CONFIDENCE_LEVELS,
  SEVERITY_LEVELS,
  generateIntelligenceId,
  validateIntelligenceObject,
};
