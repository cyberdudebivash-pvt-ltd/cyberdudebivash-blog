/**
 * SENTINEL APEX — Governance Engine
 * Policy enforcement layer for intelligence objects.
 * Controls who can create, review, approve, and publish intelligence.
 */
'use strict';

/**
 * Role-based access control for intelligence operations.
 */
const ROLES = {
  ANALYST:     'analyst',      // Can create and update intelligence
  REVIEWER:    'reviewer',     // Can review and approve
  PUBLISHER:   'publisher',    // Can publish to production
  ADMIN:       'admin',        // Can do anything
};

/**
 * Permission matrix: which roles can perform which actions.
 */
const PERMISSIONS = {
  CREATE_INTELLIGENCE:    [ROLES.ANALYST, ROLES.PUBLISHER, ROLES.ADMIN],
  UPDATE_INTELLIGENCE:    [ROLES.ANALYST, ROLES.PUBLISHER, ROLES.ADMIN],
  SUBMIT_REVIEW:          [ROLES.ANALYST, ROLES.PUBLISHER, ROLES.ADMIN],
  REVIEW_INTELLIGENCE:    [ROLES.REVIEWER, ROLES.PUBLISHER, ROLES.ADMIN],
  APPROVE_INTELLIGENCE:   [ROLES.REVIEWER, ROLES.PUBLISHER, ROLES.ADMIN],
  PUBLISH_INTELLIGENCE:   [ROLES.PUBLISHER, ROLES.ADMIN],
  RETRACT_INTELLIGENCE:   [ROLES.PUBLISHER, ROLES.ADMIN],
  DELETE_INTELLIGENCE:    [ROLES.ADMIN],
  VIEW_AUDIT_LOG:         [ROLES.REVIEWER, ROLES.PUBLISHER, ROLES.ADMIN],
};

/**
 * Governance policies — rules that intelligence objects must follow.
 */
const GOVERNANCE_POLICIES = {
  /**
   * Minimum review requirement: how many reviewers must approve before publishing?
   */
  MIN_APPROVERS: 1,

  /**
   * Confidence floor: intelligence below this confidence level cannot be published.
   */
  MIN_CONFIDENCE_TO_PUBLISH: 'MEDIUM',

  /**
   * Source validation: intelligence must cite at least this many sources.
   */
  MIN_SOURCES: 1,

  /**
   * Data classification: which intelligence types require special handling?
   */
  DATA_CLASSIFICATION_RULES: {
    THREAT_ACTOR: 'CONFIDENTIAL',
    MALWARE: 'PUBLIC',
    VULNERABILITY: 'PUBLIC',
    CAMPAIGN: 'CONFIDENTIAL',
  },

  /**
   * TTL (Time To Live): how long is intelligence valid before requiring review?
   */
  INTELLIGENCE_TTL_DAYS: 90,

  /**
   * Retention: how long to keep archived intelligence?
   */
  RETENTION_DAYS: 365,
};

/**
 * Check if a user/role can perform an action.
 */
function canPerformAction(userRole, action) {
  if (!ROLES[userRole]) return false;
  const allowedRoles = PERMISSIONS[action] || [];
  return allowedRoles.includes(userRole);
}

/**
 * Validate intelligence against governance policies.
 */
function validateAgainstPolicies(intelligenceObject) {
  const errors = [];

  // Confidence floor
  const confidenceLevels = { HIGH: 3, MEDIUM: 2, LOW: 1 };
  const minLevel = confidenceLevels[GOVERNANCE_POLICIES.MIN_CONFIDENCE_TO_PUBLISH];
  const objLevel = confidenceLevels[intelligenceObject.confidence];

  if (objLevel < minLevel && intelligenceObject.status === 'published') {
    errors.push(`Confidence (${intelligenceObject.confidence}) below minimum (${GOVERNANCE_POLICIES.MIN_CONFIDENCE_TO_PUBLISH}) for publication`);
  }

  // Source requirement
  if ((intelligenceObject.sources || []).length < GOVERNANCE_POLICIES.MIN_SOURCES) {
    errors.push(`Intelligence must cite at least ${GOVERNANCE_POLICIES.MIN_SOURCES} source(s)`);
  }

  // Data classification
  const classRule = GOVERNANCE_POLICIES.DATA_CLASSIFICATION_RULES[intelligenceObject.type];
  if (classRule && intelligenceObject.dataClassification !== classRule) {
    errors.push(`Intelligence type ${intelligenceObject.type} requires classification: ${classRule}`);
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Check if intelligence requires additional reviews before publication.
 */
function determineReviewRequirement(intelligenceObject) {
  const requirements = {
    minApprovers: GOVERNANCE_POLICIES.MIN_APPROVERS,
    requiresSecurityReview: ['THREAT_ACTOR', 'MALWARE', 'CAMPAIGN'].includes(intelligenceObject.type),
    requiresLegalReview: ['MALWARE', 'CAMPAIGN'].includes(intelligenceObject.type),
    requiresIndustryReview: intelligenceObject.severity === 'CRITICAL',
  };

  return requirements;
}

/**
 * Generate review checklist for analysts.
 */
function generateReviewChecklist(intelligenceObject) {
  return {
    contentAccuracy: {
      completed: false,
      description: 'Verify all facts and claims are accurate and sourced',
    },
    sourceValidation: {
      completed: false,
      description: 'Confirm all sources are credible and properly cited',
    },
    confidenceJustification: {
      completed: false,
      description: 'Verify confidence level is justified by evidence',
    },
    relevance: {
      completed: false,
      description: 'Confirm intelligence is actionable for enterprise customers',
    },
    compliance: {
      completed: false,
      description: 'Verify intelligence meets TLP and data classification requirements',
    },
    ...(determineReviewRequirement(intelligenceObject).requiresSecurityReview && {
      securityImplications: {
        completed: false,
        description: 'Review for sensitive security information that should not be published',
      },
    }),
    ...(determineReviewRequirement(intelligenceObject).requiresLegalReview && {
      legalCompliance: {
        completed: false,
        description: 'Legal review for attribution claims and liability',
      },
    }),
  };
}

/**
 * Audit access to sensitive intelligence operations.
 */
async function auditGovernanceAction(redis, action, actor, intelligenceId, metadata = {}) {
  const auditEntry = JSON.stringify({
    action,
    actor,
    intelligenceId,
    timestamp: new Date().toISOString(),
    metadata,
  });

  try {
    await redis.zadd('governance:audit:log', Date.now(), auditEntry);
    await redis.zadd(`governance:audit:by:actor:${actor}`, Date.now(), auditEntry);
    await redis.zadd(`governance:audit:by:action:${action}`, Date.now(), auditEntry);
  } catch (e) {
    console.error(`Failed to audit governance action: ${e.message}`);
  }
}

/**
 * Enforce governance constraints before allowing state transitions.
 */
async function enforceGovernance(intelligenceObject, targetAction, userRole, redis) {
  // Permission check
  if (!canPerformAction(userRole, targetAction)) {
    return {
      allowed: false,
      reason: `Role ${userRole} is not permitted to ${targetAction}`,
    };
  }

  // Policy validation
  const { valid, errors } = validateAgainstPolicies(intelligenceObject);
  if (!valid) {
    return {
      allowed: false,
      reason: `Policy violation: ${errors.join('; ')}`,
      violations: errors,
    };
  }

  // Review requirements
  if (targetAction === 'PUBLISH_INTELLIGENCE') {
    const requirements = determineReviewRequirement(intelligenceObject);
    if (intelligenceObject.approvedBy === null || !intelligenceObject.approvedAt) {
      return {
        allowed: false,
        reason: `Intelligence must be approved before publication`,
      };
    }
  }

  return { allowed: true };
}

module.exports = {
  ROLES,
  PERMISSIONS,
  GOVERNANCE_POLICIES,
  canPerformAction,
  validateAgainstPolicies,
  determineReviewRequirement,
  generateReviewChecklist,
  auditGovernanceAction,
  enforceGovernance,
};
