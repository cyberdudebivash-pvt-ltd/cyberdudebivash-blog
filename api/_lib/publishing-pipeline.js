/**
 * SENTINEL APEX — Publishing Pipeline
 * Automated workflow for intelligence publication.
 * Coordinates review, approval, quality checks, and publication to customers.
 */
'use strict';

const { IntelligenceManager } = require('./intelligence-manager');
const governance = require('./governance-engine');

/**
 * Publishing Pipeline — production orchestrator.
 * Handles: auto-submission, review coordination, approval, publishing, distribution.
 */
class PublishingPipeline {
  constructor(redis) {
    this.redis = redis;
    this.manager = new IntelligenceManager(redis);
  }

  /**
   * Submit intelligence for review (DRAFT → REVIEW).
   * Validates that intelligence meets minimum requirements before review.
   */
  async submitForReview(intelligenceId, actor = 'system', reason = '') {
    const obj = await this.manager.getIntelligence(intelligenceId);
    if (!obj) {
      throw new Error(`Intelligence not found: ${intelligenceId}`);
    }

    // Governance check
    const govCheck = await governance.enforceGovernance(
      obj,
      'SUBMIT_REVIEW',
      'analyst',
      this.redis
    );
    if (!govCheck.allowed) {
      throw new Error(`Cannot submit for review: ${govCheck.reason}`);
    }

    // Validate against policies
    const { valid, errors } = governance.validateAgainstPolicies(obj);
    if (!valid) {
      throw new Error(`Policy violations: ${errors.join('; ')}`);
    }

    // Transition
    const result = await this.manager.transitionIntelligence(
      intelligenceId,
      'review',
      actor,
      reason || 'Submitted for review'
    );

    // Generate review checklist
    const checklist = governance.generateReviewChecklist(obj);
    await this.redis.hset(
      `intelligence:review:${intelligenceId}`,
      'checklist',
      JSON.stringify(checklist)
    );

    // Notify reviewers
    await this.notifyReviewers(intelligenceId, obj);

    // Audit
    await governance.auditGovernanceAction(this.redis, 'SUBMIT_REVIEW', actor, intelligenceId, { reason });

    return result;
  }

  /**
   * Approve intelligence for publication (REVIEW → APPROVED).
   * Can only be done by reviewers. Records approval.
   */
  async approveForPublication(intelligenceId, actor = 'reviewer', reason = '', feedback = '') {
    const obj = await this.manager.getIntelligence(intelligenceId);
    if (!obj) {
      throw new Error(`Intelligence not found: ${intelligenceId}`);
    }

    // Governance check
    const govCheck = await governance.enforceGovernance(
      obj,
      'APPROVE_INTELLIGENCE',
      'reviewer',
      this.redis
    );
    if (!govCheck.allowed) {
      throw new Error(`Cannot approve: ${govCheck.reason}`);
    }

    // Transition
    const result = await this.manager.transitionIntelligence(
      intelligenceId,
      'approved',
      actor,
      reason || 'Approved for publication'
    );

    // Record review feedback
    await this.redis.zadd(
      `intelligence:approvals:${intelligenceId}`,
      Date.now(),
      JSON.stringify({
        actor,
        timestamp: new Date().toISOString(),
        feedback,
      })
    );

    // Audit
    await governance.auditGovernanceAction(this.redis, 'APPROVE_INTELLIGENCE', actor, intelligenceId, { feedback });

    return result;
  }

  /**
   * Publish intelligence to production (APPROVED → PUBLISHED).
   * Triggers distribution to all channels (API, webhooks, email, etc.)
   */
  async publishToProduction(intelligenceId, actor = 'publisher', reason = '') {
    const obj = await this.manager.getIntelligence(intelligenceId);
    if (!obj) {
      throw new Error(`Intelligence not found: ${intelligenceId}`);
    }

    if (obj.status !== 'approved') {
      throw new Error(`Can only publish APPROVED intelligence. Current status: ${obj.status}`);
    }

    // Governance check
    const govCheck = await governance.enforceGovernance(
      obj,
      'PUBLISH_INTELLIGENCE',
      'publisher',
      this.redis
    );
    if (!govCheck.allowed) {
      throw new Error(`Cannot publish: ${govCheck.reason}`);
    }

    // Transition
    const result = await this.manager.publishIntelligence(intelligenceId, actor);

    // Trigger distribution
    await this.distributeIntelligence(intelligenceId, result);

    // Audit
    await governance.auditGovernanceAction(this.redis, 'PUBLISH_INTELLIGENCE', actor, intelligenceId);

    return result;
  }

  /**
   * Distribute published intelligence to all channels.
   * - Add to published feed
   * - Send webhooks to subscribers
   * - Queue for email digest
   * - Update knowledge graph
   * - Index for search
   */
  async distributeIntelligence(intelligenceId, intelligenceObject) {
    try {
      // Add to published feed (most recent first)
      await this.redis.zadd(
        'intelligence:published:feed',
        -Date.now(), // negative for reverse sort (newest first)
        intelligenceId
      );

      // Index by type
      await this.redis.zadd(
        `intelligence:published:by:type:${intelligenceObject.type}`,
        -Date.now(),
        intelligenceId
      );

      // Queue for email digest
      await this.redis.zadd(
        'intelligence:email:queue',
        Date.now(),
        JSON.stringify({
          intelligenceId,
          type: intelligenceObject.type,
          title: intelligenceObject.title,
          severity: intelligenceObject.severity,
        })
      );

      // Trigger webhooks to subscribers
      await this.triggerWebhooks(intelligenceObject);

      // Trigger knowledge graph update
      await this.updateKnowledgeGraph(intelligenceObject);

      return { distributed: true };
    } catch (e) {
      console.error(`Distribution failed for ${intelligenceId}: ${e.message}`);
      throw new Error(`Failed to distribute intelligence: ${e.message}`);
    }
  }

  /**
   * Send webhooks to subscribers who are watching this type of intelligence.
   */
  async triggerWebhooks(intelligenceObject) {
    try {
      const subscribers = await this.redis.zrange(
        `webhooks:subscribers:type:${intelligenceObject.type}`,
        0,
        -1
      );

      for (const webhookUrl of subscribers) {
        // Queue webhook for async delivery (don't block publication)
        await this.redis.zadd(
          'webhooks:delivery:queue',
          Date.now(),
          JSON.stringify({
            url: webhookUrl,
            event: 'intelligence.published',
            data: intelligenceObject,
          })
        );
      }

      return { webhooksQueued: subscribers.length };
    } catch (e) {
      console.error(`Failed to trigger webhooks: ${e.message}`);
      return { webhooksQueued: 0, error: e.message };
    }
  }

  /**
   * Update knowledge graph with new intelligence relationships.
   * This is called after publication to make intelligence discoverable.
   */
  async updateKnowledgeGraph(intelligenceObject) {
    try {
      // Index related entities
      if (intelligenceObject.relatedIntelligence) {
        for (const related of intelligenceObject.relatedIntelligence) {
          await this.redis.zadd(
            `graph:edges:${intelligenceObject.id}`,
            Date.now(),
            JSON.stringify({
              target: related.id,
              type: related.relationshipType,
            })
          );
        }
      }

      // Index by tags
      if (intelligenceObject.tags) {
        for (const tag of intelligenceObject.tags) {
          await this.redis.zadd(
            `graph:tags:${tag}`,
            Date.now(),
            intelligenceObject.id
          );
        }
      }

      return { graphUpdated: true };
    } catch (e) {
      console.error(`Failed to update knowledge graph: ${e.message}`);
      return { graphUpdated: false, error: e.message };
    }
  }

  /**
   * Retract published intelligence (emergency remove from production).
   */
  async retractFromProduction(intelligenceId, actor = 'publisher', reason = '') {
    const obj = await this.manager.getIntelligence(intelligenceId);
    if (!obj) {
      throw new Error(`Intelligence not found: ${intelligenceId}`);
    }

    // Transition to retracted
    const result = await this.manager.retractIntelligence(intelligenceId, actor, reason);

    // Remove from published feed
    await this.redis.zrem('intelligence:published:feed', intelligenceId);
    await this.redis.zrem(`intelligence:published:by:type:${obj.type}`, intelligenceId);

    // Notify customers of retraction
    await this.notifyRetraction(intelligenceId, obj);

    // Audit
    await governance.auditGovernanceAction(this.redis, 'RETRACT_INTELLIGENCE', actor, intelligenceId, { reason });

    return result;
  }

  /**
   * Notify reviewers that intelligence is awaiting review.
   */
  async notifyReviewers(intelligenceId, intelligenceObject) {
    try {
      // Queue notification (for async delivery)
      await this.redis.zadd(
        'notifications:review:queue',
        Date.now(),
        JSON.stringify({
          intelligenceId,
          type: intelligenceObject.type,
          title: intelligenceObject.title,
          recipient: 'reviewers@cyberdudebivash.com',
        })
      );
      return true;
    } catch (e) {
      console.error(`Failed to notify reviewers: ${e.message}`);
      return false;
    }
  }

  /**
   * Notify customers that previously published intelligence has been retracted.
   */
  async notifyRetraction(intelligenceId, intelligenceObject) {
    try {
      // Queue notification
      await this.redis.zadd(
        'notifications:retraction:queue',
        Date.now(),
        JSON.stringify({
          intelligenceId,
          type: intelligenceObject.type,
          title: intelligenceObject.title,
          reason: 'Intelligence has been retracted from production',
        })
      );
      return true;
    } catch (e) {
      console.error(`Failed to notify retraction: ${e.message}`);
      return false;
    }
  }

  /**
   * Get pipeline status for intelligence object.
   */
  async getPipelineStatus(intelligenceId) {
    const obj = await this.manager.getIntelligence(intelligenceId);
    if (!obj) {
      return null;
    }

    const reviewChecklist = await this.redis.hgetall(`intelligence:review:${intelligenceId}`);
    const approvals = await this.redis.zrange(`intelligence:approvals:${intelligenceId}`, 0, -1);

    return {
      intelligenceId,
      currentStatus: obj.status,
      title: obj.title,
      type: obj.type,
      confidence: obj.confidence,
      createdAt: obj.createdAt,
      createdBy: obj.createdBy,
      timeline: {
        submittedFor Review: obj.reviewedAt ? { at: obj.reviewedAt, by: obj.reviewedBy } : null,
        approved: obj.approvedAt ? { at: obj.approvedAt, by: obj.approvedBy } : null,
        published: obj.publishedAt ? { at: obj.publishedAt, by: obj.publishedBy } : null,
      },
      reviewChecklist: reviewChecklist.checklist ? JSON.parse(reviewChecklist.checklist) : null,
      approvals: approvals.map(a => JSON.parse(a)),
      nextActions: this.getNextActions(obj.status),
    };
  }

  /**
   * Get recommended next actions based on current status.
   */
  getNextActions(status) {
    const actions = {
      draft: ['Submit for review'],
      review: ['Request changes', 'Approve for publication'],
      approved: ['Publish to production'],
      published: ['Retract from production (emergency only)', 'Archive'],
      archived: [],
      retracted: ['Archive'],
    };
    return actions[status] || [];
  }
}

module.exports = {
  PublishingPipeline,
};
