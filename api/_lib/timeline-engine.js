'use strict';

class TimelineEngine {
  constructor(redis, investigationManager, intelligenceManager) {
    this.redis = redis;
    this.investigationManager = investigationManager;
    this.manager = intelligenceManager;
  }

  async buildInvestigationTimeline(investigationId) {
    const investigation = await this.investigationManager.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const events = [];

    // Add investigation creation event
    events.push({
      timestamp: investigation.createdAt,
      action: 'INVESTIGATION_CREATED',
      actor: investigation.createdBy,
      description: `Investigation created: ${investigation.title}`,
      source: 'investigation',
      severity: 'info',
    });

    // Add linked intelligence events
    if (investigation.linkedIntelligence && investigation.linkedIntelligence.length > 0) {
      for (const intelId of investigation.linkedIntelligence) {
        try {
          const intel = await this.manager.getIntelligence(intelId);
          if (intel) {
            events.push({
              timestamp: intel.createdAt,
              action: 'INTELLIGENCE_DISCOVERED',
              actor: intel.createdBy,
              description: `${intel.type.toUpperCase()} discovered: ${intel.title}`,
              source: 'intelligence',
              severity: intel.severity || 'medium',
              intelId,
              intelType: intel.type,
            });

            if (intel.reviewedAt) {
              events.push({
                timestamp: intel.reviewedAt,
                action: 'INTELLIGENCE_REVIEWED',
                actor: intel.reviewedBy,
                description: `Intelligence reviewed: ${intel.title}`,
                source: 'intelligence',
                severity: 'info',
              });
            }

            if (intel.publishedAt) {
              events.push({
                timestamp: intel.publishedAt,
                action: 'INTELLIGENCE_PUBLISHED',
                actor: intel.publishedBy,
                description: `Intelligence published: ${intel.title}`,
                source: 'intelligence',
                severity: 'info',
              });
            }
          }
        } catch (e) {
          // Skip if intelligence not found
        }
      }
    }

    // Add investigation updates from audit trail
    const auditEvents = await this.redis.zrange(
      `investigation:audit:${investigationId}`,
      0,
      -1
    );

    for (const auditEvent of auditEvents) {
      try {
        const audit = JSON.parse(auditEvent);
        events.push({
          timestamp: audit.timestamp,
          action: audit.action,
          actor: audit.actor,
          description: this.describeAction(audit.action, audit.metadata),
          source: 'investigation',
          severity: audit.action === 'CLOSE' ? 'high' : 'info',
        });
      } catch (e) {
        // Skip malformed audit
      }
    }

    // Add evidence events
    const evidenceEvents = await this.redis.zrange(
      `investigation:timeline:${investigationId}`,
      0,
      -1
    );

    for (const evidEvent of evidenceEvents) {
      try {
        const event = JSON.parse(evidEvent);
        events.push({
          timestamp: event.timestamp,
          action: event.action,
          description: event.metadata ? `Evidence: ${event.metadata.title}` : 'Evidence added',
          source: 'evidence',
          severity: 'info',
        });
      } catch (e) {
        // Skip malformed event
      }
    }

    // Sort chronologically
    events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    // Deduplicate and cache
    const uniqueEvents = this.deduplicateEvents(events);
    await this.redis.set(
      `investigation:timeline:cached:${investigationId}`,
      JSON.stringify(uniqueEvents),
      'EX',
      3600
    );

    return uniqueEvents;
  }

  async getTimelineStats(investigationId) {
    const timeline = await this.buildInvestigationTimeline(investigationId);

    const stats = {
      totalEvents: timeline.length,
      eventsByAction: {},
      eventsBySource: {},
      eventsBySeverity: {},
      timespan: null,
    };

    for (const event of timeline) {
      stats.eventsByAction[event.action] = (stats.eventsByAction[event.action] || 0) + 1;
      stats.eventsBySource[event.source] = (stats.eventsBySource[event.source] || 0) + 1;
      stats.eventsBySeverity[event.severity] = (stats.eventsBySeverity[event.severity] || 0) + 1;
    }

    if (timeline.length > 0) {
      const first = new Date(timeline[0].timestamp);
      const last = new Date(timeline[timeline.length - 1].timestamp);
      stats.timespan = {
        start: first.toISOString(),
        end: last.toISOString(),
        durationDays: Math.ceil((last - first) / (1000 * 60 * 60 * 24)),
      };
    }

    return stats;
  }

  describeAction(action, metadata) {
    const descriptions = {
      CREATE: 'Investigation created',
      UPDATE: `Updated: ${metadata?.title || 'metadata'}`,
      LINK_INTELLIGENCE: `Linked intelligence: ${metadata?.intelligenceId}`,
      UNLINK_INTELLIGENCE: `Unlinked intelligence: ${metadata?.intelligenceId}`,
      CLOSE: `Investigation closed: ${metadata?.closureReason || 'no reason given'}`,
      EVIDENCE_ADDED: `Evidence added: ${metadata?.title}`,
    };

    return descriptions[action] || action;
  }

  deduplicateEvents(events) {
    const seen = new Set();
    const unique = [];

    for (const event of events) {
      const key = `${event.timestamp}:${event.action}:${event.description}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(event);
      }
    }

    return unique;
  }

  async buildIntelligenceTimeline(intelligenceId) {
    const intelligence = await this.manager.getIntelligence(intelligenceId);
    if (!intelligence) throw new Error(`Intelligence not found: ${intelligenceId}`);

    const events = [];

    events.push({
      timestamp: intelligence.createdAt,
      action: 'CREATED',
      actor: intelligence.createdBy,
      status: 'draft',
    });

    if (intelligence.reviewedAt) {
      events.push({
        timestamp: intelligence.reviewedAt,
        action: 'REVIEWED',
        actor: intelligence.reviewedBy,
        status: 'review',
      });
    }

    if (intelligence.approvedAt) {
      events.push({
        timestamp: intelligence.approvedAt,
        action: 'APPROVED',
        actor: intelligence.approvedBy,
        status: 'approved',
      });
    }

    if (intelligence.publishedAt) {
      events.push({
        timestamp: intelligence.publishedAt,
        action: 'PUBLISHED',
        actor: intelligence.publishedBy,
        status: 'published',
      });
    }

    return events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  }
}

module.exports = {
  TimelineEngine,
};
