'use strict';

class IntelligencMaintenanceEngine {
  constructor() {
    this.revisions = new Map();
    this.updateHistory = new Map();
    this.changeLog = new Map();
  }

  createIntelligenceRevision(reportId, changeType, previousData, updatedData, actor, reason) {
    const revisionId = `rev_${reportId}_${Date.now()}`;

    const revision = {
      id: revisionId,
      reportId,
      changeType,
      previousData,
      updatedData,
      actor,
      reason,
      timestamp: new Date().toISOString(),
      status: 'applied',
      appliedAt: new Date().toISOString(),
      reversible: this.isReversible(changeType),
    };

    this.revisions.set(revisionId, revision);
    this.recordUpdate(reportId, changeType, revision);
    return revision;
  }

  isReversible(changeType) {
    const reversibleTypes = ['ioc_update', 'confidence_revision', 'attribution_update', 'metadata_update'];
    const irreversibleTypes = ['deprecate', 'archive', 'retire'];
    return reversibleTypes.includes(changeType) && !irreversibleTypes.includes(changeType);
  }

  recordUpdate(reportId, changeType, revision) {
    if (!this.updateHistory.has(reportId)) {
      this.updateHistory.set(reportId, []);
    }
    const history = this.updateHistory.get(reportId);
    history.push({
      revisionId: revision.id,
      changeType,
      timestamp: revision.timestamp,
      actor: revision.actor,
      reason: revision.reason,
    });
  }

  updateIOCs(reportId, previousIOCs, updatedIOCs, actor, reason = '') {
    const iocChanges = {
      added: updatedIOCs.filter(u => !previousIOCs.some(p => p.value === u.value)),
      removed: previousIOCs.filter(p => !updatedIOCs.some(u => u.value === p.value)),
      modified: updatedIOCs.filter(u => {
        const prev = previousIOCs.find(p => p.value === u.value);
        return prev && JSON.stringify(prev) !== JSON.stringify(u);
      }),
    };

    return this.createIntelligenceRevision(
      reportId,
      'ioc_update',
      { iocs: previousIOCs },
      { iocs: updatedIOCs, changes: iocChanges },
      actor,
      reason || 'IOC list updated'
    );
  }

  updateAttribution(reportId, previousAttribution, updatedAttribution, actor, reason = '') {
    const attributionShift = {
      previousActors: previousAttribution.actors || [],
      updatedActors: updatedAttribution.actors || [],
      confidenceChange: updatedAttribution.confidence - previousAttribution.confidence,
      evidenceUpdate: updatedAttribution.evidence || [],
    };

    return this.createIntelligenceRevision(
      reportId,
      'attribution_update',
      previousAttribution,
      updatedAttribution,
      actor,
      reason || 'Attribution updated'
    );
  }

  updateConfidence(reportId, previousScore, updatedScore, factors, actor, reason = '') {
    const confidenceAdjustment = {
      from: previousScore,
      to: updatedScore,
      delta: updatedScore - previousScore,
      factors: factors || [],
    };

    return this.createIntelligenceRevision(
      reportId,
      'confidence_revision',
      { confidenceScore: previousScore },
      { confidenceScore: updatedScore, adjustment: confidenceAdjustment },
      actor,
      reason || 'Confidence score revised'
    );
  }

  updateDetections(reportId, previousDetections, updatedDetections, actor, reason = '') {
    const detectionChanges = {
      added: updatedDetections.filter(u => !previousDetections.some(p => p.id === u.id)),
      removed: previousDetections.filter(p => !updatedDetections.some(u => u.id === p.id)),
      modified: updatedDetections.filter(u => {
        const prev = previousDetections.find(p => p.id === u.id);
        return prev && JSON.stringify(prev) !== JSON.stringify(u);
      }),
    };

    return this.createIntelligenceRevision(
      reportId,
      'detection_update',
      { detections: previousDetections },
      { detections: updatedDetections, changes: detectionChanges },
      actor,
      reason || 'Detection rules updated'
    );
  }

  updateCampaignEvolution(reportId, previousEvolution, updatedEvolution, actor, reason = '') {
    return this.createIntelligenceRevision(
      reportId,
      'campaign_evolution_update',
      previousEvolution,
      updatedEvolution,
      actor,
      reason || 'Campaign evolution tracking updated'
    );
  }

  updateThreatActorIntelligence(reportId, previousActor, updatedActor, actor, reason = '') {
    const actorChanges = {
      aliasesAdded: updatedActor.aliases?.filter(a => !previousActor.aliases?.includes(a)) || [],
      aliasesRemoved: previousActor.aliases?.filter(a => !updatedActor.aliases?.includes(a)) || [],
      firstSeenUpdated: previousActor.firstSeen !== updatedActor.firstSeen,
      lastSeenUpdated: previousActor.lastSeen !== updatedActor.lastSeen,
      capabilitiesChanged: JSON.stringify(previousActor.capabilities) !== JSON.stringify(updatedActor.capabilities),
    };

    return this.createIntelligenceRevision(
      reportId,
      'threat_actor_update',
      previousActor,
      updatedActor,
      actor,
      reason || 'Threat actor intelligence updated'
    );
  }

  getRevisionHistory(reportId) {
    const history = this.updateHistory.get(reportId) || [];

    return {
      reportId,
      totalRevisions: history.length,
      revisions: history,
      timeline: history.map(h => ({
        timestamp: h.timestamp,
        changeType: h.changeType,
        actor: h.actor,
        reason: h.reason,
      })),
      lastUpdated: history.length > 0 ? history[history.length - 1].timestamp : null,
    };
  }

  getRevisionDetails(revisionId) {
    const revision = this.revisions.get(revisionId);
    if (!revision) throw new Error(`Revision not found: ${revisionId}`);

    return {
      id: revision.id,
      reportId: revision.reportId,
      changeType: revision.changeType,
      previousData: revision.previousData,
      updatedData: revision.updatedData,
      actor: revision.actor,
      reason: revision.reason,
      timestamp: revision.timestamp,
      status: revision.status,
      reversible: revision.reversible,
      diff: this.generateDiff(revision.previousData, revision.updatedData),
    };
  }

  generateDiff(previousData, updatedData) {
    const diff = {
      fields: {},
    };

    const allKeys = new Set([...Object.keys(previousData), ...Object.keys(updatedData)]);

    allKeys.forEach(key => {
      const prev = previousData[key];
      const updated = updatedData[key];

      if (JSON.stringify(prev) !== JSON.stringify(updated)) {
        diff.fields[key] = {
          from: prev,
          to: updated,
        };
      }
    });

    return diff;
  }

  reverseRevision(revisionId, actor, reason = '') {
    const revision = this.revisions.get(revisionId);
    if (!revision) throw new Error(`Revision not found: ${revisionId}`);
    if (!revision.reversible) throw new Error(`Revision cannot be reversed: ${revisionId}`);

    const reversal = {
      originalRevisionId: revisionId,
      reversedAt: new Date().toISOString(),
      reversedBy: actor,
      reason,
      status: 'reversed',
    };

    revision.status = 'reversed';
    revision.reversalDetails = reversal;

    return {
      revisionId,
      reversalId: `reversal_${revisionId}`,
      ...reversal,
    };
  }

  compareRevisions(revisionId1, revisionId2) {
    const rev1 = this.revisions.get(revisionId1);
    const rev2 = this.revisions.get(revisionId2);

    if (!rev1 || !rev2) throw new Error('One or both revisions not found');

    return {
      revision1: revisionId1,
      revision2: revisionId2,
      changeTypes: [rev1.changeType, rev2.changeType],
      timeline: [
        { id: rev1.id, timestamp: rev1.timestamp },
        { id: rev2.id, timestamp: rev2.timestamp },
      ],
      differences: this.generateDiff(rev1.updatedData, rev2.updatedData),
    };
  }

  getIntelligenceChangeLog(reportId) {
    const history = this.updateHistory.get(reportId) || [];

    return {
      reportId,
      changeLog: history.map(change => ({
        changeType: change.changeType,
        timestamp: change.timestamp,
        actor: change.actor,
        reason: change.reason,
        revisionId: change.revisionId,
      })),
      summaryByType: this.summarizeChangesByType(history),
      activityTimeline: this.buildActivityTimeline(history),
    };
  }

  summarizeChangesByType(history) {
    const summary = {};

    history.forEach(h => {
      summary[h.changeType] = (summary[h.changeType] || 0) + 1;
    });

    return summary;
  }

  buildActivityTimeline(history) {
    const timeline = {};

    history.forEach(change => {
      const date = change.timestamp.split('T')[0];
      if (!timeline[date]) {
        timeline[date] = [];
      }
      timeline[date].push({
        timestamp: change.timestamp,
        changeType: change.changeType,
        actor: change.actor,
      });
    });

    return timeline;
  }

  validateRevisionIntegrity(reportId) {
    const history = this.updateHistory.get(reportId) || [];

    const integrity = {
      reportId,
      totalRevisions: history.length,
      isComplete: history.length > 0,
      noGaps: this.validateNoTimelineGaps(history),
      allReversible: history.every(h => {
        const rev = this.revisions.get(h.revisionId);
        return rev && (rev.reversible || rev.status === 'reversed');
      }),
      allAuditable: history.every(h => h.actor && h.timestamp),
    };

    return {
      ...integrity,
      status: integrity.isComplete && integrity.noGaps && integrity.allAuditable ? 'valid' : 'incomplete',
    };
  }

  validateNoTimelineGaps(history) {
    if (history.length < 2) return true;

    const sorted = [...history].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    for (let i = 0; i < sorted.length - 1; i++) {
      const current = new Date(sorted[i].timestamp);
      const next = new Date(sorted[i + 1].timestamp);
      const dayGap = (next - current) / (1000 * 60 * 60 * 24);

      if (dayGap > 90) return false;
    }

    return true;
  }

  getRecentUpdates(days = 7) {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - days);

    const recentRevisions = [];

    this.revisions.forEach((revision, id) => {
      if (new Date(revision.timestamp) >= cutoff) {
        recentRevisions.push({
          revisionId: id,
          reportId: revision.reportId,
          changeType: revision.changeType,
          timestamp: revision.timestamp,
          actor: revision.actor,
        });
      }
    });

    return {
      period: { days, since: cutoff.toISOString() },
      updatedCount: recentRevisions.length,
      updates: recentRevisions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)),
      updatesByType: this.summarizeByType(recentRevisions),
    };
  }

  summarizeByType(revisions) {
    const summary = {};

    revisions.forEach(r => {
      summary[r.changeType] = (summary[r.changeType] || 0) + 1;
    });

    return summary;
  }
}

module.exports = { IntelligencMaintenanceEngine };
