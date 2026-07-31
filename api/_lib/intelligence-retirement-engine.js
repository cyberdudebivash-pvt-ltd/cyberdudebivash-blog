'use strict';

class IntelligenceRetirementEngine {
  constructor() {
    this.retirements = new Map();
    this.lineage = new Map();
    this.supersessions = new Map();
  }

  archiveIntelligence(reportId, reason, actor, metadata = {}) {
    const retirementId = `retire_${reportId}_${Date.now()}`;

    const retirement = {
      id: retirementId,
      reportId,
      status: 'archived',
      reason,
      actor,
      timestamp: new Date().toISOString(),
      metadata,
      archivedAt: new Date().toISOString(),
      replacementReport: null,
      replacementReason: null,
      reversible: true,
    };

    this.retirements.set(retirementId, retirement);
    this.recordLineage(reportId, 'archived', null, retirement);

    return retirement;
  }

  supersede(reportId, replacementReportId, reason, actor) {
    if (!replacementReportId) {
      throw new Error('Replacement report ID required for supersession');
    }

    const retirementId = `retire_${reportId}_${Date.now()}`;

    const retirement = {
      id: retirementId,
      reportId,
      status: 'superseded',
      reason,
      actor,
      timestamp: new Date().toISOString(),
      replacementReport: replacementReportId,
      replacementReason: `Superseded by ${replacementReportId}`,
      archivedAt: new Date().toISOString(),
      reversible: false,
    };

    this.retirements.set(retirementId, retirement);
    this.recordSupersession(reportId, replacementReportId, retirement);
    this.recordLineage(reportId, 'superseded', replacementReportId, retirement);

    return retirement;
  }

  withdrawIntelligence(reportId, reason, actor, scope = 'full') {
    const retirementId = `retire_${reportId}_${Date.now()}`;

    const withdrawal = {
      id: retirementId,
      reportId,
      status: 'withdrawn',
      scope: scope, // full, partial, selective
      reason,
      actor,
      timestamp: new Date().toISOString(),
      withdrawnAt: new Date().toISOString(),
      replacementReport: null,
      reversible: true,
      canPublishPartial: scope === 'partial' || scope === 'selective',
    };

    this.retirements.set(retirementId, withdrawal);
    this.recordLineage(reportId, 'withdrawn', null, withdrawal);

    return withdrawal;
  }

  retractIntelligence(reportId, reason, actor, affectedClaims = []) {
    const retirementId = `retire_${reportId}_${Date.now()}`;

    const retraction = {
      id: retirementId,
      reportId,
      status: 'retracted',
      reason,
      actor,
      timestamp: new Date().toISOString(),
      retractedAt: new Date().toISOString(),
      affectedClaims,
      affectedClaimCount: affectedClaims.length,
      reversible: false,
      correctionAvailable: true,
      correctionReportId: null,
    };

    this.retirements.set(retirementId, retraction);
    this.recordLineage(reportId, 'retracted', null, retraction);

    return retraction;
  }

  deprecateIntelligence(reportId, reason, actor, replacementReportId = null, sunsetDate) {
    const retirementId = `retire_${reportId}_${Date.now()}`;

    const deprecation = {
      id: retirementId,
      reportId,
      status: 'deprecated',
      reason,
      actor,
      timestamp: new Date().toISOString(),
      deprecatedAt: new Date().toISOString(),
      sunsetDate: sunsetDate || new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
      replacementReport: replacementReportId,
      reversible: true,
      stillReadable: true,
      stillDistributable: true,
    };

    this.retirements.set(retirementId, deprecation);
    if (replacementReportId) {
      this.recordLineage(reportId, 'deprecated', replacementReportId, deprecation);
    } else {
      this.recordLineage(reportId, 'deprecated', null, deprecation);
    }

    return deprecation;
  }

  recordSupersession(reportId, replacementId, retirement) {
    if (!this.supersessions.has(reportId)) {
      this.supersessions.set(reportId, []);
    }

    this.supersessions.get(reportId).push({
      replacedBy: replacementId,
      timestamp: retirement.timestamp,
      reason: retirement.reason,
      actor: retirement.actor,
    });
  }

  recordLineage(reportId, action, replacementId, retirement) {
    if (!this.lineage.has(reportId)) {
      this.lineage.set(reportId, {
        original: reportId,
        history: [],
        current: reportId,
      });
    }

    const lineageRecord = this.lineage.get(reportId);

    lineageRecord.history.push({
      action,
      timestamp: retirement.timestamp,
      actor: retirement.actor,
      reason: retirement.reason,
      replacementId,
    });

    if (action === 'superseded' && replacementId) {
      lineageRecord.current = replacementId;

      if (!this.lineage.has(replacementId)) {
        this.lineage.set(replacementId, {
          original: lineageRecord.original,
          history: lineageRecord.history.slice(),
          current: replacementId,
          predecessor: reportId,
        });
      } else {
        const replacementLineage = this.lineage.get(replacementId);
        replacementLineage.predecessor = reportId;
        replacementLineage.original = lineageRecord.original;
      }
    }
  }

  getLineage(reportId) {
    const lineage = this.lineage.get(reportId);

    if (!lineage) {
      return {
        reportId,
        lineage: null,
        status: 'active',
      };
    }

    return {
      reportId,
      original: lineage.original,
      current: lineage.current,
      predecessor: lineage.predecessor || null,
      successor: this.findSuccessor(reportId),
      history: lineage.history,
      status: this.determineStatus(lineage),
    };
  }

  findSuccessor(reportId) {
    for (const [id, lineage] of this.lineage.entries()) {
      if (lineage.predecessor === reportId) {
        return id;
      }
    }
    return null;
  }

  determineStatus(lineage) {
    if (lineage.history.length === 0) return 'active';

    const lastEvent = lineage.history[lineage.history.length - 1];
    return lastEvent.action;
  }

  getRetirementDetails(retirementId) {
    const retirement = this.retirements.get(retirementId);
    if (!retirement) throw new Error(`Retirement not found: ${retirementId}`);

    return {
      ...retirement,
      lineage: this.getLineage(retirement.reportId),
    };
  }

  getRetirementHistory(reportId) {
    const history = [];

    this.retirements.forEach((retirement, id) => {
      if (retirement.reportId === reportId) {
        history.push({
          retirementId: id,
          status: retirement.status,
          timestamp: retirement.timestamp,
          actor: retirement.actor,
          reason: retirement.reason,
        });
      }
    });

    return {
      reportId,
      retirementCount: history.length,
      history: history.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)),
    };
  }

  restoreFromRetirement(retirementId, actor, reason = '') {
    const retirement = this.retirements.get(retirementId);
    if (!retirement) throw new Error(`Retirement not found: ${retirementId}`);
    if (!retirement.reversible) throw new Error(`Retirement cannot be reversed: ${retirementId}`);

    const restoration = {
      retirementId,
      reportId: retirement.reportId,
      restoredAt: new Date().toISOString(),
      restoredBy: actor,
      reason,
      previousStatus: retirement.status,
      newStatus: 'active',
    };

    retirement.status = 'restored';
    retirement.restorationDetails = restoration;

    const lineage = this.lineage.get(retirement.reportId);
    if (lineage && lineage.history.length > 0) {
      lineage.history.push({
        action: 'restored',
        timestamp: restoration.restoredAt,
        actor,
        reason,
      });
    }

    return restoration;
  }

  buildSupersessionChain(reportId, direction = 'forward') {
    const chain = [];
    let currentId = reportId;

    if (direction === 'forward') {
      while (currentId) {
        chain.push(currentId);
        currentId = this.findSuccessor(currentId);
      }
    } else if (direction === 'backward') {
      while (currentId) {
        chain.push(currentId);
        const lineage = this.lineage.get(currentId);
        currentId = lineage?.predecessor || null;
      }
    }

    return {
      startReport: reportId,
      direction,
      chain,
      chainLength: chain.length,
    };
  }

  getRetiredIntelligence(filters = {}) {
    const retired = [];

    this.retirements.forEach((retirement, id) => {
      if (filters.status && retirement.status !== filters.status) return;
      if (filters.actor && retirement.actor !== filters.actor) return;

      if (filters.sinceDate) {
        if (new Date(retirement.timestamp) < new Date(filters.sinceDate)) return;
      }

      retired.push({
        retirementId: id,
        reportId: retirement.reportId,
        status: retirement.status,
        timestamp: retirement.timestamp,
        actor: retirement.actor,
        reason: retirement.reason,
        replacementReport: retirement.replacementReport,
      });
    });

    const byStatus = {};
    retired.forEach(r => {
      byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    });

    return {
      total: retired.length,
      byStatus,
      retired: retired.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)),
    };
  }

  validateRetirementIntegrity(reportId) {
    const lineage = this.lineage.get(reportId);
    const retirements = this.getRetirementHistory(reportId);

    const integrity = {
      reportId,
      hasLineage: !!lineage,
      hasRetirements: retirements.retirementCount > 0,
      lineageConsistent: this.validateLineageConsistency(reportId),
      allRetainsActor: retirements.history.every(h => h.actor),
      allRetainReason: retirements.history.every(h => h.reason),
    };

    return {
      ...integrity,
      status: Object.values(integrity).every(v => v === true || typeof v === 'number') ? 'valid' : 'invalid',
    };
  }

  validateLineageConsistency(reportId) {
    const lineage = this.lineage.get(reportId);
    if (!lineage) return true;

    for (const event of lineage.history) {
      if (event.action === 'superseded' && event.replacementId) {
        const replacement = this.lineage.get(event.replacementId);
        if (!replacement) return false;
      }
    }

    return true;
  }

  getRetirementMetrics(startDate, endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);

    const metrics = {
      archived: 0,
      superseded: 0,
      withdrawn: 0,
      retracted: 0,
      deprecated: 0,
      restored: 0,
      byActor: {},
    };

    this.retirements.forEach(retirement => {
      if (new Date(retirement.timestamp) >= start && new Date(retirement.timestamp) <= end) {
        metrics[retirement.status] = (metrics[retirement.status] || 0) + 1;

        if (!metrics.byActor[retirement.actor]) {
          metrics.byActor[retirement.actor] = 0;
        }
        metrics.byActor[retirement.actor]++;
      }
    });

    return {
      period: { start: startDate, end: endDate },
      ...metrics,
      total: Object.values(metrics).reduce((sum, v) => {
        if (typeof v === 'number') return sum + v;
        return sum;
      }, 0) - Object.keys(metrics.byActor).length,
    };
  }
}

module.exports = { IntelligenceRetirementEngine };
