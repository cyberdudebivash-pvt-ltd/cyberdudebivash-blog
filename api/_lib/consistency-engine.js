'use strict';

const redis = require('./redis');

class ConsistencyEngine {
  constructor(redisClient = redis) {
    this.redis = redisClient;
  }

  async checkIntelligenceConsistency(report, investigationId) {
    const issues = [];

    const historicalReports = await this.getHistoricalReports(investigationId);

    const attributionConflicts = await this.checkAttributionConflicts(report, historicalReports);
    issues.push(...attributionConflicts);

    const confidenceConflicts = await this.checkConfidenceConflicts(report, historicalReports);
    issues.push(...confidenceConflicts);

    const duplicateIntelligence = await this.detectDuplicateIntelligence(report, historicalReports);
    issues.push(...duplicateIntelligence);

    const timelineConflicts = await this.checkTimelineConflicts(report, historicalReports);
    issues.push(...timelineConflicts);

    const iocConflicts = await this.checkIOCConflicts(report, historicalReports);
    issues.push(...iocConflicts);

    return {
      investigationId,
      reportId: report.id,
      consistencyScore: this.calculateConsistencyScore(issues),
      issues,
      historicalReportsCount: historicalReports.length,
    };
  }

  async getHistoricalReports(investigationId) {
    const reportIds = await this.redis.zrevrange(`reports:investigation:${investigationId}`, 0, 99);
    const reports = [];

    for (const reportId of reportIds) {
      const key = `report:${reportId}`;
      const data = await this.redis.hgetall(key);

      if (data && data.length > 0) {
        const report = {};
        for (let i = 0; i < data.length; i += 2) {
          report[data[i]] = data[i + 1];
        }
        reports.push(report);
      }
    }

    return reports;
  }

  async checkAttributionConflicts(currentReport, historicalReports) {
    const issues = [];

    const currentAttributions = new Map();
    if (currentReport.assessments?.threatActors) {
      for (const actor of currentReport.assessments.threatActors) {
        currentAttributions.set(actor.attribution, actor.confidence);
      }
    }

    for (const historicalReport of historicalReports) {
      const historicalAttributions = new Map();
      if (historicalReport.assessments?.threatActors) {
        for (const actor of historicalReport.assessments.threatActors) {
          historicalAttributions.set(actor.attribution, actor.confidence);
        }
      }

      for (const [attribution, confidence] of currentAttributions.entries()) {
        if (historicalAttributions.has(attribution)) {
          const historicalConfidence = historicalAttributions.get(attribution);
          if (this.confidenceLevelValue(confidence) !== this.confidenceLevelValue(historicalConfidence)) {
            issues.push({
              severity: 'high',
              category: 'consistency',
              code: 'ATTRIBUTION_CONFIDENCE_CHANGE',
              message: `Attribution "${attribution}" confidence changed from "${historicalConfidence}" to "${confidence}"`,
              recommendation: 'Review confidence change. Document reason in change history if intentional.',
              currentConfidence: confidence,
              previousConfidence: historicalConfidence,
            });
          }
        }
      }
    }

    return issues;
  }

  async checkConfidenceConflicts(currentReport, historicalReports) {
    const issues = [];

    const currentFindings = new Map();
    if (currentReport.findings) {
      for (const finding of currentReport.findings) {
        const key = this.normalizeStatement(finding.statement);
        currentFindings.set(key, finding);
      }
    }

    for (const historicalReport of historicalReports) {
      const historicalFindings = new Map();
      if (historicalReport.findings) {
        for (const finding of historicalReport.findings) {
          const key = this.normalizeStatement(finding.statement);
          historicalFindings.set(key, finding);
        }
      }

      for (const [key, currentFinding] of currentFindings.entries()) {
        if (historicalFindings.has(key)) {
          const historicalFinding = historicalFindings.get(key);
          if (currentFinding.confidence !== historicalFinding.confidence) {
            issues.push({
              severity: 'medium',
              category: 'consistency',
              code: 'FINDING_CONFIDENCE_CHANGED',
              message: `Finding confidence changed: "${currentFinding.statement.substring(0, 50)}..."`,
              currentConfidence: currentFinding.confidence,
              previousConfidence: historicalFinding.confidence,
              recommendation: 'Verify confidence change reflects new evidence, not analysis drift',
            });
          }
        }
      }
    }

    return issues;
  }

  async detectDuplicateIntelligence(currentReport, historicalReports) {
    const issues = [];

    const currentIOCs = new Set();
    if (currentReport.iocs) {
      for (const ioc of currentReport.iocs) {
        currentIOCs.add(`${ioc.type}:${ioc.value}`);
      }
    }

    for (const historicalReport of historicalReports) {
      const historicalIOCs = new Set();
      if (historicalReport.iocs) {
        for (const ioc of historicalReport.iocs) {
          historicalIOCs.add(`${ioc.type}:${ioc.value}`);
        }
      }

      const duplicates = [...currentIOCs].filter(ioc => historicalIOCs.has(ioc));
      if (duplicates.length > 0) {
        issues.push({
          severity: 'medium',
          category: 'consistency',
          code: 'DUPLICATE_IOCS',
          message: `${duplicates.length} IOC(s) already reported in previous reports`,
          duplicateCount: duplicates.length,
          duplicates: duplicates.slice(0, 5),
          recommendation: 'Verify these are not stale indicators. Document if revalidation adds value.',
        });
      }
    }

    return issues;
  }

  async checkTimelineConflicts(currentReport, historicalReports) {
    const issues = [];

    const currentEvents = new Map();
    if (currentReport.timeline) {
      for (const event of currentReport.timeline) {
        currentEvents.set(this.normalizeEventTime(event.timestamp), event);
      }
    }

    for (const historicalReport of historicalReports) {
      const historicalEvents = new Map();
      if (historicalReport.timeline) {
        for (const event of historicalReport.timeline) {
          historicalEvents.set(this.normalizeEventTime(event.timestamp), event);
        }
      }

      for (const [timestamp, currentEvent] of currentEvents.entries()) {
        if (historicalEvents.has(timestamp)) {
          const historicalEvent = historicalEvents.get(timestamp);
          if (currentEvent.event !== historicalEvent.event) {
            issues.push({
              severity: 'high',
              category: 'consistency',
              code: 'TIMELINE_CONFLICT',
              message: `Timeline event at ${timestamp} differs from previous report`,
              currentDescription: currentEvent.event,
              previousDescription: historicalEvent.event,
              recommendation: 'Verify timeline accuracy and document changes if intentional',
            });
          }
        }
      }
    }

    return issues;
  }

  async checkIOCConflicts(currentReport, historicalReports) {
    const issues = [];

    const staleThresholdDays = 90;

    if (currentReport.iocs) {
      for (const ioc of currentReport.iocs) {
        const iocKey = `ioc:${ioc.type}:${ioc.value}`;
        const lastSeenData = await this.redis.hgetall(iocKey);

        if (lastSeenData && lastSeenData.length > 0) {
          const lastSeenStr = lastSeenData.find((val, idx) => idx % 2 === 0 && idx + 1 < lastSeenData.length && lastSeenData[idx] === 'lastSeen');
          const lastSeenIdx = lastSeenData.indexOf('lastSeen');
          if (lastSeenIdx >= 0 && lastSeenIdx + 1 < lastSeenData.length) {
            const lastSeenDate = new Date(lastSeenData[lastSeenIdx + 1]);
            const daysSinceLastSeen = (Date.now() - lastSeenDate.getTime()) / (1000 * 60 * 60 * 24);

            if (daysSinceLastSeen > staleThresholdDays) {
              issues.push({
                severity: 'medium',
                category: 'consistency',
                code: 'STALE_IOC',
                message: `IOC ${ioc.type}:${ioc.value} last seen ${Math.round(daysSinceLastSeen)} days ago`,
                ioc: `${ioc.type}:${ioc.value}`,
                lastSeen: lastSeenData[lastSeenIdx + 1],
                recommendation: 'Verify IOC is still active. Consider removing if retired.',
              });
            }
          }
        }
      }
    }

    return issues;
  }

  calculateConsistencyScore(issues) {
    const criticalCount = issues.filter(i => i.severity === 'critical').length;
    const highCount = issues.filter(i => i.severity === 'high').length;
    const mediumCount = issues.filter(i => i.severity === 'medium').length;

    const penalty = (criticalCount * 20) + (highCount * 10) + (mediumCount * 5);
    return Math.max(0, 100 - penalty);
  }

  confidenceLevelValue(level) {
    const values = {
      confirmed: 4,
      likely: 3,
      possible: 2,
      unlikely: 1,
      unsubstantiated: 0,
    };
    return values[level] || 0;
  }

  normalizeStatement(statement) {
    return statement.toLowerCase().replace(/[^a-z0-9]/g, '');
  }

  normalizeEventTime(timestamp) {
    return new Date(timestamp).toISOString().split('T')[0];
  }
}

module.exports = { ConsistencyEngine };
